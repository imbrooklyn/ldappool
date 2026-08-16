package ldappool

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestNewIsLazyAndAppliesDefaults(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(Config{
		Endpoint: "ldap://ldap.example.test",
		TLS:      TLSConfig{Mode: TLSPlaintext},
		Auth:     AuthConfig{Mode: AuthAnonymous},
		Dialer:   dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 0 {
		t.Fatalf("New dialed %d time(s), want 0", dialer.count())
	}
	if pool.cfg.maxOpen != defaultMaxOpen || pool.cfg.maxIdle != defaultMaxIdle {
		t.Fatalf("unexpected defaults: maxOpen=%d maxIdle=%d", pool.cfg.maxOpen, pool.cfg.maxIdle)
	}
	if pool.Snapshot().State != PoolCold {
		t.Fatalf("new pool state = %s, want cold", pool.Snapshot().State)
	}
	if snapshot := pool.Snapshot(); snapshot.LastFailureStage != StageNone || snapshot.LastFailureReason != ReasonNone {
		t.Fatalf("new pool failure projection = %s/%s", snapshot.LastFailureStage, snapshot.LastFailureReason)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	clientCertificate, _ := testCertificate(t, []string{"client.example.test"}, nil)
	valid := Config{
		Endpoint: "ldap://ldap.example.test",
		TLS:      TLSConfig{Mode: TLSStartTLS},
		Auth:     AuthConfig{Mode: AuthAnonymous},
	}
	tests := []struct {
		name   string
		change func(*Config)
		field  string
	}{
		{"missing endpoint", func(c *Config) { c.Endpoint = "" }, "Endpoint"},
		{"malformed URL", func(c *Config) { c.Endpoint = "ldap://%" }, "Endpoint"},
		{"unsupported scheme", func(c *Config) { c.Endpoint = "http://ldap.example.test" }, "Endpoint"},
		{"missing host", func(c *Config) { c.Endpoint = "ldap://:389" }, "Endpoint"},
		{"userinfo", func(c *Config) { c.Endpoint = "ldap://user@ldap.example.test" }, "Endpoint"},
		{"path", func(c *Config) { c.Endpoint = "ldap://ldap.example.test/base" }, "Endpoint"},
		{"query", func(c *Config) { c.Endpoint = "ldap://ldap.example.test?base=x" }, "Endpoint"},
		{"fragment", func(c *Config) { c.Endpoint = "ldap://ldap.example.test#base" }, "Endpoint"},
		{"bad port", func(c *Config) { c.Endpoint = "ldap://ldap.example.test:99999" }, "Endpoint"},
		{"empty port", func(c *Config) { c.Endpoint = "ldap://ldap.example.test:" }, "Endpoint"},
		{"empty query", func(c *Config) { c.Endpoint = "ldap://ldap.example.test?" }, "Endpoint"},
		{"empty fragment", func(c *Config) { c.Endpoint = "ldap://ldap.example.test#" }, "Endpoint"},
		{"implicit mismatch", func(c *Config) { c.TLS.Mode = TLSImplicit }, "TLS.Mode"},
		{"starttls mismatch", func(c *Config) { c.Endpoint = "ldaps://ldap.example.test" }, "TLS.Mode"},
		{"unsupported TLS mode", func(c *Config) { c.TLS.Mode = TLSMode(255) }, "TLS.Mode"},
		{"bad server name", func(c *Config) { c.TLS.ServerName = "host:636" }, "TLS.ServerName"},
		{"empty normalized server name", func(c *Config) { c.TLS.ServerName = "." }, "TLS.ServerName"},
		{"bad DNS label", func(c *Config) { c.TLS.ServerName = "bad name.example" }, "TLS.ServerName"},
		{"empty DNS label", func(c *Config) { c.TLS.ServerName = "bad..example" }, "TLS.ServerName"},
		{"leading DNS hyphen", func(c *Config) { c.TLS.ServerName = "-bad.example" }, "TLS.ServerName"},
		{"trailing DNS hyphen", func(c *Config) { c.TLS.ServerName = "bad-.example" }, "TLS.ServerName"},
		{"long DNS label", func(c *Config) { c.TLS.ServerName = strings.Repeat("a", 64) + ".example" }, "TLS.ServerName"},
		{"long DNS name", func(c *Config) { c.TLS.ServerName = strings.Repeat("a.", 127) + "aa" }, "TLS.ServerName"},
		{"unicode server name", func(c *Config) { c.TLS.ServerName = "münchen.example" }, "TLS.ServerName"},
		{"old TLS", func(c *Config) { c.TLS.MinVersion = tls.VersionTLS11 }, "TLS.MinVersion"},
		{"empty client certificate", func(c *Config) { c.TLS.ClientCertificates = []tls.Certificate{{}} }, "TLS.ClientCertificates"},
		{"client certificate without key", func(c *Config) {
			certificate := clientCertificate
			certificate.PrivateKey = nil
			c.TLS.ClientCertificates = []tls.Certificate{certificate}
		}, "TLS.ClientCertificates"},
		{"invalid client certificate DER", func(c *Config) {
			certificate := clientCertificate
			certificate.Certificate = [][]byte{{0x01, 0x02, 0x03}}
			c.TLS.ClientCertificates = []tls.Certificate{certificate}
		}, "TLS.ClientCertificates"},
		{"auth unspecified", func(c *Config) { c.Auth.Mode = AuthUnspecified }, "Auth.Mode"},
		{"unsupported auth mode", func(c *Config) { c.Auth.Mode = AuthMode(255) }, "Auth.Mode"},
		{"simple principal", func(c *Config) { c.Auth = AuthConfig{Mode: AuthSimple, Password: NewSecret([]byte("x"))} }, "Auth.BindPrincipal"},
		{"simple password", func(c *Config) { c.Auth = AuthConfig{Mode: AuthSimple, BindPrincipal: "cn=service"} }, "Auth.Password"},
		{"anonymous fields", func(c *Config) { c.Auth.BindPrincipal = "cn=service" }, "Auth"},
		{"anonymous password", func(c *Config) { c.Auth.Password = NewSecret([]byte("x")) }, "Auth"},
		{"plaintext simple", func(c *Config) {
			c.TLS.Mode = TLSPlaintext
			c.Auth = AuthConfig{Mode: AuthSimple, BindPrincipal: "cn=service", Password: NewSecret([]byte("x"))}
		}, "AllowInsecurePlaintextCredentials"},
		{"plaintext certificate settings", func(c *Config) { c.TLS.Mode = TLSPlaintext; c.TLS.ServerName = "ldap.example.test" }, "TLS"},
		{"plaintext root CA", func(c *Config) { c.TLS.Mode = TLSPlaintext; c.TLS.RootCAs = x509.NewCertPool() }, "TLS"},
		{"unused plaintext flag", func(c *Config) { c.AllowInsecurePlaintextCredentials = true }, "AllowInsecurePlaintextCredentials"},
		{"negative max open", func(c *Config) { c.MaxOpen = -1 }, "MaxOpen"},
		{"negative max idle", func(c *Config) { c.MaxIdle = -1 }, "MaxIdle"},
		{"max idle", func(c *Config) { c.MaxOpen = 1; c.MaxIdle = 2 }, "MaxIdle"},
		{"negative waiter", func(c *Config) { c.MaxWaiters = -1 }, "MaxWaiters"},
		{"negative idle", func(c *Config) { c.MaxIdleTime = -1 }, "MaxIdleTime"},
		{"negative lifetime", func(c *Config) { c.MaxLifetime = -1 }, "MaxLifetime"},
		{"negative connect timeout", func(c *Config) { c.ConnectTimeout = -1 }, "ConnectTimeout"},
		{"negative request timeout", func(c *Config) { c.RequestTimeout = -1 }, "RequestTimeout"},
		{"negative close timeout", func(c *Config) { c.CloseTimeout = -1 }, "CloseTimeout"},
		{"bad backoff multiplier", func(c *Config) { c.ConnectBackoff.Multiplier = .5 }, "ConnectBackoff"},
		{"negative backoff initial", func(c *Config) { c.ConnectBackoff.Initial = -1 }, "ConnectBackoff"},
		{"negative backoff max", func(c *Config) { c.ConnectBackoff.Max = -1 }, "ConnectBackoff"},
		{"negative backoff multiplier", func(c *Config) { c.ConnectBackoff.Multiplier = -1 }, "ConnectBackoff"},
		{"negative backoff jitter", func(c *Config) { c.ConnectBackoff.Jitter = -1 }, "ConnectBackoff"},
		{"backoff max below initial", func(c *Config) { c.ConnectBackoff.Initial = time.Second; c.ConnectBackoff.Max = time.Millisecond }, "ConnectBackoff"},
		{"bad jitter", func(c *Config) { c.CredentialBackoff.Jitter = 1 }, "CredentialBackoff"},
		{"NaN jitter", func(c *Config) { c.CredentialBackoff.Jitter = math.NaN() }, "CredentialBackoff"},
		{"NaN multiplier", func(c *Config) { c.CredentialBackoff.Multiplier = math.NaN() }, "CredentialBackoff"},
		{"infinite multiplier", func(c *Config) { c.ConnectBackoff.Multiplier = math.Inf(1) }, "ConnectBackoff"},
		{"infinite jitter", func(c *Config) { c.ConnectBackoff.Jitter = math.Inf(1) }, "ConnectBackoff"},
		{"negative observer buffer", func(c *Config) { c.Observer = ObserverFunc(func(Event) {}); c.ObserverBuffer = -1 }, "ObserverBuffer"},
		{"observer buffer without observer", func(c *Config) { c.ObserverBuffer = 1 }, "ObserverBuffer"},
		{"observer buffer too large", func(c *Config) { c.Observer = ObserverFunc(func(Event) {}); c.ObserverBuffer = maxObserverQueue + 1 }, "ObserverBuffer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			pool, err := New(config)
			if pool != nil {
				_ = pool.ForceClose(contextWithTimeout(t))
				t.Fatal("New returned a non-nil Pool for invalid configuration")
			}
			var configErr *ConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("error %T does not match *ConfigError", err)
			}
			if configErr.Field != test.field {
				t.Fatalf("field = %q, want %q", configErr.Field, test.field)
			}
		})
	}
}

func TestEndpointAndServerNameNormalization(t *testing.T) {
	tests := []struct {
		endpoint   string
		serverName string
		address    string
		wantName   string
	}{
		{"ldap://EXAMPLE.COM", "", "EXAMPLE.COM:389", "example.com"},
		{"ldaps://example.com/", "EXAMPLE.COM.", "example.com:636", "example.com"},
		{"ldaps://127.0.0.1:1636", "", "127.0.0.1:1636", "127.0.0.1"},
		{"ldaps://[2001:db8::1]", "directory.example", "[2001:db8::1]:636", "directory.example"},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			mode := TLSStartTLS
			if strings.HasPrefix(test.endpoint, "ldaps") {
				mode = TLSImplicit
			}
			resolved, err := resolveConfig(Config{
				Endpoint: test.endpoint,
				TLS:      TLSConfig{Mode: mode, ServerName: test.serverName},
				Auth:     AuthConfig{Mode: AuthAnonymous},
			})
			if err != nil {
				t.Fatal(err)
			}
			if resolved.address != test.address || resolved.tlsConfig.ServerName != test.wantName {
				t.Fatalf("got address=%q name=%q", resolved.address, resolved.tlsConfig.ServerName)
			}
		})
	}
}

func TestSecretIsAlwaysRedactedAndCopied(t *testing.T) {
	input := []byte("secret")
	secret := NewSecret(input)
	input[0] = 'X'
	if got := fmt.Sprintf("%s %#v", secret, secret); strings.Contains(got, "secret") || got != "[REDACTED] [REDACTED]" {
		t.Fatalf("secret formatting was not redacted: %q", got)
	}
	if string(secret.cloneBytes()) != "secret" {
		t.Fatal("NewSecret did not copy its input")
	}
}

func TestSensitiveContainerFormattingIsAlwaysRedacted(t *testing.T) {
	const principal = "cn=format-secret,dc=example"
	const password = "format-password-secret"
	config := Config{
		Endpoint: "ldap://ldap.example.test",
		TLS:      TLSConfig{Mode: TLSPlaintext},
		Auth: AuthConfig{
			Mode: AuthSimple, BindPrincipal: principal, Password: NewSecret([]byte(password)),
		},
		AllowInsecurePlaintextCredentials: true,
		Dialer:                            &testDialer{factory: pipeFactory(successfulLDAPServer, nil)},
	}
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool.Close(contextWithTimeout(t)) }()

	values := []any{
		config,
		config.TLS,
		config.Auth,
		pool,
		*pool,
		CredentialFailure{ResultCode: 49, Diagnostic: "format-diagnostic-secret"},
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		for _, sensitive := range []string{principal, password, "format-diagnostic-secret"} {
			if strings.Contains(formatted, sensitive) {
				t.Fatalf("%T formatting leaked sensitive data: %q", value, formatted)
			}
		}
		if !strings.Contains(formatted, redactedSecret) {
			t.Fatalf("%T formatting was not explicitly redacted: %q", value, formatted)
		}
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		formatted := fmt.Sprintf("%v %+v %#v %v %+v %#v", connection, connection, connection, *connection, *connection, *connection)
		if strings.Contains(formatted, principal) || strings.Contains(formatted, password) || !strings.Contains(formatted, redactedSecret) {
			t.Fatalf("Connection formatting was not redacted: %q", formatted)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTLSMaterialIsDefensivelyCopied(t *testing.T) {
	certificate, roots := testCertificate(t, []string{"ldap.example.test"}, nil)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certificate.Leaf = leaf
	certificate.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PSSWithSHA256}
	resolved, err := resolveConfig(Config{
		Endpoint: "ldaps://ldap.example.test",
		TLS: TLSConfig{
			Mode: TLSImplicit, RootCAs: roots, ClientCertificates: []tls.Certificate{certificate},
		},
		Auth: AuthConfig{Mode: AuthAnonymous},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantByte := resolved.tlsConfig.Certificates[0].Certificate[0][0]
	certificate.Certificate[0][0] ^= 0xff
	certificate.SupportedSignatureAlgorithms[0] = tls.PKCS1WithSHA1
	if resolved.tlsConfig.Certificates[0].Certificate[0][0] != wantByte {
		t.Fatal("certificate DER was aliased")
	}
	if resolved.tlsConfig.Certificates[0].SupportedSignatureAlgorithms[0] != tls.PSSWithSHA256 {
		t.Fatal("signature algorithm slice was aliased")
	}
	if resolved.tlsConfig.Certificates[0].Leaf != nil {
		t.Fatal("parsed Leaf pointer was retained instead of reparsing copied DER")
	}
	otherCertificate, _ := testCertificate(t, []string{"third.example.test"}, nil)
	otherLeaf, err := x509.ParseCertificate(otherCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	before := len(resolved.tlsConfig.RootCAs.Subjects())
	roots.AddCert(otherLeaf)
	if len(resolved.tlsConfig.RootCAs.Subjects()) != before {
		t.Fatal("root CA pool was aliased")
	}
}

func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}
