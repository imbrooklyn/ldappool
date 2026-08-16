package ldappool

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestImplicitTLSVerifiesDNSAndIPSANs(t *testing.T) {
	tests := []struct {
		name       string
		endpoint   string
		serverName string
		dnsNames   []string
		ips        []net.IP
		wantSNI    string
	}{
		{"DNS", "ldaps://ldap.example.test:636", "LDAP.EXAMPLE.TEST.", []string{"ldap.example.test"}, nil, "ldap.example.test"},
		{"DNS wildcard", "ldaps://node.example.test:636", "", []string{"*.example.test"}, nil, "node.example.test"},
		{"IP", "ldaps://127.0.0.1:636", "", nil, []net.IP{net.ParseIP("127.0.0.1")}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate, roots := testCertificate(t, test.dnsNames, test.ips)
			sni := make(chan string, 1)
			dialer := &testDialer{factory: tlsPipeFactory(t, &tls.Config{
				Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					sni <- hello.ServerName
					return nil, nil
				},
			})}
			pool, err := New(Config{
				Endpoint:       test.endpoint,
				TLS:            TLSConfig{Mode: TLSImplicit, ServerName: test.serverName, RootCAs: roots},
				Auth:           AuthConfig{Mode: AuthAnonymous},
				Dialer:         dialer,
				ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if got := receive(t, sni); got != test.wantSNI {
				t.Fatalf("TLS SNI = %q, want %q", got, test.wantSNI)
			}
			if err := pool.Close(contextWithTimeout(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImplicitTLSRejectsCertificateWithoutServerAuth(t *testing.T) {
	certificate, roots := testCertificateWithExtKeyUsage(
		t, []string{"ldap.example.test"}, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	dialer := &testDialer{factory: tlsPipeFactory(t, &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
	})}
	pool, err := New(Config{
		Endpoint: "ldaps://ldap.example.test:636",
		TLS:      TLSConfig{Mode: TLSImplicit, RootCAs: roots},
		Auth:     AuthConfig{Mode: AuthAnonymous}, Dialer: dialer,
		ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	var acquireErr *AcquireError
	if !errors.As(err, &acquireErr) || acquireErr.Stage != StageTLS {
		t.Fatalf("wrong EKU certificate error = %v", err)
	}
	_ = pool.Close(contextWithTimeout(t))
}

func TestImplicitTLSRejectsWrongIdentityCAAndVersion(t *testing.T) {
	certificate, roots := testCertificate(t, []string{"ldap.example.test"}, nil)
	tests := []struct {
		name       string
		serverName string
		roots      *x509.CertPool
		minVersion uint16
		serverMax  uint16
	}{
		{"wrong identity", "wrong.example.test", roots, tls.VersionTLS12, tls.VersionTLS13},
		{"wrong CA", "ldap.example.test", x509.NewCertPool(), tls.VersionTLS12, tls.VersionTLS13},
		{"minimum version", "ldap.example.test", roots, tls.VersionTLS13, tls.VersionTLS12},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &testDialer{factory: tlsPipeFactory(t, &tls.Config{
				Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: test.serverMax,
			})}
			pool, err := New(Config{
				Endpoint: "ldaps://ldap.example.test:636",
				TLS:      TLSConfig{Mode: TLSImplicit, ServerName: test.serverName, RootCAs: test.roots, MinVersion: test.minVersion},
				Auth:     AuthConfig{Mode: AuthAnonymous}, Dialer: dialer,
				ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
			if err == nil {
				t.Fatal("TLS verification unexpectedly succeeded")
			}
			var acquireErr *AcquireError
			if !errors.As(err, &acquireErr) || acquireErr.Stage != StageTLS {
				t.Fatalf("TLS error = %v", err)
			}
			_ = pool.Close(contextWithTimeout(t))
		})
	}
}

func TestImplicitTLSRejectsExpiredCertificate(t *testing.T) {
	now := time.Now()
	certificate, roots := testCertificateWithValidity(t, []string{"ldap.example.test"}, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	dialer := &testDialer{factory: tlsPipeFactory(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})}
	pool, err := New(Config{
		Endpoint: "ldaps://ldap.example.test:636",
		TLS:      TLSConfig{Mode: TLSImplicit, RootCAs: roots},
		Auth:     AuthConfig{Mode: AuthAnonymous}, Dialer: dialer,
		ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	var acquireErr *AcquireError
	if !errors.As(err, &acquireErr) || acquireErr.Stage != StageTLS {
		t.Fatalf("expired certificate error = %v", err)
	}
	_ = pool.Close(contextWithTimeout(t))
}

func TestStartTLSSucceedsBeforeLDAPUse(t *testing.T) {
	certificate, roots := testCertificate(t, []string{"ldap.example.test"}, nil)
	dialer := &testDialer{factory: func(_ context.Context, _ int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			reader := bufio.NewReader(server)
			request, err := readLDAPRequest(reader)
			if err != nil || request.tag != ldap.ApplicationExtendedRequest {
				_ = server.Close()
				return
			}
			if writeLDAPResult(server, request.messageID, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess, "") != nil {
				_ = server.Close()
				return
			}
			tlsServer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			if tlsServer.Handshake() != nil {
				_ = tlsServer.Close()
				return
			}
			successfulLDAPServer(tlsServer, 1)
		}()
		return client, nil
	}}
	pool, err := New(Config{
		Endpoint: "ldap://ldap.example.test:389",
		TLS:      TLSConfig{Mode: TLSStartTLS, RootCAs: roots},
		Auth:     AuthConfig{Mode: AuthAnonymous}, Dialer: dialer,
		ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestStartTLSRejectionNeverContinuesToBind(t *testing.T) {
	requests := make(chan byte, 2)
	dialer := &testDialer{factory: func(_ context.Context, _ int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			request, err := readLDAPRequest(reader)
			if err != nil {
				return
			}
			requests <- request.tag
			_ = writeLDAPResult(server, request.messageID, ldap.ApplicationExtendedResponse, ldap.LDAPResultUnwillingToPerform, "do not upgrade")
			if next, err := readLDAPRequest(reader); err == nil {
				requests <- next.tag
			}
		}()
		return client, nil
	}}
	_, roots := testCertificate(t, []string{"ldap.example.test"}, nil)
	config := Config{
		Endpoint: "ldap://ldap.example.test:389",
		TLS:      TLSConfig{Mode: TLSStartTLS, RootCAs: roots},
		Auth:     AuthConfig{Mode: AuthSimple, BindPrincipal: "cn=service", Password: NewSecret([]byte("secret"))},
		Dialer:   dialer, ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
	}
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	if err == nil {
		t.Fatal("rejected StartTLS unexpectedly succeeded")
	}
	if tag := receive(t, requests); tag != ldap.ApplicationExtendedRequest {
		t.Fatalf("first request tag = %d", tag)
	}
	select {
	case tag := <-requests:
		t.Fatalf("request tag %d was sent after StartTLS rejection", tag)
	default:
	}
	_ = pool.Close(contextWithTimeout(t))
}

func TestMutualTLSClientCertificate(t *testing.T) {
	serverCertificate, roots := testCertificate(t, []string{"ldap.example.test"}, nil)
	clientCertificate, clientRoots := testCertificate(t, []string{"client.example.test"}, nil)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
	}
	dialer := &testDialer{factory: tlsPipeFactory(t, serverConfig)}
	pool, err := New(Config{
		Endpoint: "ldaps://ldap.example.test:636",
		TLS:      TLSConfig{Mode: TLSImplicit, RootCAs: roots, ClientCertificates: []tls.Certificate{clientCertificate}},
		Auth:     AuthConfig{Mode: AuthAnonymous}, Dialer: dialer,
		ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}

	missingDialer := &testDialer{factory: tlsPipeFactory(t, serverConfig)}
	missingPool, err := New(Config{
		Endpoint: "ldaps://ldap.example.test:636",
		TLS:      TLSConfig{Mode: TLSImplicit, RootCAs: roots},
		Auth:     AuthConfig{Mode: AuthAnonymous}, Dialer: missingDialer,
		ConnectTimeout: testTimeout, RequestTimeout: testTimeout, CloseTimeout: testTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = missingPool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	var acquireErr *AcquireError
	if !errors.As(err, &acquireErr) || acquireErr.Stage != StageTLS {
		t.Fatalf("missing client certificate error = %v", err)
	}
	_ = missingPool.Close(contextWithTimeout(t))
}

func tlsPipeFactory(_ *testing.T, serverConfig *tls.Config) func(context.Context, int) (net.Conn, error) {
	return func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			tlsServer := tls.Server(server, serverConfig.Clone())
			if err := tlsServer.Handshake(); err != nil {
				_ = tlsServer.Close()
				return
			}
			successfulLDAPServer(tlsServer, call)
		}()
		return client, nil
	}
}
