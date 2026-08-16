package ldappool

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxOpen       = 8
	defaultMaxIdle       = 2
	defaultMaxWaiters    = 1024
	defaultIdleTime      = 5 * time.Minute
	defaultLifetime      = 30 * time.Minute
	defaultConnectTime   = 10 * time.Second
	defaultRequestTime   = 30 * time.Second
	defaultCloseTime     = 10 * time.Second
	defaultObserverQueue = 256
	maxObserverQueue     = 65536
)

// TLSMode controls how transport security is established.
type TLSMode uint8

const (
	// TLSAuto selects implicit TLS for ldaps:// and StartTLS for ldap://.
	TLSAuto TLSMode = iota
	// TLSStartTLS upgrades an ldap:// connection before authentication.
	TLSStartTLS
	// TLSImplicit establishes TLS before starting LDAP.
	TLSImplicit
	// TLSPlaintext disables transport encryption. Simple authentication also
	// requires AllowInsecurePlaintextCredentials and is intended only for
	// isolated development environments.
	TLSPlaintext
)

// AuthMode selects the fixed authentication identity for a Pool.
type AuthMode uint8

const (
	// AuthUnspecified is invalid and forces callers to choose an authentication mode.
	AuthUnspecified AuthMode = iota
	// AuthSimple performs one simple Bind while creating each connection.
	AuthSimple
	// AuthAnonymous sends no Bind request.
	AuthAnonymous
)

// Dialer creates a fresh transport for every call.
//
// Implementations must honor ctx and must never return the same live net.Conn
// instance from more than one call. A proxying implementation must still route
// the supplied address to one stable logical LDAP endpoint for the Pool's
// lifetime.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TLSConfig configures server authentication and optional client certificates.
type TLSConfig struct {
	// Mode selects implicit TLS, StartTLS, or the explicit plaintext escape
	// hatch. Its zero value is TLSAuto.
	Mode TLSMode
	// ServerName is the DNS name or IP reference identity used for verification.
	// An empty value uses the endpoint host.
	ServerName string
	// RootCAs replaces the system trust roots when non-nil. Nil uses the system
	// roots.
	RootCAs *x509.CertPool
	// ClientCertificates contains optional client certificate chains and keys.
	// Certificate slices and DER are copied; arbitrary private-key signers are
	// retained by reference and must be immutable after New.
	ClientCertificates []tls.Certificate
	// MinVersion is either tls.VersionTLS12 or tls.VersionTLS13. Zero defaults
	// to TLS 1.2.
	MinVersion uint16
}

// String returns a constant redacted representation.
func (TLSConfig) String() string { return "ldappool.TLSConfig{[REDACTED]}" }

// GoString returns a constant redacted representation.
func (TLSConfig) GoString() string { return "ldappool.TLSConfig{[REDACTED]}" }

// AuthConfig configures the Pool's fixed LDAP authentication identity.
type AuthConfig struct {
	// Mode must explicitly select simple or anonymous authentication.
	Mode AuthMode
	// BindPrincipal is the fixed simple-Bind identity.
	BindPrincipal string
	// Password is the fixed simple-Bind secret.
	Password Secret
}

// String returns a constant redacted representation.
func (AuthConfig) String() string { return "ldappool.AuthConfig{[REDACTED]}" }

// GoString returns a constant redacted representation.
func (AuthConfig) GoString() string { return "ldappool.AuthConfig{[REDACTED]}" }

// BackoffConfig configures capped exponential backoff with multiplicative
// jitter. Jitter is a fraction in [0, 1).
type BackoffConfig struct {
	// Initial is the first failure delay.
	Initial time.Duration
	// Multiplier controls exponential growth and must be at least one.
	Multiplier float64
	// Max caps the jittered delay.
	Max time.Duration
	// Jitter is a multiplicative fraction in [0, 1).
	Jitter float64
}

// Config configures a Pool. New applies documented defaults, validates all
// fields, and copies copyable security material. Trusted interface values and
// arbitrary private-key signers are retained by reference and must be immutable
// after New. Changing ordinary Config fields after New has no effect.
type Config struct {
	// Endpoint is a required ldap:// or ldaps:// URL containing only host and port.
	Endpoint string
	// TLS configures transport encryption and peer verification.
	TLS TLSConfig
	// Auth configures the fixed LDAP identity.
	Auth AuthConfig

	// AllowInsecurePlaintextCredentials is a development-only second gate for a
	// plaintext simple Bind.
	AllowInsecurePlaintextCredentials bool

	// MaxOpen includes connecting, idle, borrowed, and physically closing
	// connections. Zero defaults to 8.
	MaxOpen int
	// MaxIdle bounds retained idle connections. Zero defaults to min(2, MaxOpen).
	MaxIdle int
	// MaxWaiters bounds externally queued acquisitions. Zero defaults to 1024.
	MaxWaiters int

	// MaxIdleTime retires a connection after this idle duration. Zero defaults
	// to 5 minutes.
	MaxIdleTime time.Duration
	// MaxLifetime retires a connection after this total lifetime. Zero defaults
	// to 30 minutes; it is independent of MaxIdleTime.
	MaxLifetime time.Duration
	// ConnectTimeout bounds Dial, TLS, and Bind together. Zero defaults to 10 seconds.
	ConnectTimeout time.Duration
	// RequestTimeout bounds one public synchronous operation. Zero defaults to 30 seconds.
	RequestTimeout time.Duration
	// CloseTimeout bounds shutdown, callback cleanup, and Warmup cleanup waits.
	// Zero defaults to 10 seconds.
	CloseTimeout time.Duration

	// ConnectBackoff limits new connection attempts after ordinary failures.
	// Zero fields default to 100ms initial, 2x, 30s maximum, and 20% jitter.
	ConnectBackoff BackoffConfig
	// CredentialBackoff controls delayed credential probes. Zero fields default
	// to 5s initial, 2x, 5m maximum, and 30% jitter.
	CredentialBackoff BackoffConfig

	// Dialer optionally supplies a context-aware transport. Nil uses net.Dialer.
	Dialer Dialer
	// CredentialFailureClassifier optionally applies deployment credential
	// policy. Nil uses the conservative built-in classifier.
	CredentialFailureClassifier CredentialFailureClassifier
	// Observer optionally receives redacted asynchronous events. Nil disables events.
	Observer Observer
	// ObserverBuffer bounds the observer event queue. Zero defaults to 256 when
	// Observer is non-nil and is invalid otherwise when nonzero.
	ObserverBuffer int
}

// String returns a constant redacted representation.
func (Config) String() string { return "ldappool.Config{[REDACTED]}" }

// GoString returns a constant redacted representation.
func (Config) GoString() string { return "ldappool.Config{[REDACTED]}" }

type resolvedConfig struct {
	address       string
	tlsMode       TLSMode
	tlsConfig     *tls.Config
	authMode      AuthMode
	bindPrincipal string
	password      []byte

	allowPlaintext    bool
	maxOpen           int
	maxIdle           int
	maxWaiters        int
	maxIdleTime       time.Duration
	maxLifetime       time.Duration
	connectTimeout    time.Duration
	requestTimeout    time.Duration
	closeTimeout      time.Duration
	connectBackoff    backoffPolicy
	credentialBackoff backoffPolicy
	dialer            Dialer
	classifier        CredentialFailureClassifier
	observer          Observer
	observerBuffer    int
}

type backoffPolicy struct {
	initial    time.Duration
	multiplier float64
	max        time.Duration
	jitter     float64
}

func resolveConfig(c Config) (resolvedConfig, error) {
	var out resolvedConfig
	u, address, err := normalizeEndpoint(c.Endpoint)
	if err != nil {
		return out, err
	}
	out.address = address

	mode := c.TLS.Mode
	if mode == TLSAuto {
		if u.Scheme == "ldaps" {
			mode = TLSImplicit
		} else {
			mode = TLSStartTLS
		}
	}
	switch mode {
	case TLSImplicit:
		if u.Scheme != "ldaps" {
			return out, configError("TLS.Mode", "implicit TLS requires an ldaps:// endpoint")
		}
	case TLSStartTLS, TLSPlaintext:
		if u.Scheme != "ldap" {
			return out, configError("TLS.Mode", "StartTLS and plaintext require an ldap:// endpoint")
		}
	default:
		return out, configError("TLS.Mode", "unsupported TLS mode")
	}
	out.tlsMode = mode
	out.allowPlaintext = c.AllowInsecurePlaintextCredentials
	if mode == TLSPlaintext && (c.TLS.ServerName != "" || c.TLS.RootCAs != nil || len(c.TLS.ClientCertificates) != 0 || c.TLS.MinVersion != 0) {
		return out, configError("TLS", "certificate settings cannot be used in plaintext mode")
	}

	serverName, err := normalizeServerName(c.TLS.ServerName, u.Hostname())
	if err != nil {
		return out, err
	}
	minVersion := c.TLS.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	if minVersion != tls.VersionTLS12 && minVersion != tls.VersionTLS13 {
		return out, configError("TLS.MinVersion", "must be TLS 1.2 or TLS 1.3")
	}
	if mode != TLSPlaintext {
		for _, certificate := range c.TLS.ClientCertificates {
			if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
				return out, configError("TLS.ClientCertificates", "each certificate requires a chain and private key")
			}
			for _, encoded := range certificate.Certificate {
				if _, parseErr := x509.ParseCertificate(encoded); parseErr != nil {
					return out, configError("TLS.ClientCertificates", "contains an invalid certificate")
				}
			}
		}
		out.tlsConfig = &tls.Config{
			ServerName:   serverName,
			MinVersion:   minVersion,
			RootCAs:      cloneCertPool(c.TLS.RootCAs),
			Certificates: cloneCertificates(c.TLS.ClientCertificates),
		}
	}

	switch c.Auth.Mode {
	case AuthSimple:
		if strings.TrimSpace(c.Auth.BindPrincipal) == "" {
			return out, configError("Auth.BindPrincipal", "is required for simple authentication")
		}
		if c.Auth.Password.empty() {
			return out, configError("Auth.Password", "must not be empty for simple authentication")
		}
		if mode == TLSPlaintext && !c.AllowInsecurePlaintextCredentials {
			return out, configError("AllowInsecurePlaintextCredentials", "must be explicitly enabled for a plaintext simple Bind")
		}
		out.bindPrincipal = c.Auth.BindPrincipal
	case AuthAnonymous:
		if c.Auth.BindPrincipal != "" || !c.Auth.Password.empty() {
			return out, configError("Auth", "anonymous authentication cannot include a principal or password")
		}
	default:
		return out, configError("Auth.Mode", "must explicitly select simple or anonymous authentication")
	}
	out.authMode = c.Auth.Mode
	if c.AllowInsecurePlaintextCredentials && !(mode == TLSPlaintext && c.Auth.Mode == AuthSimple) {
		return out, configError("AllowInsecurePlaintextCredentials", "is valid only for plaintext simple authentication")
	}

	if out.maxOpen, err = defaultPositiveInt("MaxOpen", c.MaxOpen, defaultMaxOpen); err != nil {
		return out, err
	}
	defaultIdle := defaultMaxIdle
	if out.maxOpen < defaultIdle {
		defaultIdle = out.maxOpen
	}
	if out.maxIdle, err = defaultPositiveInt("MaxIdle", c.MaxIdle, defaultIdle); err != nil {
		return out, err
	}
	if out.maxIdle > out.maxOpen {
		return out, configError("MaxIdle", "must not exceed MaxOpen")
	}
	if out.maxWaiters, err = defaultPositiveInt("MaxWaiters", c.MaxWaiters, defaultMaxWaiters); err != nil {
		return out, err
	}
	if out.maxIdleTime, err = defaultDuration("MaxIdleTime", c.MaxIdleTime, defaultIdleTime); err != nil {
		return out, err
	}
	if out.maxLifetime, err = defaultDuration("MaxLifetime", c.MaxLifetime, defaultLifetime); err != nil {
		return out, err
	}
	if out.connectTimeout, err = defaultDuration("ConnectTimeout", c.ConnectTimeout, defaultConnectTime); err != nil {
		return out, err
	}
	if out.requestTimeout, err = defaultDuration("RequestTimeout", c.RequestTimeout, defaultRequestTime); err != nil {
		return out, err
	}
	if out.closeTimeout, err = defaultDuration("CloseTimeout", c.CloseTimeout, defaultCloseTime); err != nil {
		return out, err
	}
	if out.connectBackoff, err = resolveBackoff("ConnectBackoff", c.ConnectBackoff, BackoffConfig{
		Initial: 100 * time.Millisecond, Multiplier: 2, Max: 30 * time.Second, Jitter: .20,
	}); err != nil {
		return out, err
	}
	if out.credentialBackoff, err = resolveBackoff("CredentialBackoff", c.CredentialBackoff, BackoffConfig{
		Initial: 5 * time.Second, Multiplier: 2, Max: 5 * time.Minute, Jitter: .30,
	}); err != nil {
		return out, err
	}
	if c.Dialer == nil {
		out.dialer = &net.Dialer{}
	} else {
		out.dialer = c.Dialer
	}
	out.classifier = c.CredentialFailureClassifier
	out.observer = c.Observer
	if c.ObserverBuffer < 0 {
		return out, configError("ObserverBuffer", "must not be negative")
	}
	if c.Observer == nil && c.ObserverBuffer != 0 {
		return out, configError("ObserverBuffer", "requires an Observer")
	}
	if c.ObserverBuffer > maxObserverQueue {
		return out, configError("ObserverBuffer", "must not exceed 65536")
	}
	if c.Observer != nil {
		out.observerBuffer = c.ObserverBuffer
		if out.observerBuffer == 0 {
			out.observerBuffer = defaultObserverQueue
		}
	}
	if out.authMode == AuthSimple {
		out.password = c.Auth.Password.cloneBytes()
	}
	return out, nil
}

func normalizeEndpoint(raw string) (*url.URL, string, error) {
	if raw == "" {
		return nil, "", configError("Endpoint", "is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", configError("Endpoint", "is not a valid URL")
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, "", configError("Endpoint", "scheme must be ldap or ldaps")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || (u.Path != "" && u.Path != "/") {
		return nil, "", configError("Endpoint", "must contain only scheme, host, and optional port")
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", configError("Endpoint", "host is required")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return nil, "", configError("Endpoint", "port must not be empty")
	}
	if port == "" {
		if u.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	} else if n, parseErr := strconv.Atoi(port); parseErr != nil || n < 1 || n > 65535 {
		return nil, "", configError("Endpoint", "port must be between 1 and 65535")
	}
	return u, net.JoinHostPort(host, port), nil
}

func normalizeServerName(given, endpointHost string) (string, error) {
	name := given
	if name == "" {
		name = endpointHost
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" || strings.Contains(name, ":") && net.ParseIP(name) == nil {
		return "", configError("TLS.ServerName", "must be a DNS name or IP address without a port")
	}
	for _, r := range name {
		if r > 127 {
			return "", configError("TLS.ServerName", "must use an ASCII A-label for internationalized names")
		}
	}
	if ip := net.ParseIP(name); ip != nil {
		return ip.String(), nil
	}
	name = strings.ToLower(name)
	if len(name) > 253 {
		return "", configError("TLS.ServerName", "DNS name is too long")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", configError("TLS.ServerName", "contains an invalid DNS label")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", configError("TLS.ServerName", "contains an invalid DNS label")
			}
		}
	}
	return name, nil
}

func cloneCertPool(pool *x509.CertPool) *x509.CertPool {
	if pool == nil {
		return nil
	}
	return pool.Clone()
}

func cloneCertificates(in []tls.Certificate) []tls.Certificate {
	out := make([]tls.Certificate, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Certificate = cloneByteSlices(in[i].Certificate)
		out[i].OCSPStaple = append([]byte(nil), in[i].OCSPStaple...)
		out[i].SignedCertificateTimestamps = cloneByteSlices(in[i].SignedCertificateTimestamps)
		out[i].SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), in[i].SupportedSignatureAlgorithms...)
		out[i].Leaf = nil
	}
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func defaultPositiveInt(field string, value, fallback int) (int, error) {
	if value < 0 {
		return 0, configError(field, "must not be negative")
	}
	if value == 0 {
		return fallback, nil
	}
	return value, nil
}

func defaultDuration(field string, value, fallback time.Duration) (time.Duration, error) {
	if value < 0 {
		return 0, configError(field, "must not be negative")
	}
	if value == 0 {
		return fallback, nil
	}
	return value, nil
}

func resolveBackoff(field string, value, fallback BackoffConfig) (backoffPolicy, error) {
	if value.Initial < 0 || value.Max < 0 || value.Multiplier < 0 || value.Jitter < 0 ||
		math.IsNaN(value.Multiplier) || math.IsInf(value.Multiplier, 0) || math.IsNaN(value.Jitter) || math.IsInf(value.Jitter, 0) {
		return backoffPolicy{}, configError(field, "values must not be negative")
	}
	if value.Initial == 0 {
		value.Initial = fallback.Initial
	}
	if value.Multiplier == 0 {
		value.Multiplier = fallback.Multiplier
	}
	if value.Max == 0 {
		value.Max = fallback.Max
	}
	if value.Jitter == 0 {
		value.Jitter = fallback.Jitter
	}
	if value.Initial <= 0 || value.Multiplier < 1 || value.Max < value.Initial || value.Jitter < 0 || value.Jitter >= 1 {
		return backoffPolicy{}, configError(field, "requires Initial > 0, Multiplier >= 1, Max >= Initial, and Jitter in [0,1)")
	}
	return backoffPolicy{value.Initial, value.Multiplier, value.Max, value.Jitter}, nil
}

func (c resolvedConfig) tlsClone() *tls.Config {
	if c.tlsConfig == nil {
		return nil
	}
	return c.tlsConfig.Clone()
}

func configError(field, reason string) error {
	return &ConfigError{Field: field, Reason: reason}
}

// String returns the stable TLS mode name.
func (m TLSMode) String() string {
	switch m {
	case TLSAuto:
		return "auto"
	case TLSStartTLS:
		return "starttls"
	case TLSImplicit:
		return "implicit"
	case TLSPlaintext:
		return "plaintext"
	default:
		return fmt.Sprintf("TLSMode(%d)", m)
	}
}
