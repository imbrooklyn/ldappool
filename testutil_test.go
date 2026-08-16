package ldappool

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testTimeout = 3 * time.Second

type ldapWireRequest struct {
	messageID int64
	tag       byte
}

type testDialer struct {
	mu      sync.Mutex
	calls   int
	factory func(context.Context, int) (net.Conn, error)
}

func (d *testDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	return d.factory(ctx, call)
}

func (d *testDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type countedConn struct {
	net.Conn
	closes  atomic.Int32
	started chan struct{}
	allow   <-chan struct{}
	once    sync.Once
}

func (c *countedConn) Close() error {
	c.closes.Add(1)
	c.once.Do(func() {
		if c.started != nil {
			close(c.started)
		}
	})
	if c.allow != nil {
		<-c.allow
	}
	return c.Conn.Close()
}

func pipeFactory(handler func(net.Conn, int), wrapped func(net.Conn, int) net.Conn) func(context.Context, int) (net.Conn, error) {
	return func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		go handler(server, call)
		if wrapped != nil {
			client = wrapped(client, call)
		}
		return client, nil
	}
}

func successfulLDAPServer(conn net.Conn, _ int) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		responseTag := responseTag(request.tag)
		code := uint16(0)
		if request.tag == 14 {
			code = 6
		}
		if err := writeLDAPResult(conn, request.messageID, responseTag, code, ""); err != nil {
			return
		}
	}
}

func anonymousTestConfig(dialer Dialer) Config {
	return Config{
		Endpoint:       "ldap://ldap.example.test:389",
		TLS:            TLSConfig{Mode: TLSPlaintext},
		Auth:           AuthConfig{Mode: AuthAnonymous},
		Dialer:         dialer,
		MaxOpen:        2,
		MaxIdle:        2,
		MaxWaiters:     32,
		ConnectTimeout: time.Second,
		RequestTimeout: time.Second,
		CloseTimeout:   time.Second,
		MaxIdleTime:    time.Minute,
		MaxLifetime:    time.Minute,
	}
}

func simpleTestConfig(dialer Dialer) Config {
	config := anonymousTestConfig(dialer)
	config.Auth = AuthConfig{
		Mode: AuthSimple, BindPrincipal: "cn=service,dc=example,dc=test", Password: NewSecret([]byte("secret")),
	}
	config.AllowInsecurePlaintextCredentials = true
	return config
}

func readLDAPRequest(reader *bufio.Reader) (ldapWireRequest, error) {
	tag, err := reader.ReadByte()
	if err != nil {
		return ldapWireRequest{}, err
	}
	if tag != 0x30 {
		return ldapWireRequest{}, errors.New("expected LDAP message sequence")
	}
	length, err := readBERLength(reader)
	if err != nil {
		return ldapWireRequest{}, err
	}
	payload := make([]byte, length)
	if _, err = io.ReadFull(reader, payload); err != nil {
		return ldapWireRequest{}, err
	}
	offset := 0
	if len(payload) < 3 || payload[offset] != 0x02 {
		return ldapWireRequest{}, errors.New("missing LDAP message ID")
	}
	offset++
	idLength, n, err := decodeBERLength(payload[offset:])
	if err != nil {
		return ldapWireRequest{}, err
	}
	offset += n
	if idLength < 1 || offset+idLength >= len(payload) {
		return ldapWireRequest{}, errors.New("invalid LDAP message ID")
	}
	var id int64
	for _, b := range payload[offset : offset+idLength] {
		id = id<<8 | int64(b)
	}
	offset += idLength
	applicationTag := payload[offset] & 0x1f
	return ldapWireRequest{messageID: id, tag: applicationTag}, nil
}

func readBERLength(reader *bufio.Reader) (int, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	if first&0x80 == 0 {
		return int(first), nil
	}
	count := int(first & 0x7f)
	if count < 1 || count > 4 {
		return 0, errors.New("unsupported BER length")
	}
	buffer := make([]byte, count)
	if _, err = io.ReadFull(reader, buffer); err != nil {
		return 0, err
	}
	var length int
	for _, b := range buffer {
		length = length<<8 | int(b)
	}
	return length, nil
}

func decodeBERLength(buffer []byte) (int, int, error) {
	if len(buffer) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	if buffer[0]&0x80 == 0 {
		return int(buffer[0]), 1, nil
	}
	count := int(buffer[0] & 0x7f)
	if count < 1 || count > 4 || len(buffer) < count+1 {
		return 0, 0, errors.New("invalid BER length")
	}
	var length int
	for _, b := range buffer[1 : count+1] {
		length = length<<8 | int(b)
	}
	return length, count + 1, nil
}

func responseTag(requestTag byte) byte {
	switch requestTag {
	case 0:
		return 1
	case 3:
		return 5
	case 6:
		return 7
	case 8:
		return 9
	case 10:
		return 11
	case 12:
		return 13
	case 14:
		return 15
	case 23:
		return 24
	default:
		return requestTag + 1
	}
}

func writeLDAPResult(writer io.Writer, messageID int64, applicationTag byte, code uint16, diagnostic string) error {
	result := append(berInteger(0x0a, int64(code)), berOctet(nil)...)
	result = append(result, berOctet([]byte(diagnostic))...)
	response := berTLV(0x60|applicationTag, result)
	message := append(berInteger(0x02, messageID), response...)
	_, err := writer.Write(berTLV(0x30, message))
	return err
}

func berInteger(tag byte, value int64) []byte {
	var bytes [8]byte
	binary.BigEndian.PutUint64(bytes[:], uint64(value))
	start := 0
	for start < len(bytes)-1 && bytes[start] == 0 && bytes[start+1]&0x80 == 0 {
		start++
	}
	return berTLV(tag, bytes[start:])
}

func berOctet(value []byte) []byte { return berTLV(0x04, value) }

func berTLV(tag byte, value []byte) []byte {
	out := []byte{tag}
	switch {
	case len(value) < 128:
		out = append(out, byte(len(value)))
	case len(value) <= 255:
		out = append(out, 0x81, byte(len(value)))
	default:
		out = append(out, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(out, value...)
}

func receive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for test synchronization")
		var zero T
		return zero
	}
}

func waitForCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		testingContextSwitch()
	}
}

func waitUntil(t *testing.T, deadline time.Time) {
	t.Helper()
	if deadline.IsZero() {
		t.Fatal("cannot wait for a zero deadline")
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for deadline")
	}
}

func testingContextSwitch() {
	runtime.Gosched()
}

// assertClosedPoolInvariants is the shared terminal quiescence assertion for
// tests that exercise concurrent lifecycle transitions.
func assertClosedPoolInvariants(t *testing.T, pool *Pool) {
	t.Helper()
	select {
	case <-pool.schedulerDone:
	case <-time.After(testTimeout):
		t.Fatal("pool scheduler did not terminate")
	}
	if pool.observer != nil {
		select {
		case <-pool.observer.done:
		case <-time.After(testTimeout):
			t.Fatal("observer dispatcher did not terminate")
		}
	}
	waitForCondition(t, func() bool { return len(pool.closeSlots) == 0 })
	waitForCondition(t, func() bool {
		pool.credential.mu.Lock()
		defer pool.credential.mu.Unlock()
		return len(pool.credential.password) == 0
	})
	select {
	case <-pool.rootCtx.Done():
	default:
		t.Fatal("closed pool retained a live root context")
	}
	select {
	case <-pool.closeDone:
	default:
		t.Fatal("closed pool did not publish terminal completion")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	counts := pool.countsLocked()
	if counts.Open != counts.Connecting+counts.Idle+counts.Borrowed+counts.Closing {
		t.Fatalf("open-count conservation failed: %+v", counts)
	}
	if pool.lifecycle != poolClosedLifecycle {
		t.Fatalf("pool lifecycle = %d, want closed", pool.lifecycle)
	}
	if counts != (Counts{}) {
		t.Fatalf("closed pool retained counts: %+v", counts)
	}
	if len(pool.physical) != 0 || len(pool.idle) != 0 || pool.waiters.Len() != 0 || pool.externalWaiters != 0 {
		t.Fatalf(
			"closed pool retained registries: physical=%d idle=%d waiters=%d external_waiters=%d",
			len(pool.physical), len(pool.idle), pool.waiters.Len(), pool.externalWaiters,
		)
	}
	if pool.connectCancel != nil {
		t.Fatal("closed pool retained a connect cancel function")
	}
	if pool.graceTimer != nil {
		t.Fatal("closed pool retained a shutdown timer")
	}
}

func testCertificate(t *testing.T, dnsNames []string, ips []net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	return testCertificateWithValidity(t, dnsNames, ips, now.Add(-time.Hour), now.Add(time.Hour))
}

func testCertificateWithValidity(t *testing.T, dnsNames []string, ips []net.IP, notBefore, notAfter time.Time) (tls.Certificate, *x509.CertPool) {
	return testCertificateWithProperties(
		t, dnsNames, ips, notBefore, notAfter,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	)
}

func testCertificateWithExtKeyUsage(t *testing.T, dnsNames []string, ips []net.IP, usage []x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	return testCertificateWithProperties(t, dnsNames, ips, now.Add(-time.Hour), now.Add(time.Hour), usage)
}

func testCertificateWithProperties(
	t *testing.T,
	dnsNames []string,
	ips []net.IP,
	notBefore, notAfter time.Time,
	usage []x509.ExtKeyUsage,
) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test only"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: usage,
		DNSNames:    dnsNames, IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pemBlock("CERTIFICATE", der), pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return certificate, roots
}

func pemBlock(kind string, der []byte) []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	encodedLength := (len(der) + 2) / 3 * 4
	encoded := make([]byte, encodedLength)
	for source, target := 0, 0; source < len(der); source, target = source+3, target+4 {
		var value uint32
		remaining := len(der) - source
		value = uint32(der[source]) << 16
		if remaining > 1 {
			value |= uint32(der[source+1]) << 8
		}
		if remaining > 2 {
			value |= uint32(der[source+2])
		}
		encoded[target] = alphabet[value>>18&63]
		encoded[target+1] = alphabet[value>>12&63]
		if remaining > 1 {
			encoded[target+2] = alphabet[value>>6&63]
		} else {
			encoded[target+2] = '='
		}
		if remaining > 2 {
			encoded[target+3] = alphabet[value&63]
		} else {
			encoded[target+3] = '='
		}
	}
	line := []byte("-----BEGIN " + kind + "-----\n")
	for len(encoded) > 64 {
		line = append(line, encoded[:64]...)
		line = append(line, '\n')
		encoded = encoded[64:]
	}
	line = append(line, encoded...)
	line = append(line, []byte("\n-----END "+kind+"-----\n")...)
	return line
}
