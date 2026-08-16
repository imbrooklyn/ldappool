package ldappool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestDialerPanicDoesNotLeakOpenSlot(t *testing.T) {
	dialer := &testDialer{factory: func(context.Context, int) (net.Conn, error) {
		panic("dialer payload")
	}}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	if !errors.Is(err, ErrDependencyPanic) {
		t.Fatalf("Dialer panic error = %v", err)
	}
	snapshot := pool.Snapshot()
	if snapshot.Counts.Open != 0 || snapshot.Counts.Connecting != 0 {
		t.Fatalf("Dialer panic leaked capacity: %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	assertClosedPoolInvariants(t, pool)
}

func TestConnectAttemptDestroyCancelsAndWipesExactlyOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	owned := []byte("attempt secret")
	attempt := &connectAttempt{ctx: ctx, cancel: cancel, password: owned}
	attempt.destroy()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("connect attempt context remained live after destroy")
	}
	if attempt.password != nil {
		t.Fatal("connect attempt retained its password slice")
	}
	for _, value := range owned {
		if value != 0 {
			t.Fatal("connect attempt password storage was not wiped")
		}
	}
	attempt.destroy()
}

func TestClosedPoolQuiescesOwnedLifecycleAndEveryTransport(t *testing.T) {
	serverDone := make(chan struct{}, 3)
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			successfulLDAPServer(server, call)
			serverDone <- struct{}{}
		}()
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 3
	config.MaxIdle = 3
	config.Observer = ObserverFunc(func(Event) {})
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Warmup(contextWithTimeout(t), 3); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		receive(t, serverDone)
	}
	if dialer.count() != 3 {
		t.Fatalf("Dial count = %d, want three independent transports", dialer.count())
	}
	assertClosedPoolInvariants(t, pool)
}

func TestDialFailureRetainsCauseAndTransportClassification(t *testing.T) {
	root := errors.New("synthetic dial failure")
	dialer := &testDialer{factory: func(context.Context, int) (net.Conn, error) {
		return nil, root
	}}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	var acquireErr *AcquireError
	if !errors.As(err, &acquireErr) || !errors.Is(err, root) || !errors.Is(err, ErrTransport) || acquireErr.Stage != StageDial || acquireErr.RetryAt.IsZero() {
		t.Fatalf("dial failure = %v", err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestDialErrorWithTransportClosesBeforeReleasingCapacity(t *testing.T) {
	closeStarted := make(chan struct{})
	allowClose := make(chan struct{})
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	returned := &countedConn{Conn: client, started: closeStarted, allow: allowClose}
	dialFailure := errors.New("synthetic partial dial failure")
	dialer := &testDialer{factory: func(context.Context, int) (net.Conn, error) {
		return returned, dialFailure
	}}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	}()
	receive(t, closeStarted)
	if snapshot := pool.Snapshot(); snapshot.Counts.Open != 1 || snapshot.Counts.Closing != 1 {
		t.Fatalf("partial Dial transport released capacity early: %+v", snapshot.Counts)
	}
	close(allowClose)
	err = receive(t, result)
	if !errors.Is(err, dialFailure) || !errors.Is(err, ErrTransport) {
		t.Fatalf("Dial failure = %v", err)
	}
	if returned.closes.Load() != 1 {
		t.Fatalf("partial Dial transport closed %d times", returned.closes.Load())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestTransientBindFailureBacksOffAndRecovers(t *testing.T) {
	observer := &eventCollector{events: make(chan Event, 64)}
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			request, err := readLDAPRequest(reader)
			if err != nil {
				return
			}
			code := uint16(ldap.LDAPResultSuccess)
			if call == 1 {
				code = ldap.LDAPResultBusy
			}
			_ = writeLDAPResult(server, request.messageID, ldap.ApplicationBindResponse, code, "sensitive diagnostic")
			if code == ldap.LDAPResultSuccess {
				successfulLDAPServerFromReader(server, reader)
			}
		}()
		return client, nil
	}}
	config := simpleTestConfig(dialer)
	config.Observer = observer
	config.ConnectBackoff = BackoffConfig{Initial: 20 * time.Millisecond, Multiplier: 1, Max: 20 * time.Millisecond, Jitter: .01}
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultBusy) || errors.Is(err, ErrCredentialBlocked) {
		t.Fatalf("transient Bind error = %v", err)
	}
	retryAt := pool.Snapshot().RetryAt
	timer := time.NewTimer(time.Until(retryAt))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-time.After(testTimeout):
		t.Fatal("transient Bind retry deadline was not reached")
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatalf("pool did not recover after transient Bind: %v", err)
	}
	if dialer.count() != 2 {
		t.Fatalf("dial count = %d, want 2", dialer.count())
	}
	waitForEvent(t, observer, EventPoolRecovered)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestBindNetworkFailureRetainsRawTransportCause(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		_, _ = readLDAPRequest(bufio.NewReader(conn))
	}, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	var acquireErr *AcquireError
	if !errors.As(err, &acquireErr) || acquireErr.Stage != StageBind || !errors.Is(err, ErrTransport) || !errors.Is(err, io.EOF) {
		t.Fatalf("Bind transport failure = %v", err)
	}
	if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialClear {
		t.Fatalf("Bind transport failure changed Guard state: %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestBindSuccessRequiresStrictBindResponse(t *testing.T) {
	callbackCalled := false
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		request, err := readLDAPRequest(bufio.NewReader(conn))
		if err == nil {
			_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationAddResponse, ldap.LDAPResultSuccess, "")
		}
	}, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, ErrProtocol) || callbackCalled {
		t.Fatalf("wrong-tag Bind success = %v, protocol=%v, callback=%v, snapshot=%+v", err, errors.Is(err, ErrProtocol), callbackCalled, pool.Snapshot())
	}
	if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialClear {
		t.Fatalf("wrong-tag Bind changed Guard state: %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestBindSuccessRequiresHealthyTransport(t *testing.T) {
	if failure := validateBindTransport(traceSnapshot{}); failure != nil {
		t.Fatalf("clean Bind transport was rejected: %+v", failure)
	}
	root := io.EOF
	failure := validateBindTransport(traceSnapshot{readErr: root})
	if failure == nil || failure.reason != ReasonTransport || !errors.Is(failure.cause, root) {
		t.Fatalf("closed Bind transport failure = %+v", failure)
	}
	if failure := validateBindTransport(traceSnapshot{writeInFlight: 1}); failure == nil || failure.reason != ReasonTransport {
		t.Fatalf("in-flight Bind transport failure = %+v", failure)
	}
}

func TestBindRejectsTruncatedNonzeroResultCode(t *testing.T) {
	callbackCalled := false
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		request, err := readLDAPRequest(bufio.NewReader(conn))
		if err == nil {
			_ = writeLDAPResultCode(conn, request.messageID, ldap.ApplicationBindResponse, 65536, "")
		}
	}, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, ErrCredentialBlocked) || callbackCalled {
		t.Fatalf("truncated Bind result code = %v, callback=%v", err, callbackCalled)
	}
	if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialBlocked || snapshot.CredentialReason != CredentialReasonUnknown {
		t.Fatalf("credential snapshot = %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedBindControlStillBlocksInvalidCredentials(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		request, err := readLDAPRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		result := append(berInteger(0x0a, ldap.LDAPResultInvalidCredentials), berOctet(nil)...)
		result = append(result, berOctet([]byte("sensitive diagnostic"))...)
		response := berTLV(0x60|ldap.ApplicationBindResponse, result)
		malformedControls := berTLV(0xa0, berTLV(0x30, nil))
		message := append(berInteger(0x02, request.messageID), response...)
		message = append(message, malformedControls...)
		_, _ = conn.Write(berTLV(0x30, message))
	}, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
		if !errors.Is(err, ErrCredentialBlocked) || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || strings.Contains(err.Error(), "sensitive diagnostic") {
			t.Fatalf("malformed-control Bind attempt %d = %v", attempt+1, err)
		}
	}
	if dialer.count() != 1 {
		t.Fatalf("credential guard allowed %d malformed-control Bind attempts", dialer.count())
	}
	if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialBlocked || snapshot.CredentialReason != CredentialReasonInvalid {
		t.Fatalf("credential snapshot = %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestUnexpectedBindErrorResponseDoesNotPoisonCredentialGuard(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		request, err := readLDAPRequest(bufio.NewReader(conn))
		if err == nil {
			_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationAddResponse, ldap.LDAPResultInvalidCredentials, "sensitive diagnostic")
		}
	}, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrCredentialBlocked) || strings.Contains(err.Error(), "sensitive diagnostic") {
		t.Fatalf("unexpected Bind response error = %v", err)
	}
	if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialClear {
		t.Fatalf("unexpected Bind response changed Guard state: %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialDelayDoesNotBusyLoopAndRecoversHalfOpen(t *testing.T) {
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			request, err := readLDAPRequest(reader)
			if err != nil {
				return
			}
			code := uint16(ldap.LDAPResultSuccess)
			if call == 1 {
				code = ldap.LDAPResultInvalidCredentials
			}
			_ = writeLDAPResult(server, request.messageID, ldap.ApplicationBindResponse, code, "vendor text")
			if code == ldap.LDAPResultSuccess {
				successfulLDAPServerFromReader(server, reader)
			}
		}()
		return client, nil
	}}
	config := simpleTestConfig(dialer)
	config.CredentialBackoff = BackoffConfig{Initial: 25 * time.Millisecond, Multiplier: 1, Max: 25 * time.Millisecond, Jitter: .01}
	config.CredentialFailureClassifier = CredentialFailureClassifierFunc(func(CredentialFailure) CredentialDecision {
		return CredentialDecision{Action: CredentialDelay, Reason: CredentialReasonPolicy}
	})
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	if !errors.Is(err, ErrCredentialDelayed) {
		t.Fatalf("first delayed error = %v", err)
	}
	for i := 0; i < 10; i++ {
		err = pool.WithConnection(context.Background(), func(*Connection) error { return nil })
		if !errors.Is(err, ErrCredentialDelayed) {
			t.Fatalf("guarded attempt %d = %v", i, err)
		}
	}
	if dialer.count() != 1 {
		t.Fatalf("guard busy-looped: dial count=%d", dialer.count())
	}
	retryAt := pool.Snapshot().CredentialRetryAt
	timer := time.NewTimer(time.Until(retryAt))
	<-timer.C
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatalf("half-open recovery failed: %v", err)
	}
	if dialer.count() != 2 || pool.Snapshot().CredentialState != CredentialClear {
		t.Fatalf("half-open state: dials=%d snapshot=%+v", dialer.count(), pool.Snapshot())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestHalfOpenDialFailureReleasesProbeAndRecovers(t *testing.T) {
	dialFailure := errors.New("synthetic half-open Dial failure")
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		if call == 2 {
			return nil, dialFailure
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			request, err := readLDAPRequest(reader)
			if err != nil {
				return
			}
			code := uint16(ldap.LDAPResultSuccess)
			if call == 1 {
				code = ldap.LDAPResultInvalidCredentials
			}
			_ = writeLDAPResult(server, request.messageID, ldap.ApplicationBindResponse, code, "redacted")
			if code == ldap.LDAPResultSuccess {
				successfulLDAPServerFromReader(server, reader)
			}
		}()
		return client, nil
	}}
	config := simpleTestConfig(dialer)
	config.ConnectBackoff = BackoffConfig{Initial: 10 * time.Millisecond, Multiplier: 1, Max: 10 * time.Millisecond, Jitter: .01}
	config.CredentialBackoff = BackoffConfig{Initial: 20 * time.Millisecond, Multiplier: 1, Max: 20 * time.Millisecond, Jitter: .01}
	config.CredentialFailureClassifier = CredentialFailureClassifierFunc(func(CredentialFailure) CredentialDecision {
		return CredentialDecision{Action: CredentialDelay, Reason: CredentialReasonPolicy}
	})
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}

	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); !errors.Is(err, ErrCredentialDelayed) {
		t.Fatalf("initial credential error = %v", err)
	}
	waitUntil(t, pool.Snapshot().CredentialRetryAt)
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); !errors.Is(err, dialFailure) {
		t.Fatalf("half-open Dial error = %v", err)
	}
	afterDial := pool.Snapshot()
	if afterDial.CredentialState != CredentialDelayed || afterDial.CredentialRetryAt.IsZero() {
		t.Fatalf("half-open probe remained live after Dial failure: %+v", afterDial)
	}
	waitUntil(t, laterGate(afterDial.RetryAt, afterDial.CredentialRetryAt))
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatalf("pool did not recover after half-open Dial failure: %v", err)
	}
	if dialer.count() != 3 {
		t.Fatalf("Dial count = %d, want 3", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestResetCredentialGuardAllowsExplicitProbe(t *testing.T) {
	handler := func(conn net.Conn, call int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		code := uint16(ldap.LDAPResultInvalidCredentials)
		if call > 1 {
			code = ldap.LDAPResultSuccess
		}
		_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationBindResponse, code, "redacted")
		if code == ldap.LDAPResultSuccess {
			successfulLDAPServerFromReader(conn, reader)
		}
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); !errors.Is(err, ErrCredentialBlocked) {
		t.Fatalf("initial Bind error = %v", err)
	}
	if err := pool.ResetCredentialGuard(); err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatalf("manual reset did not allow probe: %v, dials=%d, snapshot=%+v", err, dialer.count(), pool.Snapshot())
	}
	if dialer.count() != 2 {
		t.Fatalf("dial count = %d, want 2", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestForceCloseInterruptsBusyOperation(t *testing.T) {
	requestReceived := make(chan struct{})
	callbackRelease := make(chan struct{})
	operationResult := make(chan error, 1)
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readLDAPRequest(reader); err != nil {
			return
		}
		close(requestReceived)
		_, _ = readLDAPRequest(reader)
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	callbackResult := make(chan error, 1)
	go func() {
		callbackResult <- pool.WithConnection(context.Background(), func(connection *Connection) error {
			go func() {
				_, opErr := connection.Search(context.Background(), ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
				operationResult <- opErr
			}()
			receive(t, requestReceived)
			<-callbackRelease
			return nil
		})
	}()
	receive(t, requestReceived)
	if err := pool.ForceClose(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	if opErr := receive(t, operationResult); !errors.Is(opErr, ErrTransport) {
		t.Fatalf("force-closed operation error = %v", opErr)
	}
	close(callbackRelease)
	if err := receive(t, callbackResult); err != nil {
		t.Fatal(err)
	}
	if pool.Snapshot().State != PoolClosed {
		t.Fatalf("state = %s", pool.Snapshot().State)
	}
}

func TestGracefulCloseLetsInflightSuccessFinishThenRetiresLease(t *testing.T) {
	requestReceived := make(chan ldapWireRequest, 1)
	releaseResponse := make(chan struct{})
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		requestReceived <- request
		<-releaseResponse
		_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
		_, _ = readLDAPRequest(reader)
	}, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	operationDone := make(chan error, 1)
	go func() {
		operationDone <- pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
			_, operationErr := connection.Search(context.Background(), ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
			return operationErr
		})
	}()
	receive(t, requestReceived)
	closeDone := make(chan error, 1)
	go func() { closeDone <- pool.Close(contextWithTimeout(t)) }()
	waitForCondition(t, func() bool { return pool.Snapshot().State == PoolClosing })
	close(releaseResponse)
	if err := receive(t, operationDone); err != nil {
		t.Fatalf("in-flight confirmed success was reversed: %v", err)
	}
	if err := receive(t, closeDone); err != nil {
		t.Fatal(err)
	}
	if pool.Snapshot().State != PoolClosed {
		t.Fatalf("state = %s, want closed", pool.Snapshot().State)
	}
}

func TestCredentialRotationRetiresBorrowedConnectionAfterSuccess(t *testing.T) {
	requestReceived := make(chan ldapWireRequest, 1)
	releaseResponse := make(chan struct{})
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		if call == 1 {
			go func() {
				defer server.Close()
				reader := bufio.NewReader(server)
				bind, err := readLDAPRequest(reader)
				if err != nil {
					return
				}
				_ = writeLDAPResult(server, bind.messageID, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "")
				search, err := readLDAPRequest(reader)
				if err != nil {
					return
				}
				requestReceived <- search
				<-releaseResponse
				_ = writeLDAPResult(server, search.messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
				_, _ = readLDAPRequest(reader)
			}()
		} else {
			go successfulLDAPServer(server, call)
		}
		return client, nil
	}}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	operationDone := make(chan error, 1)
	go func() {
		operationDone <- pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
			_, operationErr := connection.Search(context.Background(), ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
			return operationErr
		})
	}()
	receive(t, requestReceived)
	if err := pool.RotateCredentials(NewSecret([]byte("rotated"))); err != nil {
		t.Fatal(err)
	}
	close(releaseResponse)
	if err := receive(t, operationDone); err != nil {
		t.Fatalf("confirmed old-generation result was reversed: %v", err)
	}
	waitForCondition(t, func() bool { return pool.Snapshot().Counts.Open == 0 })
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 2 || pool.Snapshot().Generation != 2 {
		t.Fatalf("rotation recovery: dials=%d snapshot=%+v", dialer.count(), pool.Snapshot())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialRotationInvalidatesBorrowedLeaseBetweenOperations(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	borrowed := make(chan *Connection, 1)
	rotated := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
			borrowed <- connection
			<-rotated
			_, operationErr := connection.Compare(context.Background(), "cn=x", "cn", "x")
			return operationErr
		})
	}()
	receive(t, borrowed)
	if err := pool.RotateCredentials(NewSecret([]byte("rotated"))); err != nil {
		t.Fatal(err)
	}
	close(rotated)
	if err := receive(t, callbackDone); !errors.Is(err, ErrLeaseInvalid) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("old-generation lease error = %v", err)
	}
	waitForCondition(t, func() bool { return pool.Snapshot().Counts.Open == 0 })
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 2 {
		t.Fatalf("dial count = %d, want 2", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

type blockingCloseConn struct {
	net.Conn
	started chan struct{}
	allow   chan struct{}
	once    sync.Once
	err     error
}

type parallelCloseCounters struct {
	active  atomic.Int32
	maximum atomic.Int32
	started atomic.Int32
}

type parallelCloseConn struct {
	net.Conn
	counters *parallelCloseCounters
	allow    <-chan struct{}
}

func (c *parallelCloseConn) Close() error {
	active := c.counters.active.Add(1)
	for {
		maximum := c.counters.maximum.Load()
		if active <= maximum || c.counters.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	c.counters.started.Add(1)
	<-c.allow
	c.counters.active.Add(-1)
	return c.Conn.Close()
}

type panicCloseConn struct {
	net.Conn
}

func (c *panicCloseConn) Close() error {
	_ = c.Conn.Close()
	panic("transport close payload")
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.allow
	_ = c.Conn.Close()
	return c.err
}

func TestPhysicalCloseConcurrencyIsBounded(t *testing.T) {
	allow := make(chan struct{})
	counters := &parallelCloseCounters{}
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		return &parallelCloseConn{Conn: conn, counters: counters, allow: allow}
	})}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 12
	config.MaxIdle = 12
	config.CloseTimeout = 100 * time.Millisecond
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Warmup(contextWithTimeout(t), 12); err != nil {
		t.Fatal(err)
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- pool.Close(context.Background()) }()
	waitForCondition(t, func() bool { return counters.started.Load() == 8 })
	err = receive(t, closeResult)
	var closeErr *CloseError
	if !errors.As(err, &closeErr) || !closeErr.TimedOut {
		t.Fatalf("first Close error = %v, want timeout", err)
	}
	if started := counters.started.Load(); started != 8 {
		t.Fatalf("physical closes started before capacity was released = %d, want 8", started)
	}
	close(allow)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	if counters.started.Load() != 12 || counters.maximum.Load() > 8 {
		t.Fatalf("close concurrency: started=%d maximum=%d", counters.started.Load(), counters.maximum.Load())
	}
	assertClosedPoolInvariants(t, pool)
}

func TestCloseTimeoutLeavesConnectionCountedUntilTransportReturns(t *testing.T) {
	started := make(chan struct{})
	allow := make(chan struct{})
	var blocking *blockingCloseConn
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		blocking = &blockingCloseConn{Conn: conn, started: started, allow: allow}
		return blocking
	})}
	config := anonymousTestConfig(dialer)
	config.CloseTimeout = 20 * time.Millisecond
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	err = pool.Close(context.Background())
	if !errors.Is(err, ErrCloseFailed) {
		t.Fatalf("Close timeout error = %v", err)
	}
	receive(t, started)
	snapshot := pool.Snapshot()
	if snapshot.Counts.Open != 1 || snapshot.Counts.Closing != 1 {
		t.Fatalf("timed-out Close released capacity: %+v", snapshot.Counts)
	}
	close(allow)
	waitForCondition(t, func() bool { return pool.Snapshot().State == PoolClosed })
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestTransportCloseErrorIsReportedAfterOwnershipEnds(t *testing.T) {
	started := make(chan struct{})
	allow := make(chan struct{})
	closeFailure := errors.New("synthetic close failure")
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		return &blockingCloseConn{Conn: conn, started: started, allow: allow, err: closeFailure}
	})}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- pool.Close(contextWithTimeout(t)) }()
	receive(t, started)
	close(allow)
	err = receive(t, result)
	if !errors.Is(err, ErrCloseFailed) || !errors.Is(err, closeFailure) {
		t.Fatalf("close error = %v", err)
	}
	if pool.Snapshot().Counts.Open != 0 {
		t.Fatal("close error retained capacity after Close returned")
	}
}

func TestTransportClosePanicDoesNotReplaceCallbackPanic(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		return &panicCloseConn{Conn: conn}
	})}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	const callbackPanic = "original callback panic"
	func() {
		defer func() {
			if recovered := recover(); recovered != callbackPanic {
				t.Fatalf("recovered %v, want %q", recovered, callbackPanic)
			}
		}()
		_ = pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			panic(callbackPanic)
		})
	}()
	if snapshot := pool.Snapshot(); snapshot.Counts.Open != 0 || snapshot.Counts.Closing != 0 {
		t.Fatalf("close panic leaked capacity: %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); !errors.Is(err, ErrCloseFailed) || !errors.Is(err, ErrDependencyPanic) {
		t.Fatalf("terminal close error = %v", err)
	}
}

func TestAnonymousPoolDoesNotEmitBindSuccess(t *testing.T) {
	observer := &eventCollector{events: make(chan Event, 64)}
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.Observer = observer
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitForEvent(t, observer, EventAcquireSuccess)
	for _, eventType := range observer.types() {
		if eventType == EventBindSuccess {
			t.Fatal("anonymous connection emitted Bind success")
		}
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestTransportWriteFailureEmitsUnknownOutcome(t *testing.T) {
	observer := &eventCollector{events: make(chan Event, 64)}
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		_, _ = readLDAPRequest(bufio.NewReader(conn))
		_ = conn.Close()
	}, nil)}
	config := anonymousTestConfig(dialer)
	config.Observer = observer
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		return connection.Modify(context.Background(), ldap.NewModifyRequest("cn=x", nil))
	})
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("write error = %v", err)
	}
	event := waitForEvent(t, observer, EventWriteOutcomeUnknown)
	if event.Operation != OperationModify || event.Reason != ReasonTransport {
		t.Fatalf("unknown-outcome event = %+v", event)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestIdlePeerCloseEvictsConnectionAfterNotSentFailure(t *testing.T) {
	closeFirstPeer := make(chan struct{})
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		if call == 1 {
			go func() {
				<-closeFirstPeer
				_ = server.Close()
			}()
		} else {
			go successfulLDAPServer(server, call)
		}
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	close(closeFirstPeer)
	waitForCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		for _, physical := range pool.physical {
			if client, ok := physical.client.(*ldap.Conn); ok && client.IsClosing() {
				return true
			}
		}
		return false
	})
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		_, searchErr := connection.Search(context.Background(), ldap.NewSearchRequest(
			"dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil,
		))
		return searchErr
	})
	if !errors.Is(err, ErrNotSent) || !errors.Is(err, ErrTransport) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("idle-close operation = %v", err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		_, searchErr := connection.Search(context.Background(), ldap.NewSearchRequest(
			"dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil,
		))
		return searchErr
	}); err != nil {
		t.Fatalf("replacement connection failed: %v", err)
	}
	if dialer.count() != 2 {
		t.Fatalf("idle-close recovery dial count = %d, want 2", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestFatalOperationAllowsRecoveryBeforeCallbackReturns(t *testing.T) {
	errorObserved := make(chan struct{})
	releaseCallback := make(chan struct{})
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		if call == 1 {
			go func() {
				_, _ = readLDAPRequest(bufio.NewReader(server))
				_ = server.Close()
			}()
		} else {
			go successfulLDAPServer(server, call)
		}
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
			err := connection.Modify(context.Background(), ldap.NewModifyRequest("cn=x", nil))
			if !errors.Is(err, ErrOutcomeUnknown) {
				return err
			}
			close(errorObserved)
			<-releaseCallback
			return nil
		})
	}()
	receive(t, errorObserved)
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(secondEntered)
			return nil
		})
	}()
	receive(t, secondEntered)
	if dialer.count() != 2 {
		t.Fatalf("replacement dial count = %d, want 2", dialer.count())
	}
	close(releaseCallback)
	if err := receive(t, firstDone); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, secondDone); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentBorrowReturnMaintainsAccounting(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 4
	config.MaxIdle = 4
	config.MaxWaiters = 128
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	errorsChannel := make(chan error, 64)
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for j := 0; j < 20; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
				err := pool.WithConnection(ctx, func(*Connection) error { return nil })
				cancel()
				if err != nil {
					errorsChannel <- err
					return
				}
				pool.mu.Lock()
				counts := pool.countsLocked()
				valid := counts.Open == counts.Connecting+counts.Idle+counts.Borrowed+counts.Closing && counts.Open <= config.MaxOpen
				pool.mu.Unlock()
				if !valid {
					errorsChannel <- fmt.Errorf("invalid counts: %+v", counts)
					return
				}
			}
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	receive(t, done)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	snapshot := pool.Snapshot()
	if snapshot.Counts.Borrowed != 0 || snapshot.Counts.Waiters != 0 || snapshot.Counts.Open > config.MaxOpen {
		t.Fatalf("non-quiescent counts: %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	assertClosedPoolInvariants(t, pool)
}
