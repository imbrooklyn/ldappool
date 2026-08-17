package ldappool

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestConfirmedWriteSurvivesNoticeOfDisconnection(t *testing.T) {
	dialer := &testDialer{factory: func(_ context.Context, _ int) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, err := readLDAPRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			var combined bytes.Buffer
			_ = writeLDAPResult(&combined, request.messageID, ldap.ApplicationAddResponse, ldap.LDAPResultSuccess, "")
			_ = writeLDAPResultElements(&combined, 0, ldap.ApplicationExtendedResponse,
				berInteger(0x0a, ldap.LDAPResultUnavailable), berOctet(nil), berOctet(nil),
				berTLV(0x8a, []byte(noticeOfDisconnectionOID)),
			)
			_, _ = server.Write(combined.Bytes())
		}()
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		return connection.Add(context.Background(), ldap.NewAddRequest("cn=x", nil))
	})
	if err != nil {
		t.Fatalf("confirmed Add was reversed by Notice of Disconnection: %v", err)
	}
	waitForCondition(t, func() bool { return pool.Snapshot().Counts.Open == 0 })
	if err = pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestSynchronousOperationSurface(t *testing.T) {
	var mu sync.Mutex
	seen := make(map[byte]int)
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			request, err := readLDAPRequest(reader)
			if err != nil {
				return
			}
			mu.Lock()
			seen[request.tag]++
			mu.Unlock()
			code := uint16(ldap.LDAPResultSuccess)
			if request.tag == ldap.ApplicationCompareRequest {
				code = ldap.LDAPResultCompareTrue
			}
			if err := writeLDAPResult(conn, request.messageID, responseTag(request.tag), code, ""); err != nil {
				return
			}
		}
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := contextWithTimeout(t)
	search := ldap.NewSearchRequest("dc=example,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10, 5, false, "(objectClass=*)", []string{"cn"}, nil)
	paged := ldap.NewSearchRequest("dc=example,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10, 5, false, "(objectClass=*)", []string{"cn"}, nil)
	dirSync := ldap.NewSearchRequest("dc=example,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10, 5, false, "(objectClass=*)", []string{"cn"}, nil)
	err = pool.WithConnection(ctx, func(connection *Connection) error {
		if _, err := connection.Search(ctx, search); err != nil {
			return err
		}
		if _, err := connection.SearchWithPaging(ctx, paged, 50); err != nil {
			return err
		}
		if len(paged.Controls) != 0 {
			return errors.New("SearchWithPaging mutated the caller's request")
		}
		if _, err := connection.DirSync(ctx, dirSync, 0, 100, []byte("cookie")); err != nil {
			return err
		}
		if len(dirSync.Controls) != 0 {
			return errors.New("DirSync mutated the caller's request")
		}
		matched, err := connection.Compare(ctx, "cn=entry,dc=example,dc=test", "cn", "entry")
		if err != nil || !matched {
			return fmt.Errorf("Compare = %v, %v", matched, err)
		}
		add := ldap.NewAddRequest("cn=new,dc=example,dc=test", nil)
		add.Attribute("objectClass", []string{"top"})
		if err := connection.Add(ctx, add); err != nil {
			return err
		}
		modify := ldap.NewModifyRequest("cn=new,dc=example,dc=test", nil)
		modify.Replace("description", []string{"updated"})
		if err := connection.Modify(ctx, modify); err != nil {
			return err
		}
		if err := connection.Del(ctx, ldap.NewDelRequest("cn=new,dc=example,dc=test", nil)); err != nil {
			return err
		}
		if err := connection.ModifyDN(ctx, ldap.NewModifyDNRequest("cn=old,dc=example,dc=test", "cn=new", true, "")); err != nil {
			return err
		}
		_, err = connection.PasswordModify(ctx, ldap.NewPasswordModifyRequest("cn=user,dc=example,dc=test", "old", "new"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 1 {
		t.Fatalf("dial count = %d, want 1", dialer.count())
	}
	for _, requestTag := range []byte{
		ldap.ApplicationSearchRequest, ldap.ApplicationCompareRequest, ldap.ApplicationAddRequest,
		ldap.ApplicationModifyRequest, ldap.ApplicationDelRequest, ldap.ApplicationModifyDNRequest,
		ldap.ApplicationExtendedRequest,
	} {
		mu.Lock()
		count := seen[requestTag]
		mu.Unlock()
		if count == 0 {
			t.Errorf("LDAP request tag %d was not observed", requestTag)
		}
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEscapedLeaseIsInvalid(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	var escaped *Connection
	if err := pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		escaped = connection
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = escaped.Compare(context.Background(), "cn=x", "cn", "x")
	if !errors.Is(err, ErrLeaseInvalid) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("escaped lease error = %v", err)
	}
	if snapshot := pool.Snapshot(); snapshot.Counts.Idle != 1 || snapshot.Counts.Open != 1 {
		t.Fatalf("snapshot after escaped use = %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCopiedLeaseSharesInvalidationState(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	var copied Connection
	if err := pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		copied = *connection
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = copied.Compare(context.Background(), "cn=x", "cn", "x")
	if !errors.Is(err, ErrLeaseInvalid) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("copied lease error = %v", err)
	}
	if snapshot := pool.Snapshot(); snapshot.Counts.Idle != 1 || snapshot.Counts.Open != 1 {
		t.Fatalf("snapshot after copied lease use = %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestGracefulInvalidationLinearizesWithOperationEntry(t *testing.T) {
	for range 1000 {
		connection := newConnection(&Pool{}, &physicalConn{})
		start := make(chan struct{})
		entered := make(chan error, 1)
		invalidated := make(chan leaseState, 1)
		go func() {
			<-start
			entered <- connection.enter(OperationCompare)
		}()
		go func() {
			<-start
			invalidated <- connection.invalidateUnlessBusy()
		}()
		close(start)
		enterErr := receive(t, entered)
		priorState := receive(t, invalidated)
		switch {
		case enterErr == nil && priorState != leaseBusy:
			t.Fatalf("operation entered but graceful invalidation observed %v", priorState)
		case errors.Is(enterErr, ErrLeaseInvalid) && priorState != leaseActive:
			t.Fatalf("invalidation won but observed prior state %v", priorState)
		case enterErr != nil && !errors.Is(enterErr, ErrLeaseInvalid):
			t.Fatalf("operation entry error = %v", enterErr)
		}
	}
}

func TestCopiedLeaseFatalOperationEvictsBeforeCallbackReturn(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		_, _ = readLDAPRequest(bufio.NewReader(conn))
	}, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	operationDone := make(chan error, 1)
	releaseCallback := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
			copied := *connection
			request := ldap.NewModifyRequest("cn=x", nil)
			request.Replace("description", []string{"x"})
			operationDone <- copied.Modify(context.Background(), request)
			<-releaseCallback
			return nil
		})
	}()
	if operationErr := receive(t, operationDone); !errors.Is(operationErr, ErrOutcomeUnknown) {
		t.Fatalf("copied lease operation error = %v", operationErr)
	}
	waitForCondition(t, func() bool { return pool.Snapshot().Counts.Open == 0 })
	close(releaseCallback)
	if err := receive(t, callbackDone); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentLeaseUseFailsImmediately(t *testing.T) {
	requestReceived := make(chan ldapWireRequest, 1)
	releaseResponse := make(chan struct{})
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		requestReceived <- request
		<-releaseResponse
		_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
		successfulLDAPServerFromReader(conn, reader)
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := contextWithTimeout(t)
	err = pool.WithConnection(ctx, func(connection *Connection) error {
		firstResult := make(chan error, 1)
		go func() {
			_, searchErr := connection.Search(ctx, ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
			firstResult <- searchErr
		}()
		receive(t, requestReceived)
		_, concurrentErr := connection.Compare(ctx, "cn=x", "cn", "x")
		if !errors.Is(concurrentErr, ErrConcurrentUse) || !errors.Is(concurrentErr, ErrNotSent) {
			return fmt.Errorf("concurrent error = %w", concurrentErr)
		}
		close(releaseResponse)
		return receive(t, firstResult)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackReturningWithBusyWriteDestroysConnection(t *testing.T) {
	requestReceived := make(chan struct{}, 1)
	operationResult := make(chan error, 1)
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readLDAPRequest(reader); err != nil {
			return
		}
		requestReceived <- struct{}{}
		_, _ = readLDAPRequest(reader)
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		go func() {
			operationResult <- connection.Add(context.Background(), ldap.NewAddRequest("cn=x", nil))
		}()
		receive(t, requestReceived)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	opErr := receive(t, operationResult)
	if !errors.Is(opErr, ErrOutcomeUnknown) {
		t.Fatalf("busy write error = %v, want outcome unknown", opErr)
	}
	if snapshot := pool.Snapshot(); snapshot.Counts.Open != 0 {
		t.Fatalf("open = %d after busy callback return", snapshot.Counts.Open)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackPanicCleansUpThenPropagates(t *testing.T) {
	closed := &countedConn{}
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		closed.Conn = conn
		return closed
	})}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	const panicValue = "callback panic sentinel"
	func() {
		defer func() {
			if recovered := recover(); recovered != panicValue {
				t.Fatalf("recovered %v, want %q", recovered, panicValue)
			}
		}()
		_ = pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			panic(panicValue)
		})
	}()
	if closed.closes.Load() != 1 {
		t.Fatalf("transport close count = %d, want 1", closed.closes.Load())
	}
	if pool.Snapshot().Counts.Open != 0 {
		t.Fatal("panicked callback connection remained open")
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackGoexitCleansUpWithoutPanicking(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	recovered := make(chan any, 1)
	done := make(chan struct{})
	ctx := contextWithTimeout(t)
	go func() {
		defer func() {
			recovered <- recover()
			close(done)
		}()
		_ = pool.WithConnection(ctx, func(*Connection) error {
			runtime.Goexit()
			return nil
		})
	}()
	receive(t, done)
	if value := receive(t, recovered); value != nil {
		t.Fatalf("runtime.Goexit became panic: %v", value)
	}
	if snapshot := pool.Snapshot(); snapshot.Counts.Open != 0 {
		t.Fatalf("Goexit callback retained connection: %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectionRemainsHealthyEvenWhenCallbackSwallowsError(t *testing.T) {
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		first := true
		for {
			request, err := readLDAPRequest(reader)
			if err != nil {
				return
			}
			if first {
				first = false
				_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationAddResponse, ldap.LDAPResultEntryAlreadyExists, "sensitive diagnostic")
				continue
			}
			_ = writeLDAPResult(conn, request.messageID, responseTag(request.tag), ldap.LDAPResultSuccess, "")
		}
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := contextWithTimeout(t)
	if err := pool.WithConnection(ctx, func(connection *Connection) error {
		err := connection.Add(ctx, ldap.NewAddRequest("cn=x", nil))
		var operationErr *OperationError
		if !errors.As(err, &operationErr) {
			return fmt.Errorf("Add error = %T, want *OperationError", err)
		}
		code, ok := operationErr.ResultCode()
		if !ok || code != ldap.LDAPResultEntryAlreadyExists {
			return fmt.Errorf("result code = %d, %v", code, ok)
		}
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) || ldapErr.Packet != nil || ldapErr.MatchedDN != "" {
			return fmt.Errorf("sanitized LDAP error = %#v", ldapErr)
		}
		if strings.Contains(err.Error(), "sensitive diagnostic") {
			return errors.New("server diagnostic leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(ctx, func(connection *Connection) error {
		_, err := connection.Search(ctx, ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 1 {
		t.Fatalf("server rejection caused redial: count=%d", dialer.count())
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWriteTransportFailureHasUnknownOutcome(t *testing.T) {
	handler := func(conn net.Conn, _ int) {
		reader := bufio.NewReader(conn)
		_, _ = readLDAPRequest(reader)
		_ = conn.Close()
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		return connection.Modify(context.Background(), ldap.NewModifyRequest("cn=x", nil))
	})
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrTransport) || errors.Is(err, ErrNotSent) {
		t.Fatalf("write failure = %v", err)
	}
	if pool.Snapshot().Counts.Open != 0 {
		t.Fatal("failed write connection was reused")
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestEveryWriteReportsUnknownAfterDispatchLoss(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *Connection) error
	}{
		{"Add", func(ctx context.Context, connection *Connection) error {
			request := ldap.NewAddRequest("cn=x", nil)
			request.Attribute("objectClass", []string{"top"})
			return connection.Add(ctx, request)
		}},
		{"Modify", func(ctx context.Context, connection *Connection) error {
			request := ldap.NewModifyRequest("cn=x", nil)
			request.Replace("description", []string{"x"})
			return connection.Modify(ctx, request)
		}},
		{"Delete", func(ctx context.Context, connection *Connection) error {
			return connection.Del(ctx, ldap.NewDelRequest("cn=x", nil))
		}},
		{"ModifyDN", func(ctx context.Context, connection *Connection) error {
			return connection.ModifyDN(ctx, ldap.NewModifyDNRequest("cn=x", "cn=y", true, ""))
		}},
		{"PasswordModify", func(ctx context.Context, connection *Connection) error {
			_, err := connection.PasswordModify(ctx, ldap.NewPasswordModifyRequest("cn=x", "old", "new"))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			received := make(chan struct{})
			dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
				reader := bufio.NewReader(conn)
				if _, err := readLDAPRequest(reader); err == nil {
					close(received)
				}
				_ = conn.Close()
			}, nil)}
			pool, err := New(anonymousTestConfig(dialer))
			if err != nil {
				t.Fatal(err)
			}
			err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
				return test.call(context.Background(), connection)
			})
			receive(t, received)
			if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, ErrTransport) || errors.Is(err, ErrNotSent) {
				t.Fatalf("write result = %v", err)
			}
			if pool.Snapshot().Counts.Open != 0 {
				t.Fatal("ambiguous write connection remained open")
			}
			if err := pool.Close(contextWithTimeout(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEveryWriteRejectsTruncatedNonzeroResultCode(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *Connection) error
	}{
		{"Add", func(ctx context.Context, connection *Connection) error {
			request := ldap.NewAddRequest("cn=x", nil)
			request.Attribute("objectClass", []string{"top"})
			return connection.Add(ctx, request)
		}},
		{"Modify", func(ctx context.Context, connection *Connection) error {
			request := ldap.NewModifyRequest("cn=x", nil)
			request.Replace("description", []string{"x"})
			return connection.Modify(ctx, request)
		}},
		{"Delete", func(ctx context.Context, connection *Connection) error {
			return connection.Del(ctx, ldap.NewDelRequest("cn=x", nil))
		}},
		{"ModifyDN", func(ctx context.Context, connection *Connection) error {
			return connection.ModifyDN(ctx, ldap.NewModifyDNRequest("cn=x", "cn=y", true, ""))
		}},
		{"PasswordModify", func(ctx context.Context, connection *Connection) error {
			_, err := connection.PasswordModify(ctx, ldap.NewPasswordModifyRequest("cn=x", "old", "new"))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				request, err := readLDAPRequest(reader)
				if err != nil {
					return
				}
				_ = writeLDAPResultCode(conn, request.messageID, responseTag(request.tag), 65536, "")
				_, _ = readLDAPRequest(reader)
			}, nil)}
			pool, err := New(anonymousTestConfig(dialer))
			if err != nil {
				t.Fatal(err)
			}
			err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
				return test.call(context.Background(), connection)
			})
			if !errors.Is(err, ErrProtocol) || !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrNotSent) {
				t.Fatalf("truncated result code was accepted: %v", err)
			}
			if err := pool.Close(contextWithTimeout(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriteRejectsMalformedSuccessfulLDAPResult(t *testing.T) {
	tests := []struct {
		name       string
		resultCode []byte
		matchedDN  []byte
	}{
		{"wrong matchedDN tag", berInteger(0x0a, 0), berInteger(0x02, 0)},
		{"oversized resultCode", berTLV(0x0a, make([]byte, 9)), berOctet(nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				request, err := readLDAPRequest(reader)
				if err != nil {
					return
				}
				_ = writeLDAPResultElements(conn, request.messageID, ldap.ApplicationAddResponse,
					test.resultCode, test.matchedDN, berOctet(nil))
				_, _ = readLDAPRequest(reader)
			}, nil)}
			pool, err := New(anonymousTestConfig(dialer))
			if err != nil {
				t.Fatal(err)
			}
			err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
				request := ldap.NewAddRequest("cn=x", nil)
				request.Attribute("objectClass", []string{"top"})
				return connection.Add(context.Background(), request)
			})
			if !errors.Is(err, ErrProtocol) || !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("malformed LDAPResult was accepted: %v", err)
			}
			if err := pool.Close(contextWithTimeout(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCompareRejectsSuccessResultCode(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err == nil {
			_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationCompareResponse, ldap.LDAPResultSuccess, "")
			_, _ = readLDAPRequest(reader)
		}
	}, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		matched, compareErr := connection.Compare(context.Background(), "cn=x", "uid", "x")
		if matched {
			t.Fatal("Compare returned true for success resultCode")
		}
		return compareErr
	})
	if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrNotSent) {
		t.Fatalf("Compare success resultCode = %v", err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestSearchOperationsRejectTruncatedNonzeroResultCode(t *testing.T) {
	newRequest := func() *ldap.SearchRequest {
		return ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil)
	}
	tests := []struct {
		name string
		call func(context.Context, *Connection) error
	}{
		{"Search", func(ctx context.Context, connection *Connection) error {
			_, err := connection.Search(ctx, newRequest())
			return err
		}},
		{"SearchWithPaging", func(ctx context.Context, connection *Connection) error {
			_, err := connection.SearchWithPaging(ctx, newRequest(), 10)
			return err
		}},
		{"DirSync", func(ctx context.Context, connection *Connection) error {
			_, err := connection.DirSync(ctx, newRequest(), 0, 0, nil)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				request, err := readLDAPRequest(reader)
				if err == nil {
					_ = writeLDAPResultCode(conn, request.messageID, ldap.ApplicationSearchResultDone, 65536, "")
					_, _ = readLDAPRequest(reader)
				}
			}, nil)}
			pool, err := New(anonymousTestConfig(dialer))
			if err != nil {
				t.Fatal(err)
			}
			err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
				return test.call(context.Background(), connection)
			})
			if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrNotSent) {
				t.Fatalf("truncated search result code was accepted: %v", err)
			}
			if err := pool.Close(contextWithTimeout(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnexpectedWriteResponseIsProtocolUnknown(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err == nil {
			_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
			_, _ = readLDAPRequest(reader)
		}
	}, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		request := ldap.NewAddRequest("cn=x", nil)
		request.Attribute("objectClass", []string{"top"})
		return connection.Add(context.Background(), request)
	})
	if !errors.Is(err, ErrProtocol) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unexpected response error = %v", err)
	}
	if pool.Snapshot().Counts.Open != 0 {
		t.Fatal("protocol-misaligned connection remained open")
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestSuccessfulAssessmentRequiresTransportDispatch(t *testing.T) {
	assessment := assessOperation(OperationAdd, true, nil, traceSnapshot{}, false)
	if !assessment.fatal || assessment.reason != ReasonProtocol {
		t.Fatalf("assessment = %+v, want fatal protocol failure", assessment)
	}
	if !errors.Is(assessment.err, ErrProtocol) || !errors.Is(assessment.err, ErrNotSent) || errors.Is(assessment.err, ErrOutcomeUnknown) {
		t.Fatalf("undispatched success error = %v", assessment.err)
	}
	var operationErr *OperationError
	if !errors.As(assessment.err, &operationErr) || operationErr.Delivery != DeliveryNotSent {
		t.Fatalf("undispatched success delivery = %v", assessment.err)
	}
}

func TestExpectedResponseTags(t *testing.T) {
	tests := []struct {
		operation Operation
		tag       uint64
	}{
		{OperationSearch, ldap.ApplicationSearchResultDone},
		{OperationSearchWithPaging, ldap.ApplicationSearchResultDone},
		{OperationDirSync, ldap.ApplicationSearchResultDone},
		{OperationCompare, ldap.ApplicationCompareResponse},
		{OperationAdd, ldap.ApplicationAddResponse},
		{OperationModify, ldap.ApplicationModifyResponse},
		{OperationDelete, ldap.ApplicationDelResponse},
		{OperationModifyDN, ldap.ApplicationModifyDNResponse},
		{OperationPasswordModify, ldap.ApplicationExtendedResponse},
		{Operation("unsupported"), ^uint64(0)},
	}
	for _, test := range tests {
		if got := expectedResponseTag(test.operation); got != test.tag {
			t.Errorf("expectedResponseTag(%q) = %d, want %d", test.operation, got, test.tag)
		}
	}
}

func TestWorkerPublishesTerminalBeforeHealthAssessment(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	tracked := newTrackedConn(clientSide)
	defer tracked.Close()
	pool := &Pool{poolState: &poolState{cfg: resolvedConfig{requestTimeout: time.Second}}}
	physical := &physicalConn{
		pool:      pool,
		client:    ldap.NewConn(tracked, false),
		transport: tracked,
	}
	connection := newConnection(pool, physical)
	trace := tracked.begin()

	trace.mu.Lock()
	locked := true
	defer func() {
		if locked {
			trace.mu.Unlock()
		}
	}()
	callReturned := make(chan struct{})
	results := make(chan workerResult[bool], 1)
	var terminal atomic.Uint32
	go executeLDAPOperation(
		connection,
		context.Background(),
		OperationCompare,
		false,
		trace,
		func(ldapClient) (bool, error) {
			close(callReturned)
			return true, nil
		},
		&terminal,
		results,
	)

	receive(t, callReturned)
	waitForCondition(t, func() bool { return terminal.Load() == terminalWorker })
	trace.mu.Unlock()
	locked = false
	result := receive(t, results)
	if !errors.Is(result.assessment.err, ErrProtocol) {
		t.Fatalf("undispatched result assessment = %v, want protocol error", result.assessment.err)
	}
}

type panicWriteConn struct {
	net.Conn
}

func (c *panicWriteConn) Write([]byte) (int, error) {
	panic("transport write payload")
}

func TestWritePanicAfterTransportEntryIsOutcomeUnknown(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		return &panicWriteConn{Conn: conn}
	})}
	config := anonymousTestConfig(dialer)
	config.RequestTimeout = 50 * time.Millisecond
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		request := ldap.NewModifyRequest("cn=x", nil)
		request.Replace("description", []string{"x"})
		return connection.Modify(context.Background(), request)
	})
	if !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrNotSent) {
		t.Fatalf("write panic error = %v", err)
	}
	if pool.Snapshot().Counts.Open != 0 {
		t.Fatal("write-panic connection remained open")
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledDispatchedWriteHasUnknownOutcome(t *testing.T) {
	received := make(chan struct{}, 1)
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := readLDAPRequest(reader); err != nil {
			return
		}
		received <- struct{}{}
		_, _ = readLDAPRequest(reader)
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		result := make(chan error, 1)
		go func() { result <- connection.Del(ctx, ldap.NewDelRequest("cn=x", nil)) }()
		receive(t, received)
		cancel()
		return receive(t, result)
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("canceled write error = %v", err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestLocalValidationFailureDoesNotPoisonConnection(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := contextWithTimeout(t)
	err = pool.WithConnection(ctx, func(connection *Connection) error {
		_, localErr := connection.Search(ctx, ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(", nil, nil))
		if !errors.Is(localErr, ErrNotSent) {
			return fmt.Errorf("local validation error = %v", localErr)
		}
		_, validErr := connection.Search(ctx, ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
		return validErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 1 {
		t.Fatalf("dial count = %d, want 1", dialer.count())
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedResponsePanicIsContainedAndEvicted(t *testing.T) {
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		malformedSearchEntry := berTLV(0x64, nil)
		message := append(berInteger(0x02, request.messageID), malformedSearchEntry...)
		_, _ = conn.Write(berTLV(0x30, message))
		_, _ = readLDAPRequest(reader)
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		_, err := connection.Search(context.Background(), ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
		return err
	})
	if !errors.Is(err, ErrDependencyPanic) {
		t.Fatalf("malformed response error = %v", err)
	}
	if pool.Snapshot().Counts.Open != 0 {
		t.Fatal("connection survived a dependency panic")
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestPublicConnectionMethodSurface(t *testing.T) {
	typeOf := reflect.TypeOf((*Connection)(nil))
	got := make([]string, 0, typeOf.NumMethod())
	for i := 0; i < typeOf.NumMethod(); i++ {
		got = append(got, typeOf.Method(i).Name)
	}
	want := []string{"Add", "Compare", "Del", "DirSync", "GoString", "Modify", "ModifyDN", "PasswordModify", "Search", "SearchWithPaging", "String"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Connection methods = %v, want %v", got, want)
	}
}

func successfulLDAPServerFromReader(conn net.Conn, reader *bufio.Reader) {
	for {
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		if err := writeLDAPResult(conn, request.messageID, responseTag(request.tag), ldap.LDAPResultSuccess, ""); err != nil {
			return
		}
	}
}
