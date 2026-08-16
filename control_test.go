package ldappool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type blockingControl struct {
	*ldap.ControlString
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingControl) GetControlType() string {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.ControlString.GetControlType()
}

type writeCountingConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *writeCountingConn) Write(buffer []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(buffer)
}

func TestMutableControlsAreDeepCopied(t *testing.T) {
	paging := &ldap.ControlPaging{PagingSize: 10, Cookie: []byte("paging")}
	clonedPaging, err := clonePagingControls([]ldap.Control{paging})
	if err != nil {
		t.Fatal(err)
	}
	pagingCopy := clonedPaging[0].(*ldap.ControlPaging)
	pagingCopy.Cookie[0] = 'X'
	if string(paging.Cookie) != "paging" {
		t.Fatal("paging cookie alias escaped")
	}

	dirSync := &ldap.ControlDirSync{Criticality: true, Flags: 1, MaxAttrCount: 2, Cookie: []byte("cookie")}
	clonedDirSync, err := cloneDirSyncControls([]ldap.Control{dirSync})
	if err != nil {
		t.Fatal(err)
	}
	dirSyncCopy := clonedDirSync[0].(*ldap.ControlDirSync)
	dirSyncCopy.Cookie[0] = 'X'
	if string(dirSync.Cookie) != "cookie" {
		t.Fatal("DirSync cookie alias escaped")
	}
}

func TestMisleadingMutableControlIsRejectedBeforeDispatch(t *testing.T) {
	if _, err := clonePagingControls([]ldap.Control{&ldap.ControlString{ControlType: ldap.ControlTypePaging}}); err == nil {
		t.Fatal("misleading paging control was accepted")
	}
	if _, err := cloneDirSyncControls([]ldap.Control{&ldap.ControlString{ControlType: ldap.ControlTypeDirSync}}); err == nil {
		t.Fatal("misleading DirSync control was accepted")
	}
	if _, err := cloneSearchRequest(nil, cloneControlsShallow); err == nil {
		t.Fatal("nil SearchRequest was accepted")
	}
	if _, err := cloneSearchRequest(&ldap.SearchRequest{}, func([]ldap.Control) ([]ldap.Control, error) {
		return nil, errors.New("clone failure")
	}); err == nil {
		t.Fatal("control clone failure was ignored")
	}
}

func TestCancellationDuringPreflightCannotDispatch(t *testing.T) {
	var transport *writeCountingConn
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		transport = &writeCountingConn{Conn: conn}
		return transport
	})}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	control := &blockingControl{
		ControlString: &ldap.ControlString{ControlType: "1.2.3.4"},
		entered:       entered,
		release:       release,
	}
	result := make(chan error, 1)
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		go func() {
			_, operationErr := connection.SearchWithPaging(ctx, ldap.NewSearchRequest(
				"dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false,
				"(objectClass=*)", nil, []ldap.Control{control},
			), 10)
			result <- operationErr
		}()
		receive(t, entered)
		cancel()
		close(release)
		return receive(t, result)
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrNotSent) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("preflight cancellation error = %v", err)
	}
	if transport.writes.Load() != 0 {
		t.Fatalf("preflight cancellation wrote %d request(s)", transport.writes.Load())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackReturnDuringPreflightCannotDispatchLater(t *testing.T) {
	var transport *writeCountingConn
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, _ int) net.Conn {
		transport = &writeCountingConn{Conn: conn}
		return transport
	})}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	control := &blockingControl{
		ControlString: &ldap.ControlString{ControlType: "1.2.3.4"},
		entered:       entered,
		release:       release,
	}
	result := make(chan error, 1)
	err = pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
		go func() {
			_, operationErr := connection.SearchWithPaging(context.Background(), ldap.NewSearchRequest(
				"dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false,
				"(objectClass=*)", nil, []ldap.Control{control},
			), 10)
			result <- operationErr
		}()
		receive(t, entered)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	operationErr := receive(t, result)
	if !errors.Is(operationErr, ErrLeaseInvalid) || !errors.Is(operationErr, ErrNotSent) {
		t.Fatalf("post-callback operation error = %v", operationErr)
	}
	if transport.writes.Load() != 0 {
		t.Fatalf("post-callback preflight wrote %d request(s)", transport.writes.Load())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}
