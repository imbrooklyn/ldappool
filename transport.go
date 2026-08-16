package ldappool

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type operationTrace struct {
	mu            sync.Mutex
	writes        uint64
	writtenBytes  uint64
	writeInFlight uint64
	reads         uint64
	writeErr      error
	readErr       error
	stopWrites    bool
}

var errTraceCanceled = errors.New("ldappool: operation canceled before transport write")

func (t *operationTrace) beforeWrite() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writes++
	if t.stopWrites {
		if t.writeErr == nil {
			t.writeErr = errTraceCanceled
		}
		return false
	}
	t.writeInFlight++
	return true
}

func (t *operationTrace) afterWrite(n int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeInFlight--
	if n > 0 {
		t.writtenBytes += uint64(n)
	}
	if err != nil {
		if t.writeErr == nil {
			t.writeErr = err
		}
	}
}

func (t *operationTrace) recordRead(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reads++
	if err != nil {
		if t.readErr == nil {
			t.readErr = err
		}
	}
}

func (t *operationTrace) snapshot() traceSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return traceSnapshot{
		writes:        t.writes,
		writtenBytes:  t.writtenBytes,
		writeInFlight: t.writeInFlight,
		reads:         t.reads,
		writeErr:      t.writeErr,
		readErr:       t.readErr,
	}
}

func (t *operationTrace) cancel() traceSnapshot {
	t.mu.Lock()
	t.stopWrites = true
	snapshot := traceSnapshot{
		writes: t.writes, writtenBytes: t.writtenBytes, writeInFlight: t.writeInFlight,
		reads: t.reads, writeErr: t.writeErr, readErr: t.readErr,
	}
	t.mu.Unlock()
	return snapshot
}

type traceSnapshot struct {
	writes        uint64
	writtenBytes  uint64
	writeInFlight uint64
	reads         uint64
	writeErr      error
	readErr       error
}

type trackedConn struct {
	net.Conn
	active atomic.Pointer[operationTrace]

	closeOnce sync.Once
	closeMu   sync.Mutex
	closeErr  error
}

func newTrackedConn(conn net.Conn) *trackedConn { return &trackedConn{Conn: conn} }

func (c *trackedConn) begin() *operationTrace {
	trace := &operationTrace{}
	c.active.Store(trace)
	return trace
}

func (c *trackedConn) end(trace *operationTrace) traceSnapshot {
	c.active.CompareAndSwap(trace, nil)
	return trace.snapshot()
}

func (c *trackedConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if trace := c.active.Load(); trace != nil {
		trace.recordRead(err)
	}
	return n, err
}

func (c *trackedConn) Write(buffer []byte) (int, error) {
	trace := c.active.Load()
	if trace != nil && !trace.beforeWrite() {
		return 0, errTraceCanceled
	}
	n, err := c.Conn.Write(buffer)
	if trace != nil {
		trace.afterWrite(n, err)
	}
	return n, err
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() {
		func() {
			defer func() {
				if recover() != nil {
					c.closeMu.Lock()
					c.closeErr = &PanicError{Source: "transport close"}
					c.closeMu.Unlock()
				}
			}()
			err := c.Conn.Close()
			c.closeMu.Lock()
			c.closeErr = err
			c.closeMu.Unlock()
		}()
	})
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closeErr
}

type ldapClient interface {
	SetTimeout(time.Duration)
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error)
	DirSync(*ldap.SearchRequest, int64, int64, []byte) (*ldap.SearchResult, error)
	Compare(string, string, string) (bool, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	ModifyDN(*ldap.ModifyDNRequest) error
	PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
}

type connectionState uint8

const (
	connectionConnecting connectionState = iota
	connectionIdle
	connectionBorrowed
	connectionClosing
	connectionClosed
)

type physicalConn struct {
	id         uint64
	pool       *Pool
	client     ldapClient
	transport  *trackedConn
	createdAt  time.Time
	lastUsedAt time.Time
	generation uint64

	state  connectionState // guarded by Pool.mu
	lease  *Connection     // guarded by Pool.mu
	retire atomic.Bool
	fatal  atomic.Bool

	closeOnce   sync.Once
	closeDone   chan struct{}
	closeMu     sync.Mutex
	closeErr    error
	closeReason FailureReason
}

func (c *physicalConn) markFatal(reason FailureReason) {
	c.fatal.Store(true)
	if reason != ReasonNone {
		c.closeMu.Lock()
		if c.closeReason == "" || c.closeReason == ReasonNone {
			c.closeReason = reason
		}
		c.closeMu.Unlock()
	}
}

func (c *physicalConn) startClose(reason FailureReason) {
	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		if c.closeReason == "" || c.closeReason == ReasonNone {
			c.closeReason = reason
		}
		c.closeMu.Unlock()
		go func() {
			c.pool.closeSlots <- struct{}{}
			defer func() { <-c.pool.closeSlots }()
			err := c.transport.Close()
			c.closeMu.Lock()
			c.closeErr = err
			c.closeMu.Unlock()
			c.pool.physicalClosed(c)
			close(c.closeDone)
		}()
	})
}

func (c *physicalConn) closeResult() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closeErr
}

func (c *physicalConn) reason() FailureReason {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closeReason
}
