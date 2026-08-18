package ldappool

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type closingStateLDAPClient struct {
	ldapClient
}

func (closingStateLDAPClient) IsClosing() bool { return true }

type directConnectFixture struct {
	pool      *Pool
	attempt   *connectAttempt
	physical  *physicalConn
	transport *countedConn
	peer      net.Conn
}

func newDirectConnectFixture(t *testing.T) directConnectFixture {
	t.Helper()
	pool, err := New(anonymousTestConfig(&testDialer{factory: func(context.Context, int) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	}}))
	if err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	transport := &countedConn{Conn: client}
	attemptCtx, cancel := context.WithCancel(context.Background())
	attempt := &connectAttempt{id: 41, ctx: attemptCtx, cancel: cancel, generation: 1}
	now := pool.now()
	physical := &physicalConn{
		pool:       pool,
		transport:  newTrackedConn(transport),
		createdAt:  now,
		lastUsedAt: now,
		generation: 1,
		state:      connectionConnecting,
		closeDone:  make(chan struct{}),
	}
	pool.mu.Lock()
	pool.connectAttemptID = attempt.id
	pool.connectCancel = cancel
	pool.open = 1
	pool.connecting = 1
	pool.mu.Unlock()
	t.Cleanup(func() {
		_ = pool.ForceClose(context.Background())
		_ = peer.Close()
	})
	return directConnectFixture{
		pool: pool, attempt: attempt, physical: physical, transport: transport, peer: peer,
	}
}

func TestFinishConnectSuccessDirectIdleRecoveryTransition(t *testing.T) {
	fixture := newDirectConnectFixture(t)
	fixture.pool.mu.Lock()
	fixture.pool.connectFailures = 2
	fixture.pool.retryAt = fixture.pool.now().Add(time.Minute)
	fixture.pool.lastFailure = errors.New("previous failure")
	fixture.pool.lastStage = StageDial
	fixture.pool.lastReason = ReasonDial
	fixture.pool.mu.Unlock()

	fixture.pool.finishConnectSuccess(fixture.attempt, fixture.physical)
	snapshot := fixture.pool.Snapshot()
	if snapshot.State != PoolReady || snapshot.Counts.Open != 1 || snapshot.Counts.Idle != 1 {
		t.Fatalf("successful completion snapshot = %+v", snapshot)
	}
	if snapshot.ConnectFailures != 0 || !snapshot.RetryAt.IsZero() || snapshot.LastFailureStage != StageNone || snapshot.LastFailureReason != ReasonNone {
		t.Fatalf("successful completion did not clear recovery state: %+v", snapshot)
	}
	if fixture.transport.closes.Load() != 0 {
		t.Fatal("healthy completion closed its transport")
	}
}

func TestFinishConnectSuccessDirectHandoffSkipsCanceledWaiter(t *testing.T) {
	fixture := newDirectConnectFixture(t)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := &waiter{ctx: canceledCtx, result: make(chan acquireResult, 1)}
	ready := &waiter{ctx: context.Background(), result: make(chan acquireResult, 1)}
	fixture.pool.mu.Lock()
	canceled.element = fixture.pool.waiters.PushBack(canceled)
	ready.element = fixture.pool.waiters.PushBack(ready)
	fixture.pool.externalWaiters = 2
	fixture.pool.mu.Unlock()

	fixture.pool.finishConnectSuccess(fixture.attempt, fixture.physical)
	if result := receive(t, canceled.result); !errors.Is(result.err, context.Canceled) || result.connection != nil {
		t.Fatalf("canceled waiter result = %+v", result)
	}
	result := receive(t, ready.result)
	if result.err != nil || result.connection == nil {
		t.Fatalf("ready waiter result = %+v", result)
	}
	snapshot := fixture.pool.Snapshot()
	if snapshot.Counts.Borrowed != 1 || snapshot.Counts.Waiters != 0 {
		t.Fatalf("handoff snapshot = %+v", snapshot)
	}
	if err := fixture.pool.releaseAndWait(result.connection, false); err != nil {
		t.Fatal(err)
	}
}

func TestFinishConnectSuccessDirectRetirementTransitions(t *testing.T) {
	tests := []struct {
		name   string
		reason FailureReason
		mutate func(directConnectFixture)
	}{
		{
			name:   "stale credential generation",
			reason: ReasonCredentialRotation,
			mutate: func(fixture directConnectFixture) { fixture.physical.generation = 0 },
		},
		{
			name:   "LDAP client already closing",
			reason: ReasonTransport,
			mutate: func(fixture directConnectFixture) { fixture.physical.client = closingStateLDAPClient{} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDirectConnectFixture(t)
			test.mutate(fixture)
			fixture.pool.finishConnectSuccess(fixture.attempt, fixture.physical)
			receive(t, fixture.physical.closeDone)
			snapshot := fixture.pool.Snapshot()
			if snapshot.Counts != (Counts{}) {
				t.Fatalf("retired completion counts = %+v", snapshot.Counts)
			}
			if !fixture.physical.retire.Load() || !fixture.physical.fatal.Load() || fixture.physical.reason() != test.reason {
				t.Fatalf("retired completion state: retire=%t fatal=%t reason=%s", fixture.physical.retire.Load(), fixture.physical.fatal.Load(), fixture.physical.reason())
			}
			if fixture.transport.closes.Load() != 1 {
				t.Fatalf("transport close count = %d, want 1", fixture.transport.closes.Load())
			}
		})
	}
}

func TestFinishConnectSuccessDirectRetiresExcessIdle(t *testing.T) {
	fixture := newDirectConnectFixture(t)
	idleClient, idlePeer := net.Pipe()
	t.Cleanup(func() { _ = idlePeer.Close() })
	idle := &physicalConn{
		id:         1,
		pool:       fixture.pool,
		transport:  newTrackedConn(idleClient),
		createdAt:  fixture.pool.now(),
		lastUsedAt: fixture.pool.now(),
		generation: 1,
		state:      connectionIdle,
		closeDone:  make(chan struct{}),
	}
	fixture.pool.mu.Lock()
	fixture.pool.cfg.maxIdle = 1
	fixture.pool.nextConnectionID = idle.id
	fixture.pool.open++
	fixture.pool.idleCount++
	fixture.pool.physical[idle.id] = idle
	fixture.pool.idle = append(fixture.pool.idle, idle)
	fixture.pool.mu.Unlock()

	fixture.pool.finishConnectSuccess(fixture.attempt, fixture.physical)
	receive(t, fixture.physical.closeDone)
	snapshot := fixture.pool.Snapshot()
	if snapshot.Counts.Open != 1 || snapshot.Counts.Idle != 1 || snapshot.Counts.Closing != 0 {
		t.Fatalf("excess-idle completion counts = %+v", snapshot.Counts)
	}
	if fixture.physical.reason() != ReasonMaxIdle || fixture.transport.closes.Load() != 1 {
		t.Fatalf("excess-idle completion reason=%s closes=%d", fixture.physical.reason(), fixture.transport.closes.Load())
	}
}

func TestFinishConnectSuccessDirectDiscardsStaleAttempt(t *testing.T) {
	fixture := newDirectConnectFixture(t)
	fixture.pool.mu.Lock()
	fixture.pool.connectAttemptID++
	fixture.pool.connectCancel = nil
	fixture.pool.open = 0
	fixture.pool.connecting = 0
	fixture.pool.mu.Unlock()

	fixture.pool.finishConnectSuccess(fixture.attempt, fixture.physical)
	waitForCondition(t, func() bool { return fixture.transport.closes.Load() == 1 })
	fixture.pool.mu.Lock()
	registered := len(fixture.pool.physical)
	fixture.pool.mu.Unlock()
	if registered != 0 || fixture.pool.Snapshot().Counts != (Counts{}) {
		t.Fatalf("stale completion was registered: physical=%d snapshot=%+v", registered, fixture.pool.Snapshot())
	}
}

func TestFinishConnectSuccessDirectClosesCompletionDuringShutdown(t *testing.T) {
	fixture := newDirectConnectFixture(t)
	fixture.pool.startShutdown(false)
	if state := fixture.pool.Snapshot().State; state != PoolClosing {
		t.Fatalf("state before completion = %s, want closing", state)
	}

	fixture.pool.finishConnectSuccess(fixture.attempt, fixture.physical)
	receive(t, fixture.physical.closeDone)
	if fixture.physical.reason() != ReasonPoolClose {
		t.Fatalf("completion close reason = %s, want pool close", fixture.physical.reason())
	}
	if err := fixture.pool.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertClosedPoolInvariants(t, fixture.pool)
}

func TestShutdownPublicMethodsValidateContextAndShareTerminalState(t *testing.T) {
	pool, err := New(anonymousTestConfig(&testDialer{factory: pipeFactory(successfulLDAPServer, nil)}))
	if err != nil {
		t.Fatal(err)
	}
	for name, closePool := range map[string]func(context.Context) error{
		"Close":      pool.Close,
		"ForceClose": pool.ForceClose,
	} {
		t.Run(name+" nil context", func(t *testing.T) {
			err := closePool(nil)
			var configErr *ConfigError
			if !errors.As(err, &configErr) || configErr.Field != "context" {
				t.Fatalf("nil context error = %v, want context config error", err)
			}
			if pool.Snapshot().State != PoolCold {
				t.Fatalf("nil context changed pool state to %s", pool.Snapshot().State)
			}
		})
	}

	if err := pool.ForceClose(context.Background()); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pool.Close(canceled); err != nil {
		t.Fatalf("idempotent Close after terminal state = %v", err)
	}
	if err := pool.ForceClose(canceled); err != nil {
		t.Fatalf("idempotent ForceClose after terminal state = %v", err)
	}
	assertClosedPoolInvariants(t, pool)
}
