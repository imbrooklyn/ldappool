package ldappool

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type eventCollector struct {
	mu      sync.Mutex
	history []Event
	events  chan Event
}

func (o *eventCollector) Observe(event Event) {
	o.mu.Lock()
	o.history = append(o.history, event)
	o.mu.Unlock()
	o.events <- event
}

func (o *eventCollector) types() []EventType {
	o.mu.Lock()
	defer o.mu.Unlock()
	types := make([]EventType, len(o.history))
	for i := range o.history {
		types[i] = o.history[i].Type
	}
	return types
}

func waitForEvent(t *testing.T, observer *eventCollector, eventType EventType) Event {
	t.Helper()
	deadline := time.After(testTimeout)
	for {
		select {
		case event := <-observer.events:
			if event.Type == eventType {
				return event
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event %s", eventType)
		}
	}
}

func TestShortAcquireDeadlineDoesNotCancelSharedColdConnect(t *testing.T) {
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var startOnce sync.Once
	dialer := &testDialer{factory: func(ctx context.Context, call int) (net.Conn, error) {
		startOnce.Do(func() { close(dialStarted) })
		select {
		case <-releaseDial:
			client, server := net.Pipe()
			go successfulLDAPServer(server, call)
			return client, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	shortCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- pool.WithConnection(shortCtx, func(*Connection) error { return nil })
	}()
	receive(t, dialStarted)
	if err := receive(t, firstResult); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first acquire error = %v", err)
	}
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	}()
	close(releaseDial)
	if err := receive(t, secondResult); err != nil {
		t.Fatalf("second acquire did not recover: %v", err)
	}
	if dialer.count() != 1 {
		t.Fatalf("dial count = %d, want 1", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestBackoffDoesNotBlockBorrowedConnectionHandoff(t *testing.T) {
	dialTwo := make(chan struct{})
	observer := &eventCollector{events: make(chan Event, 64)}
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		if call == 2 {
			close(dialTwo)
			return nil, errors.New("temporary dial failure")
		}
		client, server := net.Pipe()
		go successfulLDAPServer(server, call)
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.Observer = observer
	config.ConnectBackoff = BackoffConfig{Initial: time.Second, Multiplier: 2, Max: time.Second, Jitter: .01}
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(held)
			<-release
			return nil
		})
	}()
	receive(t, held)
	secondEntered := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(secondEntered)
			return nil
		})
	}()
	receive(t, dialTwo)
	waitForEvent(t, observer, EventBackoffArmed)
	close(release)
	receive(t, secondEntered)
	if err := receive(t, firstResult); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, secondResult); err != nil {
		t.Fatalf("waiting request fast-failed during backoff: %v", err)
	}
	if dialer.count() != 2 {
		t.Fatalf("dial count = %d, want 2", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestRetryAtTimerWakesWaiterWithoutConnectionEvent(t *testing.T) {
	dialTwo := make(chan struct{})
	dialThree := make(chan struct{})
	observer := &eventCollector{events: make(chan Event, 64)}
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		switch call {
		case 2:
			close(dialTwo)
			return nil, errors.New("temporary dial failure")
		case 3:
			close(dialThree)
		}
		client, server := net.Pipe()
		go successfulLDAPServer(server, call)
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.Observer = observer
	config.ConnectBackoff = BackoffConfig{Initial: 25 * time.Millisecond, Multiplier: 1, Max: 25 * time.Millisecond, Jitter: .01}
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(held)
			<-release
			return nil
		})
	}()
	receive(t, held)
	secondEntered := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(secondEntered)
			return nil
		})
	}()
	receive(t, dialTwo)
	waitForEvent(t, observer, EventBackoffArmed)
	receive(t, dialThree)
	receive(t, secondEntered)
	close(release)
	if err := receive(t, firstResult); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, secondResult); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 3 {
		t.Fatalf("dial count = %d, want 3", dialer.count())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedCredentialGuardDoesNotScheduleExpiredCreationGate(t *testing.T) {
	pool := &Pool{poolState: &poolState{
		cfg:       resolvedConfig{maxOpen: 2, maxIdleTime: time.Minute, maxLifetime: time.Minute},
		lifecycle: poolRunning,
		retryAt:   time.Now().Add(-time.Second),
		credentials: newCredentialAuthority("", nil, backoffPolicy{
			initial: time.Second, multiplier: 2, max: time.Minute, jitter: .1,
		}, nil, false),
	}}
	pool.credentials.guard.mu.Lock()
	pool.credentials.guard.state = CredentialBlocked
	pool.credentials.guard.reason = CredentialReasonInvalid
	pool.credentials.guard.mu.Unlock()

	pool.mu.Lock()
	waiter := &waiter{ctx: context.Background(), internal: true}
	waiter.element = pool.waiters.PushBack(waiter)
	pool.mu.Unlock()
	if next, ok := pool.nextSchedulerWake(); ok || !next.IsZero() {
		t.Fatalf("blocked Guard scheduled stale creation deadline %v", next)
	}
}

func TestFIFOAndCanceledWaiterRemoval(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(held)
			<-release
			return nil
		})
	}()
	receive(t, held)

	order := make(chan int, 3)
	results := make(chan error, 3)
	for i := 1; i <= 3; i++ {
		i := i
		go func() {
			results <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
				order <- i
				return nil
			})
		}()
		want := i
		waitForCondition(t, func() bool {
			p := pool
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.waiters.Len() == want
		})
	}
	close(release)
	if err := receive(t, firstResult); err != nil {
		t.Fatal(err)
	}
	for want := 1; want <= 3; want++ {
		if got := receive(t, order); got != want {
			t.Fatalf("FIFO order got %d, want %d", got, want)
		}
		if err := receive(t, results); err != nil {
			t.Fatal(err)
		}
	}

	heldAgain := make(chan struct{})
	releaseAgain := make(chan struct{})
	go func() {
		_ = pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(heldAgain)
			<-releaseAgain
			return nil
		})
	}()
	receive(t, heldAgain)
	waitCtx, cancel := context.WithCancel(context.Background())
	canceledResult := make(chan error, 1)
	go func() {
		canceledResult <- pool.WithConnection(waitCtx, func(*Connection) error { return nil })
	}()
	waitForCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.waiters.Len() == 1
	})
	cancel()
	if err := receive(t, canceledResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	waitForCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.waiters.Len() == 0
	})
	close(releaseAgain)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestWaitQueueLimit(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	config.MaxWaiters = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = pool.WithConnection(contextWithTimeout(t), func(*Connection) error {
			close(held)
			<-release
			return nil
		})
	}()
	receive(t, held)
	waitCtx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() { waiting <- pool.WithConnection(waitCtx, func(*Connection) error { return nil }) }()
	waitForCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.waiters.Len() == 1
	})
	err = pool.WithConnection(context.Background(), func(*Connection) error { return nil })
	if !errors.Is(err, ErrWaitQueueFull) {
		t.Fatalf("queue overflow error = %v", err)
	}
	cancel()
	_ = receive(t, waiting)
	close(release)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCopiedPoolHandleSharesLifecycleState(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	copied := *pool
	if err := (&copied).WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	if snapshot := (&copied).Snapshot(); snapshot.State != PoolClosed || snapshot.Counts != (Counts{}) {
		t.Fatalf("copied Pool forked lifecycle state: %+v", snapshot)
	}
}

func TestWarmupFillsToMaxOpenWithoutExceedingMaxIdle(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 3
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Warmup(contextWithTimeout(t), 3); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 3 {
		t.Fatalf("Warmup dial count = %d, want 3", dialer.count())
	}
	snapshot := pool.Snapshot()
	if snapshot.Counts.Open != 1 || snapshot.Counts.Idle != 1 {
		t.Fatalf("post-Warmup counts = %+v, want one retained idle", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestWarmupReportsExcessConnectionCloseFailure(t *testing.T) {
	closeFailure := errors.New("synthetic Warmup close failure")
	allowClose := make(chan struct{})
	close(allowClose)
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, call int) net.Conn {
		if call == 2 {
			return &blockingCloseConn{Conn: conn, started: make(chan struct{}), allow: allowClose, err: closeFailure}
		}
		return conn
	})}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 2
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.Warmup(contextWithTimeout(t), 2)
	if !errors.Is(err, ErrCloseFailed) || !errors.Is(err, closeFailure) {
		t.Fatalf("Warmup cleanup error = %v", err)
	}
	if snapshot := pool.Snapshot(); snapshot.Counts.Open != 1 || snapshot.Counts.Idle != 1 {
		t.Fatalf("Warmup cleanup damaged healthy capacity: %+v", snapshot.Counts)
	}
	if err := pool.Close(contextWithTimeout(t)); !errors.Is(err, ErrCloseFailed) || !errors.Is(err, closeFailure) {
		t.Fatalf("terminal cleanup error = %v", err)
	}
}

func TestWarmupDoesNotCountFatalBorrowedConnectionAsHealthy(t *testing.T) {
	requestReceived := make(chan struct{})
	dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
		client, server := net.Pipe()
		if call == 1 {
			go func() {
				defer server.Close()
				if _, err := readLDAPRequest(bufio.NewReader(server)); err == nil {
					close(requestReceived)
				}
				buffer := make([]byte, 1)
				_, _ = server.Read(buffer)
			}()
		} else {
			go successfulLDAPServer(server, call)
		}
		return client, nil
	}}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 2
	config.MaxIdle = 2
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	operationDone := make(chan error, 1)
	releaseCallback := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- pool.WithConnection(contextWithTimeout(t), func(connection *Connection) error {
			_, operationErr := connection.Search(cancelCtx, ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", nil, nil))
			operationDone <- operationErr
			<-releaseCallback
			return nil
		})
	}()
	receive(t, requestReceived)
	cancel()
	if err := receive(t, operationDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled operation error = %v", err)
	}
	if err := pool.Warmup(contextWithTimeout(t), 1); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 2 {
		t.Fatalf("Warmup counted fatal borrowed connection; dials=%d", dialer.count())
	}
	close(releaseCallback)
	if err := receive(t, callbackDone); err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestPhysicalCloseHoldsCapacityUntilItReturns(t *testing.T) {
	closeStarted := make(chan struct{})
	allowClose := make(chan struct{})
	firstConn := &countedConn{started: closeStarted, allow: allowClose}
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, func(conn net.Conn, call int) net.Conn {
		if call == 1 {
			firstConn.Conn = conn
			return firstConn
		}
		return conn
	})}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	config.MaxLifetime = time.Nanosecond
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	}()
	receive(t, closeStarted)
	snapshot := pool.Snapshot()
	if snapshot.Counts.Open != 1 || snapshot.Counts.Closing != 1 {
		t.Fatalf("counts while Close blocks = %+v", snapshot.Counts)
	}
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	}()
	waitForCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.waiters.Len() == 1
	})
	if dialer.count() != 1 {
		t.Fatalf("replacement dial started before physical close: %d", dialer.count())
	}
	close(allowClose)
	if err := receive(t, firstResult); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, secondResult); err != nil {
		t.Fatal(err)
	}
	if firstConn.closes.Load() != 1 {
		t.Fatalf("first transport closed %d times", firstConn.closes.Load())
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCloseCancelsDialAndWakesWaiters(t *testing.T) {
	dialStarted := make(chan struct{})
	dialer := &testDialer{factory: func(ctx context.Context, _ int) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	acquireResult := make(chan error, 1)
	go func() {
		acquireResult <- pool.WithConnection(context.Background(), func(*Connection) error { return nil })
	}()
	receive(t, dialStarted)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, acquireResult); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("acquire error = %v, want pool closed", err)
	}
	snapshot := pool.Snapshot()
	if snapshot.State != PoolClosed || snapshot.Counts.Open != 0 {
		t.Fatalf("closed snapshot = %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestCloseInvalidatesBorrowedLeaseAndWakesQueuedWaiter(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan *Connection, 1)
	release := make(chan struct{})
	borrowResult := make(chan error, 1)
	go func() {
		borrowResult <- pool.WithConnection(context.Background(), func(connection *Connection) error {
			held <- connection
			<-release
			return nil
		})
	}()
	lease := receive(t, held)
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- pool.WithConnection(context.Background(), func(*Connection) error { return nil })
	}()
	waitForCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.waiters.Len() == 1
	})
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
	if err := receive(t, waitResult); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("queued waiter error = %v", err)
	}
	_, err = lease.Compare(context.Background(), "cn=x", "cn", "x")
	if !errors.Is(err, ErrLeaseInvalid) {
		t.Fatalf("borrowed lease after Close = %v", err)
	}
	close(release)
	if err := receive(t, borrowResult); err != nil {
		t.Fatal(err)
	}
}

func TestIdleReaperClosesLowQPSConnection(t *testing.T) {
	observer := &eventCollector{events: make(chan Event, 64)}
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxIdleTime = 20 * time.Millisecond
	config.Observer = observer
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitForEvent(t, observer, EventAcquireSuccess)
	event := waitForEvent(t, observer, EventEviction)
	if event.Reason != ReasonIdleTimeout {
		t.Fatalf("eviction reason = %s, want %s", event.Reason, ReasonIdleTimeout)
	}
	waitForCondition(t, func() bool { return pool.Snapshot().Counts.Open == 0 })
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialRotationRetiresOldGeneration(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := contextWithTimeout(t)
	if err := pool.WithConnection(ctx, func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := pool.RotateCredentials(NewSecret([]byte("new secret"))); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, func() bool { return pool.Snapshot().Counts.Open == 0 })
	if err := pool.WithConnection(ctx, func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if dialer.count() != 2 || pool.Snapshot().Generation != 2 {
		t.Fatalf("rotation: dials=%d snapshot=%+v", dialer.count(), pool.Snapshot())
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

type blockingObserver struct {
	entered chan struct{}
	allow   chan struct{}
	once    sync.Once
}

func (o *blockingObserver) Observe(Event) {
	o.once.Do(func() { close(o.entered) })
	<-o.allow
}

func TestObserverCannotBlockPool(t *testing.T) {
	observer := &blockingObserver{entered: make(chan struct{}), allow: make(chan struct{})}
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.Observer = observer
	config.ObserverBuffer = 1
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }) }()
	receive(t, observer.entered)
	if err := receive(t, result); err != nil {
		t.Fatalf("blocked observer blocked Pool: %v", err)
	}
	if pool.Snapshot().ObserverDropped == 0 {
		t.Fatal("expected observer queue drops")
	}
	close(observer.allow)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestObserverPanicIsContained(t *testing.T) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.Observer = ObserverFunc(func(Event) { panic("observer") })
	pool, err := New(config)
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

func TestObserverCanReenterSnapshot(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	var pool *Pool
	observer := ObserverFunc(func(Event) {
		_ = pool.Snapshot()
		once.Do(func() { close(entered) })
	})
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.Observer = observer
	var err error
	pool, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); err != nil {
		t.Fatal(err)
	}
	receive(t, entered)
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialGuardBlocksRepeatedBadBind(t *testing.T) {
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request, err := readLDAPRequest(reader)
		if err != nil {
			return
		}
		_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "data 52e")
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	pool, err := New(simpleTestConfig(dialer))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
		if !errors.Is(err, ErrCredentialBlocked) || !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			t.Fatalf("attempt %d error = %v", i+1, err)
		}
	}
	if dialer.count() != 1 {
		t.Fatalf("blocked guard dialed %d times", dialer.count())
	}
	snapshot := pool.Snapshot()
	if snapshot.CredentialState != CredentialBlocked || snapshot.CredentialReason != CredentialReasonInvalid {
		t.Fatalf("credential snapshot = %+v", snapshot)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}
