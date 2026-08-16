package ldappool

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

type poolLifecycle uint8

const (
	poolRunning poolLifecycle = iota
	poolClosingLifecycle
	poolClosedLifecycle
)

type credentialStore struct {
	mu         sync.Mutex
	generation atomic.Uint64
	password   []byte
}

func (s *credentialStore) snapshot() (uint64, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation.Load(), append([]byte(nil), s.password...)
}

func (s *credentialStore) rotateOwned(password []byte) (generation uint64, old []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old = s.password
	s.password = password
	generation = s.generation.Add(1)
	return generation, old
}

func (s *credentialStore) destroy() {
	s.mu.Lock()
	wipe(s.password)
	s.password = nil
	s.mu.Unlock()
}

type waiter struct {
	ctx      context.Context
	queuedAt time.Time
	result   chan acquireResult
	element  *list.Element
	done     bool
	internal bool
}

type acquireResult struct {
	connection *Connection
	err        error
}

// Pool owns reusable physical LDAP connections for one fixed identity. Its
// zero value is invalid; construct it with New. Its state is held behind an
// opaque pointer so accidental value formatting cannot traverse secrets.
type Pool struct {
	*poolState
}

type poolState struct {
	cfg        resolvedConfig
	identityMu sync.Mutex

	rootCtx    context.Context
	rootCancel context.CancelFunc

	// Nested lock order is identityMu, mu, then credential.mu or guard.mu.
	mu sync.Mutex

	lifecycle  poolLifecycle
	open       int
	idleCount  int
	borrowed   int
	connecting int
	closing    int

	idle             []*physicalConn
	physical         map[uint64]*physicalConn
	waiters          list.List
	externalWaiters  int
	nextConnectionID uint64
	nextAttemptID    uint64
	connectAttemptID uint64
	connectCancel    context.CancelFunc

	connectFailures uint64
	retryAt         time.Time
	lastFailure     error
	lastStage       FailureStage
	lastReason      FailureReason

	wake          chan struct{}
	wakeSeq       atomic.Uint64
	schedulerDone chan struct{}
	closeDone     chan struct{}
	forceOnce     sync.Once
	graceTimer    *time.Timer
	closeCause    error

	credential credentialStore
	guard      credentialGuard

	observer    *observerDispatcher
	closeSlots  chan struct{}
	warmupToken chan struct{}
	now         func() time.Time
	random      func() float64
}

// String returns a constant redacted representation.
func (Pool) String() string { return "ldappool.Pool{[REDACTED]}" }

// GoString returns a constant redacted representation.
func (Pool) GoString() string { return "ldappool.Pool{[REDACTED]}" }

// New validates static configuration and returns a cold Pool. It performs no
// DNS lookup, network dial, TLS handshake, or Bind.
func New(config Config) (*Pool, error) {
	resolved, err := resolveConfig(config)
	if err != nil {
		return nil, err
	}
	rootCtx, cancel := context.WithCancel(context.Background())
	p := &Pool{poolState: &poolState{
		cfg:           resolved,
		rootCtx:       rootCtx,
		rootCancel:    cancel,
		lifecycle:     poolRunning,
		lastStage:     StageNone,
		lastReason:    ReasonNone,
		physical:      make(map[uint64]*physicalConn),
		wake:          make(chan struct{}, 1),
		schedulerDone: make(chan struct{}),
		closeDone:     make(chan struct{}),
		guard:         newCredentialGuard(resolved.credentialBackoff),
		observer:      newObserverDispatcher(resolved.observer, resolved.observerBuffer),
		closeSlots:    make(chan struct{}, min(resolved.maxOpen, 8)),
		warmupToken:   make(chan struct{}, 1),
		now:           time.Now,
		random:        rand.Float64,
	}}
	p.credential.password = resolved.password
	p.credential.generation.Store(1)
	p.warmupToken <- struct{}{}
	p.cfg.password = nil
	go p.scheduler()
	return p, nil
}

// WithConnection acquires a FIFO callback-scoped lease. The Connection becomes
// permanently invalid when callback returns. callback must not be nil and must
// not allow an LDAP operation to outlive it; a busy return invalidates the
// lease, force-closes its transport, and waits only for the cleanup budget.
func (p *Pool) WithConnection(ctx context.Context, callback func(*Connection) error) (returnErr error) {
	if callback == nil {
		return configError("callback", "must not be nil")
	}
	connection, err := p.acquire(ctx, false)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		panicValue := recover()
		abnormal := !completed
		closeErr := p.releaseAndWait(connection, abnormal)
		if panicValue != nil {
			panic(panicValue)
		}
		if !abnormal {
			returnErr = errors.Join(returnErr, closeErr)
		}
	}()
	returnErr = callback(connection)
	completed = true
	return returnErr
}

// Warmup establishes enough authenticated connections for the Pool to have at
// least target healthy open connections at one instant. Excess idle connections
// above MaxIdle are closed within one cleanup budget before Warmup returns;
// cleanup failures are returned. A failure does not close or permanently poison
// the Pool.
func (p *Pool) Warmup(ctx context.Context, target int) (returnErr error) {
	if target < 1 || target > p.cfg.maxOpen {
		return configError("Warmup target", "must be between 1 and MaxOpen")
	}
	if ctx == nil {
		return configError("context", "must not be nil")
	}
	select {
	case <-ctx.Done():
		return &AcquireError{Stage: StageAcquire, Cause: ctx.Err()}
	case <-p.warmupToken:
	}
	defer func() { p.warmupToken <- struct{}{} }()
	held := make([]*Connection, 0, target)
	defer func() {
		returnErr = errors.Join(returnErr, p.releaseWarmupConnections(held))
	}()
	for {
		p.mu.Lock()
		healthy := p.healthyLocked()
		life := p.lifecycle
		p.mu.Unlock()
		if life != poolRunning {
			return ErrPoolClosed
		}
		if healthy >= target {
			return nil
		}
		connection, err := p.acquire(ctx, true)
		if err != nil {
			return err
		}
		held = append(held, connection)
	}
}

func (p *Pool) releaseWarmupConnections(connections []*Connection) error {
	waiting := make([]*physicalConn, 0, len(connections))
	for _, connection := range connections {
		physical, wait := p.release(connection, false)
		if physical != nil && wait {
			waiting = append(waiting, physical)
		}
	}
	if len(waiting) == 0 {
		return nil
	}

	timer := time.NewTimer(p.cfg.closeTimeout)
	defer timer.Stop()
	var result error
	for index, physical := range waiting {
		select {
		case <-physical.closeDone:
			if err := physical.closeResult(); err != nil {
				result = errors.Join(result, &CloseError{Cause: err})
			}
		case <-timer.C:
			remaining := 0
			for _, pending := range waiting[index:] {
				select {
				case <-pending.closeDone:
					if err := pending.closeResult(); err != nil {
						result = errors.Join(result, &CloseError{Cause: err})
					}
				default:
					remaining++
				}
			}
			if remaining == 0 {
				return result
			}
			return errors.Join(result, &CloseError{Remaining: remaining, TimedOut: true, Cause: context.DeadlineExceeded})
		}
	}
	return result
}

// RotateCredentials replaces the simple-Bind password, increments the Pool
// identity generation, cancels an old connection attempt, and retires all old
// generation connections. The Bind principal cannot be changed.
func (p *Pool) RotateCredentials(secret Secret) error {
	p.identityMu.Lock()
	defer p.identityMu.Unlock()
	if p.cfg.authMode != AuthSimple {
		return configError("Auth.Password", "credential rotation requires simple authentication")
	}
	if secret.empty() {
		return configError("Auth.Password", "must not be empty")
	}
	newPassword := secret.cloneBytes()
	var closeList []*physicalConn
	var cancelConnect context.CancelFunc
	var oldPassword []byte
	var guard guardSnapshot
	p.mu.Lock()
	if p.lifecycle != poolRunning {
		p.mu.Unlock()
		wipe(newPassword)
		return ErrPoolClosed
	}
	generation, oldPassword := p.credential.rotateOwned(newPassword)
	cancelConnect = p.connectCancel
	for _, connection := range append([]*physicalConn(nil), p.idle...) {
		if connection.generation != generation {
			p.beginCloseLocked(connection, ReasonCredentialRotation)
			closeList = append(closeList, connection)
		}
	}
	p.compactIdleLocked()
	for _, connection := range p.physical {
		if connection.state == connectionBorrowed && connection.generation != generation {
			connection.retire.Store(true)
			lease := connection.lease
			if lease == nil || lease.invalidateUnlessBusy() != leaseBusy {
				reason := ReasonCredentialRotation
				if connection.fatal.Load() {
					reason = connection.reason()
				}
				p.beginCloseLocked(connection, reason)
				closeList = append(closeList, connection)
			}
		}
	}
	guard = p.guard.reset(generation, CredentialReasonCredentialRotated)
	p.mu.Unlock()
	wipe(oldPassword)
	if cancelConnect != nil {
		cancelConnect()
	}
	p.startCloseAll(closeList)
	p.signal()
	p.emit(Event{Type: EventCredentialState, CredentialState: guard.state, CredentialReason: guard.reason})
	return nil
}

// ResetCredentialGuard explicitly clears this Pool's in-process credential guard.
// It does not change credentials or revive existing connections.
func (p *Pool) ResetCredentialGuard() error {
	p.identityMu.Lock()
	defer p.identityMu.Unlock()
	p.mu.Lock()
	if p.lifecycle != poolRunning {
		p.mu.Unlock()
		return ErrPoolClosed
	}
	generation := p.credential.generation.Load()
	guard := p.guard.reset(generation, CredentialReasonManualReset)
	p.mu.Unlock()
	p.signal()
	p.emit(Event{Type: EventCredentialState, CredentialState: guard.state, CredentialReason: guard.reason})
	return nil
}

// Snapshot returns a passive, redacted state snapshot.
func (p *Pool) Snapshot() Snapshot {
	now := p.now()
	p.mu.Lock()
	counts := p.countsLocked()
	healthy := p.healthyLocked()
	lifecycle := p.lifecycle
	retryAt := p.retryAt
	failures := p.connectFailures
	lastStage := p.lastStage
	lastReason := p.lastReason
	p.mu.Unlock()
	guard := p.guard.snapshot()
	state := projectPoolState(lifecycle, counts, healthy, retryAt, guard, now)
	dropped := uint64(0)
	if p.observer != nil {
		dropped = p.observer.dropped.Load()
	}
	return Snapshot{
		CapturedAt:         now,
		State:              state,
		Counts:             counts,
		Generation:         p.credential.generation.Load(),
		RetryAt:            retryAt,
		ConnectFailures:    failures,
		LastFailureStage:   lastStage,
		LastFailureReason:  lastReason,
		CredentialState:    guard.state,
		CredentialReason:   guard.reason,
		CredentialRetryAt:  guard.retryAt,
		CredentialFailures: guard.failures,
		ObserverDropped:    dropped,
	}
}

// Close stops acquisition, allows in-flight operations to finish within the
// shutdown budget, and then force-closes remaining transports. It is idempotent.
func (p *Pool) Close(ctx context.Context) error {
	return p.close(ctx, false)
}

// ForceClose stops acquisition and immediately closes every transport. It is
// idempotent and shares the same terminal lifecycle as Close.
func (p *Pool) ForceClose(ctx context.Context) error {
	return p.close(ctx, true)
}

func (p *Pool) acquire(ctx context.Context, internal bool) (*Connection, error) {
	if ctx == nil {
		return nil, &AcquireError{Stage: StageAcquire, Cause: configError("context", "must not be nil")}
	}
	if err := ctx.Err(); err != nil {
		return nil, &AcquireError{Stage: StageAcquire, Cause: err}
	}
	now := p.now()
	var expired []*physicalConn
	p.mu.Lock()
	if p.lifecycle != poolRunning {
		p.mu.Unlock()
		return nil, &AcquireError{Stage: StageAcquire, Cause: ErrPoolClosed, kind: ErrPoolClosed}
	}
	expired = p.collectExpiredLocked(now)
	if p.waiters.Len() == 0 {
		if physical := p.takeIdleLocked(); physical != nil {
			connection := p.borrowLocked(physical)
			p.mu.Unlock()
			p.startCloseAll(expired)
			if err := ctx.Err(); err != nil {
				p.releaseAndWait(connection, false)
				return nil, &AcquireError{Stage: StageAcquire, Cause: err}
			}
			p.emit(Event{Type: EventAcquireSuccess})
			return connection, nil
		}
	}
	if p.open == 0 {
		guard := p.guard.snapshot()
		if err := p.immediateGateErrorLocked(now, guard); err != nil {
			p.mu.Unlock()
			p.startCloseAll(expired)
			return nil, err
		}
	}
	if !internal && p.externalWaiters >= p.cfg.maxWaiters {
		p.mu.Unlock()
		p.startCloseAll(expired)
		return nil, &AcquireError{Stage: StageAcquire, Cause: ErrWaitQueueFull, kind: ErrWaitQueueFull}
	}
	w := &waiter{ctx: ctx, queuedAt: now, result: make(chan acquireResult, 1), internal: internal}
	w.element = p.waiters.PushBack(w)
	if !internal {
		p.externalWaiters++
	}
	p.mu.Unlock()
	p.startCloseAll(expired)
	p.emit(Event{Type: EventAcquireQueued})
	p.signal()

	select {
	case result := <-w.result:
		if result.connection != nil {
			if err := ctx.Err(); err != nil {
				p.releaseAndWait(result.connection, false)
				return nil, &AcquireError{Stage: StageAcquire, Cause: err}
			}
			p.emit(Event{Type: EventAcquireSuccess, Duration: p.now().Sub(now)})
		}
		return result.connection, result.err
	case <-ctx.Done():
		p.mu.Lock()
		removed := false
		if !w.done && w.element != nil {
			p.removeWaiterLocked(w)
			removed = true
		}
		p.mu.Unlock()
		if removed {
			p.emit(Event{Type: EventAcquireCanceled, Duration: p.now().Sub(now), Reason: ReasonContextCancellation})
			return nil, &AcquireError{Stage: StageAcquire, Cause: ctx.Err()}
		}
		result := <-w.result
		if result.connection != nil {
			p.releaseAndWait(result.connection, false)
		}
		return nil, &AcquireError{Stage: StageAcquire, Cause: ctx.Err()}
	}
}

func (p *Pool) releaseAndWait(connection *Connection, panicked bool) error {
	physical, wait := p.release(connection, panicked)
	if physical == nil || !wait {
		return nil
	}
	timer := time.NewTimer(p.cfg.closeTimeout)
	defer timer.Stop()
	select {
	case <-physical.closeDone:
		if err := physical.closeResult(); err != nil {
			return &CloseError{Cause: err}
		}
		return nil
	case <-timer.C:
		return &CloseError{Remaining: 1, TimedOut: true}
	}
}

func (p *Pool) evictBorrowed(connection *Connection, reason FailureReason) {
	if connection == nil || connection.physical == nil {
		return
	}
	physical := connection.physical
	shouldClose := false
	p.mu.Lock()
	if physical.state == connectionBorrowed && sameLease(physical.lease, connection) {
		p.beginCloseLocked(physical, reason)
		shouldClose = true
	}
	p.mu.Unlock()
	if shouldClose {
		physical.startClose(reason)
		p.emit(Event{Type: EventEviction, Reason: reason})
		p.signal()
	}
}

func (p *Pool) retirementReason(physical *physicalConn) FailureReason {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lifecycle != poolRunning {
		return ReasonPoolClose
	}
	if physical.generation != p.credential.generation.Load() {
		return ReasonCredentialRotation
	}
	return physical.reason()
}

func (p *Pool) release(connection *Connection, panicked bool) (*physicalConn, bool) {
	oldState := connection.invalidate()
	physical := connection.physical
	if physical == nil {
		return nil, false
	}
	if oldState == leaseBusy {
		if trace := physical.transport.active.Load(); trace != nil {
			trace.cancel()
		}
	}
	now := p.now()
	var closeReason FailureReason
	p.mu.Lock()
	if physical.state != connectionBorrowed || !sameLease(physical.lease, connection) {
		closing := sameLease(physical.lease, connection) && (physical.state == connectionClosing || physical.state == connectionClosed)
		p.mu.Unlock()
		return physical, closing
	}
	physical.lease = nil
	currentGeneration := p.credential.generation.Load()
	healthy := oldState == leaseActive && !physical.fatal.Load() && !physical.retire.Load() &&
		physical.generation == currentGeneration && p.lifecycle == poolRunning
	switch {
	case panicked:
		healthy = false
		closeReason = ReasonCallbackPanic
	case oldState == leaseBusy:
		healthy = false
		closeReason = ReasonLeaseReturnedBusy
	case physical.fatal.Load():
		healthy = false
		closeReason = physical.reason()
	case physical.retire.Load():
		healthy = false
		closeReason = ReasonCredentialRotation
	case physical.generation != currentGeneration:
		healthy = false
		closeReason = ReasonCredentialRotation
	case p.lifecycle != poolRunning:
		healthy = false
		closeReason = ReasonPoolClose
	case now.Sub(physical.createdAt) >= p.cfg.maxLifetime:
		healthy = false
		closeReason = ReasonMaxLifetime
	}
	if healthy {
		if p.handoffLocked(physical) {
			p.mu.Unlock()
			p.signal()
			return nil, false
		}
		if p.idleCount < p.cfg.maxIdle {
			physical.state = connectionIdle
			physical.lastUsedAt = now
			p.borrowed--
			p.idleCount++
			p.idle = append(p.idle, physical)
			p.mu.Unlock()
			p.signal()
			return nil, false
		}
		closeReason = ReasonMaxIdle
	}
	p.beginCloseLocked(physical, closeReason)
	p.mu.Unlock()
	physical.startClose(closeReason)
	p.emit(Event{Type: EventEviction, Reason: closeReason})
	p.signal()
	return physical, true
}

func (p *Pool) borrowLocked(physical *physicalConn) *Connection {
	physical.state = connectionBorrowed
	p.idleCount--
	p.borrowed++
	connection := newConnection(p, physical)
	physical.lease = connection
	return connection
}

func (p *Pool) handoffLocked(physical *physicalConn) bool {
	for p.waiters.Len() > 0 {
		front := p.waiters.Front()
		w := front.Value.(*waiter)
		p.removeWaiterLocked(w)
		if err := w.ctx.Err(); err != nil {
			w.result <- acquireResult{err: &AcquireError{Stage: StageAcquire, Cause: err}}
			continue
		}
		connection := newConnection(p, physical)
		physical.lease = connection
		physical.state = connectionBorrowed
		w.result <- acquireResult{connection: connection}
		return true
	}
	return false
}

func (p *Pool) removeWaiterLocked(w *waiter) {
	if w.done {
		return
	}
	if w.element != nil {
		p.waiters.Remove(w.element)
		w.element = nil
	}
	w.done = true
	if !w.internal {
		p.externalWaiters--
	}
}

func (p *Pool) takeIdleLocked() *physicalConn {
	for len(p.idle) > 0 {
		last := len(p.idle) - 1
		physical := p.idle[last]
		p.idle = p.idle[:last]
		if physical.state == connectionIdle {
			return physical
		}
	}
	return nil
}

func (p *Pool) collectExpiredLocked(now time.Time) []*physicalConn {
	var closing []*physicalConn
	for _, physical := range p.idle {
		if physical.state != connectionIdle {
			continue
		}
		reason := ReasonNone
		if now.Sub(physical.createdAt) >= p.cfg.maxLifetime {
			reason = ReasonMaxLifetime
		} else if now.Sub(physical.lastUsedAt) >= p.cfg.maxIdleTime {
			reason = ReasonIdleTimeout
		}
		if reason != ReasonNone {
			p.beginCloseLocked(physical, reason)
			closing = append(closing, physical)
		}
	}
	if len(closing) > 0 {
		p.compactIdleLocked()
	}
	return closing
}

func (p *Pool) compactIdleLocked() {
	out := p.idle[:0]
	for _, physical := range p.idle {
		if physical.state == connectionIdle {
			out = append(out, physical)
		}
	}
	p.idle = out
}

func (p *Pool) beginCloseLocked(physical *physicalConn, reason FailureReason) {
	switch physical.state {
	case connectionIdle:
		p.idleCount--
	case connectionBorrowed:
		p.borrowed--
	default:
		return
	}
	physical.state = connectionClosing
	physical.retire.Store(true)
	physical.markFatal(reason)
	p.closing++
}

func (p *Pool) startCloseAll(connections []*physicalConn) {
	for _, connection := range connections {
		reason := connection.reason()
		connection.startClose(reason)
		p.emit(Event{Type: EventEviction, Reason: reason})
	}
}

func (p *Pool) physicalClosed(physical *physicalConn) {
	final := false
	closeErr := physical.closeResult()
	p.mu.Lock()
	if physical.state == connectionClosing {
		physical.state = connectionClosed
		p.closing--
		p.open--
		delete(p.physical, physical.id)
	}
	if closeErr != nil {
		p.lastStage = StageClose
		p.lastReason = ReasonCloseFailure
		p.closeCause = errors.Join(p.closeCause, closeErr)
	}
	if p.lifecycle == poolClosingLifecycle && p.open == 0 && p.connecting == 0 {
		p.lifecycle = poolClosedLifecycle
		if p.graceTimer != nil {
			p.graceTimer.Stop()
			p.graceTimer = nil
		}
		final = true
		close(p.closeDone)
	}
	p.mu.Unlock()
	if closeErr != nil {
		p.emit(Event{Type: EventEviction, Stage: StageClose, Reason: ReasonCloseFailure})
	}
	if final {
		p.credential.destroy()
		p.observer.stop()
	}
	p.failWaitersIfNoOpen()
	p.signal()
}

func (p *Pool) immediateGateErrorLocked(now time.Time, guard guardSnapshot) error {
	if guard.state == CredentialBlocked {
		cause := &CredentialError{State: CredentialBlocked, Reason: guard.reason, Cause: p.lastFailure}
		return &AcquireError{Stage: StageBind, Cause: cause, kind: ErrCredentialBlocked}
	}
	if (guard.state == CredentialDelayed || guard.state == CredentialHalfOpen) && now.Before(guard.retryAt) {
		cause := &CredentialError{State: CredentialDelayed, Reason: guard.reason, RetryAt: guard.retryAt, Cause: p.lastFailure}
		return &AcquireError{Stage: StageBind, RetryAt: laterGate(guard.retryAt, p.retryAt), Cause: cause, kind: ErrCredentialDelayed}
	}
	if now.Before(p.retryAt) {
		return &AcquireError{Stage: p.lastStage, RetryAt: p.retryAt, Cause: p.lastFailure, kind: connectionFailureKind(p.lastReason)}
	}
	return nil
}

func connectionFailureKind(reason FailureReason) error {
	switch reason {
	case ReasonDial, ReasonTLSValidation, ReasonInitialization, ReasonTransport:
		return ErrTransport
	case ReasonProtocol:
		return ErrProtocol
	case ReasonDependencyPanic:
		return ErrDependencyPanic
	default:
		return nil
	}
}

func (p *Pool) countsLocked() Counts {
	return Counts{Open: p.open, Idle: p.idleCount, Borrowed: p.borrowed, Connecting: p.connecting, Closing: p.closing, Waiters: p.waiters.Len()}
}

func (p *Pool) healthyLocked() int {
	generation := p.credential.generation.Load()
	healthy := 0
	for _, physical := range p.physical {
		if (physical.state == connectionIdle || physical.state == connectionBorrowed) &&
			!physical.fatal.Load() && !physical.retire.Load() && physical.generation == generation {
			healthy++
		}
	}
	return healthy
}

func (p *Pool) emit(event Event) {
	if p.observer == nil {
		return
	}
	if event.At.IsZero() {
		event.At = p.now()
	}
	if event.Stage == "" {
		event.Stage = StageNone
	}
	if event.Reason == "" {
		event.Reason = ReasonNone
	}
	if event.CredentialReason == "" {
		event.CredentialReason = CredentialReasonNone
	}
	p.mu.Lock()
	event.Counts = p.countsLocked()
	p.mu.Unlock()
	p.observer.emit(event)
}

func (p *Pool) signal() {
	p.wakeSeq.Add(1)
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func projectPoolState(lifecycle poolLifecycle, counts Counts, healthy int, retryAt time.Time, guard guardSnapshot, now time.Time) PoolState {
	if lifecycle == poolClosedLifecycle {
		return PoolClosed
	}
	if lifecycle == poolClosingLifecycle {
		return PoolClosing
	}
	if healthy > 0 {
		return PoolReady
	}
	if guard.state == CredentialBlocked {
		return PoolCredentialBlocked
	}
	if (guard.state == CredentialDelayed || guard.state == CredentialHalfOpen) && now.Before(guard.retryAt) {
		return PoolCredentialDelayed
	}
	if counts.Connecting > 0 {
		return PoolConnecting
	}
	if now.Before(retryAt) {
		return PoolTransientBackoff
	}
	return PoolCold
}

func (p *Pool) assertLocked() {
	if p.open < 0 || p.open > p.cfg.maxOpen || p.connecting < 0 || p.connecting > 1 ||
		p.idleCount < 0 || p.idleCount > p.cfg.maxIdle || p.borrowed < 0 || p.closing < 0 ||
		p.open != p.connecting+p.idleCount+p.borrowed+p.closing {
		panic(fmt.Sprintf("ldappool: internal invariant violated: %+v", p.countsLocked()))
	}
}
