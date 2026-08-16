package ldappool

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type connectAttempt struct {
	id          uint64
	ctx         context.Context
	cancel      context.CancelFunc
	generation  uint64
	password    []byte
	permit      guardPermit
	cleanupOnce sync.Once
}

func (a *connectAttempt) destroy() {
	a.cleanupOnce.Do(func() {
		a.cancel()
		wipe(a.password)
		a.password = nil
	})
}

type connectFailure struct {
	stage      FailureStage
	reason     FailureReason
	cause      error
	credential bool
	retryAt    time.Time
}

func (p *Pool) scheduler() {
	defer close(p.schedulerDone)
	for {
		observedWake := p.wakeSeq.Load()
		select {
		case <-p.rootCtx.Done():
			return
		default:
		}

		p.reapExpired()
		p.ensureConnection()
		next, ok := p.nextSchedulerWake()
		if p.wakeSeq.Load() != observedWake {
			continue
		}
		if !ok {
			select {
			case <-p.rootCtx.Done():
				return
			case <-p.wake:
			}
			continue
		}
		delay := time.Until(next)
		if delay <= 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-p.rootCtx.Done():
			timer.Stop()
			return
		case <-p.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (p *Pool) reapExpired() {
	now := p.now()
	p.mu.Lock()
	if p.lifecycle != poolRunning {
		p.mu.Unlock()
		return
	}
	expired := p.collectExpiredLocked(now)
	p.mu.Unlock()
	p.startCloseAll(expired)
}

func (p *Pool) ensureConnection() {
	now := p.now()
	p.mu.Lock()
	needed := p.lifecycle == poolRunning && p.waiters.Len() > 0 && p.connecting == 0 && p.open < p.cfg.maxOpen
	if !needed || now.Before(p.retryAt) {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	generation, password := p.credential.snapshot()
	permit, guardErr := p.guard.permit(now, generation, p.random())
	if guardErr != nil {
		wipe(password)
		p.failWaitersIfNoOpen()
		return
	}
	p.mu.Lock()
	if p.lifecycle != poolRunning || p.waiters.Len() == 0 || p.connecting != 0 || p.open >= p.cfg.maxOpen ||
		p.now().Before(p.retryAt) || p.credential.generation.Load() != generation {
		p.mu.Unlock()
		p.guard.abort(permit)
		wipe(password)
		return
	}
	p.nextAttemptID++
	id := p.nextAttemptID
	ctx, cancel := context.WithTimeout(p.rootCtx, p.cfg.connectTimeout)
	p.connectAttemptID = id
	p.connectCancel = cancel
	p.open++
	p.connecting++
	p.assertLocked()
	p.mu.Unlock()

	attempt := &connectAttempt{id: id, ctx: ctx, cancel: cancel, generation: generation, password: password, permit: permit}
	if permit.probeID != 0 {
		guard := p.guard.snapshot()
		p.emit(Event{Type: EventCredentialState, Stage: StageBind, CredentialState: guard.state, CredentialReason: guard.reason, RetryAt: guard.retryAt})
	}
	p.emit(Event{Type: EventDialStart, Stage: StageDial})
	go p.runConnect(attempt)
}

func (p *Pool) runConnect(attempt *connectAttempt) {
	started := p.now()
	stage := StageDial
	var transport *trackedConn
	var client *ldap.Conn
	finished := false
	defer func() {
		attempt.destroy()
		if recovered := recover(); recovered != nil {
			p.guard.abort(attempt.permit)
			failure := &connectFailure{stage: stage, reason: ReasonDependencyPanic, cause: &PanicError{Source: "connection initialization"}}
			p.finishConnectFailure(attempt, transport, client, failure)
			p.emit(Event{Type: EventDependencyPanic, Stage: failure.stage, Reason: failure.reason, Duration: p.now().Sub(started)})
			return
		}
		if !finished {
			p.guard.abort(attempt.permit)
		}
	}()

	raw, err := p.cfg.dialer.DialContext(attempt.ctx, "tcp", p.cfg.address)
	if err != nil {
		finished = true
		p.guard.abort(attempt.permit)
		failure := &connectFailure{stage: StageDial, reason: ReasonDial, cause: err}
		if raw != nil {
			transport = newTrackedConn(raw)
		}
		p.finishConnectFailure(attempt, transport, nil, failure)
		p.emit(Event{Type: EventDialFailure, Stage: StageDial, Reason: ReasonDial, Duration: p.now().Sub(started)})
		return
	}
	if raw == nil {
		finished = true
		p.guard.abort(attempt.permit)
		failure := &connectFailure{stage: StageDial, reason: ReasonDial, cause: errors.New("dialer returned a nil connection")}
		p.finishConnectFailure(attempt, nil, nil, failure)
		p.emit(Event{Type: EventDialFailure, Stage: StageDial, Reason: ReasonDial, Duration: p.now().Sub(started)})
		return
	}
	transport = newTrackedConn(raw)
	stopWatchdog := context.AfterFunc(attempt.ctx, func() { _ = transport.Close() })
	watchdogStopped := false
	defer func() {
		if !watchdogStopped {
			stopWatchdog()
		}
	}()
	if deadline, ok := attempt.ctx.Deadline(); ok {
		if err = transport.SetDeadline(deadline); err != nil {
			finished = true
			failure := &connectFailure{stage: StageDial, reason: ReasonInitialization, cause: err}
			p.guard.abort(attempt.permit)
			p.finishConnectFailure(attempt, transport, nil, failure)
			return
		}
	}
	p.emit(Event{Type: EventDialSuccess, Stage: StageDial, Duration: p.now().Sub(started)})

	switch p.cfg.tlsMode {
	case TLSImplicit:
		stage = StageTLS
		tlsConn := tls.Client(transport, p.cfg.tlsClone())
		if err = tlsConn.HandshakeContext(attempt.ctx); err != nil {
			finished = true
			failure := &connectFailure{stage: StageTLS, reason: ReasonTLSValidation, cause: err}
			p.guard.abort(attempt.permit)
			p.finishConnectFailure(attempt, transport, nil, failure)
			p.emit(Event{Type: EventTLSFailure, Stage: StageTLS, Reason: ReasonTLSValidation, Duration: p.now().Sub(started)})
			return
		}
		client = ldap.NewConn(tlsConn, true)
		client.Start()
	case TLSStartTLS:
		stage = StageTLS
		client = ldap.NewConn(transport, false)
		client.SetTimeout(remainingTimeout(attempt.ctx, p.cfg.connectTimeout))
		client.Start()
		if err = client.StartTLS(p.cfg.tlsClone()); err != nil {
			finished = true
			failure := &connectFailure{stage: StageTLS, reason: ReasonTLSValidation, cause: sanitizeLDAPDiagnostic(err)}
			p.guard.abort(attempt.permit)
			p.finishConnectFailure(attempt, transport, client, failure)
			p.emit(Event{Type: EventTLSFailure, Stage: StageTLS, Reason: ReasonTLSValidation, Duration: p.now().Sub(started)})
			return
		}
		if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete {
			finished = true
			failure := &connectFailure{stage: StageTLS, reason: ReasonTLSValidation, cause: errors.New("StartTLS did not produce a verified TLS session")}
			p.guard.abort(attempt.permit)
			p.finishConnectFailure(attempt, transport, client, failure)
			p.emit(Event{Type: EventTLSFailure, Stage: StageTLS, Reason: ReasonTLSValidation, Duration: p.now().Sub(started)})
			return
		}
	case TLSPlaintext:
		client = ldap.NewConn(transport, false)
		client.Start()
	}

	if err = attempt.ctx.Err(); err != nil {
		finished = true
		p.guard.abort(attempt.permit)
		p.finishConnectFailure(attempt, transport, client, &connectFailure{stage: StageDial, reason: ReasonContextCancellation, cause: err})
		return
	}
	if guardErr := p.guard.recheck(attempt.permit); guardErr != nil {
		finished = true
		p.guard.abort(attempt.permit)
		p.finishConnectFailure(attempt, transport, client, &connectFailure{
			stage: StageBind, reason: ReasonBind, cause: guardErr, credential: true, retryAt: guardErr.RetryAt,
		})
		return
	}

	if p.cfg.authMode == AuthSimple {
		stage = StageBind
		client.SetTimeout(remainingTimeout(attempt.ctx, p.cfg.connectTimeout))
		trace := transport.begin()
		_, bindErr := client.SimpleBind(&ldap.SimpleBindRequest{
			Username: p.cfg.bindPrincipal,
			Password: string(attempt.password),
		})
		bindTrace := transport.end(trace)
		if bindErr != nil {
			decision, panicErr := classifyCredential(p.cfg.classifier, bindErr)
			guard := p.guard.bindFailed(attempt.permit, decision, p.now(), p.random())
			eventReason := ReasonBind
			finished = true
			if panicErr != nil {
				p.emit(Event{Type: EventDependencyPanic, Stage: StageBind, Reason: ReasonDependencyPanic})
			}
			if decision.Action == CredentialNotCredential {
				reason, cause := assessBindFailure(bindErr, bindTrace)
				eventReason = reason
				failure := &connectFailure{stage: StageBind, reason: reason, cause: cause}
				p.finishConnectFailure(attempt, transport, client, failure)
			} else {
				state := guard.state
				cause := &CredentialError{
					State: state, Reason: guard.reason, RetryAt: guard.retryAt,
					Cause: errors.Join(sanitizeBindError(bindErr), panicErr),
				}
				failure := &connectFailure{stage: StageBind, reason: ReasonBind, cause: cause, credential: true, retryAt: guard.retryAt}
				p.finishConnectFailure(attempt, transport, client, failure)
				p.emit(Event{Type: EventCredentialState, Stage: StageBind, CredentialState: guard.state, CredentialReason: guard.reason, RetryAt: guard.retryAt})
			}
			p.emit(Event{Type: EventBindFailure, Stage: StageBind, Reason: eventReason, CredentialState: guard.state, CredentialReason: guard.reason, RetryAt: guard.retryAt, Duration: p.now().Sub(started)})
			return
		}
		if failure := validateBindSuccess(bindTrace); failure != nil {
			finished = true
			p.guard.abort(attempt.permit)
			p.finishConnectFailure(attempt, transport, client, failure)
			return
		}
		guard := p.guard.bindSucceeded(attempt.permit)
		p.emit(Event{Type: EventBindSuccess, Stage: StageBind, CredentialState: guard.state, CredentialReason: guard.reason, Duration: p.now().Sub(started)})
	}

	client.SetTimeout(p.cfg.requestTimeout)
	if err = transport.SetDeadline(time.Time{}); err != nil {
		finished = true
		failure := &connectFailure{stage: StageDial, reason: ReasonInitialization, cause: err}
		p.finishConnectFailure(attempt, transport, client, failure)
		return
	}
	if !stopWatchdog() {
		finished = true
		err = attempt.ctx.Err()
		if err == nil {
			err = context.Canceled
		}
		p.finishConnectFailure(attempt, transport, client, &connectFailure{stage: StageDial, reason: ReasonContextCancellation, cause: err})
		return
	}
	watchdogStopped = true
	if err = attempt.ctx.Err(); err != nil {
		finished = true
		p.finishConnectFailure(attempt, transport, client, &connectFailure{stage: StageDial, reason: ReasonContextCancellation, cause: err})
		return
	}

	physical := &physicalConn{
		pool: p, client: client, transport: transport, createdAt: p.now(), lastUsedAt: p.now(),
		generation: attempt.generation, state: connectionConnecting, closeDone: make(chan struct{}),
	}
	finished = true
	p.finishConnectSuccess(attempt, physical)
}

func (p *Pool) finishConnectSuccess(attempt *connectAttempt, physical *physicalConn) {
	attempt.destroy()
	now := p.now()
	var shouldClose bool
	var closeReason FailureReason
	recovered := false
	p.mu.Lock()
	if p.connectAttemptID != attempt.id || p.connecting != 1 {
		p.mu.Unlock()
		go func() { _ = physical.transport.Close() }()
		return
	}
	p.connecting--
	p.connectCancel = nil
	p.nextConnectionID++
	physical.id = p.nextConnectionID
	p.physical[physical.id] = physical
	if p.lifecycle != poolRunning {
		closeReason = ReasonPoolClose
		shouldClose = true
	} else if physical.generation != p.credential.generation.Load() {
		closeReason = ReasonCredentialRotation
		shouldClose = true
	} else {
		recovered = p.connectFailures > 0 || p.lastFailure != nil
		p.connectFailures = 0
		p.retryAt = time.Time{}
		p.lastFailure = nil
		p.lastStage = StageNone
		p.lastReason = ReasonNone
		if p.handoffConnectingLocked(physical) {
			// Direct handoff completed under the lock.
		} else if p.idleCount < p.cfg.maxIdle {
			physical.state = connectionIdle
			physical.lastUsedAt = now
			p.idleCount++
			p.idle = append(p.idle, physical)
		} else {
			closeReason = ReasonMaxIdle
			shouldClose = true
		}
	}
	if shouldClose {
		physical.state = connectionClosing
		physical.retire.Store(true)
		physical.markFatal(closeReason)
		p.closing++
	}
	p.assertLocked()
	p.mu.Unlock()
	if shouldClose {
		physical.startClose(closeReason)
		p.emit(Event{Type: EventEviction, Reason: closeReason})
	}
	if recovered {
		p.emit(Event{Type: EventPoolRecovered})
	}
	p.signal()
}

func (p *Pool) handoffConnectingLocked(physical *physicalConn) bool {
	for p.waiters.Len() > 0 {
		front := p.waiters.Front()
		w := front.Value.(*waiter)
		p.removeWaiterLocked(w)
		if err := w.ctx.Err(); err != nil {
			w.result <- acquireResult{err: &AcquireError{Stage: StageAcquire, Cause: err}}
			continue
		}
		physical.state = connectionBorrowed
		p.borrowed++
		connection := newConnection(p, physical)
		physical.lease = connection
		w.result <- acquireResult{connection: connection}
		return true
	}
	return false
}

func (p *Pool) finishConnectFailure(attempt *connectAttempt, transport *trackedConn, client *ldap.Conn, failure *connectFailure) {
	attempt.destroy()
	now := p.now()
	var physical *physicalConn
	var final bool
	p.mu.Lock()
	if p.connectAttemptID != attempt.id || p.connecting != 1 {
		p.mu.Unlock()
		if transport != nil {
			go func() { _ = transport.Close() }()
		}
		return
	}
	p.connecting--
	p.connectCancel = nil
	currentGeneration := p.credential.generation.Load()
	armBackoff := p.lifecycle == poolRunning && currentGeneration == attempt.generation && !failure.credential
	if armBackoff {
		p.connectFailures = incrementFailureCount(p.connectFailures)
		p.retryAt = now.Add(backoffDuration(p.cfg.connectBackoff, p.connectFailures, p.random()))
	}
	p.lastFailure = failure.cause
	p.lastStage = failure.stage
	p.lastReason = failure.reason
	if transport == nil {
		p.open--
	} else {
		p.nextConnectionID++
		physical = &physicalConn{
			id: p.nextConnectionID, pool: p, client: client, transport: transport,
			createdAt: now, lastUsedAt: now, generation: attempt.generation,
			state: connectionClosing, closeDone: make(chan struct{}), closeReason: failure.reason,
		}
		physical.retire.Store(true)
		physical.fatal.Store(true)
		p.physical[physical.id] = physical
		p.closing++
	}
	if p.lifecycle == poolClosingLifecycle && p.open == 0 {
		p.lifecycle = poolClosedLifecycle
		if p.graceTimer != nil {
			p.graceTimer.Stop()
			p.graceTimer = nil
		}
		close(p.closeDone)
		final = true
	}
	p.assertLocked()
	retryAt := p.retryAt
	p.mu.Unlock()
	if physical != nil {
		physical.startClose(failure.reason)
	}
	if armBackoff {
		p.emit(Event{Type: EventBackoffArmed, Stage: failure.stage, Reason: failure.reason, RetryAt: retryAt})
	}
	if final {
		p.credential.destroy()
		p.observer.stop()
	}
	p.failWaitersIfNoOpen()
	p.signal()
}

func (p *Pool) failWaitersIfNoOpen() {
	guard := p.guard.snapshot()
	now := p.now()
	p.mu.Lock()
	if p.lifecycle != poolRunning || p.open != 0 {
		p.mu.Unlock()
		return
	}
	err := p.immediateGateErrorLocked(now, guard)
	if err == nil {
		p.mu.Unlock()
		return
	}
	for p.waiters.Len() > 0 {
		w := p.waiters.Front().Value.(*waiter)
		p.removeWaiterLocked(w)
		w.result <- acquireResult{err: err}
	}
	p.mu.Unlock()
}

func (p *Pool) nextSchedulerWake() (time.Time, bool) {
	guard := p.guard.snapshot()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lifecycle != poolRunning {
		return time.Time{}, false
	}
	var next time.Time
	for _, physical := range p.idle {
		if physical.state != connectionIdle {
			continue
		}
		idleDeadline := physical.lastUsedAt.Add(p.cfg.maxIdleTime)
		lifeDeadline := physical.createdAt.Add(p.cfg.maxLifetime)
		if lifeDeadline.Before(idleDeadline) {
			idleDeadline = lifeDeadline
		}
		next = earlierNonZero(next, idleDeadline)
	}
	if p.waiters.Len() > 0 && p.connecting == 0 && p.open < p.cfg.maxOpen {
		if guard.state == CredentialBlocked {
			return next, !next.IsZero()
		}
		gate := p.retryAt
		if guard.state == CredentialDelayed || guard.state == CredentialHalfOpen {
			gate = laterGate(gate, guard.retryAt)
		}
		next = earlierNonZero(next, gate)
	}
	return next, !next.IsZero()
}

func earlierNonZero(current, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current
	}
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}

func laterGate(current, gate time.Time) time.Time {
	if gate.IsZero() {
		return current
	}
	if current.IsZero() || gate.After(current) {
		return gate
	}
	return current
}

func remainingTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return remaining
		}
		return time.Nanosecond
	}
	return fallback
}

func sanitizeBindError(err error) error {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return sanitizedLDAPError(ldapErr.ResultCode)
	}
	return errors.New("LDAP Bind failed; diagnostic redacted")
}

func validateBindSuccess(trace traceSnapshot) *connectFailure {
	if trace.writtenBytes == 0 {
		return &connectFailure{
			stage: StageBind, reason: ReasonProtocol,
			cause: errors.New("LDAP Bind returned success without a dispatched request"),
		}
	}
	if trace.writeErr != nil || trace.readErr != nil || trace.writeInFlight != 0 {
		return &connectFailure{
			stage: StageBind, reason: ReasonTransport,
			cause: errors.Join(
				errors.New("LDAP Bind succeeded but the transport became unusable"),
				trace.writeErr,
				trace.readErr,
			),
		}
	}
	return nil
}

func assessBindFailure(err error, trace traceSnapshot) (FailureReason, error) {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) && ldapErrorHasResponseTag(ldapErr, ldap.ApplicationBindResponse) && isServerResultCode(ldapErr.ResultCode) {
		return ReasonBind, sanitizedLDAPError(ldapErr.ResultCode)
	}
	if errors.As(err, &ldapErr) && ldapErr.Packet != nil {
		return ReasonProtocol, errors.New("LDAP Bind response validation failed; diagnostic redacted")
	}
	if trace.writeErr != nil || trace.readErr != nil ||
		(errors.As(err, &ldapErr) && ldapErr.Packet == nil && ldapErr.ResultCode == ldap.ErrorNetwork) {
		return ReasonTransport, errors.Join(err, trace.writeErr, trace.readErr)
	}
	return ReasonProtocol, errors.New("LDAP Bind response validation failed; diagnostic redacted")
}

func sanitizeLDAPDiagnostic(err error) error {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) && isServerResultCode(ldapErr.ResultCode) {
		return sanitizedLDAPError(ldapErr.ResultCode)
	}
	return err
}
