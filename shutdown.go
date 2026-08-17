package ldappool

import (
	"context"
	"time"
)

func (p *Pool) close(ctx context.Context, force bool) error {
	if ctx == nil {
		return configError("context", "must not be nil")
	}
	p.startShutdown(force)
	select {
	case <-p.closeDone:
		p.mu.Lock()
		cause := p.closeCause
		p.mu.Unlock()
		if cause != nil {
			return &CloseError{Cause: cause}
		}
		return nil
	default:
	}
	waitCtx, cancel := context.WithTimeout(ctx, p.cfg.closeTimeout)
	defer cancel()
	select {
	case <-p.closeDone:
		p.mu.Lock()
		cause := p.closeCause
		p.mu.Unlock()
		if cause != nil {
			return &CloseError{Cause: cause}
		}
		return nil
	case <-waitCtx.Done():
		p.forceAll()
		select {
		case <-p.closeDone:
			p.mu.Lock()
			cause := p.closeCause
			p.mu.Unlock()
			if cause != nil {
				return &CloseError{Cause: cause}
			}
			return nil
		default:
		}
		p.mu.Lock()
		if p.lifecycle == poolClosedLifecycle {
			cause := p.closeCause
			p.mu.Unlock()
			if cause != nil {
				return &CloseError{Cause: cause}
			}
			return nil
		}
		remaining := p.open
		p.mu.Unlock()
		p.emit(Event{Type: EventCloseTimeout, Stage: StageClose, Reason: ReasonPoolClose})
		return &CloseError{Remaining: remaining, TimedOut: true, Cause: waitCtx.Err()}
	}
}

func (p *Pool) startShutdown(force bool) {
	p.credentials.identityMu.Lock()
	var closeList []*physicalConn
	var cancelConnect context.CancelFunc
	final := false
	p.mu.Lock()
	switch p.lifecycle {
	case poolClosedLifecycle:
		p.mu.Unlock()
		p.credentials.identityMu.Unlock()
		return
	case poolRunning:
		p.lifecycle = poolClosingLifecycle
		p.credentials.unregisterLocked(p.poolState)
		cancelConnect = p.connectCancel
		for p.waiters.Len() > 0 {
			w := p.waiters.Front().Value.(*waiter)
			p.removeWaiterLocked(w)
			w.result <- acquireResult{err: &AcquireError{Stage: StageAcquire, Cause: ErrPoolClosed, kind: ErrPoolClosed}}
		}
		for _, physical := range append([]*physicalConn(nil), p.idle...) {
			p.beginCloseLocked(physical, ReasonPoolClose)
			closeList = append(closeList, physical)
		}
		p.compactIdleLocked()
		for _, physical := range p.physical {
			if physical.state != connectionBorrowed {
				continue
			}
			physical.retire.Store(true)
			lease := physical.lease
			if lease == nil || lease.invalidateUnlessBusy() != leaseBusy {
				p.beginCloseLocked(physical, ReasonPoolClose)
				closeList = append(closeList, physical)
			}
		}
		if p.open == 0 {
			p.lifecycle = poolClosedLifecycle
			close(p.closeDone)
			final = true
		}
	}
	p.mu.Unlock()
	p.credentials.identityMu.Unlock()
	p.rootCancel()
	if cancelConnect != nil {
		cancelConnect()
	}
	for _, physical := range closeList {
		physical.startClose(ReasonPoolClose)
	}
	if force {
		p.emit(Event{Type: EventForceClose, Stage: StageClose, Reason: ReasonPoolClose})
	}
	if final {
		p.finalize()
	}
	if force {
		p.forceAll()
		return
	}
	p.mu.Lock()
	if p.lifecycle == poolClosingLifecycle && p.graceTimer == nil {
		p.graceTimer = time.AfterFunc(p.cfg.closeTimeout, p.forceAll)
	}
	p.mu.Unlock()
}

func (p *Pool) forceAll() {
	p.forceOnce.Do(func() {
		var closeList []*physicalConn
		var cancelConnect context.CancelFunc
		p.mu.Lock()
		cancelConnect = p.connectCancel
		for _, physical := range p.physical {
			if physical.state != connectionBorrowed {
				continue
			}
			if physical.lease != nil {
				oldState := physical.lease.invalidate()
				if oldState == leaseBusy {
					if trace := physical.transport.active.Load(); trace != nil {
						trace.cancel()
					}
				}
			}
			p.beginCloseLocked(physical, ReasonPoolClose)
			closeList = append(closeList, physical)
		}
		p.mu.Unlock()
		if cancelConnect != nil {
			cancelConnect()
		}
		for _, physical := range closeList {
			physical.startClose(ReasonPoolClose)
		}
	})
}
