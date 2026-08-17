package ldappool

import (
	"context"
	"strings"
	"sync"
	"time"
)

// CredentialGuard owns a simple-Bind identity, its current password, and the
// credential failure state shared by every attached Pool. It serializes Bind
// operations across those pools. Its zero value is invalid; construct it with
// NewCredentialGuard.
type CredentialGuard struct {
	*credentialAuthority
}

type credentialAuthority struct {
	// Lock order is identityMu, a member Pool.mu, then credential.mu or guard.mu.
	identityMu sync.Mutex

	principal  string
	classifier CredentialFailureClassifier
	shared     bool
	credential credentialStore
	guard      credentialGuard
	members    map[*poolState]struct{}
	bindSlot   chan struct{}
}

type credentialRotationEffect struct {
	pool      *Pool
	closeList []*physicalConn
	cancel    context.CancelFunc
	active    bool
}

// NewCredentialGuard validates and copies one simple-Bind identity. Pools can
// share the returned guard by assigning it to AuthConfig.CredentialGuard.
func NewCredentialGuard(config CredentialGuardConfig) (*CredentialGuard, error) {
	if strings.TrimSpace(config.BindPrincipal) == "" {
		return nil, configError("CredentialGuard.BindPrincipal", "is required")
	}
	if config.Password.empty() {
		return nil, configError("CredentialGuard.Password", "must not be empty")
	}
	policy, err := resolveBackoff("CredentialGuard.CredentialBackoff", config.CredentialBackoff, BackoffConfig{
		Initial: 5 * time.Second, Multiplier: 2, Max: 5 * time.Minute, Jitter: .30,
	})
	if err != nil {
		return nil, err
	}
	password := config.Password.cloneBytes()
	authority := newCredentialAuthority(config.BindPrincipal, password, policy, config.CredentialFailureClassifier, true)
	return &CredentialGuard{credentialAuthority: authority}, nil
}

func newCredentialAuthority(
	principal string,
	password []byte,
	policy backoffPolicy,
	classifier CredentialFailureClassifier,
	shared bool,
) *credentialAuthority {
	authority := &credentialAuthority{
		principal:  principal,
		classifier: classifier,
		shared:     shared,
		guard:      newCredentialGuard(policy),
		members:    make(map[*poolState]struct{}),
	}
	if shared {
		authority.bindSlot = make(chan struct{}, 1)
		authority.bindSlot <- struct{}{}
	}
	authority.credential.password = password
	authority.credential.generation.Store(1)
	return authority
}

// String returns a constant redacted representation.
func (CredentialGuard) String() string { return "ldappool.CredentialGuard{[REDACTED]}" }

// GoString returns a constant redacted representation.
func (CredentialGuard) GoString() string { return "ldappool.CredentialGuard{[REDACTED]}" }

func (g *CredentialGuard) bindPrincipal() string {
	if g == nil || g.credentialAuthority == nil {
		return ""
	}
	return g.principal
}

func (g *CredentialGuard) classifier() CredentialFailureClassifier {
	if g == nil || g.credentialAuthority == nil {
		return nil
	}
	return g.credentialAuthority.classifier
}

// RotateCredentials replaces the shared password, resets credential state,
// cancels old-generation connection attempts, and retires old-generation
// connections in every attached Pool.
func (g *CredentialGuard) RotateCredentials(secret Secret) error {
	if g == nil || g.credentialAuthority == nil {
		return configError("CredentialGuard", "must be constructed with NewCredentialGuard")
	}
	if secret.empty() {
		return configError("CredentialGuard.Password", "must not be empty")
	}
	return g.credentialAuthority.rotateCredentials(nil, secret)
}

// Reset clears shared credential guard state without changing the password or
// reviving existing connections.
func (g *CredentialGuard) Reset() error {
	if g == nil || g.credentialAuthority == nil {
		return configError("CredentialGuard", "must be constructed with NewCredentialGuard")
	}
	return g.credentialAuthority.reset(nil)
}

func (a *credentialAuthority) register(state *poolState) {
	a.identityMu.Lock()
	a.members[state] = struct{}{}
	a.identityMu.Unlock()
}

func (a *credentialAuthority) unregister(state *poolState) {
	a.identityMu.Lock()
	delete(a.members, state)
	a.identityMu.Unlock()
}

func (a *credentialAuthority) unregisterLocked(state *poolState) {
	delete(a.members, state)
}

func (a *credentialAuthority) notifyMembers() {
	a.identityMu.Lock()
	members := a.memberPoolsLocked()
	a.identityMu.Unlock()
	for _, pool := range members {
		pool.signal()
	}
}

func (a *credentialAuthority) memberPoolsLocked() []*Pool {
	members := make([]*Pool, 0, len(a.members))
	for state := range a.members {
		members = append(members, &Pool{poolState: state})
	}
	return members
}

func (a *credentialAuthority) permit(now time.Time, generation uint64, random float64) (guardPermit, error) {
	return a.guard.permit(now, generation, random)
}

func (a *credentialAuthority) recheck(permit guardPermit) *CredentialError {
	return a.guard.recheck(permit)
}

func (a *credentialAuthority) acquireBind(ctx context.Context) (func(), error) {
	if !a.shared {
		return func() {}, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.bindSlot:
		if err := ctx.Err(); err != nil {
			a.bindSlot <- struct{}{}
			return nil, err
		}
		return func() { a.bindSlot <- struct{}{} }, nil
	}
}

func (a *credentialAuthority) abort(permit guardPermit) {
	if a.guard.abort(permit) {
		a.notifyMembers()
	}
}

func (a *credentialAuthority) bindFailed(permit guardPermit, decision CredentialDecision, now time.Time, random float64) guardSnapshot {
	snapshot := a.guard.bindFailed(permit, decision, now, random)
	a.notifyMembers()
	return snapshot
}

func (a *credentialAuthority) bindSucceeded(permit guardPermit) guardSnapshot {
	snapshot := a.guard.bindSucceeded(permit)
	a.notifyMembers()
	return snapshot
}

func (a *credentialAuthority) rotateCredentials(required *poolState, secret Secret) error {
	if secret.empty() {
		return configError("Auth.Password", "must not be empty")
	}
	newPassword := secret.cloneBytes()
	a.identityMu.Lock()
	if required != nil {
		required.mu.Lock()
		running := required.lifecycle == poolRunning
		required.mu.Unlock()
		if !running {
			a.identityMu.Unlock()
			wipe(newPassword)
			return ErrPoolClosed
		}
	}
	generation, oldPassword := a.credential.rotateOwned(newPassword)
	guard := a.guard.reset(generation, CredentialReasonCredentialRotated)
	members := a.memberPoolsLocked()
	effects := make([]credentialRotationEffect, 0, len(members))
	for _, pool := range members {
		effects = append(effects, pool.prepareCredentialRotation(generation))
	}
	a.identityMu.Unlock()
	wipe(oldPassword)
	for _, effect := range effects {
		if !effect.active {
			continue
		}
		if effect.cancel != nil {
			effect.cancel()
		}
		effect.pool.startCloseAll(effect.closeList)
		effect.pool.signal()
		effect.pool.emit(Event{Type: EventCredentialState, CredentialState: guard.state, CredentialReason: guard.reason})
	}
	return nil
}

func (a *credentialAuthority) reset(required *poolState) error {
	a.identityMu.Lock()
	if required != nil {
		required.mu.Lock()
		running := required.lifecycle == poolRunning
		required.mu.Unlock()
		if !running {
			a.identityMu.Unlock()
			return ErrPoolClosed
		}
	}
	generation := a.credential.generation.Load()
	guard := a.guard.reset(generation, CredentialReasonManualReset)
	members := a.memberPoolsLocked()
	a.identityMu.Unlock()
	for _, pool := range members {
		pool.signal()
		pool.emit(Event{Type: EventCredentialState, CredentialState: guard.state, CredentialReason: guard.reason})
	}
	return nil
}

func (a *credentialAuthority) destroyPrivate() {
	if !a.shared {
		a.credential.destroy()
	}
}
