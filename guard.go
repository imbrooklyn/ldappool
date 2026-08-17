package ldappool

import (
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// CredentialAction controls only future connection authentication attempts.
// It never determines whether an existing connection is healthy.
type CredentialAction uint8

const (
	// CredentialNotCredential treats a Bind result as an ordinary connection failure.
	CredentialNotCredential CredentialAction = iota
	// CredentialDelay delays a future authentication probe using credential backoff.
	CredentialDelay
	// CredentialBlock blocks authentication probes until reset or rotation.
	CredentialBlock
)

// CredentialFailure contains the server result presented to a custom
// classifier. Diagnostic may contain vendor-specific text and must not be
// logged or retained. The core package never publishes it in errors or events.
type CredentialFailure struct {
	// ResultCode is the standard LDAP result code.
	ResultCode uint16
	// Diagnostic is sensitive vendor text available only at the classifier boundary.
	Diagnostic string
}

// String returns a constant redacted representation because Diagnostic is sensitive.
func (CredentialFailure) String() string { return "ldappool.CredentialFailure{[REDACTED]}" }

// GoString returns a constant redacted representation because Diagnostic is sensitive.
func (CredentialFailure) GoString() string { return "ldappool.CredentialFailure{[REDACTED]}" }

// CredentialDecision is returned by CredentialFailureClassifier.
type CredentialDecision struct {
	// Action controls future connection authentication attempts.
	Action CredentialAction
	// Reason must be a safe, low-cardinality reason value.
	Reason CredentialReason
}

// CredentialFailureClassifier optionally classifies a complete Bind result.
// Implementations must return promptly and must not retain or log
// CredentialFailure.Diagnostic. They must not wait on the Pool whose connection
// attempt is being classified.
type CredentialFailureClassifier interface {
	Classify(CredentialFailure) CredentialDecision
}

// CredentialFailureClassifierFunc adapts a function to a classifier.
type CredentialFailureClassifierFunc func(CredentialFailure) CredentialDecision

// Classify calls f(failure).
func (f CredentialFailureClassifierFunc) Classify(failure CredentialFailure) CredentialDecision {
	return f(failure)
}

type guardPermit struct {
	generation uint64
	probeID    uint64
}

type guardSnapshot struct {
	state    CredentialState
	reason   CredentialReason
	retryAt  time.Time
	failures uint64
}

type credentialGuard struct {
	mu sync.Mutex

	generation uint64
	state      CredentialState
	reason     CredentialReason
	retryAt    time.Time
	failures   uint64
	probeID    uint64
	probeLive  bool
	policy     backoffPolicy
}

func newCredentialGuard(policy backoffPolicy) credentialGuard {
	return credentialGuard{
		generation: 1, state: CredentialClear, reason: CredentialReasonNone,
		policy: policy,
	}
}

func (g *credentialGuard) permit(now time.Time, generation uint64, random float64) (guardPermit, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if generation != g.generation {
		return guardPermit{}, &CredentialError{State: CredentialDelayed, Reason: CredentialReasonCredentialRotated}
	}
	switch g.state {
	case CredentialBlocked:
		return guardPermit{}, &CredentialError{State: g.state, Reason: g.reason}
	case CredentialDelayed, CredentialHalfOpen:
		if g.probeLive || now.Before(g.retryAt) {
			return guardPermit{}, &CredentialError{State: CredentialDelayed, Reason: g.reason, RetryAt: g.retryAt}
		}
		g.failures = incrementFailureCount(g.failures)
		g.probeID++
		g.probeLive = true
		g.state = CredentialHalfOpen
		g.retryAt = now.Add(backoffDuration(g.policy, g.failures, random))
		return guardPermit{generation: generation, probeID: g.probeID}, nil
	default:
		return guardPermit{generation: generation}, nil
	}
}

func (g *credentialGuard) recheck(permit guardPermit) *CredentialError {
	g.mu.Lock()
	defer g.mu.Unlock()
	if permit.generation != g.generation {
		return &CredentialError{State: CredentialDelayed, Reason: CredentialReasonCredentialRotated}
	}
	if permit.probeID == 0 {
		if g.state == CredentialClear {
			return nil
		}
		return &CredentialError{State: g.state, Reason: g.reason, RetryAt: g.retryAt}
	}
	if g.state != CredentialHalfOpen || !g.probeLive || permit.probeID != g.probeID {
		return &CredentialError{State: g.state, Reason: g.reason, RetryAt: g.retryAt}
	}
	return nil
}

func (g *credentialGuard) abort(permit guardPermit) bool {
	if permit.probeID == 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if permit.generation == g.generation && permit.probeID == g.probeID {
		g.probeLive = false
		if g.state == CredentialHalfOpen {
			g.state = CredentialDelayed
		}
		return true
	}
	return false
}

func (g *credentialGuard) bindFailed(permit guardPermit, decision CredentialDecision, now time.Time, random float64) guardSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	if permit.generation != g.generation {
		return g.snapshotLocked()
	}
	if permit.probeID == 0 {
		if g.state != CredentialClear {
			return g.snapshotLocked()
		}
	} else if g.state != CredentialHalfOpen || !g.probeLive || permit.probeID != g.probeID {
		return g.snapshotLocked()
	} else {
		g.probeLive = false
	}
	switch decision.Action {
	case CredentialNotCredential:
		if g.state == CredentialHalfOpen {
			g.state = CredentialDelayed
		}
	case CredentialDelay:
		if g.state == CredentialClear {
			g.failures = 1
			g.retryAt = now.Add(backoffDuration(g.policy, g.failures, random))
		}
		g.state = CredentialDelayed
		g.reason = safeCredentialReason(decision.Reason)
	case CredentialBlock:
		if permit.probeID == 0 {
			g.failures = incrementFailureCount(g.failures)
		}
		g.state = CredentialBlocked
		g.reason = safeCredentialReason(decision.Reason)
		g.retryAt = time.Time{}
	default:
		if permit.probeID == 0 {
			g.failures = incrementFailureCount(g.failures)
		}
		g.state = CredentialBlocked
		g.reason = CredentialReasonUnknown
		g.retryAt = time.Time{}
	}
	return g.snapshotLocked()
}

func (g *credentialGuard) bindSucceeded(permit guardPermit) guardSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	valid := permit.generation == g.generation
	if permit.probeID == 0 {
		valid = valid && g.state == CredentialClear
	} else {
		valid = valid && g.state == CredentialHalfOpen && g.probeLive && permit.probeID == g.probeID
	}
	if valid {
		g.state = CredentialClear
		g.reason = CredentialReasonNone
		g.retryAt = time.Time{}
		g.failures = 0
		g.probeLive = false
	}
	return g.snapshotLocked()
}

func (g *credentialGuard) reset(generation uint64, reason CredentialReason) guardSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.generation = generation
	g.state = CredentialClear
	g.reason = reason
	g.retryAt = time.Time{}
	g.failures = 0
	g.probeLive = false
	g.probeID++
	return g.snapshotLocked()
}

func (g *credentialGuard) snapshot() guardSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshotLocked()
}

func (g *credentialGuard) snapshotLocked() guardSnapshot {
	return guardSnapshot{state: g.state, reason: g.reason, retryAt: g.retryAt, failures: g.failures}
}

func classifyCredentialResult(classifier CredentialFailureClassifier, result *strictLDAPResult) (CredentialDecision, error) {
	if result == nil || result.code <= 0 {
		return CredentialDecision{Action: CredentialNotCredential}, nil
	}
	if result.code > int64(^uint16(0)) {
		return CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonUnknown}, nil
	}
	return classifyCredentialFailure(classifier, CredentialFailure{
		ResultCode: uint16(result.code),
		Diagnostic: string(result.diagnostic),
	})
}

func classifyCredentialFailure(classifier CredentialFailureClassifier, failure CredentialFailure) (decision CredentialDecision, panicErr error) {
	if classifier == nil {
		return defaultCredentialDecision(failure), nil
	}
	defer func() {
		if recover() != nil {
			decision = CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonClassifierPanic}
			panicErr = &PanicError{Source: "credential classifier"}
		}
	}()
	return classifier.Classify(failure), nil
}

func defaultCredentialDecision(failure CredentialFailure) CredentialDecision {
	switch failure.ResultCode {
	case ldap.LDAPResultBusy, ldap.LDAPResultUnavailable:
		return CredentialDecision{Action: CredentialNotCredential}
	case ldap.LDAPResultInvalidCredentials:
		return CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonInvalid}
	case ldap.LDAPResultAuthMethodNotSupported:
		return CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonUnsupported}
	case ldap.LDAPResultInappropriateAuthentication,
		ldap.LDAPResultStrongAuthRequired,
		ldap.LDAPResultConfidentialityRequired,
		ldap.LDAPResultInsufficientAccessRights:
		return CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonPolicy}
	default:
		return CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonUnknown}
	}
}

func safeCredentialReason(reason CredentialReason) CredentialReason {
	if reason == "" || len(reason) > 64 {
		return CredentialReasonUnknown
	}
	for _, r := range reason {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return CredentialReasonUnknown
		}
	}
	return reason
}

func backoffDuration(policy backoffPolicy, failures uint64, random float64) time.Duration {
	if failures == 0 {
		return 0
	}
	exponent := float64(failures - 1)
	value := float64(policy.initial) * math.Pow(policy.multiplier, exponent)
	if math.IsInf(value, 1) || value > float64(policy.max) {
		value = float64(policy.max)
	}
	if math.IsNaN(random) || random < 0 || random >= 1 {
		random = rand.Float64()
	}
	factor := 1 - policy.jitter + 2*policy.jitter*random
	value *= factor
	if value >= float64(policy.max) {
		return policy.max
	}
	if value < 1 {
		value = 1
	}
	return time.Duration(value)
}

func incrementFailureCount(value uint64) uint64 {
	if value != ^uint64(0) {
		value++
	}
	return value
}

func isServerResultCode(code uint16) bool {
	return code < ldap.ErrorNetwork || code == ldap.LDAPResultSyncRefreshRequired
}
