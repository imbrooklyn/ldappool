package ldappool

import (
	"bufio"
	"context"
	"errors"
	"math"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestCredentialGuardArmThenConfirm(t *testing.T) {
	policy := backoffPolicy{initial: time.Second, multiplier: 2, max: 10 * time.Second, jitter: 0}
	guard := newCredentialGuard(policy)
	now := time.Unix(100, 0)
	initial, err := guard.permit(now, 1, .5)
	if err != nil || initial.probeID != 0 {
		t.Fatalf("initial permit = %+v, %v", initial, err)
	}
	snapshot := guard.bindFailed(initial, CredentialDecision{Action: CredentialDelay, Reason: CredentialReasonPolicy}, now, .5)
	if snapshot.state != CredentialDelayed || !snapshot.retryAt.Equal(now.Add(time.Second)) {
		t.Fatalf("delayed snapshot = %+v", snapshot)
	}
	if _, err := guard.permit(now.Add(time.Millisecond), 1, .5); !errors.Is(err, ErrCredentialDelayed) {
		t.Fatalf("early permit error = %v", err)
	}
	probeAt := now.Add(time.Second)
	probe, err := guard.permit(probeAt, 1, .5)
	if err != nil || probe.probeID == 0 {
		t.Fatalf("half-open permit = %+v, %v", probe, err)
	}
	armed := guard.snapshot()
	if armed.state != CredentialHalfOpen || !armed.retryAt.Equal(probeAt.Add(2*time.Second)) {
		t.Fatalf("half-open was not pre-armed: %+v", armed)
	}
	guard.abort(probe)
	afterDialFailure := guard.snapshot()
	if afterDialFailure.state != CredentialDelayed || !afterDialFailure.retryAt.Equal(armed.retryAt) {
		t.Fatalf("Dial failure cleared guard window: %+v", afterDialFailure)
	}
	if _, err := guard.permit(probeAt.Add(time.Second), 1, .5); !errors.Is(err, ErrCredentialDelayed) {
		t.Fatalf("pre-armed window was not retained: %v", err)
	}
	confirmedProbe, err := guard.permit(armed.retryAt, 1, .5)
	if err != nil {
		t.Fatal(err)
	}
	cleared := guard.bindSucceeded(confirmedProbe)
	if cleared.state != CredentialClear || cleared.failures != 0 || !cleared.retryAt.IsZero() {
		t.Fatalf("successful Bind did not clear guard: %+v", cleared)
	}
}

func TestBackoffSaturatesAtMaximumDurationWithoutFloatOverflow(t *testing.T) {
	maximum := time.Duration(math.MaxInt64)
	policy := backoffPolicy{initial: maximum, multiplier: 2, max: maximum, jitter: 0}
	if got := backoffDuration(policy, math.MaxUint64, .5); got != maximum {
		t.Fatalf("maximum backoff = %s (%d), want %s (%d)", got, got, maximum, maximum)
	}
	if got := incrementFailureCount(math.MaxUint64); got != math.MaxUint64 {
		t.Fatalf("saturated failure count = %d", got)
	}
}

func TestCredentialGuardGenerationAndBlock(t *testing.T) {
	guard := newCredentialGuard(backoffPolicy{initial: time.Second, multiplier: 2, max: time.Minute})
	permit, err := guard.permit(time.Now(), 1, .5)
	if err != nil {
		t.Fatal(err)
	}
	blocked := guard.bindFailed(permit, CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonInvalid}, time.Now(), .5)
	if blocked.state != CredentialBlocked {
		t.Fatalf("state = %s", blocked.state)
	}
	if _, err := guard.permit(time.Now(), 1, .5); !errors.Is(err, ErrCredentialBlocked) {
		t.Fatalf("blocked permit error = %v", err)
	}
	guard.reset(2, CredentialReasonCredentialRotated)
	if _, err := guard.permit(time.Now(), 1, .5); err == nil {
		t.Fatal("stale generation was permitted")
	}
	if _, err := guard.permit(time.Now(), 2, .5); err != nil {
		t.Fatalf("new generation was not permitted: %v", err)
	}
}

func TestCredentialGuardRejectsStaleTerminalTransitions(t *testing.T) {
	guard := newCredentialGuard(backoffPolicy{initial: time.Second, multiplier: 2, max: time.Minute})
	now := time.Unix(100, 0)
	permit, err := guard.permit(now, 1, .5)
	if err != nil {
		t.Fatal(err)
	}
	blocked := guard.bindFailed(permit, CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonInvalid}, now, .5)
	if blocked.state != CredentialBlocked {
		t.Fatalf("state = %s", blocked.state)
	}

	if got := guard.bindFailed(permit, CredentialDecision{Action: CredentialDelay, Reason: CredentialReasonPolicy}, now, .5); got.state != CredentialBlocked || !got.retryAt.IsZero() {
		t.Fatalf("stale failure changed blocked guard: %+v", got)
	}
	if got := guard.bindSucceeded(permit); got.state != CredentialBlocked || !got.retryAt.IsZero() {
		t.Fatalf("stale success changed blocked guard: %+v", got)
	}

	guard.reset(2, CredentialReasonCredentialRotated)
	initial, err := guard.permit(now, 2, .5)
	if err != nil {
		t.Fatal(err)
	}
	delayed := guard.bindFailed(initial, CredentialDecision{Action: CredentialDelay, Reason: CredentialReasonPolicy}, now, .5)
	probe, err := guard.permit(delayed.retryAt, 2, .5)
	if err != nil {
		t.Fatal(err)
	}
	guard.abort(probe)
	if got := guard.bindSucceeded(probe); got.state != CredentialDelayed || got.retryAt.IsZero() {
		t.Fatalf("aborted probe success cleared guard: %+v", got)
	}
}

func TestCredentialClassifierPanicIsConservativelyBlocked(t *testing.T) {
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		request, err := readLDAPRequest(bufio.NewReader(conn))
		if err == nil {
			_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "vendor diagnostic")
		}
	}
	dialer := &testDialer{factory: pipeFactory(handler, nil)}
	config := simpleTestConfig(dialer)
	config.CredentialFailureClassifier = CredentialFailureClassifierFunc(func(CredentialFailure) CredentialDecision {
		panic("classifier payload")
	})
	pool, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
	if !errors.Is(err, ErrCredentialBlocked) || !errors.Is(err, ErrDependencyPanic) {
		t.Fatalf("classifier panic error = %v", err)
	}
	if snapshot := pool.Snapshot(); snapshot.CredentialReason != CredentialReasonClassifierPanic {
		t.Fatalf("credential reason = %s", snapshot.CredentialReason)
	}
	_ = pool.Close(context.Background())
}

func TestDefaultCredentialClassifierDoesNotParseVendorText(t *testing.T) {
	for _, test := range []struct {
		code   uint16
		action CredentialAction
	}{
		{ldap.LDAPResultInvalidCredentials, CredentialBlock},
		{ldap.LDAPResultBusy, CredentialNotCredential},
		{ldap.LDAPResultUnavailable, CredentialNotCredential},
		{ldap.LDAPResultOther, CredentialBlock},
	} {
		decision := defaultCredentialDecision(CredentialFailure{ResultCode: test.code, Diagnostic: "data 52e"})
		if decision.Action != test.action {
			t.Fatalf("code %d action = %d, want %d", test.code, decision.Action, test.action)
		}
	}
}

func TestAcquireCredentialDelayReportsEffectiveCombinedGate(t *testing.T) {
	pool, err := New(anonymousTestConfig(&testDialer{factory: pipeFactory(successfulLDAPServer, nil)}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	guardRetry := now.Add(time.Second)
	ordinaryRetry := now.Add(2 * time.Second)
	pool.mu.Lock()
	pool.retryAt = ordinaryRetry
	err = pool.immediateGateErrorLocked(now, guardSnapshot{
		state: CredentialDelayed, reason: CredentialReasonPolicy, retryAt: guardRetry,
	})
	pool.mu.Unlock()
	var acquireErr *AcquireError
	var credentialErr *CredentialError
	if !errors.As(err, &acquireErr) || !errors.As(err, &credentialErr) {
		t.Fatalf("combined gate error = %v", err)
	}
	if !acquireErr.RetryAt.Equal(ordinaryRetry) || !credentialErr.RetryAt.Equal(guardRetry) {
		t.Fatalf("outer retry=%s credential retry=%s", acquireErr.RetryAt, credentialErr.RetryAt)
	}
	if err := pool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}
}
