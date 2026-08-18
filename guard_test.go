package ldappool

import (
	"bufio"
	"context"
	"errors"
	"math"
	"net"
	"sync/atomic"
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

func TestSharedCredentialGuardSingleFlightsFailureAfterPriorSuccessAcrossPools(t *testing.T) {
	guard, err := NewCredentialGuard(CredentialGuardConfig{
		BindPrincipal: "cn=service,dc=example,dc=test",
		Password:      NewSecret([]byte("secret")),
	})
	if err != nil {
		t.Fatal(err)
	}
	validationConfig := simpleTestConfig(&testDialer{factory: pipeFactory(successfulLDAPServer, nil)})
	validationConfig.Auth = AuthConfig{Mode: AuthSimple, CredentialGuard: guard}
	validationPool, err := New(validationConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err = validationPool.Warmup(contextWithTimeout(t), 1); err != nil {
		t.Fatal(err)
	}
	if err = validationPool.Close(contextWithTimeout(t)); err != nil {
		t.Fatal(err)
	}

	var bindAttempts atomic.Int64
	handler := func(conn net.Conn, _ int) {
		defer conn.Close()
		request, readErr := readLDAPRequest(bufio.NewReader(conn))
		if readErr == nil {
			bindAttempts.Add(1)
			_ = writeLDAPResult(conn, request.messageID, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "data 52e")
		}
	}
	dialers := []*testDialer{
		{factory: pipeFactory(handler, nil)},
		{factory: pipeFactory(handler, nil)},
	}
	pools := make([]*Pool, 0, len(dialers))
	for _, dialer := range dialers {
		config := simpleTestConfig(dialer)
		config.Auth = AuthConfig{Mode: AuthSimple, CredentialGuard: guard}
		pool, newErr := New(config)
		if newErr != nil {
			t.Fatal(newErr)
		}
		pools = append(pools, pool)
	}
	results := make(chan error, len(pools))
	for _, pool := range pools {
		go func(pool *Pool) {
			results <- pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil })
		}(pool)
	}
	for range pools {
		if result := receive(t, results); !errors.Is(result, ErrCredentialBlocked) {
			t.Fatalf("shared credential failure = %v", result)
		}
	}
	if got := bindAttempts.Load(); got != 1 {
		t.Fatalf("shared guard allowed %d failed Bind attempts, want 1", got)
	}
	for _, pool := range pools {
		if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialBlocked || snapshot.Generation != 1 {
			t.Fatalf("shared blocked snapshot = %+v", snapshot)
		}
		if closeErr := pool.Close(contextWithTimeout(t)); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}

func TestSharedCredentialRotationRetiresEveryPool(t *testing.T) {
	guard, err := NewCredentialGuard(CredentialGuardConfig{
		BindPrincipal: "cn=service,dc=example,dc=test",
		Password:      NewSecret([]byte("secret")),
	})
	if err != nil {
		t.Fatal(err)
	}
	dialers := []*testDialer{
		{factory: pipeFactory(successfulLDAPServer, nil)},
		{factory: pipeFactory(successfulLDAPServer, nil)},
	}
	pools := make([]*Pool, 0, len(dialers))
	for _, dialer := range dialers {
		config := simpleTestConfig(dialer)
		config.Auth = AuthConfig{Mode: AuthSimple, CredentialGuard: guard}
		pool, newErr := New(config)
		if newErr != nil {
			t.Fatal(newErr)
		}
		pools = append(pools, pool)
		if warmErr := pool.Warmup(contextWithTimeout(t), 1); warmErr != nil {
			t.Fatal(warmErr)
		}
	}
	if err = guard.RotateCredentials(NewSecret([]byte("rotated"))); err != nil {
		t.Fatal(err)
	}
	generation, password := guard.credential.snapshot()
	if generation != 2 || string(password) != "rotated" {
		wipe(password)
		t.Fatalf("shared credential after rotation = generation %d, password length %d", generation, len(password))
	}
	wipe(password)
	for _, pool := range pools {
		waitForCondition(t, func() bool {
			snapshot := pool.Snapshot()
			return snapshot.Generation == 2 && snapshot.Counts.Open == 0
		})
		if acquireErr := pool.WithConnection(contextWithTimeout(t), func(*Connection) error { return nil }); acquireErr != nil {
			t.Fatal(acquireErr)
		}
	}
	for index, dialer := range dialers {
		if dialer.count() != 2 {
			t.Fatalf("pool %d dial count = %d, want 2", index, dialer.count())
		}
	}
	if err = guard.Reset(); err != nil {
		t.Fatal(err)
	}
	for _, pool := range pools {
		if snapshot := pool.Snapshot(); snapshot.CredentialState != CredentialClear || snapshot.CredentialReason != CredentialReasonManualReset {
			t.Fatalf("shared reset snapshot = %+v", snapshot)
		}
		if closeErr := pool.Close(contextWithTimeout(t)); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}

func TestCredentialGuardDirectLifecycleWithoutAttachedPools(t *testing.T) {
	guard, err := NewCredentialGuard(CredentialGuardConfig{
		BindPrincipal: "cn=service,dc=example,dc=test",
		Password:      NewSecret([]byte("original")),
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(100, 0)
	permit, err := guard.permit(now, 1, .5)
	if err != nil {
		t.Fatal(err)
	}
	blocked := guard.bindFailed(
		permit,
		CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonInvalid},
		now,
		.5,
	)
	if blocked.state != CredentialBlocked {
		t.Fatalf("guard state before rotation = %s, want blocked", blocked.state)
	}

	oldPassword := guard.credential.password
	if err = guard.RotateCredentials(NewSecret([]byte("rotated"))); err != nil {
		t.Fatal(err)
	}
	for index, value := range oldPassword {
		if value != 0 {
			t.Fatalf("old password byte %d was not wiped", index)
		}
	}
	generation, password := guard.credential.snapshot()
	if generation != 2 || string(password) != "rotated" {
		wipe(password)
		t.Fatalf("rotated credential = generation %d, password length %d", generation, len(password))
	}
	wipe(password)
	rotated := guard.guard.snapshot()
	guard.guard.mu.Lock()
	rotatedGeneration := guard.guard.generation
	guard.guard.mu.Unlock()
	if rotated.state != CredentialClear || rotated.reason != CredentialReasonCredentialRotated || rotatedGeneration != 2 {
		t.Fatalf("guard state after rotation = %+v", rotated)
	}

	if err = guard.Reset(); err != nil {
		t.Fatal(err)
	}
	reset := guard.guard.snapshot()
	guard.guard.mu.Lock()
	resetGeneration := guard.guard.generation
	guard.guard.mu.Unlock()
	if reset.state != CredentialClear || reset.reason != CredentialReasonManualReset || resetGeneration != 2 {
		t.Fatalf("guard state after reset = %+v", reset)
	}
}

func TestCredentialGuardPublicMethodsRejectInvalidReceiverAndSecret(t *testing.T) {
	var nilGuard *CredentialGuard
	for name, guard := range map[string]*CredentialGuard{
		"nil":  nilGuard,
		"zero": {},
	} {
		t.Run(name, func(t *testing.T) {
			for method, err := range map[string]error{
				"RotateCredentials": guard.RotateCredentials(NewSecret([]byte("rotated"))),
				"Reset":             guard.Reset(),
			} {
				var configErr *ConfigError
				if !errors.As(err, &configErr) || configErr.Field != "CredentialGuard" {
					t.Fatalf("%s error = %v, want CredentialGuard config error", method, err)
				}
			}
		})
	}

	guard, err := NewCredentialGuard(CredentialGuardConfig{
		BindPrincipal: "cn=service,dc=example,dc=test",
		Password:      NewSecret([]byte("secret")),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = guard.RotateCredentials(Secret{})
	var configErr *ConfigError
	if !errors.As(err, &configErr) || configErr.Field != "CredentialGuard.Password" {
		t.Fatalf("empty rotation secret error = %v, want CredentialGuard.Password config error", err)
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
