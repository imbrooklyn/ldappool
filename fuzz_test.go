package ldappool

import (
	"bufio"
	"context"
	"math"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func FuzzEndpointAndServerNameNeverPanic(f *testing.F) {
	for _, seed := range []struct{ endpoint, name string }{
		{"ldap://example.com", ""},
		{"ldaps://127.0.0.1:636", "127.0.0.1"},
		{"not a URL", "host:port"},
		{"ldap://[2001:db8::1]", "directory.example"},
	} {
		f.Add(seed.endpoint, seed.name)
	}
	f.Fuzz(func(t *testing.T, endpoint, name string) {
		u, _, err := normalizeEndpoint(endpoint)
		if err != nil {
			return
		}
		normalized, err := normalizeServerName(name, u.Hostname())
		if err == nil && normalized == "" {
			t.Fatal("successful normalization returned an empty name")
		}
	})
}

func FuzzBackoffIsPositiveAndCapped(f *testing.F) {
	f.Add(uint64(1), float64(.5))
	f.Add(uint64(math.MaxUint64), float64(-1))
	f.Add(uint64(50), math.Inf(1))
	f.Fuzz(func(t *testing.T, failures uint64, random float64) {
		policy := backoffPolicy{initial: time.Millisecond, multiplier: 2, max: time.Minute, jitter: .5}
		duration := backoffDuration(policy, failures, random)
		if failures == 0 {
			if duration != 0 {
				t.Fatalf("zero failures returned %s", duration)
			}
			return
		}
		if duration <= 0 || duration > policy.max {
			t.Fatalf("duration %s outside (0,%s]", duration, policy.max)
		}
	})
}

func FuzzCredentialReasonSanitization(f *testing.F) {
	for _, seed := range []string{"invalid", "ad.locked", "diagnostic with spaces", "", "ümlaut"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		reason := safeCredentialReason(CredentialReason(value))
		if reason == "" || len(reason) > 64 {
			t.Fatalf("unsafe sanitized reason %q", reason)
		}
	})
}

func FuzzCredentialGuardCommandSequence(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{1, 1, 4, 0, 5, 3, 2})
	f.Fuzz(func(t *testing.T, commands []byte) {
		policy := backoffPolicy{initial: time.Millisecond, multiplier: 2, max: time.Second, jitter: .25}
		guard := newCredentialGuard(policy)
		now := time.Unix(1, 0)
		generation := uint64(1)
		var permit guardPermit
		for _, command := range commands {
			switch command % 6 {
			case 0:
				candidate, err := guard.permit(now, generation, .5)
				if err == nil {
					permit = candidate
				}
			case 1:
				guard.bindFailed(permit, CredentialDecision{Action: CredentialDelay, Reason: CredentialReasonPolicy}, now, .5)
			case 2:
				guard.bindFailed(permit, CredentialDecision{Action: CredentialBlock, Reason: CredentialReasonInvalid}, now, .5)
			case 3:
				guard.bindSucceeded(permit)
			case 4:
				guard.abort(permit)
			case 5:
				generation++
				guard.reset(generation, CredentialReasonCredentialRotated)
			}
			now = now.Add(time.Millisecond)
			snapshot := guard.snapshot()
			switch snapshot.state {
			case CredentialClear, CredentialDelayed, CredentialHalfOpen, CredentialBlocked:
			default:
				t.Fatalf("invalid credential state %q", snapshot.state)
			}
			if snapshot.state == CredentialBlocked && !snapshot.retryAt.IsZero() {
				t.Fatal("blocked guard retained a retry deadline")
			}
			if (snapshot.state == CredentialDelayed || snapshot.state == CredentialHalfOpen) && snapshot.retryAt.IsZero() {
				t.Fatal("delayed guard lost its retry deadline")
			}
		}
	})
}

func FuzzMalformedLDAPResponseNeverEscapesPanic(f *testing.F) {
	f.Add([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	f.Add([]byte{0x30, 0x0e, 0x02, 0x01, 0x01, 0x65, 0x09, 0x0a, 0x03, 0x01, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00})
	f.Add([]byte{0x30, 0x0d, 0x02, 0x01, 0x01, 0x65, 0x08, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00})
	f.Add([]byte{0x30, 0x80, 0xff, 0x00})
	f.Add([]byte("not-ber"))
	f.Fuzz(func(t *testing.T, response []byte) {
		if len(response) > 4096 {
			t.Skip()
		}
		response = append([]byte(nil), response...)
		dialer := &testDialer{factory: pipeFactory(func(conn net.Conn, _ int) {
			defer conn.Close()
			if _, err := readLDAPRequest(bufio.NewReader(conn)); err == nil {
				_, _ = conn.Write(response)
			}
		}, nil)}
		config := anonymousTestConfig(dialer)
		config.ConnectTimeout = 250 * time.Millisecond
		config.RequestTimeout = 250 * time.Millisecond
		config.CloseTimeout = 250 * time.Millisecond
		pool, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		operationErr := pool.WithConnection(ctx, func(connection *Connection) error {
			_, searchErr := connection.Search(ctx, ldap.NewSearchRequest(
				"dc=example", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1,
				false, "(objectClass=*)", nil, nil,
			))
			return searchErr
		})
		if operationErr == nil && !isStrictSearchSuccessWireResponse(response) {
			t.Fatal("malformed LDAP response was accepted as Search success")
		}
		if err := pool.Close(ctx); err != nil {
			t.Fatal(err)
		}
		assertClosedPoolInvariants(t, pool)
	})
}

func isStrictSearchSuccessWireResponse(response []byte) bool {
	var stream ldapMessageStream
	stream.feed(response)
	inspection := inspectOperationExchange(OperationSearch, traceSnapshot{
		requests: ldapStreamSnapshot{messages: []ldapMessageObservation{{
			messageID: 1, applicationTag: ldap.ApplicationSearchRequest, constructed: true,
		}}},
		responses: stream.snapshot(),
	})
	defer inspection.destroy()
	if inspection.err != nil || !inspection.complete {
		return false
	}
	success, _, hasFailure, err := operationResultStatus(OperationSearch, inspection.results)
	return err == nil && success && !hasFailure
}
