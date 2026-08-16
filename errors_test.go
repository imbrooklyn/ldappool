package ldappool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestErrorTypesAndSentinelChains(t *testing.T) {
	root := errors.New("root cause")
	retryAt := time.Unix(100, 0)
	tests := []struct {
		name string
		err  error
		is   []error
	}{
		{"config", &ConfigError{Field: "Endpoint", Reason: "required"}, nil},
		{"acquire", &AcquireError{Stage: StageDial, RetryAt: retryAt, Cause: root, kind: ErrTransport}, []error{root, ErrTransport}},
		{"credential delayed", &CredentialError{State: CredentialDelayed, Reason: CredentialReasonPolicy, RetryAt: retryAt, Cause: root}, []error{root, ErrCredentialDelayed}},
		{"credential blocked", &CredentialError{State: CredentialBlocked, Reason: CredentialReasonInvalid}, []error{ErrCredentialBlocked}},
		{"operation", &OperationError{Operation: OperationAdd, Delivery: DeliveryDispatched, Cause: root, kinds: []error{ErrOutcomeUnknown, ErrTransport}}, []error{root, ErrOutcomeUnknown, ErrTransport}},
		{"panic", &PanicError{Source: "test"}, []error{ErrDependencyPanic}},
		{"close timeout", &CloseError{Remaining: 2, TimedOut: true, Cause: context.DeadlineExceeded}, []error{ErrCloseFailed, context.DeadlineExceeded}},
		{"close failure", &CloseError{Cause: root}, []error{ErrCloseFailed, root}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.err.Error() == "" {
				t.Fatal("empty Error string")
			}
			for _, target := range test.is {
				if !errors.Is(test.err, target) {
					t.Errorf("errors.Is(%v, %v) = false", test.err, target)
				}
			}
		})
	}
}

func TestOperationResultCodeSupportsLDAPClassification(t *testing.T) {
	err := &OperationError{
		Operation: OperationModify, Delivery: DeliveryConfirmed,
		Code: ldap.LDAPResultConstraintViolation, HasCode: true,
		Cause: sanitizedLDAPError(ldap.LDAPResultConstraintViolation),
	}
	code, ok := err.ResultCode()
	if !ok || code != ldap.LDAPResultConstraintViolation {
		t.Fatalf("ResultCode = %d, %v", code, ok)
	}
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) {
		t.Fatal("ldap.IsErrorWithCode did not traverse OperationError")
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.Packet != nil || ldapErr.MatchedDN != "" {
		t.Fatalf("sanitized LDAP error = %#v", ldapErr)
	}
}

func TestEnumStringsAreStable(t *testing.T) {
	if DeliveryNotSent.String() != "not_sent" || DeliveryDispatched.String() != "dispatched" || DeliveryConfirmed.String() != "confirmed" {
		t.Fatal("delivery strings changed")
	}
	if DeliveryState(99).String() != "unknown" {
		t.Fatal("unknown delivery state was not sanitized")
	}
	if TLSAuto.String() != "auto" || TLSStartTLS.String() != "starttls" || TLSImplicit.String() != "implicit" || TLSPlaintext.String() != "plaintext" {
		t.Fatal("TLS mode strings changed")
	}
	if !strings.HasPrefix(TLSMode(99).String(), "TLSMode(") {
		t.Fatal("unknown TLS mode string changed")
	}
}

func TestStartTLSSanitizationDoesNotRequirePacket(t *testing.T) {
	serverErr := ldap.NewError(ldap.LDAPResultUnavailable, errors.New("sensitive server diagnostic"))
	sanitized := sanitizeLDAPDiagnostic(serverErr)
	if strings.Contains(sanitized.Error(), "sensitive server diagnostic") {
		t.Fatalf("sanitized error leaked diagnostic: %v", sanitized)
	}
	if !ldap.IsErrorWithCode(sanitized, ldap.LDAPResultUnavailable) {
		t.Fatalf("sanitized error lost result code: %v", sanitized)
	}

	root := errors.New("transport root")
	networkErr := ldap.NewError(ldap.ErrorNetwork, root)
	if got := sanitizeLDAPDiagnostic(networkErr); got != networkErr {
		t.Fatalf("network error was replaced: %v", got)
	}
}
