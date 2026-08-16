package ldappool

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	// ErrPoolClosed indicates that the Pool is closing or closed.
	ErrPoolClosed = errors.New("ldappool: pool closed")
	// ErrWaitQueueFull indicates that MaxWaiters has been reached.
	ErrWaitQueueFull = errors.New("ldappool: wait queue full")
	// ErrCredentialDelayed indicates that new authentication attempts are delayed.
	ErrCredentialDelayed = errors.New("ldappool: credential attempt delayed")
	// ErrCredentialBlocked indicates that new authentication attempts are blocked.
	ErrCredentialBlocked = errors.New("ldappool: credential attempt blocked")
	// ErrNotSent indicates that no byte of the LDAP request was written.
	ErrNotSent = errors.New("ldappool: request was not sent")
	// ErrOutcomeUnknown indicates that a write may have taken effect but was not confirmed.
	ErrOutcomeUnknown = errors.New("ldappool: write outcome unknown")
	// ErrLeaseInvalid indicates use outside the callback-scoped lease.
	ErrLeaseInvalid = errors.New("ldappool: connection lease invalid")
	// ErrConcurrentUse indicates overlapping operations on one lease.
	ErrConcurrentUse = errors.New("ldappool: concurrent lease use")
	// ErrDependencyPanic indicates a recovered panic in a dependency boundary.
	ErrDependencyPanic = errors.New("ldappool: dependency panic")
	// ErrTransport indicates a transport failure.
	ErrTransport = errors.New("ldappool: transport failure")
	// ErrProtocol indicates a malformed, mismatched, or unexpected response.
	ErrProtocol = errors.New("ldappool: protocol failure")
	// ErrCloseFailed indicates that resource cleanup failed or exceeded its budget.
	ErrCloseFailed = errors.New("ldappool: close failed")
)

// FailureStage identifies a sanitized lifecycle stage.
type FailureStage string

const (
	// StageNone means no failure stage has been recorded.
	StageNone FailureStage = "none"
	// StageAcquire identifies acquisition and waiter failures.
	StageAcquire FailureStage = "acquire"
	// StageDial identifies raw transport creation.
	StageDial FailureStage = "dial"
	// StageTLS identifies TLS establishment or verification.
	StageTLS FailureStage = "tls"
	// StageBind identifies fixed-identity authentication.
	StageBind FailureStage = "bind"
	// StageOperation identifies a public LDAP operation.
	StageOperation FailureStage = "operation"
	// StageClose identifies physical resource cleanup.
	StageClose FailureStage = "close"
)

// Operation identifies a supported LDAP operation without including request data.
type Operation string

const (
	// OperationSearch identifies Search.
	OperationSearch Operation = "search"
	// OperationSearchWithPaging identifies SearchWithPaging.
	OperationSearchWithPaging Operation = "search_with_paging"
	// OperationDirSync identifies synchronous DirSync.
	OperationDirSync Operation = "dir_sync"
	// OperationCompare identifies Compare.
	OperationCompare Operation = "compare"
	// OperationAdd identifies Add.
	OperationAdd Operation = "add"
	// OperationModify identifies Modify.
	OperationModify Operation = "modify"
	// OperationDelete identifies Del.
	OperationDelete Operation = "delete"
	// OperationModifyDN identifies ModifyDN.
	OperationModifyDN Operation = "modify_dn"
	// OperationPasswordModify identifies PasswordModify.
	OperationPasswordModify Operation = "password_modify"
)

// DeliveryState describes whether a request could have reached the server.
type DeliveryState uint8

const (
	// DeliveryNotSent means no request byte was written.
	DeliveryNotSent DeliveryState = iota
	// DeliveryDispatched means the request may have reached the server.
	DeliveryDispatched
	// DeliveryConfirmed means a complete expected LDAP result was received.
	DeliveryConfirmed
)

// String returns the stable delivery-state name.
func (d DeliveryState) String() string {
	switch d {
	case DeliveryNotSent:
		return "not_sent"
	case DeliveryDispatched:
		return "dispatched"
	case DeliveryConfirmed:
		return "confirmed"
	default:
		return "unknown"
	}
}

// ConfigError reports invalid static configuration without echoing field values.
type ConfigError struct {
	// Field identifies the invalid field without including its value.
	Field string
	// Reason is a static, non-sensitive validation reason.
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("ldappool: invalid %s: %s", e.Field, e.Reason)
}

// AcquireError reports why a connection could not be acquired.
type AcquireError struct {
	// Stage identifies where acquisition failed.
	Stage FailureStage
	// RetryAt is the earliest effective retry time when known.
	RetryAt time.Time
	// Cause retains a programmatically inspectable error chain.
	Cause error
	kind  error
}

func (e *AcquireError) Error() string {
	if !e.RetryAt.IsZero() {
		return fmt.Sprintf("ldappool: acquire failed during %s; retry at %s", e.Stage, e.RetryAt.UTC().Format(time.RFC3339Nano))
	}
	return fmt.Sprintf("ldappool: acquire failed during %s", e.Stage)
}

func (e *AcquireError) Unwrap() []error { return compactErrors(e.kind, e.Cause) }

// CredentialError reports a delayed or blocked connection-creation decision.
type CredentialError struct {
	// State is the credential guard state that denied creation.
	State CredentialState
	// Reason is a sanitized, low-cardinality classification.
	Reason CredentialReason
	// RetryAt is the credential probe time when delayed.
	RetryAt time.Time
	// Cause retains sanitized LDAP result and dependency causes.
	Cause error
}

func (e *CredentialError) Error() string {
	if e.State == CredentialBlocked {
		return "ldappool: credentials are blocked"
	}
	return fmt.Sprintf("ldappool: credentials are delayed until %s", e.RetryAt.UTC().Format(time.RFC3339Nano))
}

func (e *CredentialError) Unwrap() []error {
	kind := ErrCredentialDelayed
	if e.State == CredentialBlocked {
		kind = ErrCredentialBlocked
	}
	return compactErrors(kind, e.Cause)
}

// OperationError reports a sanitized LDAP operation failure.
type OperationError struct {
	// Operation identifies the LDAP operation.
	Operation Operation
	// Delivery describes whether the request could have reached the server.
	Delivery DeliveryState
	// Code is a standard LDAP result code when HasCode is true.
	Code uint16
	// HasCode reports whether a complete server LDAP result was received.
	HasCode bool
	// Cause retains a redacted, programmatically inspectable chain.
	Cause error
	kinds []error
}

func (e *OperationError) Error() string {
	if e.HasCode {
		return fmt.Sprintf("ldappool: %s failed with LDAP result code %d", e.Operation, e.Code)
	}
	return fmt.Sprintf("ldappool: %s failed (%s)", e.Operation, e.Delivery)
}

func (e *OperationError) Unwrap() []error {
	all := make([]error, 0, len(e.kinds)+1)
	all = append(all, e.kinds...)
	if e.Cause != nil {
		all = append(all, e.Cause)
	}
	return all
}

// ResultCode returns a server LDAP result code when the operation received a
// complete LDAP result.
func (e *OperationError) ResultCode() (uint16, bool) { return e.Code, e.HasCode }

// PanicError describes a recovered panic without retaining or printing its payload.
type PanicError struct {
	// Source is a fixed internal dependency-boundary category.
	Source string
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("ldappool: recovered dependency panic in %s", e.Source)
}
func (e *PanicError) Unwrap() error { return ErrDependencyPanic }

// CloseError reports incomplete or failed physical cleanup.
type CloseError struct {
	// Remaining is the number of open physical connections at timeout.
	Remaining int
	// TimedOut reports whether the shutdown wait budget expired.
	TimedOut bool
	// Cause retains timeout or physical-close errors.
	Cause error
}

func (e *CloseError) Error() string {
	if e.TimedOut {
		return fmt.Sprintf("ldappool: close timed out with %d connection(s) remaining", e.Remaining)
	}
	return "ldappool: connection close failed"
}

func (e *CloseError) Unwrap() []error { return compactErrors(ErrCloseFailed, e.Cause) }

func compactErrors(values ...error) []error {
	out := make([]error, 0, len(values))
	for _, value := range values {
		if value != nil {
			out = append(out, value)
		}
	}
	return out
}

func sanitizedLDAPError(code uint16) error {
	return ldap.NewError(code, errors.New("LDAP server returned a result error; diagnostic redacted"))
}

func sanitizedStrictLDAPResult(code int64) error {
	if code >= 0 && code <= int64(^uint16(0)) {
		return sanitizedLDAPError(uint16(code))
	}
	return errors.New("LDAP server returned an unsupported result code; diagnostic redacted")
}

func ldapErrorHasResponseTag(err *ldap.Error, expected uint64) bool {
	return err != nil && err.Packet != nil && len(err.Packet.Children) >= 2 &&
		err.Packet.Children[1] != nil && uint64(err.Packet.Children[1].Tag) == expected
}

func notSentError(op Operation, kinds ...error) error {
	return &OperationError{
		Operation: op,
		Delivery:  DeliveryNotSent,
		kinds:     append([]error{ErrNotSent}, kinds...),
	}
}
