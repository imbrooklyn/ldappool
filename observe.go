package ldappool

import (
	"sync"
	"sync/atomic"
	"time"
)

// PoolState is a read-only projection of lifecycle and connectivity state.
type PoolState string

const (
	PoolCold              PoolState = "cold"
	PoolConnecting        PoolState = "connecting"
	PoolReady             PoolState = "ready"
	PoolTransientBackoff  PoolState = "transient_backoff"
	PoolCredentialDelayed PoolState = "credential_delayed"
	PoolCredentialBlocked PoolState = "credential_blocked"
	PoolClosing           PoolState = "closing"
	PoolClosed            PoolState = "closed"
)

// CredentialState is the process-local credential guard state.
type CredentialState string

const (
	CredentialClear    CredentialState = "clear"
	CredentialDelayed  CredentialState = "delayed"
	CredentialHalfOpen CredentialState = "half_open"
	CredentialBlocked  CredentialState = "blocked"
)

// CredentialReason is a sanitized, low-cardinality classification.
type CredentialReason string

const (
	CredentialReasonNone              CredentialReason = "none"
	CredentialReasonInvalid           CredentialReason = "invalid"
	CredentialReasonPolicy            CredentialReason = "policy"
	CredentialReasonUnsupported       CredentialReason = "unsupported"
	CredentialReasonUnknown           CredentialReason = "unknown"
	CredentialReasonClassifierPanic   CredentialReason = "classifier_panic"
	CredentialReasonManualReset       CredentialReason = "manual_reset"
	CredentialReasonCredentialRotated CredentialReason = "credential_rotated"
)

// FailureReason is a sanitized event or eviction reason.
type FailureReason string

const (
	ReasonNone                FailureReason = "none"
	ReasonDial                FailureReason = "dial_failure"
	ReasonTLSValidation       FailureReason = "tls_validation_failure"
	ReasonBind                FailureReason = "bind_failure"
	ReasonIdleTimeout         FailureReason = "idle_timeout"
	ReasonMaxLifetime         FailureReason = "max_lifetime"
	ReasonMaxIdle             FailureReason = "max_idle"
	ReasonCredentialRotation  FailureReason = "credential_rotation"
	ReasonTransport           FailureReason = "transport_error"
	ReasonProtocol            FailureReason = "protocol_error"
	ReasonRequestTimeout      FailureReason = "request_timeout"
	ReasonContextCancellation FailureReason = "context_cancellation"
	ReasonCallbackPanic       FailureReason = "callback_panic"
	ReasonDependencyPanic     FailureReason = "dependency_panic"
	ReasonLeaseReturnedBusy   FailureReason = "lease_returned_busy"
	ReasonPoolClose           FailureReason = "pool_close"
	ReasonInitialization      FailureReason = "initialization_failure"
	ReasonCloseFailure        FailureReason = "close_failure"
)

// EventType identifies an observation event. Values are stable and contain no
// request or identity data.
type EventType string

const (
	EventDialStart           EventType = "dial_start"
	EventDialSuccess         EventType = "dial_success"
	EventDialFailure         EventType = "dial_failure"
	EventTLSFailure          EventType = "tls_failure"
	EventBindSuccess         EventType = "bind_success"
	EventBindFailure         EventType = "bind_failure"
	EventAcquireQueued       EventType = "acquire_queued"
	EventAcquireSuccess      EventType = "acquire_success"
	EventAcquireCanceled     EventType = "acquire_canceled"
	EventBackoffArmed        EventType = "backoff_armed"
	EventCredentialState     EventType = "credential_state"
	EventEviction            EventType = "eviction"
	EventOperationCanceled   EventType = "operation_canceled"
	EventWriteOutcomeUnknown EventType = "write_outcome_unknown"
	EventCloseTimeout        EventType = "close_timeout"
	EventForceClose          EventType = "force_close"
	EventPoolRecovered       EventType = "pool_recovered"
	EventDependencyPanic     EventType = "dependency_panic"
)

// Counts is a consistent snapshot of Pool counters taken under the Pool lock.
type Counts struct {
	// Open is connecting plus idle plus borrowed plus closing.
	Open int
	// Idle is the number available for immediate acquisition.
	Idle int
	// Borrowed is the number owned by callback leases.
	Borrowed int
	// Connecting is zero or one.
	Connecting int
	// Closing remains part of Open until physical close terminates.
	Closing int
	// Waiters includes queued external and internal acquisitions.
	Waiters int
}

// Event is a redacted observation record.
type Event struct {
	// Sequence is monotonically delivered within one Pool observer.
	Sequence uint64
	// Type identifies the event.
	Type EventType
	// At is the event time.
	At time.Time
	// Duration is populated for timed events.
	Duration time.Duration
	// Operation is populated for LDAP operation events.
	Operation Operation
	// Stage identifies a lifecycle failure stage or StageNone.
	Stage FailureStage
	// Reason is a sanitized event or eviction reason.
	Reason FailureReason
	// CredentialState is populated for credential events.
	CredentialState CredentialState
	// CredentialReason is a sanitized credential classification.
	CredentialReason CredentialReason
	// RetryAt is populated for delayed creation events.
	RetryAt time.Time
	// Counts is a mutually consistent pool-counter sample.
	Counts Counts
}

// Observer receives events from a bounded asynchronous dispatcher. Observe
// must return promptly. A panic is recovered and a blocked observer cannot
// block Pool operations, although it can permanently occupy its dispatcher.
type Observer interface {
	Observe(Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Event)

// Observe calls f(event).
func (f ObserverFunc) Observe(event Event) { f(event) }

// Snapshot is a passive, redacted view of in-memory state. Counts are mutually
// consistent; credential fields are sampled separately and may straddle one
// concurrent transition.
type Snapshot struct {
	// CapturedAt is the snapshot time.
	CapturedAt time.Time
	// State is the projected pool lifecycle/connectivity state.
	State PoolState
	// Counts is captured atomically under the Pool lock.
	Counts Counts
	// Generation is the current fixed-identity credential generation.
	Generation uint64

	// RetryAt is the ordinary connection-creation retry time.
	RetryAt time.Time
	// ConnectFailures is the current consecutive ordinary failure count.
	ConnectFailures uint64
	// LastFailureStage is the last sanitized connection lifecycle stage.
	LastFailureStage FailureStage
	// LastFailureReason is the last sanitized connection lifecycle reason.
	LastFailureReason FailureReason

	// CredentialState is sampled separately from Counts.
	CredentialState CredentialState
	// CredentialReason is the current sanitized guard reason.
	CredentialReason CredentialReason
	// CredentialRetryAt is the next delayed half-open probe time.
	CredentialRetryAt time.Time
	// CredentialFailures is the guard backoff failure count.
	CredentialFailures uint64

	// ObserverDropped is the cumulative number of events dropped at enqueue.
	ObserverDropped uint64
}

type observerDispatcher struct {
	observer Observer
	queue    chan Event
	done     chan struct{}
	dropped  atomic.Uint64
	sequence atomic.Uint64
	mu       sync.Mutex
	stopped  bool
}

func newObserverDispatcher(observer Observer, size int) *observerDispatcher {
	if observer == nil {
		return nil
	}
	d := &observerDispatcher{observer: observer, queue: make(chan Event, size), done: make(chan struct{})}
	go d.run()
	return d
}

func (d *observerDispatcher) emit(event Event) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	event.Sequence = d.sequence.Add(1)
	select {
	case d.queue <- event:
	default:
		d.dropped.Add(1)
	}
}

func (d *observerDispatcher) stop() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if !d.stopped {
		d.stopped = true
		close(d.queue)
	}
	d.mu.Unlock()
}

func (d *observerDispatcher) run() {
	defer close(d.done)
	for event := range d.queue {
		func() {
			defer func() { _ = recover() }()
			d.observer.Observe(event)
		}()
	}
}
