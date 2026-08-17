package ldappool

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/go-ldap/ldap/v3"
)

type leaseState uint32

const (
	leaseInvalid leaseState = iota
	leaseActive
	leaseBusy
)

// Connection is a callback-scoped, single-operation-at-a-time LDAP lease.
// Its zero value and every value retained after WithConnection returns are
// invalid. Copying a Connection does not create a new lease; copies share the
// same invalidation and busy state. Connection intentionally exposes no raw
// client or session-changing methods.
type Connection struct {
	*leaseHandle
}

type leaseHandle struct {
	canonical Connection
	pool      *Pool
	physical  *physicalConn
	state     atomic.Uint32
}

// String returns a constant redacted representation.
func (Connection) String() string { return "ldappool.Connection{[REDACTED]}" }

// GoString returns a constant redacted representation.
func (Connection) GoString() string { return "ldappool.Connection{[REDACTED]}" }

func newConnection(pool *Pool, physical *physicalConn) *Connection {
	handle := &leaseHandle{pool: pool, physical: physical}
	handle.canonical.leaseHandle = handle
	handle.state.Store(uint32(leaseActive))
	return &handle.canonical
}

func sameLease(left, right *Connection) bool {
	return left != nil && right != nil && left.leaseHandle != nil && left.leaseHandle == right.leaseHandle
}

func (c *Connection) invalidate() leaseState {
	if c == nil || c.leaseHandle == nil {
		return leaseInvalid
	}
	for {
		state := leaseState(c.state.Load())
		if state == leaseInvalid || c.state.CompareAndSwap(uint32(state), uint32(leaseInvalid)) {
			return state
		}
	}
}

// invalidateUnlessBusy linearizes graceful retirement against operation entry.
// An operation that has already changed the lease to busy keeps the transport
// until that operation finishes; otherwise retirement invalidates the lease
// before another operation can enter.
func (c *Connection) invalidateUnlessBusy() leaseState {
	if c == nil || c.leaseHandle == nil {
		return leaseInvalid
	}
	for {
		state := leaseState(c.state.Load())
		switch state {
		case leaseBusy, leaseInvalid:
			return state
		case leaseActive:
			if c.state.CompareAndSwap(uint32(leaseActive), uint32(leaseInvalid)) {
				return leaseActive
			}
		}
	}
}

func (c *Connection) enter(op Operation) error {
	if c == nil || c.leaseHandle == nil || c.pool == nil || c.physical == nil {
		return notSentError(op, ErrLeaseInvalid)
	}
	for {
		switch leaseState(c.state.Load()) {
		case leaseActive:
			if c.state.CompareAndSwap(uint32(leaseActive), uint32(leaseBusy)) {
				return nil
			}
		case leaseBusy:
			return notSentError(op, ErrConcurrentUse)
		default:
			return notSentError(op, ErrLeaseInvalid)
		}
	}
}

// Search performs one complete synchronous LDAP search.
func (c *Connection) Search(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	var cloned *ldap.SearchRequest
	return runOperation(c, ctx, OperationSearch, false, func() error {
		var err error
		cloned, err = cloneSearchRequest(request, cloneControlsShallow)
		return err
	}, func(client ldapClient) (*ldap.SearchResult, error) {
		result, err := client.Search(cloned)
		if err == nil && result == nil {
			return nil, errors.New("LDAP Search returned no result")
		}
		return result, err
	})
}

// SearchWithPaging performs all pages synchronously within this lease. It
// copies the paging control and outer request slices before go-ldap mutates them.
func (c *Connection) SearchWithPaging(ctx context.Context, request *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error) {
	var cloned *ldap.SearchRequest
	return runOperation(c, ctx, OperationSearchWithPaging, false, func() error {
		var err error
		cloned, err = cloneSearchRequest(request, clonePagingControls)
		return err
	}, func(client ldapClient) (*ldap.SearchResult, error) {
		result, err := client.SearchWithPaging(cloned, pagingSize)
		if err == nil && result == nil {
			return nil, errors.New("LDAP SearchWithPaging returned no result")
		}
		return result, err
	})
}

// DirSync performs one bounded synchronous search using the Microsoft DirSync
// control. It does not expose the asynchronous response API.
func (c *Connection) DirSync(ctx context.Context, request *ldap.SearchRequest, flags, maxAttrCount int64, cookie []byte) (*ldap.SearchResult, error) {
	var cloned *ldap.SearchRequest
	cookieCopy := append([]byte(nil), cookie...)
	return runOperation(c, ctx, OperationDirSync, false, func() error {
		var err error
		cloned, err = cloneSearchRequest(request, cloneDirSyncControls)
		return err
	}, func(client ldapClient) (*ldap.SearchResult, error) {
		result, err := client.DirSync(cloned, flags, maxAttrCount, cookieCopy)
		if err == nil && result == nil {
			return nil, errors.New("LDAP DirSync returned no result")
		}
		return result, err
	})
}

// Compare performs an LDAP Compare operation.
func (c *Connection) Compare(ctx context.Context, dn, attribute, value string) (bool, error) {
	return runOperation(c, ctx, OperationCompare, false, nil, func(client ldapClient) (bool, error) {
		return client.Compare(dn, attribute, value)
	})
}

// Add performs an LDAP Add operation. It is never retried automatically.
func (c *Connection) Add(ctx context.Context, request *ldap.AddRequest) error {
	var cloned *ldap.AddRequest
	_, err := runOperation(c, ctx, OperationAdd, true, func() error {
		if request == nil {
			return errors.New("AddRequest must not be nil")
		}
		cloned = cloneAddRequest(request)
		return nil
	}, func(client ldapClient) (struct{}, error) {
		return struct{}{}, client.Add(cloned)
	})
	return err
}

// Modify performs an LDAP Modify operation. It is never retried automatically.
func (c *Connection) Modify(ctx context.Context, request *ldap.ModifyRequest) error {
	var cloned *ldap.ModifyRequest
	_, err := runOperation(c, ctx, OperationModify, true, func() error {
		if request == nil {
			return errors.New("ModifyRequest must not be nil")
		}
		cloned = cloneModifyRequest(request)
		return nil
	}, func(client ldapClient) (struct{}, error) {
		return struct{}{}, client.Modify(cloned)
	})
	return err
}

// Del performs an LDAP Delete operation. It is never retried automatically.
func (c *Connection) Del(ctx context.Context, request *ldap.DelRequest) error {
	var cloned *ldap.DelRequest
	_, err := runOperation(c, ctx, OperationDelete, true, func() error {
		if request == nil {
			return errors.New("DelRequest must not be nil")
		}
		cloned = cloneDelRequest(request)
		return nil
	}, func(client ldapClient) (struct{}, error) {
		return struct{}{}, client.Del(cloned)
	})
	return err
}

// ModifyDN performs an LDAP Modify DN operation. It is never retried automatically.
func (c *Connection) ModifyDN(ctx context.Context, request *ldap.ModifyDNRequest) error {
	var cloned *ldap.ModifyDNRequest
	_, err := runOperation(c, ctx, OperationModifyDN, true, func() error {
		if request == nil {
			return errors.New("ModifyDNRequest must not be nil")
		}
		cloned = cloneModifyDNRequest(request)
		return nil
	}, func(client ldapClient) (struct{}, error) {
		return struct{}{}, client.ModifyDN(cloned)
	})
	return err
}

// PasswordModify performs RFC 3062 Password Modify. It is a write and is never
// retried automatically.
func (c *Connection) PasswordModify(ctx context.Context, request *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	var cloned *ldap.PasswordModifyRequest
	return runOperation(c, ctx, OperationPasswordModify, true, func() error {
		if request == nil {
			return errors.New("PasswordModifyRequest must not be nil")
		}
		copy := *request
		cloned = &copy
		return nil
	}, func(client ldapClient) (*ldap.PasswordModifyResult, error) {
		result, err := client.PasswordModify(cloned)
		if err == nil && result == nil {
			return nil, errors.New("LDAP PasswordModify returned no result")
		}
		return result, err
	})
}

type workerResult[T any] struct {
	value      T
	assessment operationAssessment
}

type operationAssessment struct {
	err    error
	fatal  bool
	reason FailureReason
}

const (
	terminalRunning uint32 = iota
	terminalWorker
	terminalCanceled
)

func runOperation[T any](
	connection *Connection,
	ctx context.Context,
	op Operation,
	write bool,
	preflight func() error,
	call func(ldapClient) (T, error),
) (zero T, returnErr error) {
	if err := connection.enter(op); err != nil {
		return zero, err
	}
	leaveActive := func() {
		connection.state.CompareAndSwap(uint32(leaseBusy), uint32(leaseActive))
	}
	if ctx == nil {
		leaveActive()
		return zero, notSentError(op, configError("context", "must not be nil"))
	}
	if err := ctx.Err(); err != nil {
		leaveActive()
		return zero, &OperationError{Operation: op, Delivery: DeliveryNotSent, Cause: err, kinds: []error{ErrNotSent}}
	}
	if preflight != nil {
		var preflightErr error
		func() {
			defer func() {
				if recover() != nil {
					preflightErr = &PanicError{Source: "LDAP request control"}
				}
			}()
			preflightErr = preflight()
		}()
		if preflightErr != nil {
			leaveActive()
			return zero, &OperationError{
				Operation: op, Delivery: DeliveryNotSent,
				Cause: preflightErr, kinds: []error{ErrNotSent},
			}
		}
	}
	if err := ctx.Err(); err != nil {
		leaveActive()
		return zero, &OperationError{Operation: op, Delivery: DeliveryNotSent, Cause: err, kinds: []error{ErrNotSent}}
	}
	if leaseState(connection.state.Load()) != leaseBusy {
		return zero, notSentError(op, ErrLeaseInvalid)
	}

	opCtx, cancel := context.WithTimeout(ctx, connection.pool.cfg.requestTimeout)
	defer cancel()
	trace := connection.physical.transport.begin()
	if leaseState(connection.state.Load()) != leaseBusy {
		trace.cancel()
		connection.physical.transport.end(trace)
		trace.destroy()
		return zero, notSentError(op, ErrLeaseInvalid)
	}
	resultChannel := make(chan workerResult[T], 1)
	var terminal atomic.Uint32
	go executeLDAPOperation(connection, opCtx, op, write, trace, call, &terminal, resultChannel)

	select {
	case result := <-resultChannel:
		return finishOperation(connection, op, result)
	case <-opCtx.Done():
		if terminal.CompareAndSwap(terminalRunning, terminalCanceled) {
			snapshot := trace.cancel()
			reason := cancellationReason(opCtx.Err())
			connection.physical.markFatal(reason)
			connection.state.CompareAndSwap(uint32(leaseBusy), uint32(leaseInvalid))
			connection.pool.evictBorrowed(connection, reason)
			delivery := DeliveryNotSent
			kinds := []error{ErrNotSent}
			if snapshot.writtenBytes > 0 || snapshot.writeInFlight > 0 {
				delivery = DeliveryDispatched
				kinds = []error{ErrTransport}
				if write {
					kinds = append(kinds, ErrOutcomeUnknown)
					connection.pool.emit(Event{Type: EventWriteOutcomeUnknown, Operation: op, Reason: cancellationReason(opCtx.Err())})
				}
			}
			connection.pool.emit(Event{Type: EventOperationCanceled, Operation: op, Reason: cancellationReason(opCtx.Err())})
			return zero, &OperationError{Operation: op, Delivery: delivery, Cause: opCtx.Err(), kinds: kinds}
		}
		result := <-resultChannel
		return finishOperation(connection, op, result)
	}
}

func executeLDAPOperation[T any](
	connection *Connection,
	ctx context.Context,
	op Operation,
	write bool,
	trace *operationTrace,
	call func(ldapClient) (T, error),
	terminal *atomic.Uint32,
	resultChannel chan<- workerResult[T],
) {
	defer trace.destroy()
	var value T
	var rawErr error
	dependencyPanic := false
	func() {
		defer func() {
			if recover() != nil {
				dependencyPanic = true
				rawErr = &PanicError{Source: "go-ldap operation"}
			}
		}()
		connection.physical.client.SetTimeout(remainingTimeout(ctx, connection.pool.cfg.requestTimeout))
		value, rawErr = call(connection.physical.client)
	}()
	terminal.CompareAndSwap(terminalRunning, terminalWorker)
	snapshot := connection.physical.transport.end(trace)
	assessment := assessOperation(op, write, rawErr, snapshot, dependencyPanic)

	resetPanic := false
	func() {
		defer func() {
			if recover() != nil {
				resetPanic = true
			}
		}()
		connection.physical.client.SetTimeout(connection.pool.cfg.requestTimeout)
	}()
	if resetPanic {
		assessment.fatal = true
		assessment.reason = ReasonDependencyPanic
		if assessment.err != nil {
			assessment.err = errors.Join(assessment.err, &PanicError{Source: "go-ldap timeout reset"})
		}
	}
	resultChannel <- workerResult[T]{value: value, assessment: assessment}
}

func finishOperation[T any](connection *Connection, op Operation, result workerResult[T]) (T, error) {
	if errors.Is(result.assessment.err, ErrOutcomeUnknown) {
		connection.pool.emit(Event{Type: EventWriteOutcomeUnknown, Operation: op, Reason: result.assessment.reason})
	}
	if result.assessment.reason == ReasonDependencyPanic {
		connection.pool.emit(Event{Type: EventDependencyPanic, Operation: op, Stage: StageOperation, Reason: ReasonDependencyPanic})
	}
	if result.assessment.fatal {
		connection.physical.markFatal(result.assessment.reason)
		connection.state.CompareAndSwap(uint32(leaseBusy), uint32(leaseInvalid))
		connection.pool.evictBorrowed(connection, result.assessment.reason)
	} else if connection.physical.retire.Load() {
		connection.state.CompareAndSwap(uint32(leaseBusy), uint32(leaseInvalid))
		connection.pool.evictBorrowed(connection, connection.pool.retirementReason(connection.physical))
	} else {
		connection.state.CompareAndSwap(uint32(leaseBusy), uint32(leaseActive))
	}
	return result.value, result.assessment.err
}

func assessOperation(op Operation, write bool, rawErr error, trace traceSnapshot, dependencyPanic bool) operationAssessment {
	dispatched := trace.writtenBytes > 0 || trace.writeInFlight > 0
	transportFailed := trace.readErr != nil || trace.writeErr != nil
	if dependencyPanic {
		return fatalOperation(op, write, dispatched, rawErr, ErrDependencyPanic, ReasonDependencyPanic)
	}

	var ldapErr *ldap.Error
	networkWithoutPacket := errors.As(rawErr, &ldapErr) && ldapErr.ResultCode == ldap.ErrorNetwork && ldapErr.Packet == nil
	if rawErr == nil && !dispatched {
		return fatalOperation(
			op, write, false, errors.New("LDAP operation returned success without dispatch"), ErrProtocol, ReasonProtocol,
		)
	}
	if !dispatched && trace.writeInFlight == 0 {
		if networkWithoutPacket {
			return fatalOperation(op, write, false, rawErr, ErrTransport, ReasonTransport)
		}
		operationErr := &OperationError{
			Operation: op, Delivery: DeliveryNotSent,
			Cause: errors.New("LDAP request was rejected locally"), kinds: []error{ErrNotSent},
		}
		assessment := operationAssessment{err: operationErr}
		if transportFailed {
			assessment.fatal = true
			assessment.reason = ReasonTransport
			operationErr.kinds = append(operationErr.kinds, ErrTransport)
		}
		return assessment
	}

	inspection := inspectOperationExchange(op, trace)
	defer inspection.destroy()
	if inspection.err != nil {
		return fatalOperation(
			op, write, true, protocolFailure("LDAP response validation failed"), ErrProtocol, ReasonProtocol,
		)
	}
	if !inspection.complete {
		if transportFailed || networkWithoutPacket || inspection.noticeOfDisconnection {
			return fatalOperation(op, write, true, errors.Join(rawErr, trace.writeErr, trace.readErr), ErrTransport, ReasonTransport)
		}
		return fatalOperation(
			op, write, true, protocolFailure("LDAP operation returned without a complete response"), ErrProtocol, ReasonProtocol,
		)
	}
	success, failureCode, hasFailure, resultErr := operationResultStatus(op, inspection.results)
	if resultErr != nil {
		return fatalOperation(op, write, true, protocolFailure("LDAP response used an invalid result code"), ErrProtocol, ReasonProtocol)
	}
	if rawErr == nil {
		if !success || hasFailure {
			return fatalOperation(op, write, true, protocolFailure("LDAP dependency accepted an error result as success"), ErrProtocol, ReasonProtocol)
		}
		if trace.writeInFlight != 0 {
			return fatalOperation(
				op, write, true, errors.New("LDAP operation returned while a transport write was active"), ErrTransport, ReasonTransport,
			)
		}
		if transportFailed || inspection.unsolicited {
			return operationAssessment{fatal: true, reason: ReasonTransport}
		}
		return operationAssessment{}
	}
	if success || !hasFailure {
		return fatalOperation(op, write, true, protocolFailure("LDAP dependency returned an error after a successful result"), ErrProtocol, ReasonProtocol)
	}
	if failureCode < 0 || failureCode > int64(^uint16(0)) {
		return fatalOperation(op, write, true, protocolFailure("LDAP result code exceeds the public result-code range"), ErrProtocol, ReasonProtocol)
	}
	code := uint16(failureCode)
	operationErr := &OperationError{
		Operation: op, Delivery: DeliveryConfirmed, Code: code, HasCode: true,
		Cause: sanitizedLDAPError(code),
	}
	assessment := operationAssessment{err: operationErr}
	if transportFailed {
		assessment.fatal = true
		assessment.reason = ReasonTransport
		operationErr.kinds = []error{ErrTransport}
		operationErr.Cause = errors.Join(operationErr.Cause, trace.writeErr, trace.readErr)
	} else if inspection.unsolicited {
		assessment.fatal = true
		assessment.reason = ReasonTransport
	}
	return assessment
}

func expectedResponseTag(op Operation) uint64 {
	switch op {
	case OperationSearch, OperationSearchWithPaging, OperationDirSync:
		return ldap.ApplicationSearchResultDone
	case OperationCompare:
		return ldap.ApplicationCompareResponse
	case OperationAdd:
		return ldap.ApplicationAddResponse
	case OperationModify:
		return ldap.ApplicationModifyResponse
	case OperationDelete:
		return ldap.ApplicationDelResponse
	case OperationModifyDN:
		return ldap.ApplicationModifyDNResponse
	case OperationPasswordModify:
		return ldap.ApplicationExtendedResponse
	default:
		return ^uint64(0)
	}
}

func fatalOperation(op Operation, write, dispatched bool, cause, kind error, reason FailureReason) operationAssessment {
	delivery := DeliveryNotSent
	kinds := []error{ErrNotSent, kind}
	if dispatched {
		delivery = DeliveryDispatched
		kinds = []error{kind}
		if write {
			kinds = append(kinds, ErrOutcomeUnknown)
		}
	}
	return operationAssessment{
		err:   &OperationError{Operation: op, Delivery: delivery, Cause: cause, kinds: kinds},
		fatal: true, reason: reason,
	}
}

func cancellationReason(err error) FailureReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonRequestTimeout
	}
	return ReasonContextCancellation
}

func cloneSearchRequest(request *ldap.SearchRequest, cloneControls func([]ldap.Control) ([]ldap.Control, error)) (*ldap.SearchRequest, error) {
	if request == nil {
		return nil, errors.New("SearchRequest must not be nil")
	}
	copy := *request
	copy.Attributes = append([]string(nil), request.Attributes...)
	controls, err := cloneControls(request.Controls)
	if err != nil {
		return nil, err
	}
	copy.Controls = controls
	return &copy, nil
}

func cloneControlsShallow(controls []ldap.Control) ([]ldap.Control, error) {
	return append([]ldap.Control(nil), controls...), nil
}

func clonePagingControls(controls []ldap.Control) ([]ldap.Control, error) {
	out := append([]ldap.Control(nil), controls...)
	for i, control := range out {
		if control == nil || control.GetControlType() != ldap.ControlTypePaging {
			continue
		}
		paging, ok := control.(*ldap.ControlPaging)
		if !ok || paging == nil {
			return nil, errors.New("paging control has an unsupported concrete type")
		}
		out[i] = &ldap.ControlPaging{PagingSize: paging.PagingSize, Cookie: append([]byte(nil), paging.Cookie...)}
	}
	return out, nil
}

func cloneDirSyncControls(controls []ldap.Control) ([]ldap.Control, error) {
	out := append([]ldap.Control(nil), controls...)
	for i, control := range out {
		if control == nil || control.GetControlType() != ldap.ControlTypeDirSync {
			continue
		}
		dirSync, ok := control.(*ldap.ControlDirSync)
		if !ok || dirSync == nil {
			return nil, errors.New("DirSync control has an unsupported concrete type")
		}
		out[i] = &ldap.ControlDirSync{
			Criticality: dirSync.Criticality, Flags: dirSync.Flags,
			MaxAttrCount: dirSync.MaxAttrCount, Cookie: append([]byte(nil), dirSync.Cookie...),
		}
	}
	return out, nil
}

func cloneAddRequest(request *ldap.AddRequest) *ldap.AddRequest {
	copy := *request
	copy.Controls = append([]ldap.Control(nil), request.Controls...)
	copy.Attributes = make([]ldap.Attribute, len(request.Attributes))
	for i := range request.Attributes {
		copy.Attributes[i] = request.Attributes[i]
		copy.Attributes[i].Vals = append([]string(nil), request.Attributes[i].Vals...)
	}
	return &copy
}

func cloneModifyRequest(request *ldap.ModifyRequest) *ldap.ModifyRequest {
	copy := *request
	copy.Controls = append([]ldap.Control(nil), request.Controls...)
	copy.Changes = make([]ldap.Change, len(request.Changes))
	for i := range request.Changes {
		copy.Changes[i] = request.Changes[i]
		copy.Changes[i].Modification.Vals = append([]string(nil), request.Changes[i].Modification.Vals...)
	}
	return &copy
}

func cloneDelRequest(request *ldap.DelRequest) *ldap.DelRequest {
	copy := *request
	copy.Controls = append([]ldap.Control(nil), request.Controls...)
	return &copy
}

func cloneModifyDNRequest(request *ldap.ModifyDNRequest) *ldap.ModifyDNRequest {
	copy := *request
	copy.Controls = append([]ldap.Control(nil), request.Controls...)
	return &copy
}
