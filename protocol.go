package ldappool

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const startTLSOID = "1.3.6.1.4.1.1466.20037"

func requestStartTLS(conn net.Conn) error {
	request := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP StartTLS request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Message ID"))
	extended := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "StartTLS request")
	extended.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, startTLSOID, "StartTLS OID"))
	request.AppendChild(extended)
	buffer := request.Bytes()
	for len(buffer) > 0 {
		written, err := conn.Write(buffer)
		if written > 0 {
			buffer = buffer[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	frame, err := readDefiniteBERFrame(conn)
	if err != nil {
		return err
	}
	defer wipe(frame)
	response := inspectLDAPMessage(frame)
	if response.result != nil {
		defer func() {
			wipe(response.result.diagnostic)
			wipe(response.result.responseValue)
		}()
	}
	if response.validationError != nil || response.messageID != 1 || response.applicationTag != ldap.ApplicationExtendedResponse || !response.constructed || response.result == nil {
		return protocolFailure("LDAP StartTLS returned an invalid response")
	}
	if response.result.responseNamePresent || response.result.responseValuePresent {
		return protocolFailure("LDAP StartTLS returned forbidden response data")
	}
	if response.result.code != ldap.LDAPResultSuccess {
		if response.result.code <= int64(^uint16(0)) {
			return sanitizedLDAPError(uint16(response.result.code))
		}
		return protocolFailure("LDAP StartTLS returned an unsupported result code")
	}
	return nil
}

func readDefiniteBERFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 0, 12)
	readByte := func() (byte, error) {
		var buffer [1]byte
		_, err := io.ReadFull(reader, buffer[:])
		return buffer[0], err
	}
	identifier, err := readByte()
	if err != nil {
		return nil, err
	}
	header = append(header, identifier)
	if identifier&byte(ber.TagBitmask) == byte(ber.HighTag) {
		for len(header) <= 11 {
			value, readErr := readByte()
			if readErr != nil {
				return nil, readErr
			}
			header = append(header, value)
			if value&byte(ber.HighTagContinueBitmask) == 0 {
				break
			}
		}
		if header[len(header)-1]&byte(ber.HighTagContinueBitmask) != 0 {
			return nil, errors.New("BER tag is too large")
		}
	}
	firstLength, err := readByte()
	if err != nil {
		return nil, err
	}
	header = append(header, firstLength)
	var length uint64
	if firstLength&byte(ber.LengthLongFormBitmask) == 0 {
		length = uint64(firstLength)
	} else {
		count := int(firstLength & byte(ber.LengthValueBitmask))
		if count == 0 {
			return nil, errors.New("indefinite BER length is not allowed for LDAP")
		}
		if count > 8 {
			return nil, errors.New("BER length is too large")
		}
		lengthBytes := make([]byte, count)
		if _, err = io.ReadFull(reader, lengthBytes); err != nil {
			return nil, err
		}
		header = append(header, lengthBytes...)
		for _, value := range lengthBytes {
			length = length<<8 | uint64(value)
		}
	}
	if length > uint64(math.MaxInt-len(header)) || (ber.MaxPacketLengthBytes > 0 && length > uint64(ber.MaxPacketLengthBytes)) {
		return nil, errors.New("BER frame is too large")
	}
	frame := make([]byte, len(header)+int(length))
	copy(frame, header)
	if _, err = io.ReadFull(reader, frame[len(header):]); err != nil {
		return nil, err
	}
	return frame, nil
}

type strictLDAPResult struct {
	code                 int64
	diagnostic           []byte
	responseNamePresent  bool
	responseValuePresent bool
	responseValue        []byte
}

type ldapMessageObservation struct {
	messageID       int64
	applicationTag  uint64
	constructed     bool
	result          *strictLDAPResult
	validationError error
}

type ldapStreamSnapshot struct {
	messages   []ldapMessageObservation
	incomplete bool
	err        error
}

type ldapMessageStream struct {
	pending  []byte
	messages []ldapMessageObservation
	err      error
}

func (s *ldapMessageStream) feed(buffer []byte) {
	if len(buffer) == 0 || s.err != nil {
		return
	}
	s.pending = append(s.pending, buffer...)
	for len(s.pending) > 0 {
		total, complete, err := berFrameLength(s.pending)
		if err != nil {
			s.err = errors.New("invalid LDAP BER frame")
			wipe(s.pending)
			s.pending = nil
			return
		}
		if !complete || len(s.pending) < total {
			return
		}
		s.messages = append(s.messages, inspectLDAPMessage(s.pending[:total]))
		remaining := len(s.pending) - total
		if remaining == 0 {
			wipe(s.pending)
			s.pending = nil
			return
		}
		oldLength := len(s.pending)
		copy(s.pending, s.pending[total:])
		wipe(s.pending[remaining:oldLength])
		s.pending = s.pending[:remaining]
	}
}

func (s *ldapMessageStream) snapshot() ldapStreamSnapshot {
	return ldapStreamSnapshot{
		messages:   append([]ldapMessageObservation(nil), s.messages...),
		incomplete: len(s.pending) != 0,
		err:        s.err,
	}
}

func (s *ldapMessageStream) destroy() {
	wipe(s.pending)
	for index := range s.messages {
		if result := s.messages[index].result; result != nil {
			wipe(result.diagnostic)
			wipe(result.responseValue)
			result.diagnostic = nil
			result.responseValue = nil
		}
	}
	s.pending = nil
	s.messages = nil
	s.err = nil
}

func berFrameLength(buffer []byte) (total int, complete bool, err error) {
	if len(buffer) == 0 {
		return 0, false, nil
	}
	offset := 1
	if buffer[0]&byte(ber.TagBitmask) == byte(ber.HighTag) {
		for {
			if offset >= len(buffer) {
				return 0, false, nil
			}
			value := buffer[offset]
			offset++
			if offset > 11 {
				return 0, false, errors.New("BER tag is too large")
			}
			if value&byte(ber.HighTagContinueBitmask) == 0 {
				break
			}
		}
	}
	if offset >= len(buffer) {
		return 0, false, nil
	}
	firstLength := buffer[offset]
	offset++
	if firstLength&byte(ber.LengthLongFormBitmask) == 0 {
		length := int(firstLength)
		if length > math.MaxInt-offset {
			return 0, false, errors.New("BER length overflows int")
		}
		return offset + length, true, nil
	}
	count := int(firstLength & byte(ber.LengthValueBitmask))
	if count == 0 {
		return 0, false, errors.New("indefinite BER length is not allowed for LDAP")
	}
	if count > 8 {
		return 0, false, errors.New("BER length is too large")
	}
	if len(buffer)-offset < count {
		return 0, false, nil
	}
	var length uint64
	for _, value := range buffer[offset : offset+count] {
		length = length<<8 | uint64(value)
	}
	offset += count
	if length > uint64(math.MaxInt-offset) {
		return 0, false, errors.New("BER length overflows int")
	}
	return offset + int(length), true, nil
}

func inspectLDAPMessage(buffer []byte) (observation ldapMessageObservation) {
	defer func() {
		if recover() != nil {
			observation.validationError = errors.New("LDAP response inspection panicked")
		}
	}()
	message, consumed, err := parseBERElement(buffer)
	if err != nil || consumed != len(buffer) || message.class != ber.ClassUniversal || message.tagType != ber.TypeConstructed || message.tag != ber.TagSequence {
		observation.validationError = errors.New("LDAPMessage is not a complete universal constructed sequence")
		return observation
	}
	messageID, messageIDLength, err := parseBERElement(message.content)
	if err != nil || messageID.class != ber.ClassUniversal || messageID.tagType != ber.TypePrimitive || messageID.tag != ber.TagInteger {
		observation.validationError = errors.New("LDAPMessage has an invalid message ID field")
		return observation
	}
	observation.messageID, observation.validationError = parseBERInt64(messageID.content)
	if observation.validationError != nil || observation.messageID <= 0 || observation.messageID > math.MaxInt32 {
		observation.validationError = errors.New("LDAPMessage has an invalid message ID value")
		return observation
	}
	protocolOp, protocolLength, err := parseBERElement(message.content[messageIDLength:])
	if err != nil || protocolOp.class != ber.ClassApplication {
		observation.validationError = errors.New("LDAPMessage has an invalid protocol operation")
		return observation
	}
	observation.applicationTag = uint64(protocolOp.tag)
	observation.constructed = protocolOp.tagType == ber.TypeConstructed
	if protocolOp.tagType != ber.TypePrimitive && protocolOp.tagType != ber.TypeConstructed {
		observation.validationError = errors.New("LDAPMessage has an invalid protocol operation encoding")
		return observation
	}

	if isLDAPResultResponse(observation.applicationTag) {
		packet, decodeErr := ber.DecodePacketErr(protocolOp.raw)
		if decodeErr != nil {
			observation.validationError = errors.New("LDAP result BER decoding failed")
		} else {
			var resultErr error
			observation.result, resultErr = inspectLDAPResult(packet)
			observation.validationError = errors.Join(observation.validationError, resultErr)
		}
	}
	remainder := message.content[messageIDLength+protocolLength:]
	if len(remainder) != 0 {
		controls, controlsLength, controlsErr := parseBERElement(remainder)
		if controlsErr != nil || controlsLength != len(remainder) {
			observation.validationError = errors.Join(observation.validationError, errors.New("LDAPMessage has invalid trailing fields"))
			return observation
		}
		packet, decodeErr := ber.DecodePacketErr(controls.raw)
		if decodeErr != nil {
			observation.validationError = errors.Join(observation.validationError, errors.New("LDAP controls BER decoding failed"))
		} else {
			observation.validationError = errors.Join(observation.validationError, validateLDAPControls(packet))
		}
	}
	return observation
}

type berElement struct {
	class   ber.Class
	tagType ber.Type
	tag     ber.Tag
	raw     []byte
	content []byte
}

func parseBERElement(buffer []byte) (berElement, int, error) {
	if len(buffer) < 2 {
		return berElement{}, 0, io.ErrUnexpectedEOF
	}
	first := buffer[0]
	element := berElement{
		class:   ber.Class(first & 0xc0),
		tagType: ber.Type(first & byte(ber.TypeConstructed)),
		tag:     ber.Tag(first & byte(ber.TagBitmask)),
	}
	offset := 1
	if element.tag == ber.HighTag {
		element.tag = 0
		firstTagByte := true
		for {
			if offset >= len(buffer) {
				return berElement{}, 0, io.ErrUnexpectedEOF
			}
			value := buffer[offset]
			offset++
			if firstTagByte && value&byte(ber.HighTagValueBitmask) == 0 {
				return berElement{}, 0, errors.New("BER high tag is not minimally encoded")
			}
			firstTagByte = false
			if element.tag > (ber.Tag(math.MaxUint64) >> 7) {
				return berElement{}, 0, errors.New("BER tag overflows uint64")
			}
			element.tag = element.tag<<7 | ber.Tag(value&byte(ber.HighTagValueBitmask))
			if value&byte(ber.HighTagContinueBitmask) == 0 {
				break
			}
		}
		if element.tag < ber.HighTag {
			return berElement{}, 0, errors.New("BER high tag form was unnecessary")
		}
	}
	if offset >= len(buffer) {
		return berElement{}, 0, io.ErrUnexpectedEOF
	}
	firstLength := buffer[offset]
	offset++
	var length uint64
	if firstLength&byte(ber.LengthLongFormBitmask) == 0 {
		length = uint64(firstLength)
	} else {
		count := int(firstLength & byte(ber.LengthValueBitmask))
		if count == 0 {
			return berElement{}, 0, errors.New("indefinite BER length is not allowed for LDAP")
		}
		if count > 8 || len(buffer)-offset < count {
			return berElement{}, 0, io.ErrUnexpectedEOF
		}
		if buffer[offset] == 0 {
			return berElement{}, 0, errors.New("BER length is not minimally encoded")
		}
		for _, value := range buffer[offset : offset+count] {
			length = length<<8 | uint64(value)
		}
		offset += count
		if length < 128 {
			return berElement{}, 0, errors.New("BER long length form was unnecessary")
		}
	}
	if length > uint64(math.MaxInt-offset) || int(length) > len(buffer)-offset {
		return berElement{}, 0, io.ErrUnexpectedEOF
	}
	total := offset + int(length)
	element.raw = buffer[:total]
	element.content = buffer[offset:total]
	return element, total, nil
}

func isLDAPResultResponse(tag uint64) bool {
	switch tag {
	case ldap.ApplicationBindResponse,
		ldap.ApplicationSearchResultDone,
		ldap.ApplicationModifyResponse,
		ldap.ApplicationAddResponse,
		ldap.ApplicationDelResponse,
		ldap.ApplicationModifyDNResponse,
		ldap.ApplicationCompareResponse,
		ldap.ApplicationExtendedResponse:
		return true
	default:
		return false
	}
}

func inspectLDAPResult(response *ber.Packet) (*strictLDAPResult, error) {
	if response == nil || response.ClassType != ber.ClassApplication || response.TagType != ber.TypeConstructed {
		return nil, errors.New("LDAP result response has an invalid identifier")
	}
	if len(response.Children) < 3 {
		return nil, errors.New("LDAP result is missing required fields")
	}
	codePacket := response.Children[0]
	if !packetHasIdentifier(codePacket, ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated) {
		return nil, errors.New("LDAP resultCode is not an ENUMERATED value")
	}
	code, err := parseBERInt64(codePacket.Data.Bytes())
	if err != nil || code < 0 {
		return nil, errors.New("LDAP resultCode is invalid")
	}
	result := &strictLDAPResult{code: code}
	matchedDN := response.Children[1]
	diagnostic := response.Children[2]
	if err = validateLDAPString(matchedDN); err != nil {
		return result, errors.New("LDAP matchedDN is invalid")
	}
	if err = validateLDAPString(diagnostic); err != nil {
		return result, errors.New("LDAP diagnosticMessage is invalid")
	}
	result.diagnostic = append([]byte(nil), diagnostic.Data.Bytes()...)
	index := 3
	referralPresent := false
	if index < len(response.Children) && packetHasIdentifier(response.Children[index], ber.ClassContext, ber.TypeConstructed, 3) {
		if err = validateLDAPReferral(response.Children[index]); err != nil {
			return result, err
		}
		referralPresent = true
		index++
	}
	if (code == ldap.LDAPResultReferral) != referralPresent {
		return result, errors.New("LDAP referral field does not match resultCode")
	}

	switch uint64(response.Tag) {
	case ldap.ApplicationBindResponse:
		if index < len(response.Children) {
			if index+1 != len(response.Children) || !packetHasIdentifier(response.Children[index], ber.ClassContext, ber.TypePrimitive, 7) {
				return result, errors.New("BindResponse has invalid trailing fields")
			}
		}
	case ldap.ApplicationExtendedResponse:
		if index < len(response.Children) && packetHasIdentifier(response.Children[index], ber.ClassContext, ber.TypePrimitive, 10) {
			if !utf8.Valid(response.Children[index].Data.Bytes()) {
				return result, errors.New("ExtendedResponse responseName is invalid")
			}
			result.responseNamePresent = true
			index++
		}
		if index < len(response.Children) && packetHasIdentifier(response.Children[index], ber.ClassContext, ber.TypePrimitive, 11) {
			result.responseValuePresent = true
			result.responseValue = append([]byte(nil), response.Children[index].Data.Bytes()...)
			index++
		}
		if index != len(response.Children) {
			return result, errors.New("ExtendedResponse has invalid trailing fields")
		}
	default:
		if index != len(response.Children) {
			return result, errors.New("LDAP result response has invalid trailing fields")
		}
	}
	return result, nil
}

func validateLDAPReferral(packet *ber.Packet) error {
	if packet == nil || len(packet.Children) == 0 {
		return errors.New("LDAP referral is empty")
	}
	for _, uri := range packet.Children {
		if err := validateLDAPString(uri); err != nil {
			return errors.New("LDAP referral contains an invalid URI")
		}
	}
	return nil
}

func validateLDAPControls(packet *ber.Packet) error {
	if !packetHasIdentifier(packet, ber.ClassContext, ber.TypeConstructed, 0) {
		return errors.New("LDAP controls field has an invalid identifier")
	}
	for _, control := range packet.Children {
		if !packetHasIdentifier(control, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) || len(control.Children) < 1 || len(control.Children) > 3 {
			return errors.New("LDAP response control has an invalid structure")
		}
		if err := validateLDAPString(control.Children[0]); err != nil {
			return errors.New("LDAP response control has an invalid controlType")
		}
		switch len(control.Children) {
		case 2:
			second := control.Children[1]
			if packetHasIdentifier(second, ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean) {
				if len(second.Data.Bytes()) != 1 {
					return errors.New("LDAP response control has an invalid criticality")
				}
			} else if !packetHasIdentifier(second, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) {
				return errors.New("LDAP response control has an invalid value")
			}
		case 3:
			criticality := control.Children[1]
			if !packetHasIdentifier(criticality, ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean) || len(criticality.Data.Bytes()) != 1 {
				return errors.New("LDAP response control has an invalid criticality")
			}
			if !packetHasIdentifier(control.Children[2], ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) {
				return errors.New("LDAP response control has an invalid value")
			}
		}
	}
	return nil
}

func validateLDAPString(packet *ber.Packet) error {
	if !packetHasIdentifier(packet, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) || !utf8.Valid(packet.Data.Bytes()) {
		return errors.New("invalid LDAPString")
	}
	return nil
}

func packetHasIdentifier(packet *ber.Packet, class ber.Class, tagType ber.Type, tag ber.Tag) bool {
	return packet != nil && packet.ClassType == class && packet.TagType == tagType && packet.Tag == tag
}

func parseBERInt64(buffer []byte) (int64, error) {
	if len(buffer) == 0 || len(buffer) > 8 {
		return 0, errors.New("BER integer is outside int64 range")
	}
	if len(buffer) > 1 && ((buffer[0] == 0x00 && buffer[1]&0x80 == 0) || (buffer[0] == 0xff && buffer[1]&0x80 != 0)) {
		return 0, errors.New("BER integer is not minimally encoded")
	}
	var value uint64
	for _, current := range buffer {
		value = value<<8 | uint64(current)
	}
	if buffer[0]&0x80 != 0 && len(buffer) < 8 {
		value |= ^uint64(0) << (uint(len(buffer)) * 8)
	}
	return int64(value), nil
}

type ldapExchangeInspection struct {
	results  []*strictLDAPResult
	observed []*strictLDAPResult
	complete bool
	err      error
}

func (i *ldapExchangeInspection) destroy() {
	for _, result := range i.observed {
		wipe(result.diagnostic)
		wipe(result.responseValue)
		result.diagnostic = nil
		result.responseValue = nil
	}
}

func inspectBindExchange(trace traceSnapshot) ldapExchangeInspection {
	return inspectLDAPExchange(trace, ldap.ApplicationBindRequest, ldap.ApplicationBindResponse, false)
}

func inspectOperationExchange(op Operation, trace traceSnapshot) ldapExchangeInspection {
	inspection := inspectLDAPExchange(trace, expectedRequestTag(op), expectedResponseTag(op), isSearchOperation(op))
	if inspection.err == nil && op == OperationPasswordModify {
		for _, result := range inspection.results {
			if result.responseNamePresent {
				inspection.err = errors.New("Password Modify responseName must be absent")
				break
			}
			if result.responseValuePresent {
				if err := validatePasswordModifyValue(result.responseValue); err != nil {
					inspection.err = err
					break
				}
			}
		}
	}
	return inspection
}

func inspectLDAPExchange(trace traceSnapshot, requestTag, responseTag uint64, search bool) ldapExchangeInspection {
	inspection := ldapExchangeInspection{}
	for _, response := range trace.responses.messages {
		if response.result != nil {
			inspection.observed = append(inspection.observed, response.result)
		}
	}
	if trace.requests.err != nil || trace.responses.err != nil || trace.requests.incomplete || trace.responses.incomplete {
		inspection.err = errors.New("LDAP exchange contains an invalid or incomplete BER frame")
	}
	type requestState struct {
		terminal bool
	}
	requests := make(map[int64]*requestState, len(trace.requests.messages))
	for _, request := range trace.requests.messages {
		inspection.err = errors.Join(inspection.err, request.validationError)
		if request.applicationTag != requestTag || request.constructed != requestTagIsConstructed(requestTag) {
			inspection.err = errors.Join(inspection.err, errors.New("LDAP request shape did not match the public operation"))
		}
		if _, exists := requests[request.messageID]; exists {
			inspection.err = errors.Join(inspection.err, errors.New("LDAP exchange reused an outstanding message ID"))
			continue
		}
		requests[request.messageID] = &requestState{}
	}
	if len(requests) == 0 {
		return inspection
	}
	if !search && len(requests) != 1 {
		inspection.err = errors.Join(inspection.err, errors.New("LDAP operation dispatched an unexpected number of requests"))
	}
	for _, response := range trace.responses.messages {
		inspection.err = errors.Join(inspection.err, response.validationError)
		state := requests[response.messageID]
		if state == nil {
			inspection.err = errors.Join(inspection.err, errors.New("LDAP response message ID did not match a request"))
			continue
		}
		if state.terminal {
			inspection.err = errors.Join(inspection.err, errors.New("LDAP response followed a terminal result"))
			continue
		}
		if search && (response.applicationTag == ldap.ApplicationSearchResultEntry || response.applicationTag == ldap.ApplicationSearchResultReference) {
			continue
		}
		if response.applicationTag != responseTag || !response.constructed {
			inspection.err = errors.Join(inspection.err, errors.New("LDAP response tag did not match the request"))
			continue
		}
		state.terminal = true
		if response.result == nil {
			inspection.err = errors.Join(inspection.err, errors.New("LDAP response did not contain a complete LDAPResult"))
			continue
		}
		inspection.results = append(inspection.results, response.result)
	}
	inspection.complete = true
	for _, state := range requests {
		if !state.terminal {
			inspection.complete = false
			break
		}
	}
	return inspection
}

func requestTagIsConstructed(tag uint64) bool {
	return tag != ldap.ApplicationDelRequest
}

func expectedRequestTag(op Operation) uint64 {
	switch op {
	case OperationSearch, OperationSearchWithPaging, OperationDirSync:
		return ldap.ApplicationSearchRequest
	case OperationCompare:
		return ldap.ApplicationCompareRequest
	case OperationAdd:
		return ldap.ApplicationAddRequest
	case OperationModify:
		return ldap.ApplicationModifyRequest
	case OperationDelete:
		return ldap.ApplicationDelRequest
	case OperationModifyDN:
		return ldap.ApplicationModifyDNRequest
	case OperationPasswordModify:
		return ldap.ApplicationExtendedRequest
	default:
		return ^uint64(0)
	}
}

func isSearchOperation(op Operation) bool {
	return op == OperationSearch || op == OperationSearchWithPaging || op == OperationDirSync
}

func validatePasswordModifyValue(buffer []byte) error {
	total, complete, frameErr := berFrameLength(buffer)
	if frameErr != nil || !complete || total != len(buffer) {
		return errors.New("Password Modify responseValue is invalid")
	}
	packet, err := ber.DecodePacketErr(buffer)
	if err != nil || !packetHasIdentifier(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) || len(packet.Children) > 1 {
		return errors.New("Password Modify responseValue is invalid")
	}
	if len(packet.Children) == 1 && !packetHasIdentifier(packet.Children[0], ber.ClassContext, ber.TypePrimitive, 0) {
		return errors.New("Password Modify generatedPassword is invalid")
	}
	return nil
}

func operationResultStatus(op Operation, results []*strictLDAPResult) (success bool, failureCode int64, hasFailure bool, err error) {
	if len(results) == 0 {
		return false, 0, false, errors.New("LDAP operation did not receive a result")
	}
	if op == OperationCompare {
		if len(results) != 1 {
			return false, 0, false, errors.New("LDAP Compare received an unexpected number of results")
		}
		switch results[0].code {
		case ldap.LDAPResultCompareTrue, ldap.LDAPResultCompareFalse:
			return true, 0, false, nil
		case ldap.LDAPResultSuccess:
			return false, 0, false, errors.New("LDAP Compare returned the forbidden success result code")
		default:
			return false, results[0].code, true, nil
		}
	}
	for index, result := range results {
		if result.code == ldap.LDAPResultSuccess {
			if hasFailure {
				return false, 0, false, errors.New("LDAP operation continued after an error result")
			}
			continue
		}
		if hasFailure || index != len(results)-1 {
			return false, 0, false, errors.New("LDAP operation returned an invalid result sequence")
		}
		failureCode = result.code
		hasFailure = true
	}
	return !hasFailure, failureCode, hasFailure, nil
}

func protocolFailure(message string) error {
	return fmt.Errorf("%s: %w", message, ErrProtocol)
}
