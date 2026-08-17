package ldappool

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestReadDefiniteBERFrameBoundaries(t *testing.T) {
	largeLength := append([]byte{0x04, 0x84}, []byte{0x80, 0x00, 0x00, 0x00}...)
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{name: "empty", wantErr: true},
		{name: "truncated high tag", input: []byte{0x1f}, wantErr: true},
		{name: "oversized high tag", input: append([]byte{0x1f}, bytes.Repeat([]byte{0x80}, 11)...), wantErr: true},
		{name: "missing length", input: []byte{0x04}, wantErr: true},
		{name: "indefinite length", input: []byte{0x04, 0x80}, wantErr: true},
		{name: "oversized length field", input: []byte{0x04, 0x89}, wantErr: true},
		{name: "truncated length field", input: []byte{0x04, 0x82, 0x01}, wantErr: true},
		{name: "declared frame too large", input: largeLength, wantErr: true},
		{name: "truncated content", input: []byte{0x04, 0x02, 0x01}, wantErr: true},
		{name: "short form", input: []byte{0x04, 0x01, 0x7f}, want: []byte{0x04, 0x01, 0x7f}},
		{name: "high tag", input: []byte{0x1f, 0x20, 0x00}, want: []byte{0x1f, 0x20, 0x00}},
		{name: "long form", input: append([]byte{0x04, 0x81, 0x01}, 0x7f), want: []byte{0x04, 0x81, 0x01, 0x7f}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := readDefiniteBERFrame(bytes.NewReader(test.input))
			if (err != nil) != test.wantErr {
				t.Fatalf("readDefiniteBERFrame error = %v, wantErr %v", err, test.wantErr)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("readDefiniteBERFrame = %x, want %x", got, test.want)
			}
		})
	}
}

func TestBERFrameLengthBoundaries(t *testing.T) {
	overflowLength := append([]byte{0x04, 0x88}, bytes.Repeat([]byte{0xff}, 8)...)
	tests := []struct {
		name         string
		input        []byte
		wantTotal    int
		wantComplete bool
		wantErr      bool
	}{
		{name: "empty"},
		{name: "truncated high tag", input: []byte{0x1f}},
		{name: "oversized high tag", input: append([]byte{0x1f}, bytes.Repeat([]byte{0x80}, 11)...), wantErr: true},
		{name: "missing length", input: []byte{0x1f, 0x20}},
		{name: "short form", input: []byte{0x04, 0x02}, wantTotal: 4, wantComplete: true},
		{name: "indefinite length", input: []byte{0x04, 0x80}, wantErr: true},
		{name: "oversized length field", input: []byte{0x04, 0x89}, wantErr: true},
		{name: "truncated length field", input: []byte{0x04, 0x82, 0x01}},
		{name: "overflow", input: overflowLength, wantErr: true},
		{name: "long form", input: []byte{0x04, 0x82, 0x01, 0x00}, wantTotal: 260, wantComplete: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			total, complete, err := berFrameLength(test.input)
			if (err != nil) != test.wantErr || total != test.wantTotal || complete != test.wantComplete {
				t.Fatalf("berFrameLength = (%d, %v, %v), want (%d, %v, err=%v)", total, complete, err, test.wantTotal, test.wantComplete, test.wantErr)
			}
		})
	}
}

func TestParseBERElementBoundaries(t *testing.T) {
	validLong := append([]byte{0x04, 0x81, 0x80}, make([]byte, 128)...)
	overflowTag := append([]byte{0x1f}, bytes.Repeat([]byte{0xff}, 10)...)
	overflowTag = append(overflowTag, 0x7f, 0x00)
	tests := []struct {
		name      string
		input     []byte
		wantTag   ber.Tag
		wantTotal int
		wantErr   bool
	}{
		{name: "truncated identifier", input: []byte{0x04}, wantErr: true},
		{name: "primitive", input: []byte{0x04, 0x01, 0x7f}, wantTag: ber.TagOctetString, wantTotal: 3},
		{name: "truncated high tag", input: []byte{0x1f, 0x81}, wantErr: true},
		{name: "nonminimal high tag", input: []byte{0x1f, 0x00, 0x00}, wantErr: true},
		{name: "unnecessary high tag", input: []byte{0x1f, 0x1e, 0x00}, wantErr: true},
		{name: "overflowing high tag", input: overflowTag, wantErr: true},
		{name: "valid high tag", input: []byte{0x1f, 0x20, 0x00}, wantTag: 32, wantTotal: 3},
		{name: "missing high-tag length", input: []byte{0x1f, 0x20}, wantErr: true},
		{name: "indefinite length", input: []byte{0x04, 0x80}, wantErr: true},
		{name: "oversized length field", input: []byte{0x04, 0x89}, wantErr: true},
		{name: "truncated length field", input: []byte{0x04, 0x82, 0x01}, wantErr: true},
		{name: "nonminimal length", input: []byte{0x04, 0x82, 0x00, 0x80}, wantErr: true},
		{name: "unnecessary long form", input: []byte{0x04, 0x81, 0x7f}, wantErr: true},
		{name: "truncated content", input: []byte{0x04, 0x02, 0x01}, wantErr: true},
		{name: "valid long form", input: validLong, wantTag: ber.TagOctetString, wantTotal: len(validLong)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			element, total, err := parseBERElement(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseBERElement error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && (element.tag != test.wantTag || total != test.wantTotal || len(element.raw) != total) {
				t.Fatalf("parseBERElement = (tag=%d, total=%d, raw=%d), want (tag=%d, total=%d)", element.tag, total, len(element.raw), test.wantTag, test.wantTotal)
			}
		})
	}
}

func TestLDAPMessageStreamFragmentationAndCleanup(t *testing.T) {
	message := protocolLDAPResultWire(1, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess)
	var stream ldapMessageStream
	stream.feed(nil)
	stream.feed(message[:3])
	if snapshot := stream.snapshot(); !snapshot.incomplete || len(snapshot.messages) != 0 {
		t.Fatalf("fragment snapshot = %+v", snapshot)
	}
	stream.feed(append(append([]byte(nil), message[3:]...), message...))
	if snapshot := stream.snapshot(); snapshot.incomplete || snapshot.err != nil || len(snapshot.messages) != 2 {
		t.Fatalf("complete snapshot = %+v", snapshot)
	}
	stream.destroy()
	if stream.pending != nil || stream.messages != nil || stream.err != nil {
		t.Fatalf("destroy retained stream state: %+v", stream)
	}

	stream.feed([]byte{0x30, 0x80})
	if stream.err == nil || stream.pending != nil {
		t.Fatalf("invalid frame state = %+v", stream)
	}
	stream.feed(message)
	if len(stream.messages) != 0 {
		t.Fatal("stream accepted input after a framing error")
	}
}

func TestInspectLDAPMessageStrictEnvelope(t *testing.T) {
	validResult := protocolLDAPResultWire(1, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess)
	validControl := berTLV(0xa0, berTLV(0x30, berOctet([]byte("1.2.3"))))
	resultBody := validResult[2:]
	withControl := berTLV(0x30, append(append([]byte(nil), resultBody...), validControl...))
	malformedResult := berTLV(0x30, append(berInteger(0x02, 1), berTLV(0x65, []byte{0x0a, 0x02, 0x00})...))
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{name: "valid result", input: validResult},
		{name: "valid controls", input: withControl},
		{name: "not sequence", input: berOctet(nil), wantErr: true},
		{name: "missing message ID", input: berTLV(0x30, nil), wantErr: true},
		{name: "wrong message ID tag", input: berTLV(0x30, append(berOctet(nil), berTLV(0x65, nil)...)), wantErr: true},
		{name: "zero message ID", input: berTLV(0x30, append(berInteger(0x02, 0), berTLV(0x65, nil)...)), wantErr: true},
		{name: "missing protocol operation", input: berTLV(0x30, berInteger(0x02, 1)), wantErr: true},
		{name: "wrong protocol class", input: berTLV(0x30, append(berInteger(0x02, 1), berOctet(nil)...)), wantErr: true},
		{name: "malformed LDAPResult", input: malformedResult, wantErr: true},
		{name: "multiple trailing fields", input: berTLV(0x30, append(append(append([]byte(nil), resultBody...), validControl...), validControl...)), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := inspectLDAPMessage(test.input)
			if (observation.validationError != nil) != test.wantErr {
				t.Fatalf("inspectLDAPMessage error = %v, wantErr %v", observation.validationError, test.wantErr)
			}
			if observation.result != nil {
				wipe(observation.result.diagnostic)
				wipe(observation.result.responseName)
				wipe(observation.result.responseValue)
			}
		})
	}
}

func TestInspectLDAPResultOptionalFields(t *testing.T) {
	tests := []struct {
		name    string
		build   func() *ber.Packet
		wantErr bool
		check   func(*testing.T, *strictLDAPResult)
	}{
		{name: "nil", build: func() *ber.Packet { return nil }, wantErr: true},
		{name: "wrong identifier", build: func() *ber.Packet {
			return ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "wrong")
		}, wantErr: true},
		{name: "missing fields", build: func() *ber.Packet {
			return ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationAddResponse, nil, "result")
		}, wantErr: true},
		{name: "wrong result code tag", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, 0)
			packet.Children[0] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "wrong")
			return packet
		}, wantErr: true},
		{name: "negative result code", build: func() *ber.Packet { return protocolResultPacket(ldap.ApplicationAddResponse, -1) }, wantErr: true},
		{name: "invalid matched DN", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, 0)
			packet.Children[1] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "wrong")
			return packet
		}, wantErr: true},
		{name: "invalid diagnostic", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, 0)
			packet.Children[2] = ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string([]byte{0xff}), "invalid")
			return packet
		}, wantErr: true},
		{name: "missing referral", build: func() *ber.Packet { return protocolResultPacket(ldap.ApplicationAddResponse, ldap.LDAPResultReferral) }, wantErr: true},
		{name: "unexpected referral", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, 0)
			packet.AppendChild(protocolReferral("ldap://example.test"))
			return packet
		}, wantErr: true},
		{name: "empty referral", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, ldap.LDAPResultReferral)
			packet.AppendChild(ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral"))
			return packet
		}, wantErr: true},
		{name: "invalid referral URI field", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, ldap.LDAPResultReferral)
			referral := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral")
			referral.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "wrong"))
			packet.AppendChild(referral)
			return packet
		}, wantErr: true},
		{name: "valid referral", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, ldap.LDAPResultReferral)
			packet.AppendChild(protocolReferral("ldap://example.test"))
			return packet
		}},
		{name: "valid Bind credentials", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationBindResponse, 0)
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "credentials", "server credentials"))
			return packet
		}},
		{name: "invalid Bind trailing field", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationBindResponse, 0)
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 8, "wrong", "wrong"))
			return packet
		}, wantErr: true},
		{name: "invalid Extended response name", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationExtendedResponse, 0)
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, string([]byte{0xff}), "response name"))
			return packet
		}, wantErr: true},
		{name: "valid Extended response fields", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationExtendedResponse, 0)
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, "1.2.3", "response name"))
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, "value", "response value"))
			return packet
		}, check: func(t *testing.T, result *strictLDAPResult) {
			if !result.responseNamePresent || !result.responseValuePresent || string(result.responseValue) != "value" {
				t.Fatalf("extended result = %+v", result)
			}
		}},
		{name: "invalid Extended trailing field", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationExtendedResponse, 0)
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 12, "wrong", "wrong"))
			return packet
		}, wantErr: true},
		{name: "invalid ordinary trailing field", build: func() *ber.Packet {
			packet := protocolResultPacket(ldap.ApplicationAddResponse, 0)
			packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "wrong", "wrong"))
			return packet
		}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := inspectLDAPResult(test.build())
			if (err != nil) != test.wantErr {
				t.Fatalf("inspectLDAPResult error = %v, wantErr %v", err, test.wantErr)
			}
			if result != nil {
				defer wipe(result.diagnostic)
				defer wipe(result.responseValue)
			}
			if test.check != nil {
				test.check(t, result)
			}
		})
	}
}

func TestValidateLDAPControlsShapes(t *testing.T) {
	ldapString := func(value string) *ber.Packet {
		return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "LDAPString")
	}
	control := func(children ...*ber.Packet) *ber.Packet {
		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
		for _, child := range children {
			packet.AppendChild(child)
		}
		return packet
	}
	controls := func(children ...*ber.Packet) *ber.Packet {
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
		for _, child := range children {
			packet.AppendChild(child)
		}
		return packet
	}
	validBoolean := ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality")
	invalidBooleanLength := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, "xx", "criticality")
	value := ldapString("value")
	tests := []struct {
		name    string
		packet  *ber.Packet
		wantErr bool
	}{
		{name: "nil", wantErr: true},
		{name: "empty", packet: controls(), wantErr: true},
		{name: "invalid control wrapper", packet: controls(ldapString("1.2.3")), wantErr: true},
		{name: "empty control", packet: controls(control()), wantErr: true},
		{name: "invalid control type", packet: controls(control(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "wrong"))), wantErr: true},
		{name: "valid type only", packet: controls(control(ldapString("1.2.3")))},
		{name: "valid value", packet: controls(control(ldapString("1.2.3"), value))},
		{name: "valid criticality", packet: controls(control(ldapString("1.2.3"), validBoolean))},
		{name: "invalid two-field criticality", packet: controls(control(ldapString("1.2.3"), invalidBooleanLength)), wantErr: true},
		{name: "invalid second field", packet: controls(control(ldapString("1.2.3"), ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "wrong"))), wantErr: true},
		{name: "valid complete control", packet: controls(control(ldapString("1.2.3"), validBoolean, value))},
		{name: "invalid complete criticality", packet: controls(control(ldapString("1.2.3"), value, value)), wantErr: true},
		{name: "invalid complete value", packet: controls(control(ldapString("1.2.3"), validBoolean, validBoolean)), wantErr: true},
		{name: "too many fields", packet: controls(control(ldapString("1.2.3"), validBoolean, value, value)), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateLDAPControls(test.packet); (err != nil) != test.wantErr {
				t.Fatalf("validateLDAPControls error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestPasswordModifyResponseValueShapes(t *testing.T) {
	empty := berTLV(0x30, nil)
	generated := berTLV(0x30, berTLV(0x80, []byte("generated")))
	tests := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{name: "empty sequence", value: empty},
		{name: "generated password", value: generated},
		{name: "incomplete", value: []byte{0x30}, wantErr: true},
		{name: "indefinite", value: []byte{0x30, 0x80}, wantErr: true},
		{name: "trailing bytes", value: append(append([]byte(nil), empty...), 0x00), wantErr: true},
		{name: "not sequence", value: berOctet(nil), wantErr: true},
		{name: "wrong child", value: berTLV(0x30, berTLV(0x81, []byte("wrong"))), wantErr: true},
		{name: "multiple children", value: berTLV(0x30, append(berTLV(0x80, nil), berTLV(0x80, nil)...)), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePasswordModifyValue(test.value); (err != nil) != test.wantErr {
				t.Fatalf("validatePasswordModifyValue error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestStartTLSResponseOptionalFields(t *testing.T) {
	tests := []struct {
		name     string
		optional [][]byte
		wantErr  bool
	}{
		{name: "response name absent"},
		{name: "matching response name", optional: [][]byte{berTLV(0x8a, []byte(startTLSOID))}},
		{name: "wrong response name", optional: [][]byte{berTLV(0x8a, []byte("1.2.3"))}, wantErr: true},
		{name: "response value", optional: [][]byte{berTLV(0x8b, []byte("value"))}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				defer server.Close()
				request, err := readLDAPRequest(bufio.NewReader(server))
				if err != nil {
					return
				}
				elements := [][]byte{berInteger(0x0a, ldap.LDAPResultSuccess), berOctet(nil), berOctet(nil)}
				elements = append(elements, test.optional...)
				_ = writeLDAPResultElements(server, request.messageID, ldap.ApplicationExtendedResponse, elements...)
			}()
			err := requestStartTLS(client)
			_ = client.Close()
			<-serverDone
			if (err != nil) != test.wantErr {
				t.Fatalf("requestStartTLS error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr && !errors.Is(err, ErrProtocol) {
				t.Fatalf("requestStartTLS error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestPasswordModifyExchangeSpecificValidation(t *testing.T) {
	request := ldapMessageObservation{messageID: 1, applicationTag: ldap.ApplicationExtendedRequest, constructed: true}
	validValue := berTLV(0x30, berTLV(0x80, []byte("generated")))
	tests := []struct {
		name    string
		result  *strictLDAPResult
		wantErr bool
	}{
		{name: "no optional fields", result: &strictLDAPResult{}},
		{name: "valid response value", result: &strictLDAPResult{responseValuePresent: true, responseValue: validValue}},
		{name: "forbidden response name", result: &strictLDAPResult{responseNamePresent: true}, wantErr: true},
		{name: "invalid response value", result: &strictLDAPResult{responseValuePresent: true, responseValue: []byte{0x30}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := ldapMessageObservation{
				messageID: 1, applicationTag: ldap.ApplicationExtendedResponse, constructed: true, result: test.result,
			}
			inspection := inspectOperationExchange(OperationPasswordModify, traceSnapshot{
				requests:  ldapStreamSnapshot{messages: []ldapMessageObservation{request}},
				responses: ldapStreamSnapshot{messages: []ldapMessageObservation{response}},
			})
			defer inspection.destroy()
			if (inspection.err != nil) != test.wantErr || !inspection.complete {
				t.Fatalf("Password Modify inspection = %+v, wantErr %v", inspection, test.wantErr)
			}
		})
	}
}

func TestOperationResultStatusSequences(t *testing.T) {
	result := func(code int64) *strictLDAPResult { return &strictLDAPResult{code: code} }
	tests := []struct {
		name            string
		op              Operation
		results         []*strictLDAPResult
		wantSuccess     bool
		wantFailure     bool
		wantFailureCode int64
		wantErr         bool
	}{
		{name: "empty", op: OperationSearch, wantErr: true},
		{name: "Compare multiple", op: OperationCompare, results: []*strictLDAPResult{result(5), result(6)}, wantErr: true},
		{name: "Compare true", op: OperationCompare, results: []*strictLDAPResult{result(ldap.LDAPResultCompareTrue)}, wantSuccess: true},
		{name: "Compare false", op: OperationCompare, results: []*strictLDAPResult{result(ldap.LDAPResultCompareFalse)}, wantSuccess: true},
		{name: "Compare forbidden success", op: OperationCompare, results: []*strictLDAPResult{result(ldap.LDAPResultSuccess)}, wantErr: true},
		{name: "Compare failure", op: OperationCompare, results: []*strictLDAPResult{result(ldap.LDAPResultNoSuchObject)}, wantFailure: true, wantFailureCode: ldap.LDAPResultNoSuchObject},
		{name: "single success", op: OperationAdd, results: []*strictLDAPResult{result(ldap.LDAPResultSuccess)}, wantSuccess: true},
		{name: "paged success", op: OperationSearchWithPaging, results: []*strictLDAPResult{result(0), result(0)}, wantSuccess: true},
		{name: "final failure", op: OperationSearchWithPaging, results: []*strictLDAPResult{result(0), result(ldap.LDAPResultBusy)}, wantFailure: true, wantFailureCode: ldap.LDAPResultBusy},
		{name: "early failure", op: OperationSearchWithPaging, results: []*strictLDAPResult{result(ldap.LDAPResultBusy), result(0)}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			success, failureCode, hasFailure, err := operationResultStatus(test.op, test.results)
			if (err != nil) != test.wantErr || success != test.wantSuccess || hasFailure != test.wantFailure || failureCode != test.wantFailureCode {
				t.Fatalf("operationResultStatus = (%v, %d, %v, %v)", success, failureCode, hasFailure, err)
			}
		})
	}
}

func TestNoticeOfDisconnectionPreservesConfirmedWrite(t *testing.T) {
	request := ldapMessageObservation{messageID: 1, applicationTag: ldap.ApplicationAddRequest, constructed: true}
	success := ldapMessageObservation{
		messageID: 1, applicationTag: ldap.ApplicationAddResponse, constructed: true,
		result: &strictLDAPResult{code: ldap.LDAPResultSuccess},
	}
	notice := ldapMessageObservation{
		messageID: 0, applicationTag: ldap.ApplicationExtendedResponse, constructed: true,
		result: &strictLDAPResult{
			code: ldap.LDAPResultUnavailable, responseNamePresent: true,
			responseName: []byte(noticeOfDisconnectionOID),
		},
	}
	trace := traceSnapshot{
		writtenBytes: 1,
		requests:     ldapStreamSnapshot{messages: []ldapMessageObservation{request}},
		responses:    ldapStreamSnapshot{messages: []ldapMessageObservation{success, notice}},
	}
	assessment := assessOperation(OperationAdd, true, nil, trace, false)
	if assessment.err != nil || !assessment.fatal || assessment.reason != ReasonTransport {
		t.Fatalf("confirmed write assessment = %+v", assessment)
	}

	trace.responses.messages = []ldapMessageObservation{{
		messageID: 0, applicationTag: ldap.ApplicationExtendedResponse, constructed: true,
		result: &strictLDAPResult{
			code: ldap.LDAPResultUnavailable, responseNamePresent: true,
			responseName: []byte(noticeOfDisconnectionOID),
		},
	}}
	assessment = assessOperation(OperationAdd, true, nil, trace, false)
	if !errors.Is(assessment.err, ErrTransport) || !errors.Is(assessment.err, ErrOutcomeUnknown) ||
		!assessment.fatal || assessment.reason != ReasonTransport {
		t.Fatalf("unconfirmed write assessment = %+v", assessment)
	}
}

func protocolLDAPResultWire(messageID int64, applicationTag byte, code int64) []byte {
	result := append(berInteger(0x0a, code), berOctet(nil)...)
	result = append(result, berOctet(nil)...)
	response := berTLV(0x60|applicationTag, result)
	return berTLV(0x30, append(berInteger(0x02, messageID), response...))
}

func protocolResultPacket(applicationTag uint64, code int64) *ber.Packet {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(applicationTag), nil, "LDAP result")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return packet
}

func protocolReferral(uri string) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, uri, "URI"))
	return packet
}
