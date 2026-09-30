package ebpftracer

import (
	"encoding/binary"
	"fmt"
)

// Manual decoders of the perf events emitted by the eBPF programs. They are equivalent to
// binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &v) but avoid reflection and allocations
// on the per-event hot path. The offsets follow the packed layout of the Go structs, which matches
// the layout of the corresponding C structs (see decode_test.go).

var (
	procEventSize = binary.Size(procEvent{})
	tcpEventSize  = binary.Size(tcpEvent{})
	fileEventSize = binary.Size(fileEvent{})
	// struct l7_event: the header, the payload, and the timestamp
	l7EventHeaderSize    = binary.Size(l7Event{}) - 8
	l7EventTimestampOffs = l7EventHeaderSize + MaxPayloadSize
	l7EventSize          = l7EventTimestampOffs + 8
)

var le = binary.LittleEndian

func errShortEvent(name string, got, want int) error {
	return fmt.Errorf("%s: unexpected EOF: got %d bytes, want at least %d", name, got, want)
}

func decodeProcEvent(b []byte) (procEvent, error) {
	if len(b) < procEventSize {
		return procEvent{}, errShortEvent("proc event", len(b), procEventSize)
	}
	return procEvent{
		Type:   EventType(le.Uint32(b[0:])),
		Pid:    le.Uint32(b[4:]),
		Reason: le.Uint32(b[8:]),
	}, nil
}

func decodeTCPEvent(b []byte) (tcpEvent, error) {
	if len(b) < tcpEventSize {
		return tcpEvent{}, errShortEvent("tcp event", len(b), tcpEventSize)
	}
	v := tcpEvent{
		Fd:            le.Uint64(b[0:]),
		Timestamp:     le.Uint64(b[8:]),
		Duration:      le.Uint64(b[16:]),
		Type:          EventType(le.Uint32(b[24:])),
		Pid:           le.Uint32(b[28:]),
		BytesSent:     le.Uint64(b[32:]),
		BytesReceived: le.Uint64(b[40:]),
		SPort:         le.Uint16(b[48:]),
		DPort:         le.Uint16(b[50:]),
		Aport:         le.Uint16(b[52:]),
		IsInbound:     b[102],
	}
	copy(v.SAddr[:], b[54:70])
	copy(v.DAddr[:], b[70:86])
	copy(v.AAddr[:], b[86:102])
	return v, nil
}

func decodeFileEvent(b []byte) (fileEvent, error) {
	if len(b) < fileEventSize {
		return fileEvent{}, errShortEvent("file event", len(b), fileEventSize)
	}
	return fileEvent{
		Type: EventType(le.Uint32(b[0:])),
		Pid:  le.Uint32(b[4:]),
		Fd:   le.Uint64(b[8:]),
		Mnt:  le.Uint64(b[16:]),
		Log:  le.Uint64(b[24:]),
	}, nil
}

// decodeL7Event returns the event and its payload buffer (MaxPayloadSize bytes, the actual size is v.PayloadSize).
func decodeL7Event(b []byte) (l7Event, []byte, error) {
	if len(b) < l7EventSize {
		return l7Event{}, nil, errShortEvent("l7 event", len(b), l7EventSize)
	}
	return l7Event{
		Fd:                  le.Uint64(b[0:]),
		ConnectionTimestamp: le.Uint64(b[8:]),
		Pid:                 le.Uint32(b[16:]),
		Status:              int32(le.Uint32(b[20:])),
		Duration:            le.Uint64(b[24:]),
		Protocol:            b[32],
		Method:              b[33],
		IsInbound:           b[34],
		Padding:             b[35],
		StatementId:         le.Uint32(b[36:]),
		PayloadSize:         le.Uint64(b[40:]),
		Timestamp:           le.Uint64(b[l7EventTimestampOffs:]),
	}, b[l7EventHeaderSize:l7EventTimestampOffs], nil
}
