package escp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// opcodes
const (
	opDiscovery byte = 0
	opGet       byte = 1
	opGetResp   byte = 2
	opSet       byte = 3
	opSetResp   byte = 4
)

const (
	headerLen = 32
)

// TLV type IDs (observed).
const (
	tlvDeviceType uint16 = 1
	tlvHostname   uint16 = 2
	tlvMAC        uint16 = 3
	tlvIP         uint16 = 4
	tlvMask       uint16 = 5
	tlvGateway    uint16 = 6
	tlvFirmware   uint16 = 7
	tlvHardware   uint16 = 8
	tlvDHCP       uint16 = 9
	tlvAutoSave   uint16 = 13
	tlvIsFactory  uint16 = 14
	tlvUsername   uint16 = 512
	tlvPassword   uint16 = 514
	tlvRSASession uint16 = 528
	tlvGetTokenID uint16 = 2305
	tlvPorts      uint16 = 4096
	tlvPortStats  uint16 = 16384
)

// header is the 32-byte ESCP header.
type header struct {
	Version   byte
	Op        byte
	SwitchMAC [6]byte
	ClientMAC [6]byte
	Seq       uint16
	ErrCode   uint32
	Length    uint16
	Frag      uint16
	Flag      uint16
	Token     uint16
	Checksum  uint32
}

// TLV is a Type/Length/Value tuple.
type TLV struct {
	Type  uint16
	Value []byte
}

func hasTLV(tlvs []TLV, typ uint16) bool {
	for _, t := range tlvs {
		if t.Type == typ {
			return true
		}
	}
	return false
}

func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) < headerLen {
		return h, errors.New("escp: short packet")
	}
	h.Version = b[0]
	h.Op = b[1]
	copy(h.SwitchMAC[:], b[2:8])
	copy(h.ClientMAC[:], b[8:14])
	h.Seq = binary.BigEndian.Uint16(b[14:16])
	h.ErrCode = binary.BigEndian.Uint32(b[16:20])
	h.Length = binary.BigEndian.Uint16(b[20:22])
	h.Frag = binary.BigEndian.Uint16(b[22:24])
	h.Flag = binary.BigEndian.Uint16(b[24:26])
	h.Token = binary.BigEndian.Uint16(b[26:28])
	h.Checksum = binary.BigEndian.Uint32(b[28:32])
	return h, nil
}

func parseTLVs(b []byte) ([]TLV, error) {
	if len(b) < headerLen {
		return nil, errors.New("escp: short packet")
	}
	p := b[headerLen:]
	var tlvs []TLV
	for len(p) >= 4 {
		t := binary.BigEndian.Uint16(p[0:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if t == 0xffff && l == 0 {
			break
		}
		if len(p) < 4+l {
			return tlvs, fmt.Errorf("escp: truncated TLV type=%d len=%d", t, l)
		}
		v := make([]byte, l)
		copy(v, p[4:4+l])
		tlvs = append(tlvs, TLV{Type: t, Value: v})
		p = p[4+l:]
	}
	return tlvs, nil
}

func marshalTLVs(tlvs []TLV) []byte {
	var out []byte
	for _, t := range tlvs {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], t.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(t.Value)))
		out = append(out, hdr[:]...)
		out = append(out, t.Value...)
	}
	out = append(out, 0xff, 0xff, 0x00, 0x00)
	return out
}

func buildPacket(h header, tlvs []TLV) []byte {
	payload := marshalTLVs(tlvs)
	h.Length = uint16(headerLen + len(payload))
	buf := make([]byte, headerLen)
	buf[0] = h.Version
	buf[1] = h.Op
	copy(buf[2:8], h.SwitchMAC[:])
	copy(buf[8:14], h.ClientMAC[:])
	binary.BigEndian.PutUint16(buf[14:16], h.Seq)
	binary.BigEndian.PutUint32(buf[16:20], h.ErrCode)
	binary.BigEndian.PutUint16(buf[20:22], h.Length)
	binary.BigEndian.PutUint16(buf[22:24], h.Frag)
	binary.BigEndian.PutUint16(buf[24:26], h.Flag)
	binary.BigEndian.PutUint16(buf[26:28], h.Token)
	binary.BigEndian.PutUint32(buf[28:32], h.Checksum)
	return append(buf, payload...)
}
