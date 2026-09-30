package escp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// SystemInfo is the device description returned by discovery / TLV group.
type SystemInfo struct {
	DeviceType string
	Hostname   string
	MAC        net.HardwareAddr
	IP         net.IP
	Netmask    net.IP
	Gateway    net.IP
	Firmware   string
	Hardware   string
	DHCP       bool
	AutoSave   bool
	IsFactory  bool
}

// PortStat holds per-port counters (TLV 16384).
type PortStat struct {
	Port   int
	TxGood uint32
	TxBad  uint32
	RxGood uint32
	RxBad  uint32
}

// Port holds per-port configuration (TLV 4096), raw bytes plus best-effort.
type Port struct {
	Port    int
	Enabled bool
	Raw     []byte
}

func cstr(v []byte) string {
	for i, b := range v {
		if b == 0 {
			return string(v[:i])
		}
	}
	return string(v)
}

func parseSystemInfo(tlvs []TLV) SystemInfo {
	var si SystemInfo
	for _, t := range tlvs {
		switch t.Type {
		case tlvDeviceType:
			si.DeviceType = cstr(t.Value)
		case tlvHostname:
			si.Hostname = cstr(t.Value)
		case tlvMAC:
			if len(t.Value) == 6 {
				si.MAC = net.HardwareAddr(append([]byte(nil), t.Value...))
			}
		case tlvIP:
			si.IP = net.IP(append([]byte(nil), t.Value...))
		case tlvMask:
			si.Netmask = net.IP(append([]byte(nil), t.Value...))
		case tlvGateway:
			si.Gateway = net.IP(append([]byte(nil), t.Value...))
		case tlvFirmware:
			si.Firmware = cstr(t.Value)
		case tlvHardware:
			si.Hardware = cstr(t.Value)
		case tlvDHCP:
			si.DHCP = len(t.Value) > 0 && t.Value[0] != 0
		case tlvAutoSave:
			si.AutoSave = len(t.Value) > 0 && t.Value[0] != 0
		case tlvIsFactory:
			si.IsFactory = len(t.Value) > 0 && t.Value[0] != 0
		}
	}
	return si
}

func (si SystemInfo) String() string {
	return fmt.Sprintf("%s host=%q hw=%q fw=%q mac=%s ip=%s mask=%s gw=%s dhcp=%v",
		si.DeviceType, si.Hostname, si.Hardware, si.Firmware, si.MAC, si.IP, si.Netmask, si.Gateway, si.DHCP)
}

func parsePortStats(tlvs []TLV) []PortStat {
	var out []PortStat
	for _, t := range tlvs {
		if t.Type != tlvPortStats || len(t.Value) < 19 {
			continue
		}
		v := t.Value
		out = append(out, PortStat{
			Port:   int(v[0]),
			TxGood: binary.BigEndian.Uint32(v[3:7]),
			TxBad:  binary.BigEndian.Uint32(v[7:11]),
			RxGood: binary.BigEndian.Uint32(v[11:15]),
			RxBad:  binary.BigEndian.Uint32(v[15:19]),
		})
	}
	return out
}

func parsePorts(tlvs []TLV) []Port {
	var out []Port
	for _, t := range tlvs {
		if t.Type != tlvPorts || len(t.Value) < 7 {
			continue
		}
		p := Port{Port: int(t.Value[0]), Raw: append([]byte(nil), t.Value...)}
		p.Enabled = t.Value[1] == 1
		out = append(out, p)
	}
	return out
}

// HardwareVersion returns just the model + version token form, e.g. "TL-SG108E 6.0".
func (si SystemInfo) HardwareVersion() string {
	return strings.TrimSpace(si.Hardware)
}
