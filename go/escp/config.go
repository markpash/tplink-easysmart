package escp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
)

// Additional TLV type IDs used by configuration operations.
const (
	tlvMgmtVlan           uint16 = 11
	tlvLED                uint16 = 12
	tlvNewUsername        uint16 = 513
	tlvNewPassword        uint16 = 515
	tlvConfigGet          uint16 = 768
	tlvConfigSet          uint16 = 769
	tlvReboot             uint16 = 773
	tlvFactoryReset       uint16 = 1280
	tlvSaveConfig         uint16 = 2304
	tlvIGMP               uint16 = 4352
	tlvIGMPGroups         uint16 = 4353
	tlvIGMPSuppress       uint16 = 4354
	tlvTrunk              uint16 = 4608
	tlvMTUVlan            uint16 = 8192
	tlvPortVlan           uint16 = 8448
	tlvPortVlanEntry      uint16 = 8449
	tlvPortVlanCount      uint16 = 8450
	tlvMTUMgmtStatus      uint16 = 8708
	tlvMTUMgmtPorts       uint16 = 8709
	tlvPortVlanMgmtStatus uint16 = 8710
	tlvPortVlanMgmtPorts  uint16 = 8711
	tlvVlanEnable         uint16 = 8704
	tlvVlanEntry          uint16 = 8705
	tlvVlanPvid           uint16 = 8706
	tlvVlanMgmtStatus     uint16 = 8712
	tlvVlanMgmtVlan       uint16 = 8713
	tlvQosMode            uint16 = 12288
	tlvQosPriority        uint16 = 12289
	tlvBandIngress        uint16 = 12544
	tlvBandEgress         uint16 = 12545
	tlvStorm              uint16 = 12800
	tlvMirror             uint16 = 16640
	tlvLoop               uint16 = 17152
)

// ---- small encoding helpers ----

func u16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func u32be(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
func bool1(b bool) []byte {
	if b {
		return []byte{1}
	}
	return []byte{0}
}
func cstrBytes(s string) []byte { return append([]byte(s), 0) }
func ip4(ip net.IP) []byte {
	if v := ip.To4(); v != nil {
		return []byte{v[0], v[1], v[2], v[3]}
	}
	return []byte{0, 0, 0, 0}
}
func portsMask(ports []int) uint32 {
	var m uint32
	for _, p := range ports {
		if p >= 1 && p <= 32 {
			m |= 1 << uint(p-1)
		}
	}
	return m
}
func maskPorts(m uint32) []int {
	var out []int
	for p := 1; p <= 32; p++ {
		if m&(1<<uint(p-1)) != 0 {
			out = append(out, p)
		}
	}
	return out
}

// adjustRate rounds a rate to the switch's granularity (multiples of 64 kbps,
// minimum 64). Returns 0 for "unlimited".
func adjustRate(kbps int) int {
	if kbps <= 0 {
		return 0
	}
	if kbps < 64 {
		return 64
	}
	if r := kbps % 64; r != 0 {
		if r < 32 {
			return kbps / 64 * 64
		}
		return (kbps/64 + 1) * 64
	}
	return kbps
}

func findTLV(tlvs []TLV, typ uint16) (TLV, bool) {
	for _, t := range tlvs {
		if t.Type == typ {
			return t, true
		}
	}
	return TLV{}, false
}

// credsTLVs returns the username/password TLVs that the switch requires to be
// present in every SET request (not only login).
func (c *Client) credsTLVs() []TLV {
	return []TLV{
		{Type: tlvUsername, Value: cstrBytes(c.Username)},
		{Type: tlvPassword, Value: cstrBytes(c.Password)},
	}
}

// Set sends a SET request with the given TLVs (credentials are prepended
// automatically) and expects errCode == 0.
func (c *Client) Set(ctx context.Context, tlvs ...TLV) error {
	full := append(c.credsTLVs(), tlvs...)
	rh, _, err := c.exchange(ctx, opSet, full, c.useSession)
	if err != nil {
		return err
	}
	if rh.ErrCode != 0 {
		return fmt.Errorf("escp: SET failed (err=%d)", rh.ErrCode)
	}
	return nil
}

// setTolerant sends a SET and tolerates a missing acknowledgement (used for
// reboot/reset, where the switch may restart before replying).
func (c *Client) setTolerant(ctx context.Context, tlvs ...TLV) error {
	full := append(c.credsTLVs(), tlvs...)
	rh, _, err := c.exchange(ctx, opSet, full, c.useSession)
	if err != nil {
		return nil
	}
	if rh.ErrCode != 0 {
		return fmt.Errorf("escp: SET failed (err=%d)", rh.ErrCode)
	}
	return nil
}

// ---------------- System ----------------

// SetDescription sets the device description (hostname). The switch's System
// Info request carries TLV 2 plus the current IP TLVs (9/4/5/6), so those are
// included unchanged from the last discovery.
func (c *Client) SetDescription(ctx context.Context, name string) error {
	dhcp := []byte{0}
	if c.Info.DHCP {
		dhcp = []byte{1}
	}
	return c.Set(ctx,
		TLV{Type: tlvHostname, Value: cstrBytes(name)},
		TLV{Type: tlvDHCP, Value: dhcp},
		TLV{Type: tlvIP, Value: ip4(c.Info.IP)},
		TLV{Type: tlvMask, Value: ip4(c.Info.Netmask)},
		TLV{Type: tlvGateway, Value: ip4(c.Info.Gateway)},
	)
}

// SetIP configures IPv4 addressing. With dhcp=true the address TLVs are zeroed.
// mgmtVlan is the management VLAN ID (typically 1).
func (c *Client) SetIP(ctx context.Context, dhcp bool, ip, mask, gw net.IP, mgmtVlan uint16) error {
	dhcpVal := []byte{0, 0, 0, 0}
	if dhcp {
		dhcpVal = []byte{0, 0, 0, 1}
	}
	return c.Set(ctx,
		TLV{Type: tlvDHCP, Value: dhcpVal},
		TLV{Type: tlvIP, Value: ip4(ip)},
		TLV{Type: tlvMask, Value: ip4(mask)},
		TLV{Type: tlvGateway, Value: ip4(gw)},
		TLV{Type: tlvMgmtVlan, Value: u16be(mgmtVlan)},
	)
}

// SetLED turns the port LEDs on or off, TLV 12.
func (c *Client) SetLED(ctx context.Context, on bool) error {
	return c.Set(ctx, TLV{Type: tlvLED, Value: bool1(on)})
}

// SetAccount changes the management credentials. oldPassword is the current
// password; newUsername/newPassword take effect immediately.
func (c *Client) SetAccount(ctx context.Context, oldPassword, newUsername, newPassword string) error {
	return c.Set(ctx,
		TLV{Type: tlvPassword, Value: cstrBytes(oldPassword)},
		TLV{Type: tlvNewUsername, Value: cstrBytes(newUsername)},
		TLV{Type: tlvNewPassword, Value: cstrBytes(newPassword)},
	)
}

// SaveConfig flushes the running configuration to flash (TLV 2304). Many Easy
// Smart models (e.g. TL-SG108E) auto-save and treat this as a no-op.
func (c *Client) SaveConfig(ctx context.Context) error {
	return c.Set(ctx, TLV{Type: tlvSaveConfig})
}

// Reboot restarts the switch (TLV 773). The reply may not arrive.
func (c *Client) Reboot(ctx context.Context) error {
	return c.setTolerant(ctx, TLV{Type: tlvReboot, Value: bool1(true)})
}

// FactoryReset restores factory defaults (TLV 1280). The reply may not arrive.
func (c *Client) FactoryReset(ctx context.Context) error {
	return c.setTolerant(ctx, TLV{Type: tlvFactoryReset})
}

// ExportConfig downloads the raw configuration backup (TLV 768).
func (c *Client) ExportConfig(ctx context.Context) ([]byte, error) {
	req := append(c.credsTLVs(), TLV{Type: tlvConfigGet})
	rh, tlvs, err := c.exchange(ctx, opSet, req, c.useSession)
	if err != nil {
		return nil, err
	}
	if rh.ErrCode != 0 {
		return nil, fmt.Errorf("escp: config export failed (err=%d)", rh.ErrCode)
	}
	t, ok := findTLV(tlvs, tlvConfigGet)
	if !ok {
		return nil, fmt.Errorf("escp: config export: no data TLV")
	}
	return t.Value, nil
}

// ---------------- Ports ----------------

// PortSpeed is the configured port speed/duplex.
type PortSpeed byte

const (
	SpeedAuto      PortSpeed = 1
	Speed10MHalf   PortSpeed = 2
	Speed10MFull   PortSpeed = 3
	Speed100MHalf  PortSpeed = 4
	Speed100MFull  PortSpeed = 5
	Speed1000MFull PortSpeed = 6
)

func (s PortSpeed) String() string {
	names := map[PortSpeed]string{
		SpeedAuto: "auto", Speed10MHalf: "10MHalf", Speed10MFull: "10MFull",
		Speed100MHalf: "100MHalf", Speed100MFull: "100MFull", Speed1000MFull: "1000MFull",
	}
	if n, ok := names[s]; ok {
		return n
	}
	return fmt.Sprintf("speed(%d)", byte(s))
}

// PortConfig is a writable port configuration (TLV 4096).
type PortConfig struct {
	Port        int
	Enabled     bool
	Speed       PortSpeed
	FlowControl bool
}

func portValue(cfg PortConfig) []byte {
	var en, fc byte
	if cfg.Enabled {
		en = 1
	}
	if cfg.FlowControl {
		fc = 1
	}
	return []byte{byte(cfg.Port), en, 0, byte(cfg.Speed), 0, fc, 0}
}

// SetPort configures a single port.
func (c *Client) SetPort(ctx context.Context, cfg PortConfig) error {
	return c.Set(ctx, TLV{Type: tlvPorts, Value: portValue(cfg)})
}

// SetPorts configures several ports in one request.
func (c *Client) SetPorts(ctx context.Context, cfgs ...PortConfig) error {
	tlvs := make([]TLV, 0, len(cfgs))
	for _, cfg := range cfgs {
		tlvs = append(tlvs, TLV{Type: tlvPorts, Value: portValue(cfg)})
	}
	return c.Set(ctx, tlvs...)
}

// ---------------- IGMP snooping ----------------

// GetIGMP returns IGMP snooping enabled state and report-suppression state.
func (c *Client) GetIGMP(ctx context.Context) (enabled, suppression bool, err error) {
	tlvs, err := c.Get(ctx, tlvIGMP)
	if err != nil {
		return false, false, err
	}
	if t, ok := findTLV(tlvs, tlvIGMP); ok && len(t.Value) > 0 {
		enabled = t.Value[0] == 1
	}
	if tlvs2, err2 := c.Get(ctx, tlvIGMPSuppress); err2 == nil {
		if t, ok := findTLV(tlvs2, tlvIGMPSuppress); ok && len(t.Value) > 0 {
			suppression = t.Value[0] == 1
		}
	}
	return enabled, suppression, nil
}

// SetIGMPOptions sets both IGMP snooping and report suppression. The switch's
// SET request carries TLV 4352 and TLV 4354 together.
func (c *Client) SetIGMPOptions(ctx context.Context, enabled, suppression bool) error {
	return c.Set(ctx,
		TLV{Type: tlvIGMP, Value: bool1(enabled)},
		TLV{Type: tlvIGMPSuppress, Value: bool1(suppression)},
	)
}

// SetIGMP enables or disables IGMP snooping, preserving report suppression.
func (c *Client) SetIGMP(ctx context.Context, enabled bool) error {
	_, sup, err := c.GetIGMP(ctx)
	if err != nil {
		sup = false
	}
	return c.SetIGMPOptions(ctx, enabled, sup)
}

// SetIGMPSuppression enables or disables IGMP report suppression, preserving
// the snooping enabled state.
func (c *Client) SetIGMPSuppression(ctx context.Context, on bool) error {
	en, _, err := c.GetIGMP(ctx)
	if err != nil {
		en = true
	}
	return c.SetIGMPOptions(ctx, en, on)
}

// ---------------- LAG / trunk ----------------

// GetTrunks returns LAG membership as lagID -> port list (TLV 4608).
func (c *Client) GetTrunks(ctx context.Context) (map[int][]int, error) {
	tlvs, err := c.Get(ctx, tlvTrunk)
	if err != nil {
		return nil, err
	}
	out := map[int][]int{}
	for _, t := range tlvs {
		if t.Type == tlvTrunk && len(t.Value) >= 5 {
			lag := int(t.Value[0])
			out[lag] = maskPorts(binary.BigEndian.Uint32(t.Value[1:5]))
		}
	}
	return out, nil
}

// SetTrunk assigns ports to a LAG (TLV 4608).
func (c *Client) SetTrunk(ctx context.Context, lagID int, ports []int) error {
	return c.Set(ctx, TLV{Type: tlvTrunk, Value: append([]byte{byte(lagID)}, u32be(portsMask(ports))...)})
}

// DeleteTrunk removes all ports from a LAG.
func (c *Client) DeleteTrunk(ctx context.Context, lagID int) error {
	return c.Set(ctx, TLV{Type: tlvTrunk, Value: append([]byte{byte(lagID)}, u32be(0)...)})
}

// ---------------- Monitoring ----------------

// GetLoopPrevention returns loop-prevention state (TLV 17152).
func (c *Client) GetLoopPrevention(ctx context.Context) (bool, error) {
	tlvs, err := c.Get(ctx, tlvLoop)
	if err != nil {
		return false, err
	}
	if t, ok := findTLV(tlvs, tlvLoop); ok && len(t.Value) > 0 {
		return t.Value[0] == 1, nil
	}
	return false, nil
}

// SetLoopPrevention enables or disables loop prevention (TLV 17152).
func (c *Client) SetLoopPrevention(ctx context.Context, on bool) error {
	return c.Set(ctx, TLV{Type: tlvLoop, Value: bool1(on)})
}

// MirrorConfig is the port-mirroring configuration (TLV 16640, 10 bytes).
type MirrorConfig struct {
	Enabled    bool
	MirrorPort int
	Ingress    []int
	Egress     []int
}

func (m MirrorConfig) bytes() []byte {
	out := make([]byte, 10)
	if m.Enabled {
		out[0] = 1
	}
	out[1] = byte(m.MirrorPort)
	copy(out[2:6], u32be(portsMask(m.Ingress)))
	copy(out[6:10], u32be(portsMask(m.Egress)))
	return out
}

// GetMirror returns the port-mirroring configuration.
func (c *Client) GetMirror(ctx context.Context) (MirrorConfig, error) {
	tlvs, err := c.Get(ctx, tlvMirror)
	if err != nil {
		return MirrorConfig{}, err
	}
	t, ok := findTLV(tlvs, tlvMirror)
	if !ok || len(t.Value) < 10 {
		return MirrorConfig{}, nil
	}
	v := t.Value
	m := MirrorConfig{
		Enabled:    v[0] == 1,
		MirrorPort: int(v[1]),
		Ingress:    maskPorts(binary.BigEndian.Uint32(v[2:6])),
		Egress:     maskPorts(binary.BigEndian.Uint32(v[6:10])),
	}
	return m, nil
}

// SetMirror applies the port-mirroring configuration.
func (c *Client) SetMirror(ctx context.Context, m MirrorConfig) error {
	return c.Set(ctx, TLV{Type: tlvMirror, Value: m.bytes()})
}

// ---------------- VLAN ----------------

// Dot1QVLAN is an 802.1Q VLAN entry (TLV 8705).
type Dot1QVLAN struct {
	VID      int
	Name     string
	Tagged   []int
	Untagged []int
}

func (v Dot1QVLAN) bytes() []byte {
	member := portsMask(append(append([]int{}, v.Tagged...), v.Untagged...))
	tagged := portsMask(v.Tagged)
	out := []byte{byte(v.VID >> 8), byte(v.VID)}
	out = append(out, u32be(member)...)
	out = append(out, u32be(tagged)...)
	out = append(out, []byte(v.Name)...)
	out = append(out, 0)
	return out
}

func parseDot1QVLAN(v []byte) Dot1QVLAN {
	if len(v) < 10 {
		return Dot1QVLAN{}
	}
	vid := int(binary.BigEndian.Uint16(v[0:2]))
	member := binary.BigEndian.Uint32(v[2:6])
	tagged := binary.BigEndian.Uint32(v[6:10])
	out := Dot1QVLAN{VID: vid, Name: cstr(v[10:])}
	for p := 1; p <= 32; p++ {
		bit := uint32(1) << uint(p-1)
		if member&bit == 0 {
			continue
		}
		if tagged&bit != 0 {
			out.Tagged = append(out.Tagged, p)
		} else {
			out.Untagged = append(out.Untagged, p)
		}
	}
	return out
}

// GetDot1QVLANs returns 802.1Q status, VLAN table and per-port PVIDs.
func (c *Client) GetDot1QVLANs(ctx context.Context) (enabled bool, vlans []Dot1QVLAN, pvids map[int]int, err error) {
	tlvs, err := c.Get(ctx, tlvVlanEnable)
	if err != nil {
		return false, nil, nil, err
	}
	pvids = map[int]int{}
	for _, t := range tlvs {
		switch t.Type {
		case tlvVlanEnable:
			enabled = len(t.Value) > 0 && t.Value[0] == 1
		case tlvVlanEntry:
			if len(t.Value) > 0 {
				vlans = append(vlans, parseDot1QVLAN(t.Value))
			}
		case tlvVlanPvid:
			if len(t.Value) >= 3 {
				pvids[int(t.Value[0])] = int(binary.BigEndian.Uint16(t.Value[1:3]))
			}
		}
	}
	return enabled, vlans, pvids, nil
}

// SetDot1QVLANEnabled enables or disables 802.1Q VLAN mode (TLV 8704).
func (c *Client) SetDot1QVLANEnabled(ctx context.Context, on bool) error {
	return c.Set(ctx, TLV{Type: tlvVlanEnable, Value: bool1(on)})
}

// AddDot1QVLAN creates or modifies an 802.1Q VLAN (TLV 8705).
func (c *Client) AddDot1QVLAN(ctx context.Context, v Dot1QVLAN) error {
	return c.Set(ctx, TLV{Type: tlvVlanEntry, Value: v.bytes()})
}

// DeleteDot1QVLAN deletes an 802.1Q VLAN by ID.
func (c *Client) DeleteDot1QVLAN(ctx context.Context, vid int) error {
	return c.Set(ctx, TLV{Type: tlvVlanEntry, Value: Dot1QVLAN{VID: vid}.bytes()})
}

// SetPVID sets the port VLAN ID for a set of ports (TLV 8706, one TLV/port).
func (c *Client) SetPVID(ctx context.Context, pvids map[int]uint16) error {
	tlvs := make([]TLV, 0, len(pvids))
	for port, pvid := range pvids {
		val := append([]byte{byte(port)}, u16be(pvid)...)
		tlvs = append(tlvs, TLV{Type: tlvVlanPvid, Value: val})
	}
	return c.Set(ctx, tlvs...)
}

// GetMTUVLAN returns MTU-VLAN state and uplink port (TLV 8192).
func (c *Client) GetMTUVLAN(ctx context.Context) (enabled bool, uplink int, err error) {
	tlvs, err := c.Get(ctx, tlvMTUVlan)
	if err != nil {
		return false, 0, err
	}
	if t, ok := findTLV(tlvs, tlvMTUVlan); ok && len(t.Value) >= 2 {
		return t.Value[0] == 1, int(t.Value[1]), nil
	}
	return false, 0, nil
}

// SetMTUVLAN enables/disables MTU VLAN with the given uplink port (TLV 8192).
func (c *Client) SetMTUVLAN(ctx context.Context, on bool, uplink int) error {
	return c.Set(ctx, TLV{Type: tlvMTUVlan, Value: []byte{bool1(on)[0], byte(uplink)}})
}

// PortVLAN is a port-based VLAN entry (TLV 8449).
type PortVLAN struct {
	VID   int
	Ports []int
}

// GetPortVLANs returns port-based VLAN status and entries (TLV 8448).
func (c *Client) GetPortVLANs(ctx context.Context) (enabled bool, vlans []PortVLAN, err error) {
	tlvs, err := c.Get(ctx, tlvPortVlan)
	if err != nil {
		return false, nil, err
	}
	for _, t := range tlvs {
		switch t.Type {
		case tlvPortVlan:
			enabled = len(t.Value) > 0 && t.Value[0] == 1
		case tlvPortVlanEntry:
			if len(t.Value) >= 5 {
				vlans = append(vlans, PortVLAN{
					VID:   int(t.Value[0]),
					Ports: maskPorts(binary.BigEndian.Uint32(t.Value[1:5])),
				})
			}
		}
	}
	return enabled, vlans, nil
}

// SetPortVLANEnabled enables or disables port-based VLAN mode (TLV 8448).
func (c *Client) SetPortVLANEnabled(ctx context.Context, on bool) error {
	return c.Set(ctx, TLV{Type: tlvPortVlan, Value: bool1(on)})
}

// AddPortVLAN sets the member ports of a port-based VLAN group (TLV 8449).
func (c *Client) AddPortVLAN(ctx context.Context, vid int, ports []int) error {
	val := append([]byte{byte(vid)}, u32be(portsMask(ports))...)
	return c.Set(ctx, TLV{Type: tlvPortVlanEntry, Value: val})
}

// DeletePortVLAN deletes a port-based VLAN group.
func (c *Client) DeletePortVLAN(ctx context.Context, vid int) error {
	val := append([]byte{byte(vid)}, u32be(0)...)
	return c.Set(ctx, TLV{Type: tlvPortVlanEntry, Value: val})
}

// ---------------- QoS ----------------

// QoS mode values.
const (
	QoSPortBased = 0
	QoS8021p     = 1
	QoSDSCP      = 2
)

// GetQoSMode returns the QoS mode (TLV 12288).
func (c *Client) GetQoSMode(ctx context.Context) (int, error) {
	tlvs, err := c.Get(ctx, tlvQosMode)
	if err != nil {
		return -1, err
	}
	if t, ok := findTLV(tlvs, tlvQosMode); ok && len(t.Value) > 0 {
		return int(t.Value[0]), nil
	}
	return -1, nil
}

// SetQoSMode sets the QoS mode (TLV 12288).
func (c *Client) SetQoSMode(ctx context.Context, mode int) error {
	return c.Set(ctx, TLV{Type: tlvQosMode, Value: []byte{byte(mode)}})
}

// GetPortPriorities returns per-port priority (0..3) (TLV 12289).
func (c *Client) GetPortPriorities(ctx context.Context) (map[int]int, error) {
	tlvs, err := c.Get(ctx, tlvQosPriority)
	if err != nil {
		return nil, err
	}
	out := map[int]int{}
	for _, t := range tlvs {
		if t.Type == tlvQosPriority && len(t.Value) >= 2 {
			out[int(t.Value[0])] = int(t.Value[1])
		}
	}
	return out, nil
}

// SetPortPriority sets a port's priority (0..3) (TLV 12289).
func (c *Client) SetPortPriority(ctx context.Context, port, priority int) error {
	return c.Set(ctx, TLV{Type: tlvQosPriority, Value: []byte{byte(port), byte(priority)}})
}

// Bandwidth is an ingress or egress rate limit entry (TLV 12544/12545).
type Bandwidth struct {
	Port   int
	Enable bool
	Kbps   int // 0 = unlimited
}

func parseBandwidth(tlvs []TLV, typ uint16) []Bandwidth {
	var out []Bandwidth
	for _, t := range tlvs {
		if t.Type == typ && len(t.Value) >= 6 {
			out = append(out, Bandwidth{
				Port:   int(t.Value[0]),
				Enable: t.Value[1] == 1,
				Kbps:   int(binary.BigEndian.Uint32(t.Value[2:6])),
			})
		}
	}
	return out
}

func bandwidthTLVs(typ uint16, entries []Bandwidth) []TLV {
	tlvs := make([]TLV, 0, len(entries))
	for _, e := range entries {
		rate := adjustRate(e.Kbps)
		en := byte(0)
		if e.Enable && rate > 0 {
			en = 1
		}
		val := append([]byte{byte(e.Port), en}, u32be(uint32(rate))...)
		tlvs = append(tlvs, TLV{Type: typ, Value: val})
	}
	return tlvs
}

// GetBandwidth returns ingress and egress rate limits (TLV 12544/12545).
func (c *Client) GetBandwidth(ctx context.Context) (ingress, egress []Bandwidth, err error) {
	tlvs, err := c.Get(ctx, tlvBandIngress)
	if err != nil {
		return nil, nil, err
	}
	ingress = parseBandwidth(tlvs, tlvBandIngress)
	tlvs2, err := c.Get(ctx, tlvBandEgress)
	if err != nil {
		return ingress, nil, err
	}
	egress = parseBandwidth(tlvs2, tlvBandEgress)
	return ingress, egress, nil
}

// SetIngressBandwidth sets ingress rate limits (TLV 12544).
func (c *Client) SetIngressBandwidth(ctx context.Context, entries ...Bandwidth) error {
	return c.Set(ctx, bandwidthTLVs(tlvBandIngress, entries)...)
}

// SetEgressBandwidth sets egress rate limits (TLV 12545).
func (c *Client) SetEgressBandwidth(ctx context.Context, entries ...Bandwidth) error {
	return c.Set(ctx, bandwidthTLVs(tlvBandEgress, entries)...)
}

// StormControl is a per-port storm-control entry (TLV 12800).
type StormControl struct {
	Port           int
	Enable         bool
	Broadcast      bool
	Multicast      bool
	UnknownUnicast bool
	Kbps           int // 0 = unlimited
}

// GetStormControl returns per-port storm-control settings (TLV 12800).
func (c *Client) GetStormControl(ctx context.Context) ([]StormControl, error) {
	tlvs, err := c.Get(ctx, tlvStorm)
	if err != nil {
		return nil, err
	}
	var out []StormControl
	for _, t := range tlvs {
		if t.Type != tlvStorm || len(t.Value) < 9 {
			continue
		}
		v := t.Value
		out = append(out, StormControl{
			Port:           int(v[0]),
			Enable:         v[1] == 1,
			UnknownUnicast: v[2] == 1,
			Multicast:      v[3] == 1,
			Broadcast:      v[4] == 1,
			Kbps:           int(binary.BigEndian.Uint32(v[5:9])),
		})
	}
	return out, nil
}

// SetStormControl sets per-port storm control (TLV 12800).
func (c *Client) SetStormControl(ctx context.Context, entries ...StormControl) error {
	tlvs := make([]TLV, 0, len(entries))
	for _, e := range entries {
		rate := adjustRate(e.Kbps)
		en := byte(0)
		if e.Enable && rate > 0 {
			en = 1
		}
		val := []byte{byte(e.Port), en, 0, 0, 0}
		if e.UnknownUnicast {
			val[2] = 1
		}
		if e.Multicast {
			val[3] = 1
		}
		if e.Broadcast {
			val[4] = 1
		}
		val = append(val, u32be(uint32(rate))...)
		tlvs = append(tlvs, TLV{Type: tlvStorm, Value: val})
	}
	return c.Set(ctx, tlvs...)
}
