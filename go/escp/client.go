package escp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// SecurityMode identifies the negotiated ESCP transport security.
type SecurityMode int

const (
	// SecurityStaticRC4 is the legacy transport: fixed static RC4 key.
	SecurityStaticRC4 SecurityMode = iota
	// SecurityRSASmall uses the 64-bit RSA session key (older firmware).
	SecurityRSASmall
	// SecurityRSABig uses the 1024-bit RSA session key (newer firmware).
	SecurityRSABig
)

func (m SecurityMode) String() string {
	switch m {
	case SecurityRSABig:
		return "RSA-1024 session"
	case SecurityRSASmall:
		return "RSA-64 session"
	default:
		return "legacy static RC4"
	}
}

// DefaultSecurityOrder tries the strongest mode first, then falls back.
var DefaultSecurityOrder = []SecurityMode{SecurityRSABig, SecurityRSASmall, SecurityStaticRC4}

const (
	switchPort = 29808
	localPort  = 29809
	rsaOK      = 4098
)

// Client is an ESCP (Easy Smart Configuration Protocol) client.
type Client struct {
	IP       string
	Username string
	Password string
	Timeout  time.Duration
	Verbose  bool
	Logger   func(format string, args ...any)

	// SecurityOrder overrides the default strongest-first fallback order.
	SecurityOrder []SecurityMode

	conn       *net.UDPConn
	switchMAC  [6]byte
	clientMAC  [6]byte
	seq        uint16
	token      uint16
	sessionKey string
	useSession bool

	// Mode is the security mode negotiated by Login.
	Mode SecurityMode
	// Info is the device description learned during discovery.
	Info SystemInfo
}

// NewClient returns a client for the switch at ip with the given credentials.
func NewClient(ip, username, password string) *Client {
	return &Client{
		IP:        ip,
		Username:  username,
		Password:  password,
		Timeout:   2 * time.Second,
		clientMAC: [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Logger:    func(string, ...any) {},
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Verbose && c.Logger != nil {
		c.Logger(format, args...)
	}
}

func (c *Client) securityOrder() []SecurityMode {
	if len(c.SecurityOrder) > 0 {
		return c.SecurityOrder
	}
	return DefaultSecurityOrder
}

func (c *Client) open() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: localPort})
	if err != nil {
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		return fmt.Errorf("escp: open socket: %w", err)
	}
	c.conn = conn
	c.logf("listening on %s", c.conn.LocalAddr())
	return nil
}

// Close releases the UDP socket.
func (c *Client) Close() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) decrypt(raw []byte) ([]byte, bool, bool) {
	dec := staticRC4(raw)
	if len(dec) >= 2 && dec[0] == 1 && dec[1] < 5 {
		return dec, false, true
	}
	if c.sessionKey != "" {
		d2 := sessionRC4(raw, c.sessionKey)
		if len(d2) >= 2 && d2[0] == 1 && d2[1] < 5 {
			return d2, true, true
		}
	}
	return nil, false, false
}

// exchange sends one request (optionally session-encrypted) and returns the
// first matching response from the switch.
func (c *Client) exchange(ctx context.Context, op byte, tlvs []TLV, session bool) (header, []TLV, error) {
	if err := c.open(); err != nil {
		return header{}, nil, err
	}
	var swmac [6]byte
	if op != opDiscovery {
		swmac = c.switchMAC
	}
	dst := &net.UDPAddr{IP: net.ParseIP(c.IP), Port: switchPort}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil {
			return header{}, nil, ctx.Err()
		}
		// A fresh sequence number is used for every attempt: the switch
		// ignores duplicate sequence numbers, so a naive retry is dropped.
		h := header{
			Version:   1,
			Op:        op,
			SwitchMAC: swmac,
			ClientMAC: c.clientMAC,
			Seq:       c.seq,
			Token:     c.token,
		}
		c.seq++
		plain := buildPacket(h, tlvs)
		var enc []byte
		if session && c.sessionKey != "" {
			enc = sessionRC4(plain, c.sessionKey)
		} else {
			enc = staticRC4(plain)
		}
		c.logf(">>> op=%d attempt=%d seq=%d session=%v len=%d plain=%x enc=%x", op, attempt, h.Seq, session, len(plain), plain, enc)
		if _, err := c.conn.WriteToUDP(enc, dst); err != nil {
			return header{}, nil, fmt.Errorf("escp: send: %w", err)
		}
		deadline := time.Now().Add(c.Timeout)
		for {
			_ = c.conn.SetReadDeadline(deadline)
			buf := make([]byte, 4096)
			n, addr, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				lastErr = err
				break
			}
			c.logf("raw recv from %s len=%d seq(want)=%d", addr.String(), n, h.Seq)
			if !addr.IP.Equal(net.ParseIP(c.IP)) {
				continue
			}
			dec, usingSession, ok := c.decrypt(buf[:n])
			if !ok {
				continue
			}
			rh, err := parseHeader(dec)
			if err != nil || rh.Seq != h.Seq {
				continue
			}
			if rh.Op != opGetResp && rh.Op != opSetResp {
				continue
			}
			rtlvs, _ := parseTLVs(dec)
			c.token = rh.Token
			c.logf("<<< op=%d err=%d token=%d session=%v dec=%x", rh.Op, rh.ErrCode, rh.Token, usingSession, dec)
			return rh, rtlvs, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("timeout")
	}
	return header{}, nil, fmt.Errorf("escp: no reply to opcode %d: %w", op, lastErr)
}

// discover sends a discovery probe and records the switch MAC + system info.
func (c *Client) discover(ctx context.Context) error {
	rh, tlvs, err := c.exchange(ctx, opDiscovery, nil, false)
	if err != nil {
		return err
	}
	c.switchMAC = rh.SwitchMAC
	c.Info = parseSystemInfo(tlvs)
	return nil
}

func (c *Client) tokenGet(ctx context.Context, session bool) error {
	_, _, err := c.exchange(ctx, opGet, []TLV{{Type: tlvGetTokenID}}, session)
	return err
}

func (c *Client) loginSet(ctx context.Context) error {
	tlvs := []TLV{
		{Type: tlvUsername, Value: append([]byte(c.Username), 0)},
		{Type: tlvPassword, Value: append([]byte(c.Password), 0)},
	}
	rh, _, err := c.exchange(ctx, opSet, tlvs, c.useSession)
	if err != nil {
		return err
	}
	if rh.ErrCode != 0 {
		return fmt.Errorf("escp: login rejected (err=%d)", rh.ErrCode)
	}
	return nil
}

// tryRSASession performs the RSA session-key exchange and verifies it with a
// token GET. Returns true when the session is usable.
func (c *Client) tryRSASession(ctx context.Context, modulus []byte, mode SecurityMode) bool {
	key, err := newSessionKey()
	if err != nil {
		return false
	}
	c.sessionKey = key
	c.useSession = false

	rsa := rsaEncryptSessionKey(key, modulus)
	rh, _, err := c.exchange(ctx, opSet, []TLV{{Type: tlvRSASession, Value: rsa}}, false)
	if err != nil || rh.ErrCode != rsaOK {
		c.logf("RSA session with %s failed (err=%v code=%d)", mode, err, rh.ErrCode)
		c.sessionKey = ""
		return false
	}
	// Confirm the switch actually adopted this session key.
	if err := c.tokenGet(ctx, true); err != nil {
		c.logf("RSA session with %s acknowledged but not usable: %v", mode, err)
		c.sessionKey = ""
		return false
	}
	c.useSession = true
	c.Mode = mode
	c.logf("RSA session established: %s (key=%s)", mode, key)
	return true
}

// Login negotiates the most secure transport first and falls back, then logs
// in with the switch credentials. On success, c.Mode reports the negotiated
// security mode.
func (c *Client) Login(ctx context.Context) error {
	if err := c.open(); err != nil {
		return err
	}
	if err := c.discover(ctx); err != nil {
		return err
	}

	for _, mode := range c.securityOrder() {
		switch mode {
		case SecurityRSABig:
			if c.tryRSASession(ctx, rsaBigModulus, SecurityRSABig) {
				if err := c.loginSet(ctx); err == nil {
					return nil
				}
			}
		case SecurityRSASmall:
			if c.tryRSASession(ctx, rsaSmallModulus, SecurityRSASmall) {
				if err := c.loginSet(ctx); err == nil {
					return nil
				}
			}
		case SecurityStaticRC4:
			c.sessionKey = ""
			c.useSession = false
			c.Mode = SecurityStaticRC4
			if err := c.tokenGet(ctx, false); err != nil {
				continue
			}
			if err := c.loginSet(ctx); err == nil {
				return nil
			}
		}
	}
	return errors.New("escp: authentication failed with all security modes")
}

// Get performs a generic GET for a TLV type using the negotiated session.
func (c *Client) Get(ctx context.Context, tlvType uint16) ([]TLV, error) {
	rh, tlvs, err := c.exchange(ctx, opGet, []TLV{{Type: tlvType}}, c.useSession)
	if err != nil {
		return nil, err
	}
	if rh.ErrCode != 0 {
		return nil, fmt.Errorf("escp: GET type %d failed (err=%d)", tlvType, rh.ErrCode)
	}
	return tlvs, nil
}

// GetPortStats returns per-port counters (TLV 16384).
func (c *Client) GetPortStats(ctx context.Context) ([]PortStat, error) {
	tlvs, err := c.Get(ctx, tlvPortStats)
	if err != nil {
		return nil, err
	}
	return parsePortStats(tlvs), nil
}

// GetPorts returns per-port configuration (TLV 4096).
func (c *Client) GetPorts(ctx context.Context) ([]Port, error) {
	tlvs, err := c.Get(ctx, tlvPorts)
	if err != nil {
		return nil, err
	}
	return parsePorts(tlvs), nil
}

// SystemInfo returns the cached device description learned during Login.
func (c *Client) SystemInfo() SystemInfo { return c.Info }

// Discover performs discovery only (no authentication) and returns the device
// description. Useful for enumerating switches before logging in.
func (c *Client) Discover(ctx context.Context) (SystemInfo, error) {
	if err := c.open(); err != nil {
		return SystemInfo{}, err
	}
	if err := c.discover(ctx); err != nil {
		return SystemInfo{}, err
	}
	return c.Info, nil
}
