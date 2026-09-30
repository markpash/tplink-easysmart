# TP-Link Easy Smart Switch — Management Protocol (ESCP + "Upgraded" RSA/Session variant)

Reverse-engineered from the official **Easy Smart Configuration Utility v1.3.20.0** (Java/JavaFX app,
extracted on Linux) and live captures against a **TL-SG108E 6.0, firmware `1.0.0 Build 20230218 Rel.50633`**
and a **TL-SG1016PE 5.20, firmware `1.0.1 Build 20230712 Rel.73926`** (both on the same LAN).

This document covers both the **legacy ESCP** protocol and the **2023 "upgraded management protocol"**
(RSA session-key exchange + session-key RC4) that ships in current utility/firmware.

> See also: [FIRMWARE_FORMAT.md](FIRMWARE_FORMAT.md) (`.bin`/checksums/customization),
> [LOADER_MODE.md](LOADER_MODE.md), [SPI_FLASH_RECOVERY.md](SPI_FLASH_RECOVERY.md),
> [HARDWARE_AND_RECON.md](HARDWARE_AND_RECON.md), and the [index](README.md).

---

## 1. Summary

Easy Smart switches have no SNMP/SSH/REST. They are managed by a proprietary protocol historically called
**ESCP** ("Easy Smart Configuration Protocol"), carried over **UDP 29808 (to switch) / 29809 (from switch)**,
usually via broadcast `255.255.255.255`.

- **Legacy crypto:** whole packet encrypted with **RC4 using a hardcoded static key** (the key is shipped in
  every firmware and in the utility; CVE-2017-8077 / CVE-2022-44231).
- **New crypto (2023+):** the utility generates a random **8-character session key** and sends it to the switch
  **RSA-encrypted in TLV 528**. After the switch acknowledges (`op=4, errCode 4098`), **all subsequent packets
  are encrypted with RC4 keyed by that session key** instead of the static key.

Both layers use the *same* UDP framing and the same 32-byte header. The receiver distinguishes them by trying
the static key first and checking whether the result looks like a valid header.

> **Finding for the tested TL-SG108E 6.0 (fw `1.0.0`):** `From.bw()` evaluates **false**, so the switch (and
> utility) use the **small 64-bit RSA key** (`oF`). The 1024/2048-bit key (`oG`) was **not** accepted by this
> unit (RSA-ACK was returned but the resulting session key did not work). Newer firmware (e.g. TL-SG1016PE
> `1.0.1`) uses the large key.

---

## 2. Transport

| | |
|---|---|
| Protocol | UDP |
| Switch receives on | **29808** |
| Switch replies to | **29809** (broadcast `255.255.255.255` for legacy discovery) |
| Destination used by utility | `255.255.255.255` (broadcast); unicast also works |
| Framing | 32-byte header + 0..n TLVs + terminator `FF FF 00 00` |
| Endianness | big-endian for all multi-byte fields |

The switch also exposes an HTTP web UI on TCP 80 (cookie `H_P_SSID`, TTL 600 s) and accepts unauthenticated
firmware upload (`httpupg.cgi`), but the utility drives configuration via ESCP.

---

## 3. Packet header (32 bytes)

```
 offset size field
 ------ ---- ------------------------------------------------------------
  0      1   version            always 0x01
  1      1   opcode             0=discovery req, 1=GET req, 2=GET/discovery resp,
                                3=SET/login req, 4=SET resp
  2      6   switch MAC         00:00:00:00:00:00 for discovery probes
  8      6   client MAC
 14      2   sequence number    incremented for every request; echoed by switch
 16      4   error code         0 = OK; 4098 (0x00001002) = RSA/session OK; 7/8 = user changed/token error
 20      2   length             total packet length incl. header and terminator
 22      2   fragment offset    number of fragments - 1 (0 for single packet)
 24      2   flag
 26      2   token ID           returned by GET get_token_id; must be presented on SET/login
 28      4   checksum           unused (zero)
```

Followed by TLVs, then `FF FF 00 00`.

**Important:** the switch ignores requests that reuse a sequence number. The utility increments the sequence
for every packet (`PacketHead.aB()`). A client that sends many requests with a fixed sequence will see only the
first answered.

---

## 4. Request types (utility enum `DataBean.Request`)

| enum | meaning | opcode sent |
|------|---------|-------------|
| `y` | DISCOVERY | 0 |
| `z` | GET | 1 |
| `A` | SET / LOGIN | 3 |

Responses are opcode 2 (GET/discovery) or 4 (SET/login).

---

## 5. TLV catalogue (observed)

| type | name | notes |
|------|------|-------|
| 1 | device type | e.g. `"TL-SG108E\0"` |
| 2 | hostname / description | e.g. `"TL-SG108E\0"` |
| 3 | MAC address | 6 bytes |
| 4 | IP address | 4 bytes |
| 5 | subnet mask | 4 bytes |
| 6 | gateway | 4 bytes |
| 7 | firmware version | e.g. `"1.0.0 Build 20230218 Rel.50633\0"` |
| 8 | hardware version | e.g. `"TL-SG108E 6.0\0"` |
| 9 | DHCP enabled | 1 byte |
| 13 | auto-save | 1 byte |
| 14 | is-factory | 1 byte |
| 15 | internal | 4 bytes (seen on TL-SG1016PE `00 1c 00 00`) |
| 16 | capability | 1 byte (seen on TL-SG1016PE `01`) |
| 512 | username | login SET |
| 514 | password | login SET (obfuscated in debug log via `util.mine`) |
| 528 | **RSA session key** | new protocol — value is RSA-encrypted 8-byte session key |
| 2305 | get_token_id | empty GET that returns a fresh token in the header |
| 4096 | port configuration/stats | |
| 16384 | port statistics | |

(`global.acknowledge.fq = 528`, `global.thing.eI = 4098` in the utility.)

---

## 5a. Configuration operations (GET/SET TLV map)

All SET requests are `op=3` and **must prepend TLV 512 (username) and TLV 514 (password)** — the switch
authenticates every write, not just login. Most reads are `op=1` with an empty TLV of the relevant type.

| Operation | GET TLV | SET TLV(s) | Value layout (big-endian) |
|-----------|---------|------------|---------------------------|
| Description / hostname | – | **2** (+9,4,5,6) | string+NUL; plus dhcp(1B), ip/mask/gw(4B each) |
| IP settings | 9 | **9,4,5,6,11** | dhcp int32, ip/mask/gw 4B, mgmt-vlan 2B |
| LED on/off | 12 | **12** | 1B |
| User account | 512 | **514,513,515** | old-pwd, new-username, new-pwd (NUL strings) |
| Save config | – | **2304** | (none) |
| Reboot | – | **773** | 1B (1) |
| Factory reset | – | **1280** | (none) |
| Config backup | – | **768** (SET) | response TLV 768 = config blob |
| Config restore | – | **769** (SET) | config blob |
| Port settings | 4096 | **4096** | per port: port, enabled, 0, speed, 0, flow, 0 (7B) |
| IGMP snooping | 4352 (+4354) | **4352 + 4354** | snooping 1B; report-suppression 1B |
| LAG / trunk | 4608 | **4608** | lag-id 1B, member mask 4B |
| MTU VLAN | 8192 | **8192** | enabled 1B, uplink port 1B |
| Port-based VLAN | 8448 | **8448** status, **8449** entry | entry: vid 1B, member mask 4B |
| 802.1Q enable | 8704 | **8704** | 1B |
| 802.1Q VLAN entry | 8705 | **8705** | vid 2B, member mask 4B, tagged mask 4B, name, NUL |
| 802.1Q PVID | 8706 | **8706** | per port: port 1B, pvid 2B |
| QoS mode | 12288 | **12288** | 1B (0=port, 1=802.1p, 2=DSCP) |
| QoS port priority | 12289 | **12289** | per port: port 1B, priority 0–3 |
| Ingress bandwidth | 12544 | **12544** | per port: port, enabled, rate 4B (kbps, multiple of 64) |
| Egress bandwidth | 12545 | **12545** | same as ingress |
| Storm control | 12800 | **12800** | port, enabled, unknown-unicast, multicast, broadcast, rate 4B |
| Port mirror | 16640 | **16640** | enabled 1B, mirror-port 1B, ingress mask 4B, egress mask 4B |
| Loop prevention | 17152 | **17152** | 1B |

Notes:
- Port bitmasks use bit *n-1* for port *n* (LSB = port 1), 32-bit big-endian.
- Rate limits are quantised to multiples of 64 kbps (minimum 64); 0 means unlimited.
- 802.1Q member mask is the union of tagged+untagged ports; the tagged mask is the tagged subset.
- Reconfiguring the port that carries management may drop the reply; treat a timeout as "applied".

## 6. Crypto layer 1 — legacy static RC4

- 8-bit RC4 over a 256-byte state.
- The key schedule is built once from a **264-byte key blob** that is first decoded to a string and then run
  through standard RC4 KSA (`of.aM()`), producing the table `of.ol`.
- Standard RC4 PRGA (`of.Code`). Encryption and decryption are identical.
- The same static key is used for every device and every session. Known plaintext in the wild begins with the
  header `01 xx`; older public writeups describe the key string beginning `Ei2HNryt…`.

This layer is still accepted by all tested firmware, and is used for **discovery** and for the **RSA request**
(which must be sent with the static key).

---

## 7. Crypto layer 2 — "upgraded" RSA + session RC4

### 7.1 Session key generation (`of.aM()`)

```
oo = new util.mine(8).bt();      // 8 characters
```

`util.mine` uses `java.security.SecureRandom` and the alphabet `A–Z a–z 0–9`. So the session key is
**8 alphanumeric characters** (≈47 bits). It is generated once per process (per utility run) and reused for
every switch until re-generated.

### 7.2 RSA key exchange (`RSAKeyBean` + `transfer.I.I`)

The utility sends a **SET (op=3)** request whose only TLV is type **528**, containing:

```
value = RSA_encrypt( session_key_bytes )
```

`RSA_encrypt` is the custom big-number routine `transfer.I.I(byte[], int)`:

- public exponent **e = 65537**
- modulus comes from one of two hardcoded short arrays in `transfer.I`, selected by `util.From.bw()`:
  - `oF` (8 × 16-bit words) when `bw()` is **false** → 64-bit modulus
  - `oG` (128 × 16-bit words) when `bw()` is **true** → 1024-bit modulus (array holds 2048 bits, 1024 used)
- message bytes are placed **reverse order** into the bignum; result is serialized with a leading `00` byte and
  little-endian 16-bit limbs.

For this switch the small modulus has been **validated** as:

```
n = 0xB3FAB9D6646D4EBF          (64-bit, from oF)
e = 65537
```

Message encoding (validated against live capture): the 8-byte session key is interpreted **little-endian** as
the integer `m`; `c = m^e mod n`; the TLV value is `00 04 <c little-endian, 8 bytes>`.

`oF = {191, 78, 109, 100, 214, 185, 250, 179}`

`oG = {29,26,204,231,123,126,25,129,162,172,135,140,186,197,215,219,96,215,162,51,71,152,186,217,177,249,
172,144,251,51,74,249,24,76,52,82,16,22,47,247,136,34,75,3,148,149,102,123,108,95,28,65,78,226,244,64,186,
81,66,4,63,13,235,197,125,147,210,98,124,137,199,214,75,41,22,241,100,82,166,246,3,112,235,105,22,209,231,
18,144,92,125,233,234,50,162,96,164,77,197,197,40,226,246,63,202,201,59,152,178,49,145,26,37,69,225,171,
228,180,109,170,55,41,52,65,95,187,221,229}`

### 7.3 RSA acknowledgement

The switch replies with **op=4, error code = 4098**, encrypted with the **new session key** (the receiver must
decrypt the RSA response with the session key, not the static key). There are no TLVs.

`RSAKeyBean.handleResponse()` sets success iff `errorCode == 4098`; on success the utility records the switch
MAC in `transfer.This.nV`, which is what flips subsequent packets to session-key encryption.

### 7.4 Session-key RC4 (`of.V`)

An **8-byte-state RC4**:

```
om   = 8
on[] = KSA(key = session_key_bytes, size = 8)
PRGA: i = (i+1) % 8; j = (j + S[i]) % 8; swap(S[i],S[j]); ks = S[(S[i]+S[j]) % 8]
```

This is a trivially weak cipher (8-element state), but it is what the device uses once the session is
established.

### 7.5 Encryption selection rule (`of.Code(byte[], boolean, String switchKey)`)

```
if (opcode == 0 /*discovery*/  ||  isRSARequest)      -> static RC4
else if (This.nV.get(switchMAC) != null
         && This.nV.get(switchMAC) != thing.nX)       -> session RC4
else                                                   -> static RC4
```

After a successful RSA exchange, `nV[switchMAC] = nY`, so every later GET/SET/login uses the session key.

### 7.6 Receive-side auto-detection (`transfer.darkness`)

The utility decrypts an incoming datagram with the static key first; if the result is a plausible header
(`byte0 == 1 && byte1 < 5`) it keeps it, otherwise it decrypts the original bytes with the session key.
Clients can use the same heuristic.

---

## 8. Full handshake (new protocol)

```
 client                                                        switch
   |  DISCOVERY  op=0, static RC4, swMAC=0, broadcast  --------->  |
   |  <--------------  op=2, static RC4, device info TLVs          |
   |  GET get_token_id op=1 TLV 2305, static RC4  -------------->  |
   |  <--------------  op=2, static RC4, token in header           |
   |  SET op=3 TLV 528 = RSA(session_key), STATIC RC4 ---------->  |
   |  <--------------  op=4 errCode=4098, SESSION RC4              |   <-- session established
   |  GET get_token_id op=1 TLV 2305, SESSION RC4 -------------->  |   <-- refresh token
   |  <--------------  op=2, SESSION RC4, token in header           |
   |  SET op=3 TLVs 512/514 (login), SESSION RC4 ---------------->  |
   |  <--------------  op=4 errCode=0, SESSION RC4                 |
   |  GET/SET anything, SESSION RC4                             ->  |
   |  <--------------  op=2/op=4, SESSION RC4                      |
```

> The login SET **must carry the token** returned by a token GET performed *after* the session is
> established. Login with token 0 receives no reply.

---

## 9. Annotated capture (TL-SG108E 6.0, fw 1.0.0 Build 20230218)

Session key for this run: `m4l4TacP` (`6d 34 6c 34 54 61 63 50`). Static RC4 encrypts the whole packet; the
RSA request is op=3/TLV 528 and the response is session-key encrypted.

```
# 1) RSA request (SET op=3, TLV 528), STATIC RC4
plain : 0103 48225440a8d0 001122334455 0066 00000000 0032 0000 0000 0000 0000
        0210 000a 00040450d0a86305f32c ffff0000
enc   : 5d77222629fe1862fb7a24f050c07ef3422ba2f5d79daeed508f463dc202909a
        590381cc272e2f66997123b2576c96db5971
#   header: op=3 (SET), length=0x32=50, seq=0x0066
#   TLV 0x0210 (528), len 10, value = 00 04 0450d0a86305f32c   (RSA(session_key))

# 2) RSA response, SESSION RC4 (decrypted view)
raw   : 06054f205247abd5041721324155066604071101072701040204020704020200fefe0304
dec   : 0104 48225440a8d0 001122334455 0066 00001002 0024 0000 0000 0000 0000 ffff0000
#   op=4 (SET response), errCode=0x00001002=4098  -> RSA OK / session key accepted

# 3) GET port statistics (TLV 16384), SESSION RC4 (session key m4l4TacP)
plain : 0101 48225440a8d0 001122334455 0067 00000000 0028 0000 0000 0000 0040 0000 ffff0000
        0210?  -> actually TLV 0x4000 (16384), len 0
enc   : 06004f205247abd5041721324155066704070103072b0104020402070402020041010304fdff0701
dec   : 0102 48225440a8d0 001122334455 0067 00000000 00dc ... 4000 0013 0101 00...
#   op=2, 8 TLVs of type 16384 (per-port counters), success
```

(Types are big-endian: `40 00` = 16384, `10 00` = 4096.)

### 9.x mode comparison (fresh session key per attempt)

| mode | `From.bw()` | RSA cipher len | RSA ACK | session-key GET |
|------|-------------|----------------|---------|-----------------|
| natural (real fw `1.0.0`) | false | 10 bytes | err=4098 | **op=2, err=0 (works)** |
| forced 1024-bit (`oG`) | true | 130 bytes | err=4098 | op=-1, err=-1 (fails) |
| forced small (`oF`) | false | 10 bytes | err=4098 | **op=2, err=0 (works)** |

---

## 10. `From.bw()` — firmware gating

`util.From.bw()` returns whether to use the large RSA key. It compares the firmware version prefix
(everything before the first space) against `1.0.0` (most models) or `1.0.1` (a few), or returns `true`
unconditionally for one group. For **TL-SG108E 6.0 / firmware `1.0.0` it returns false** → 64-bit key.

This means the "upgraded management protocol" is present on this very firmware (the switch answers TLV 528 and
establishes the session), but uses the small key; newer firmware revisions use the larger key.

---

## 11. Reference implementations

### 11a. Standalone Perl client (no utility code)

`tools/easysmart_client.pl` implements the entire protocol from scratch (static RC4, 8-byte-state session
RC4, and 64-bit RSA via `Math::BigInt`). Verified end-to-end against the TL-SG108E 6.0:

```
$ perl tools/easysmart_client.pl 10.0.0.106 admin admin1
... RSA accepted (4098); switching to session key
... login result: op=4 err=0
... stats result: op=2 err=0
... ports result: op=2 err=0
```

### 11b. Java harness (uses the official utility's crypto classes)

`harness/Harness.java` is a working Java reference client. It reuses the utility's own crypto classes
(`com.tplink.smb.easySmartUtility.transfer.of` for both RC4 modes and `.I` for RSA) while performing UDP itself
and logging every packet in clear and encrypted form. Run it with a JavaFX 8 JRE (needed only because the
utility's classes reference JavaFX types); the harness itself does not open a UI.

```
javac --release 8 -cp escu_inner.jar:<jfxrt.jar> -d harness harness/Harness.java
java  -cp escu_inner.jar;harness Harness
```

Standalone re-implementation checklist:
1. Static RC4 table from the 264-byte key blob (see `transfer.of.aM`).
2. 8-char SecureRandom session key; 8-byte-state RC4 (`of.V`).
3. RSA: e=65537, modulus from `oF`/`oG` selected by firmware; serialize as `transfer.I.I`.
4. Build/parse the 32-byte header; increment the sequence number on every request.
5. On receive, try static decrypt; if header invalid, session decrypt.

---

### 11c. Go library (`go/`, package `escp`)

Pure-Go, standard-library only. Implements ESCP framing, both RC4 variants and both RSA session modes, and a
**security-first negotiation with automatic fallback**:

```
SecurityRSABig (1024-bit)  ->  SecurityRSASmall (64-bit)  ->  SecurityStaticRC4 (legacy)
```

`Login` sends discovery, then attempts the strongest usable mode. Each RSA attempt is *verified* with a
session-key `get_token_id` probe, because some firmware answers `err=4098` yet does not actually adopt the
large key (this is the case for TL-SG108E fw `1.0.0`). On success `Client.Mode` reports the negotiated mode.

```go
c := escp.NewClient("10.0.0.106", "admin", "admin1")
defer c.Close()
if err := c.Login(ctx); err != nil { log.Fatal(err) }
fmt.Println(c.Mode)          // e.g. "RSA-64 session"
fmt.Println(c.SystemInfo())  // model, hw, fw, mac, ip, ...
stats, _ := c.GetPortStats(ctx)
```

Exported API: `NewClient`, `Discover`, `Login`, `Get`, `GetPortStats`, `GetPorts`, `SystemInfo`, `Close`;
`Client.SecurityOrder` overrides the fallback order.

**Post-login configuration** (all writes automatically prepend the credentials and use the negotiated session):

```go
c.SetDescription(ctx, "core-sw")                       // TLV 2 (+ IP TLVs)
c.SetIP(ctx, false, ip, mask, gw, 1)                   // static IP
c.SetLED(ctx, true)
c.SetPort(ctx, escp.PortConfig{Port: 1, Enabled: true, Speed: escp.SpeedAuto})
c.SetQoSMode(ctx, escp.QoSDSCP)
c.SetPortPriority(ctx, 1, 3)
c.SetIGMPOptions(ctx, true, false)
c.SetLoopPrevention(ctx, true)
c.SetIngressBandwidth(ctx, escp.Bandwidth{Port: 1, Enable: true, Kbps: 100000})
c.SetEgressBandwidth(ctx, escp.Bandwidth{Port: 1, Enable: true, Kbps: 100000})
c.SetStormControl(ctx, escp.StormControl{Port: 1, Enable: true, Broadcast: true, Kbps: 8000})
c.SetMirror(ctx, escp.MirrorConfig{Enabled: true, MirrorPort: 8, Ingress: []int{1}, Egress: []int{1}})
c.AddDot1QVLAN(ctx, escp.Dot1QVLAN{VID: 10, Name: "servers", Untagged: []int{1, 2}, Tagged: []int{8}})
c.SetPVID(ctx, map[int]uint16{1: 10, 2: 10})
c.SetTrunk(ctx, 1, []int{3, 4})
c.SaveConfig(ctx)
c.Reboot(ctx)
```

Read counterparts exist for each (`GetIGMP`, `GetTrunks`, `GetMirror`, `GetDot1QVLANs`, `GetPortVLANs`,
`GetMTUVLAN`, `GetQoSMode`, `GetPortPriorities`, `GetBandwidth`, `GetStormControl`, `GetLoopPrevention`).
`ExportConfig` pulls the raw backup; `FactoryReset` restores defaults. The CLI `dump` command reads them all.

CLI:

```
cd go
go run ./cmd/escpctl -host 10.0.0.106 -user admin -pass admin1 stats
go run ./cmd/escpctl -host 10.0.0.106 discover
```

Verified on the TL-SG108E 6.0: RSA-1024 attempted, correctly rejected as unusable, fell back to RSA-64,
logged in, and returned port statistics. Crypto vectors for all three primitives live in
`go/escp/crypto_test.go` (`go test ./...` passes).

## 12. Security notes

- The session key is transported with RSA but **stored/performed with an 8-byte RC4** and is only ~8
  alphanumeric chars. It is not strong cryptography.
- The "static key" RC4 path remains accepted; discovery and the RSA request itself are static-key encrypted.
- The 64-bit RSA modulus (fw `1.0.0`) is factorable instantly, trivialising recovery of the session key from a
  capture.
- Management traffic is broadcast by default and the protocol has no integrity protection.
- Mitigation: isolate switches in a dedicated management VLAN and do not expose UDP 29808/29809 or TCP 80.

---

## 13. References

- Official utility: Easy Smart Configuration Utility v1.3.20.0 (Windows, JavaFX; app is a jar-in-PE).
- `geekly.dev` — "TP-Link Easy Smart Configuration Utility Patch Review" (2023): RC4/TEA retained,
  new PRNG/RSA session encryption added.
- CVEs: CVE-2017-8074..8078 (static key / cleartext), CVE-2022-44231 (static-key encryption).
- Public prior work for the legacy protocol: `pklaus/smrt`, `rgl/ansible-collection-tp-link-easy-smart-switch`,
  `1-TB/TPLinkSwitchLibrary` (ESCP), `jfrancis42/tplink-tool` (HTTP UI).
```
