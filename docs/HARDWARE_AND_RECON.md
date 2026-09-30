# Hardware & network reconnaissance

TL-SG108E V6.0, firmware `1.0.0 Build 20230218 Rel.50633`.

## Board
- **RTL8370N** — Realtek switch ASIC with an embedded **8051** management CPU.
  Firmware is 8051 machine code (not Linux); the RTOS is proprietary/small.
- **Winbond 25Q16JVSIQ** — 2 MiB SPI NOR flash (3.3 V, SOIC-8) holding
  bootloader + application + config + MAC.
- No UART/test pads found. The RTL8370N has a UART but it is not broken out.

## Open services
| Transport | Port | Notes |
|-----------|------|-------|
| TCP | 80 | web UI (normal mode) / loader UI (loader mode) |
| UDP | 29808 → switch | ESCP / Easy Smart Configuration Protocol |
| UDP | 29809 ← switch | ESCP replies |

No SSH/Telnet/SNMP/HTTPS. Unknown UDP ports are **silently dropped** (no ICMP),
so a port scan cannot distinguish open from filtered.

## Management protocols
- **HTTP web UI** — frameset CGI; login `POST /logon.cgi` sets cookie
  `H_P_SSID` (600 s). State is in `*Rpm.htm` JS blocks; writes go to `*.cgi`.
- **ESCP over UDP 29808/29809** — 32-byte header + TLVs, RC4 with a hardcoded
  key, plus the 2023 "upgraded" RSA session-key variant. Fully documented in
  `EASY_SMART_ESCP.md`.
- **Loader mode HTTP** — unauthenticated bootloader UI:
  `LOADER_MODE.md`.

## Realtek Remote Control Protocol (RRCP) — **hello reply only**
The switch does speak RRCP (Realtek's L2 register-access protocol). Tested live
2026-09: it replies to RRCP `hello`, but register GET/SET is unavailable (see
below).

- **Transport:** raw Ethernet, **EtherType `0x8899`** (no IP/UDP).
- **Payload (RRCP proto = 1):**
  ```
  0  proto       1  (RRCP);  2 = REP, 3 = RLDP
  1  opcode|reply   opcode: 0 hello, 1 get, 2 set; 0x80 = reply bit
  2  authkey      u16 BE, default 0x2379
  4  regaddr      u16 LE
  6  regdata      u32 LE
  10 cookie1      u32
  14 cookie2      u32
  ```
- **Observed HELLO reply** (unicast back to us, 60 bytes on the wire):
  ```
  8045dd30e1ed 48225440a8d0 8899 | 01 80 2379 0700 00000000 70010000 ...
  dst=us            src=switch     proto=1 opcode=0x80 auth=0x2379 reg=0x0007
  ```
  i.e. proto `1`, opcode `0x80` (reply), auth `0x2379`, reg `0x0007`, data `0`.
  The extended hello fields (downlink/uplink/uplink-MAC/vendor/chip) are zero on
  this model.
- **GET/SET: not available.** Exhaustively probed (`tools/rrcp_probe.pl`): opcodes
  0 (hello) and 1 (get), auth `0x2379`, registers `0x0000,0x0002,0x0007,0x0100,
  0x0200,0x0201,0x0202,0x0206,0x0207,0x0208`, destination broadcast and unicast to
  the switch MAC, cookies `0` / random / echoed-from-hello — **no GET reply in any
  case** (only the hello reply). A full **16-bit auth-key brute force**
  (`tools/rrcp_bruteforce.pl`, keys `0x0000..0xffff`, read-only) also produced
  **no reply**, so the auth key is not the gate. Finally, writing the **RRCP
  security-mask registers** `0x0201`/`0x0202` (both `0x00000000` and `0xFFFFFFFF`,
  `tools/rrcp_unlock.pl`) did **not** enable GET — the writes appear to be ignored
  (hello still replies, device unaffected). Conclusion: the switch implements a
  **hello-only RRCP responder**; there is no register read/write engine to unlock.
  RRCP is closed for management purposes on this model.
- **Tools:** `tools/rrcp.pl` (hello/get), `tools/rrcp_probe.pl` (register/cookie
  sweep), `tools/rrcp_bruteforce.pl` (auth-key brute force), `tools/rrcp_unlock.pl`
  (security-mask write probe). All need root/CAP_NET_RAW; run via `pkexec`/`sudo`:
  ```bash
  pkexec perl tools/rrcp.pl wlp0s20f3 hello          # -> HELLO reply
  pkexec perl tools/rrcp_probe.pl wlp0s20f3          # register/cookie sweep
  sudo /run/current-system/sw/bin/perl tools/rrcp_bruteforce.pl wlp0s20f3
  ```
  Best run from a **wired** NIC on the same L2 segment; here it worked over Wi-Fi.

## TFTP
The loader page text says "upload by TFTP or HTTP", but **no TFTP server is
listening** — RRQ/WRQ/garbage to UDP/69 get no response in normal *or* loader
mode. It is generic SDK text, not an active feature on this firmware.

## Other CVEs / history
- CVE-2017-8074..8078 (static RC4 key, cleartext creds, `httpupg.cgi` cmd) —
  apply to V1-era firmware; the static key path still exists but is not the
  immediate issue on V6.6.
- CVE-2022-44231 (static-key encryption) — led to the RSA/session-key update.
