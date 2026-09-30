# TL-SG108E research & tooling — documentation index

Target: **TP-Link TL-SG108E V6.0**, firmware `1.0.0 Build 20230218 Rel.50633`
(Realtek RTL8370N 8051 management CPU + Winbond 25Q16JVSIQ 2 MiB SPI flash).
All findings were validated against a live device.

| | |
|---|---|
| MAC | `48:22:54:40:A8:D0` |
| IP | `10.0.0.106`, GW `10.0.0.1` |
| Creds | `admin:admin1` (web UI and ESCP) |

## Status
The firmware container is **fully solved**: same-size edits and arbitrary-size
images both build and flash through the default loader (no bootloader or flash
modification). The remaining work is **authoring custom firmware** — 8051 code in
segment B plus redirecting the app's entry/call sites (see `FIRMWARE_FORMAT.md`
and `HTTP_SERVER_RE.md`). The switch has been restored to the pristine stock
image (`firmware/stock_6.0_1.0.0_20230218.bin`, sha256 `dd09d6a13e40...`) and is
reachable at `10.0.0.106`.

## Documents
- [FIRMWARE_FORMAT.md](FIRMWARE_FORMAT.md) — `.bin` header, `f8`/`f12`
  additive checksums, the rendered layout, and same-size + arbitrary-size build
  workflows.
- [DISASSEMBLY_NOTES.md](DISASSEMBLY_NOTES.md) — bootloader self-check, app/loader
  banked code, string addresses, checksum routine.
- [LOADER_MODE.md](LOADER_MODE.md) — the unauthenticated bootloader web UI,
  endpoints and the upload/flash protocol.
- [SPI_FLASH_RECOVERY.md](SPI_FLASH_RECOVERY.md) — flash chip, CH341A + flashrom
  dumping and un-bricking.
- [HARDWARE_AND_RECON.md](HARDWARE_AND_RECON.md) — board, open ports, RRCP, TFTP,
  and historical CVEs.
- [EASY_SMART_ESCP.md](EASY_SMART_ESCP.md) — the management protocol
  (ESCP/HTTP, RC4 static key, and the 2023 RSA session-key variant), TLV map,
  config operations, and the Go client library.
- [HTTP_SERVER_RE.md](HTTP_SERVER_RE.md) — the app's `httpd.c`/lwIP layering,
  CGI router/trampoline tables, banked-code addressing, and the plan for adding
  a custom CGI handler.

## Tools (`tools/`)
- `patch_firmware.pl` — inspect/verify/patch a `.bin` (same size), recomputing
  `f8`/`f12`. Supports byte patches, equal-length string replacement, and
  sum-neutral transposition.
- `build_firmware.pl` — arbitrary-size builder: `info`/`verify`/`append`
  (`--data`/`--append-hex`/`--zero`, `--model a|b`).
- `flash_via_loader.sh` — enter loader mode and flash a `.bin` through the
  default loader, reporting accept/reject and boot status.
- `easysmart_client.pl` — standalone ESCP client (static RC4 + RSA session +
  session RC4).
- `discover_legacy.pl`, `probe_legacy.pl` — ESCP discovery/login probes.
- `align.pl` — `.bin`↔flash byte-histogram alignment (used to map the container).
- `re_map.pl` — `.bin`/payload/flash/banked-CPU address mapping and region/string
  dump helpers for the HTTP/CGI reverse-engineering.
- `rrcp.pl`, `rrcp_probe.pl`, `rrcp_bruteforce.pl`, `rrcp_unlock.pl` — RRCP
  (EtherType `0x8899`) raw-frame tools; need root (`pkexec`). Hello/discovery
  works; register GET/SET is unavailable (probed, auth brute-forced, and
  security-mask write attempted — hello-only responder).
- `udpscan.pl` — UDP port scan helper.

## Go library (`go/`)
- `go/escp` — ESCP client: discovery, security-negotiated login
  (RSA-1024 → RSA-64 → legacy), and post-login config operations.
- `go/cmd/escpctl` — CLI (`info`, `stats`, `dump`, `set-*`).

## Other artifacts
- `harness/Harness.java` — Java harness driving the official utility's crypto
  classes to capture the new protocol.
- `capture/newproto_trace.txt` — annotated new-protocol capture.
- `firmware/stock_6.0_1.0.0_20230218.bin` — target firmware (sha256 `dd09d6a13e40...`);
  `firmware/6.0_20201208.bin` and `6.0_20220930.bin` are two older builds (for
  checksum comparison); `firmware/examples/*.bin` are built test vectors
  (neutral / delta / custom).
- `dumps/` — SPI flash dumps (`fixed.bin` = working).
- `re/` — `boot_region.bin`/`.asm` (bootloader, flash `0x0..0x1000`, + disassembly)
  and `firmware_strings.txt`.

## Reproduction / environment
- Investigated on a NixOS host; used
  `nix-shell -p radare2 binwalk jdk go wine steam-run unshield`.
- Official utility: `Easy Smart Configuration Utility v1.3.20.0` (`.exe.zip`);
  install under **Wine + Xvfb**, extract the inner jar from the app PE overlay at
  **offset `0xF800`**, then decompile with **CFR**.
- Firmware URLs (TL-SG108E V6/V6.6 pages):
  - 2023-02-18: `static.tp-link.com/.../TL-SG108E(UN) 6.0_1.0.0_20230218.zip`
  - 2022-09-30 and 2020-12-08 also under `/upload/firmware/` and `/2020/...`.
- Raw-socket / RRCP work needs root/CAP_NET_RAW (`pkexec` works here).

## Quick reference — the two checksums
```
f8  (u32 BE @ header+8)  = (sum(header[0:8]) + sum(header[12:20])) & 0xFFFF   # loader
f12 (u32 BE @ header+12) = sum(payload, excluding the 20-byte app header) + 0x13EC   # bootloader
```
Both header copies (`.bin` offset `0x0` and `0x4012`) must be updated. The
`f12` window **scales with the payload length**, so growing the image works:
`f12_new = f12_old + sum(bytes added)`.
