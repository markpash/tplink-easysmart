# tplink-easysmart

Reverse-engineering research and tooling for the **TP-Link TL-SG108E V6.0**
"Easy Smart" managed switch (Realtek RTL8370N 8051 CPU, Winbond 25Q16JVSIQ
2 MiB SPI flash, firmware `1.0.0 Build 20230218 Rel.50633`).

## What was found

- **Firmware container solved.** The `.bin` is a 20-byte header (duplicated at
  `0x4012`) + payload with two additive checksums (`f8` for the loader, `f12`
  for the bootloader). Same-size edits *and* arbitrary-size images build and
  flash through the unauthenticated default loader — no bootloader or flash
  programmer needed. Remaining work is authoring custom 8051 code.
- **Management protocol reverse-engineered.** ESCP over UDP 29808/29809
  (static-key RC4 + the 2023 RSA/session-key variant) plus the HTTP web UI.
- **Loader mode, recovery, and recon documented** (CH341A/flashrom recovery;
  RRCP is a hello-only responder; no TFTP).

## Layout

| Path | Contents |
|------|----------|
| `docs/` | Write-ups — **start at [`docs/README.md`](docs/README.md)** |
| `tools/` | Perl/shell tools (patch, arbitrary-size build, flash, ESCP, RRCP) |
| `go/` | Pure-Go ESCP client library + `escpctl` CLI |
| `harness/` | Java harness reusing the official utility's crypto classes |
| `firmware/` | Stock + older firmware builds and built test vectors |
| `dumps/` | SPI flash dump (`fixed.bin`, a known-good working image) |
| `re/` | Bootloader bytes/disassembly and firmware strings |
| `capture/` | Annotated capture of the 2023 protocol handshake |

## Quick start

```bash
# Inspect / verify a firmware image
tools/build_firmware.pl info   firmware/stock_6.0_1.0.0_20230218.bin

# Same-size edit (e.g. swap a UI string)
tools/patch_firmware.pl patch stock.bin out.bin \
    --replace 'Here you can configure=HERE you can configure'

# Flash through the default loader
tools/flash_via_loader.sh 10.0.0.106 admin admin1 out.bin
```

See [`docs/FIRMWARE_FORMAT.md`](docs/FIRMWARE_FORMAT.md) for the format and
[`docs/EASY_SMART_ESCP.md`](docs/EASY_SMART_ESCP.md) for the protocol details.

## Status

Firmware format fully solved; the switch is on its pristine stock image. The
open task is authoring custom 8051 firmware and redirecting the app's
entry/call sites — see [`docs/HTTP_SERVER_RE.md`](docs/HTTP_SERVER_RE.md).
