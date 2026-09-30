# Disassembly notes (bootloader, app, loader)

Raw reverse-engineering notes for the TL-SG108E V6.0. These back the claims in
`FIRMWARE_FORMAT.md`.

## 1. Method
- 8051 disassembly with `r2` (`radare2`): `nix-shell -p radare2 --run \
  "r2 -a 8051 -b 8 -q -c 'e scr.color=0; pD <n>' <file>"`.
- Sources: the flash dump `dumps/fixed.bin` (full 2 MiB image) and the update
  `.bin` (`firmware/stock_6.0_1.0.0_20230218.bin`).
- Saved artifacts: `re/boot_region.bin` (flash `0x0..0x1000`),
  `re/boot_region.asm` (its disassembly), `re/firmware_strings.txt`.
- Container mapping used `tools/align.pl` (byte-histogram alignment of the `.bin`
  against the flash dump). See `FIRMWARE_FORMAT.md` §6 for the result.

## 2. Flash map (2 MiB, Winbond 25Q16)
```
0x000000  bootloader (8051), includes the startup self-check below
0x1D000   app header  == .bin[0x4012] rendered (second copy of the 20-byte header)
0x1D014   app payload begins
0x1FC000  persistent config / MAC ("TL-SG108E", MAC 48:22:54:40:a8:d0 ...)
0x200000  end of flash
```
The `0x18000` gap (`.bin`-external) sits at flash `0x3E0E..0x1BE0E`.

## 3. Bootloader self-check (flash `0x0..0x1000`)

### Entry / vectors
- `0x0000` reset vector; `0x000d` `ljmp 0x0deb`; `0x0015` `ljmp 0x0f0b`, etc.
- A small routine exists at `0x0000` (`jc 0x0005; ...; mov a,r7; clr c; jz 0x000a;
  setb c; mov 0x20.0,c; ret`) — a bit/flag helper.

### Additive checksum verify (the routine that guards boot)
Observed at flash `0x0018` onward (see `re/boot_region.asm`):

```
0x0018  90 0e5e        mov dptr,#0x0e5e
0x001b  12 089f        lcall 0x089f        ; store 4 bytes (r4..r7=0) -> RAM 0x0e5e..0x0e61
0x001e  e4             clr a
0x001f  ff fe fd fc    mov r7/r6/r5/r4 = 0
0x0023  90 0e62        mov dptr,#0x0e62
0x0026  12 089f        lcall 0x089f        ; store 4 bytes = 0 -> RAM 0x0e62..0x0e65
0x0029  c0 96          push 0x96           ; save code-bank SFR
0x002b  75 96 03       mov 0x96,#0x03     ; select a code bank
0x002e  e4             clr a
0x002f  ff 7e c0 fd fc mov r4..r7 = 0x00C00000
0x0034  90 0e5e        mov dptr,#0x0e5e
0x0037  12 0835        lcall 0x0835
0x003a  c3             clr c
0x003b  12 0792        lcall 0x0792        ; 32-bit compare (r4..r7 vs mem@dptr)
0x003e  50 03          jnc 0x0043
0x0040  02 00a1        ljmp 0x00a1
...
0x0043  e4 fc fd fe    clr a; r4=r5=r6=0
0x0047  90 4000        mov dptr,#0x4000
0x004a  e4 f8 f9 fa    clr a; r0=r1=r2=0
0x004e  e4 93          clr a; movc a,@a+dptr      ; page-sum inner loop
0x0050  28 f8          add a,r0 ; mov r0,a
0x0052  e4 39 f9       clr a; addc a,r1; mov r1,a
0x0055  a3             inc dptr
0x0056  da f6          djnz r2,0x004e             ; 256 bytes/page
0x0058  e8 2c fc       mov a,r0; add a,r4; mov r4,a
0x005b  e9 3d fd       mov a,r1; addc a,r5; mov r5,a
0x005e  e4 3e fe       clr a; addc a,r6; mov r6,a
0x0061  e5 83          mov a,0x83        ; DPH
0x0063  70 e5          jnz 0x004a        ; loop over pages until DPH wraps
```

Then the accumulated page value is added into the 4-byte accumulator at XRAM
`0x0e62..0x0e65` (`0x0065..0x007d`, using `movx @dptr`), the **code-bank SFR
`0x96` is incremented** (`0x007e..0x0081`), and the outer loop at `0x002c`
repeats (subtracting `0x00C00000` from `r4..r7` each pass, via `0x0089..0x009d`).

Helper routines referenced:
| addr | role (observed) |
|------|-----------------|
| `0x0792` | 32-bit compare of `r4..r7` vs memory at DPTR |
| `0x0819` | load 4 bytes from DPTR into `r4..r7` |
| `0x0835` | load/convert 4 bytes at DPTR |
| `0x089f` | store `r4..r7` (4 bytes) to DPTR |

**Interpretation (updated):**
- The check is a pure **32-bit additive byte-sum** over the app's logical image
  (`== .bin payload`, segment A ++ segment B). No hash/crypto.
- A clean inner checksum loop exists at **flash `0x00bc`** (see below).
- The `0x4000` start is the app's CPU base (payload offset `0`), not an offset
  into the payload.
- Empirically (three builds + live tests) the value at header `+12` equals
  `sum(payload excluding the 20-byte app header) + C`; on this device `C = 0x13EC`,
  and the app header is **excluded** from the sum. Confirmed live that the window
  scales with payload length. See `FIRMWARE_FORMAT.md` §6.

### The checksum routine at `0x00bc` (clean decode)
```
0x00bc  e8        mov a,r0
0x00bd  49        orl a,r1
0x00be  60 15     jz 0x00d5          ; count (r1:r0) == 0 -> store result
0x00c0  18        dec r0
0x00c1  b8 ff 01  cjne r0,#0xff,0x00c5
0x00c4  19        dec r1
0x00c5  e4        clr a
0x00c6  93        movc a,@a+dptr     ; read code byte
0x00c7  2c  fc    add a,r4 ; mov r4,a
0x00c9  e4 3d fd  clr a ; addc a,r5 ; mov r5,a
0x00cc  e4 3e fe  clr a ; addc a,r6 ; mov r6,a
0x00cf  e4 3f ff  clr a ; addc a,r7 ; mov r7,a
0x00d2  a3        inc dptr
0x00d3  80 e7     sjmp 0x00bc
0x00d5  90 0e62  mov dptr,#0x0e62  ; store r7,r6,r5,r4 (big-endian) to XDATA
0x00e3  d0 96    pop 0x96
0x00e8  12 08 19 lcall 0x0819
0x00eb  22       ret
```
Entry at `0x00a3` loads `r1:r0` = 16-bit byte count from XDATA `0x0e60/0x0e61`,
`r7..r4` = 32-bit seed from `0x0e62..0x0e65`, sets `dptr=0x4000`, and calls the
loop. So this is **"sum N bytes of code from `0x4000` into a 32-bit accumulator"**;
the outer routine (flash `0x0018`) iterates it over **code banks** (SFR `0x96`),
adding each bank's partial sum into XDATA `0x0e62..0x0e65`.

### Code-bank trampoline table (flash `0x0102..` + `0x1102..`)
Repeated 12-byte records:
```
85 96 bb   mov 0xbb,0x96      ; save current bank
75 96 NN   mov 0x96,#NN       ; select bank NN
31 18      acall 0x0118       ; run the per-bank routine in the new bank
85 bb 96   mov 0x96,0xbb      ; restore
22         ret
```
and a dispatch table of `90 <addr16> 02 01 00` = `mov dptr,#str ; ljmp 0x0100`
(URL -> handler), i.e. the loader's HTTP command router. SFR **`0x96` = code
bank**; SFRs **`0xa0..0xab` = the SPI-flash controller** (address/data + command
trigger at `0xa0`). This banked/indirect model is why flat 8051 xrefs fail.

**Fail behavior:** mismatch branches to `0x00a1` (halt/no network); there is no
auto-loader fallback. See `SPI_FLASH_RECOVERY.md`.

## 4. App + loader (banked 8051)

### String addresses in the update `.bin`
| offset | string |
|--------|--------|
| `0x10442` | `Loader Mode` |
| `0x3F9C7`, `0xE09FC` | `reboot.cgi` |
| `0xE251F`, `0xE2550` | `upgrade_ds` |
| `0xE27D1` | `httpupg.cgi` |
| `0xE27E1` | `fw_upgrade` |
| `0xE2873` | `fupg_abort.cgi` |

The loader page HTML (in `re/firmware_strings.txt`) confirms the form:
`<form method=post enctype=multipart/form-data action="httpupg.cgi?cmd=fw_upgrade">`
with `<input name=firmware type=file>`, JS `upgrade_ds.firmwareStr` /
`.hardwareStr`, and buttons to `fupg_abort.cgi` / `reboot.cgi`. Template
leftovers: `1.3.5 Build 20081014 Rel.52990`, `TL-SG3424 1.0`.

### HTTP request-router code
- Around `.bin 0xAB100` there is router-looking code: `lcall` to string helpers
  (`0x287e`, `0x28b5`, `0x18ad`) and comparisons against 32-bit ids, e.g.
  `mov dptr,#0x99EA` (low 16 bits of a `reboot.cgi`-area pointer) at `.bin
  0xAB127`.
- **Banking problem:** string references use a **16-bit window + bank register**
  (not a flat pointer), so `mov dptr,#imm16` xrefs are ambiguous and the r2 8051
  plugin does not model banking. This is why the simple xref/constant searches
  were inconclusive.
- `.bin 0x1BA00` references `mov dptr,#0x9323` / `#0x9325` (likely memory-mapped
  registers) with calls to `0x2748`/`0x26d9`.

### Constants searched (results)
- `0x1D000` appears big-endian as `01 d0 00` at `.bin 0x1BA16`, `0x6825`,
  `0xB5DC` (and little-endian at `0x33323`).
- `0x2E20` (container split), `0x18FEE` (segment B delta), `0x18000` (gap) were
  **not** found as literal far-pointers — consistent with the loader deriving
  them from the header `length` rather than embedding them.

## 5. Container mapping (how §6 of FIRMWARE_FORMAT.md was derived)
`tools/align.pl` aligns the `.bin` to the flash dump using a moving-window byte
histogram. Result: header → `flash 0xFEE`, segment A (`bin[0x14..0x2E20]`) →
`flash 0x1002`, segment B (`bin[0x2E20..]`) → `flash 0x1BE0E` (delta `+0x18FEE`),
with an `0x18000` **gap** `flash 0x3E0E..0x1BE0E` that does not come from the
`.bin` and is not part of `f12`.

## 6. Where to resume
Resolved:
- The image checksum is an additive sum over the app payload (excluding the
  20-byte app header); the routine and its banked caller are identified (§3).
- The container render and the fixed runtime region are mapped
  (`FIRMWARE_FORMAT.md` §4/§6); segment A is fixed, segment B is fixed-start and
  grows into free flash.
- The loader reads the URL dispatch table and writes segments A/B (placement
  inferred from the flash dump).
- **The checksum window scales with the payload length** and the loader accepts a
  larger `length` — confirmed live with +18 B and +262144 B appends (both booted).
  Formula: `f12 = sum(payload excl. app header) + 0x13EC`.

Optional follow-ups (not needed for building firmware):
- Trace the `POST /httpupg.cgi?cmd=fw_upgrade` handler inside the banked code
  (dispatch table at `0x1102`; `mov dptr,#str; ljmp 0x0100`).
- Map the full code-bank ↔ flash layout if a loader-side reimplementation is
  ever wanted.
