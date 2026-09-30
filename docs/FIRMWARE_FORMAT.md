# TP-Link Easy Smart firmware format & customization

Applies to TL-SG108E V6 / V6.6 (RTL8370N + Winbond 25Q16JVSIQ), firmware
`1.0.0 Build 20230218 Rel.50633`. Verified against three firmware builds
(2020-12-08, 2022-09-30, 2023-02-18) and by live loader/boot tests.

## 1. The update file

The downloadable firmware is a single `.bin` (~1.085 MB here) with a **20-byte
header**, followed by the payload. The header is **duplicated** at file offset
`0x4012` (the `0x4012` copy is inside the payload region; both copies are
identical and both are updated by tooling).

```
offset  size  field
0       2     magic            12 34
2       2     type             10 86
4       4     payload length   big-endian, e.g. 00 10 f3 40 (0x10F340)
8       4     f8               header checksum  (low 16 bits used)
12      4     f12              image checksum   (32-bit)
16      4     magic            33 22 55 ff
```

Example (2023-02-18):
```
1234 1086 0010f340 00000593 03f1ca0d 332255ff
```

## 2. Checksums (both additive, no crypto)

Reverse-engineered from the bootloader disassembly and confirmed against three
official builds:

- **f8 — header checksum, validated by the *loader* before flashing.**
  `f8 = (sum of header bytes [0:8]) + (sum of header bytes [12:20])`, mod 2^16.
  Because it includes `f12`, changing `f12` also changes `f8`.
  Verified: `0x21F + 0x374 = 0x0593` (new), `0x05c9` (2022-09), `0x0613` (2020-12).

- **f12 — image checksum, validated by the *bootloader* at startup.**
  A 32-bit **additive byte-sum** over the image (the bootloader accumulates
  256-byte pages from code address `0x4000`, `add`/`addc`, no hash/signature).
  Editing N bytes changes `f12` by exactly `sum(new) - sum(old)`.

There is **no RSA/ECDSA/HMAC** anywhere in the verify path — only addition.

## 3. Why edits brick without fixing the checksums

- The **loader** checks `f8` but does **not** reject a changed payload with an
  unchanged `f8` — it flashes and reboots.
- The **bootloader** then recomputes the image sum and compares to `f12`; a
  mismatch halts before the network starts (LEDs on, device unreachable), and
  there is **no automatic loader fallback**. Recovery needs the SPI programmer
  (see `SPI_FLASH_RECOVERY.md`).

Conversely, changing `f12` without fixing `f8` is caught by the loader
(`Invalid image! Please double check!`), so the device stays in loader mode.

## 4. How the loader renders the `.bin` into flash (corrected)

The loader does **not** write the `.bin` verbatim, and it does **not** write the
container header. It splits the payload at payload offset `0x2E0C` (file
`0x2E20`) and writes the two pieces around a fixed, *shared* runtime region:

```
REGION                FLASH RANGE            SOURCE
boot/loader          0x000000..0x001002     fixed, NOT from .bin
segment A            0x001002..0x003E0E     .bin[0x14..0x2E20]   (0x2E0C bytes)
shared runtime       0x003E0E..0x01BE0E     fixed, NOT from .bin  (0x18000 bytes)
segment B (app)      0x01BE0E..LAST         .bin[0x2E20..end]
free                   ...  ..0x1FC000       (0xFF)
config               0x1FC000..0x200000
```

- The `0x18000` runtime region is **not padding** — it contains a fixed shared
  library (lwIP TCP/IP stack + SPI-flash driver; strings like `SYN-SENT`,
  `load MAC from nvcfg`, `flash write area is protected`, `SPI FLASH VIEWER`).
  It is **not** present in the update `.bin` and is **not** part of `f12`. The
  loader preserves it (it does not erase the whole chip).
- In the app's logical (CPU) address space, segment A and segment B are
  **contiguous** (the runtime is banked out of the app's linear image), so the
  logical app image == the `.bin` payload (`file[0x14:]`).
- The `.bin[0x4012]` header copy lands at flash `0x1D000`, i.e. at payload offset
  `0x3FFE` (the app's own header), and is the copy the bootloader reads.

Practical consequence: **segment A is fixed at `0x2E0C` bytes** (bounded by the
runtime at `0x3E0E`); **segment B starts at a fixed flash `0x1BE0E` and can grow**
up to the config at `0x1FC000`. The whole segment-B window is `0x1E01F2` bytes
(`0x1BE0E..0x1FC000`); the stock app uses `0x10C534`, leaving `0xD3CBE`
(~865 KB) free.

## 5. Customization workflow

1. Take the stock `.bin`.
2. Apply edits (same size):
   - byte patches at a file offset, or
   - equal-length string replacements (handy for the embedded web UI).
3. Recompute the checksums:
   - `f12 += sum(new_bytes) - sum(old_bytes)` (mod 2^32)
   - `f8 = (sum(header[0:8]) + sum(header[12:20])) & 0xFFFF`
   - apply to **both** header copies (`0x0` and `0x4012`).
4. Flash through the default loader — no bootloader/flash modification, no
   programmer.

`tools/patch_firmware.pl` does all of this:

```bash
# inspect / validate
tools/patch_firmware.pl info   stock.bin
tools/patch_firmware.pl verify stock.bin            # checks f8

# byte patch (offsets are in the .bin)
tools/patch_firmware.pl patch stock.bin out.bin '0x100D85=47' '0x100D90=41 42'

# equal-length string replacement across the whole image
tools/patch_firmware.pl patch stock.bin out.bin \
    --replace 'Here you can configure=HERE you can configure'

# sum-neutral edit (safe path test, no checksum change)
tools/patch_firmware.pl patch stock.bin out.bin --transpose 0x100D85 0x100D86
```

Then flash via the loader:

```bash
tools/flash_via_loader.sh 10.0.0.106 admin admin1 out.bin
```

### Verified results
- Transposition (sum unchanged) → loader `OK`, device booted, edit live.
- `f12` changed but `f8` stale → loader `Invalid image!`, no flash (safe).
- `f12` and `f8` recomputed → loader `OK`, device booted, edit live.
- 12× `"Here you can configure"` → `"HERE you can configure"` (264 bytes),
  checksums fixed, flashed via loader, UI shows the new text.

## 6. What `f12` covers (checksum window) — confirmed live

The verify routine (`DISASSEMBLY_NOTES.md` §3) sums the app's **logical image =
the `.bin` payload** (`file[0x14:]`), i.e. segment A then segment B as they are
contiguous in the app's CPU address space. It is an ordinary 32-bit additive
byte-sum, and it **excludes the 20-byte app header** (the `.bin[0x4012]` copy at
payload offset `0x3FFE`):

```
f12 = sum(payload bytes, excluding the 20-byte app header at payload 0x3FFE)
      + C,                                  C = 0x13EC   (constant on this device)
```

For stock (header unchanged) this is the same as `f12 = sum(file[0x14:]) + 0xDC1`.
Because the header is excluded, growing the payload and updating the length /
`f8` / `f12` fields does **not** perturb the sum — so
`f12_new = f12_old + sum(bytes added)` is exact.

Verified live (every image booted, and every image shows `C = 0x13EC`):
| image | change | result |
|-------|--------|--------|
| stock | — | boots |
| stock + 4096×`00` | `f12` unchanged | boots |
| stock + 18 B marker | `f12 += 0x4C4` | boots |
| stock + 262144×`A5` | `f12 += 0x2940000` | boots |
| same-size string edit | `f12 += ΣΔ` | boots |

### The three official builds (computed on other flashes, for reference)
`K = f12 - sum(file)` varies slightly per build (`0x796/0x794/0x6BE`) because the
header bytes differ per build (`f12` itself is inside `K`); it is not a different
algorithm. On this device `C` is constant.

## 7. Building arbitrary-size images (works)

Segment A cannot grow (fixed `0x2E0C`); all growth goes into segment B, which
starts at flash `0x1BE0E` and can extend up to the config at `0x1FC000`
(a `0x1E01F2`-byte window; `~0xD3CBE` bytes are free after the stock app).
`tools/build_firmware.pl append --model a` computes
the correct `f12` for arbitrary appended content:

```
f12_new = f12_old + sum(bytes added)
```

This was **verified live** at +18 bytes and +262144 bytes (both booted). Because
the app header is excluded from the sum (§6), the length/`f8`/`f12` updates the
tool makes do not perturb it. `--zero N` appends `N` zero bytes with `f12`
unchanged (a useful sanity test).

To put *executable* custom code into the grown region, edit the app's entry/call
sites (sum-neutral or with `f12` recomputed by the same delta rule) and place the
code in segment B. There is no size limit other than the ~865 KB free before
config.

## 8. Tools

`tools/patch_firmware.pl` (same size) — `info`, `verify`, `patch` with byte
patches, equal-length `--replace`, and sum-neutral `--transpose`; recomputes
`f8` and `f12`.

`tools/build_firmware.pl` (arbitrary size):
```
build_firmware.pl info   <firmware.bin>
build_firmware.pl verify <firmware.bin>                 # checks f8; prints C
build_firmware.pl append <in> <out> --data BLOB --model a        # f12 += sum(BLOB)
build_firmware.pl append <in> <out> --append-hex 00112233 --model a
build_firmware.pl append <in> <out> --zero 4096                  # zero append, f12 kept
```
`append` updates the payload length and **both** header copies (file `0x0` and
`0x4012`), writes the new `f8`, and places the appended blob immediately after the
stock payload (into segment B's free room).

### Verified results (live)
- Transposition (sum unchanged) → loader `OK`, booted, edit live.
- `f12` changed but `f8` stale → loader `Invalid image!` (safe).
- `f12`+`f8` recomputed → loader `OK`, booted, edit live.
- 12× string replacement → loader `OK`, UI shows new text.
- **+4096 zero bytes** (length `0x10F340`→`0x110340`) → loader `OK`, booted.
- **+18 non-zero bytes**, `f12 += Σ` → loader `OK`, booted.
- **+262144 bytes** (`0xA5`), `f12 += Σ` → loader `OK`, booted.
