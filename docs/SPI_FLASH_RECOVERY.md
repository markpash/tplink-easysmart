# SPI flash recovery (unbricking)

When a bad image is flashed, the bootloader halts before bringing up the network
(LEDs on, no IP, ARP silent) and there is **no automatic loader fallback**. A
power cycle does not help. Recovery requires re-programming the SPI flash.

## Hardware
- **MCU/switch ASIC:** Realtek **RTL8370N** (boots from the SPI flash).
- **Flash:** Winbond **25Q16JVSIQ** — 16 Mbit / 2 MiB, **3.3 V**, SOIC-8.
- No UART/test pads were found on the board.

## Tools
- CH341A USB programmer (**must be 3.3 V**; beware 5 V clones) — or another
  3.3 V SPI programmer.
- SOIC-8 test clip (200/208 mil) **or** desolder the chip and use a SOIC-8→DIP8
  adapter. In-circuit can fail if the RTL8370N loads the SPI bus.
- `flashrom` (supports `ch341a_spi`). The CH341A can be driven from Linux.

## Flash layout (observed on a 2 MiB dump)
```
0x000000   boot/loader code (fixed, NOT from the .bin)
0x001002   segment A  (== .bin[0x14..0x2E20], 0x2E0C bytes)
0x003E0E   shared runtime library (lwIP + SPI driver; fixed, NOT from the .bin)
0x01BE0E   segment B / application (== .bin[0x2E20..])
0x01D000   application header (== .bin[0x4012..0x4026])
0x01D014   application payload
...
0x1FBFFF   end of image area
0x1FC000+  configuration / persistent data (contains e.g. "TL-SG108E", MAC)
0x1FFFFF   end of flash
```
The loader writes only the `.bin` **payload** (segments A and B) and preserves the
boot/loader code and the fixed `0x18000` shared runtime. It does **not** store the
20-byte container header. See `FIRMWARE_FORMAT.md` §4.

## Reading
Board unpowered, clip on the flash, programmer powers the chip:
```bash
flashrom -p ch341a_spi -r dump.bin        # 2 MiB
flashrom -p ch341a_spi -r dump2.bin       # read twice and compare
sha256sum dump.bin dump2.bin
```

## Writing / recovering
Write a known-good full image:
```bash
flashrom -p ch341a_spi -w fixed.bin
flashrom -p ch341a_spi -v fixed.bin       # optional verify
```

### Recovering
Preferred: if the device still runs (or can be put into loader mode), re-flash a
good `.bin` through the loader (`LOADER_MODE.md` / `tools/flash_via_loader.sh`).
The programmer is only needed when the network no longer comes up.

Programmer path: if only a small in-place edit caused the brick, the corrected
flash is the bad dump with the edit reverted **and the checksum fields fixed**.
(Historical example: a one-byte edit `0x119D73` `G`→`H` was reverted to restore a
working image.) Rewriting a full known-good image is usually simpler.

## Precautions
- Use a single power source (programmer powers the flash; do not also power the
  board).
- 3.3 V only for the 25Q16JV.
- Always keep the original dump; it holds the bootloader, config and MAC.

## Note on crafting full images
Because `f12` is an additive checksum over the rendered image, a full flash image
can also be fixed up by patching the header `f12`/`f8` (same rules as
`FIRMWARE_FORMAT.md`) if you understand the block layout.
