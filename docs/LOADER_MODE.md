# Loader mode (firmware recovery web UI)

The TL-SG108E has a minimal, **unauthenticated** bootloader/recovery web server
("Loader Mode") that runs on `TCP/80`. It is entered when the running firmware
requests a firmware upgrade, and it is the path the official utility uses to
flash firmware.

## Entering loader mode
From the normal web UI (authenticated), the "Firmware Upgrade → Ready" button
POSTs:

```
POST /fupgrade0.cgi   reset_op=fwupgrade
```

The device reboots (about 5–10 s) into loader mode. The loader keeps the
configured static IP (e.g. `10.0.0.106`).

## Endpoints (no authentication)

| Path | Purpose |
|------|---------|
| `/` , `/index.htm` | Loader "Firmware Upgrade" page (JS `upgrade_ds`) |
| `/httpug.cgi` | Same upgrade page (note: no `p`) |
| `/httpupg.cgi` | Upload endpoint; GET shows the static "Loader Mode" blurb |
| `POST /httpupg.cgi?cmd=fw_upgrade` | multipart upload, field `firmware` |
| `/reboot.cgi` | Reboot page / `cmd=reboot`, `cmd=fw_reboot` |
| `/fupg_abort.cgi`, `/lupg_abort.cgi` | abort upgrade |
| `/menu.cgi`, `/tree.js`, `/style.css` | loader UI assets |
| `/info.cgi` | static "Loader Mode" page |
| `/hidden.cgi`, `/panel.cgi` | empty |
| any other path | falls back to the loader page |

`logon.cgi` returns `501 Not implemented` in loader mode.

## Upload

```bash
curl -F "firmware=@firmware.bin;filename=TL-SG108E.bin" \
     "http://10.0.0.106/httpupg.cgi?cmd=fw_upgrade"
```

The response body tells you the result:

- accepted: `... OK, please wait for writing. ...` (flashes, then auto-reboots)
- rejected: `... error ...` with tip `Invalid image! Please double check!`

The loader validates the header checksum `f8` (see `FIRMWARE_FORMAT.md`). It does
**not** fully validate the image, so a payload edit with a valid `f8` but a stale
`f12` is flashed and then bricked by the boot check.

Typical flash time on this model: ~20–36 s, then ~40 s to boot.

## Notes
- The loader page mentions "upload your image by TFTP or HTTP". **No TFTP server
  is actually listening** (UDP/69 gives no response in normal or loader mode);
  it is generic SDK boilerplate.
- The loader UI title/hardware fields are template leftovers
  (`TL-SG3424 1.0`, `1.3.5 Build 20081014`) replaced at runtime from `upgrade_ds`.
- Leaving loader mode: upload a valid image, or POST `/reboot.cgi` with `cmd`.
