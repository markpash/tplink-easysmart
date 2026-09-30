# HTTP server & CGI routing — reverse-engineering notes

The app runs its own small HTTP daemon (`httpd.c`) on top of the **lwIP socket
API** (the fixed shared library in flash `0x3E0E..0x1BE0E`). This file records
what we know and the plan for adding custom CGI handlers.

## 1. Layers

```
TCP/80
 └─ lwIP (fixed band; sockets, tcp.c)
     ├─ app HTTP daemon  "httpd.c"  (segments A+B)   -> full UI + CGIs
     └─ loader HTTP server (fixed band)               -> firmware upload only
```

App HTTP strings (in the `.bin`, segment B):
| string | note |
|--------|------|
| `..\..\common\src\app\web\httpd.c` | source path |
| `POST`, `Cookie:`, `Content-Type:`, `Content-Length:`, `If-Modified-Since:` | request parsing |
| `multipart`, `boundary=`, `HTTPD_MULTIPART_BOUNDARY_MAX is too small!` | multipart uploads |
| `HTTPD_CLIENT_MAX is too small`, `httpd: Error - alloc socket failed!`, `bind failed!`, `listen failed!`, `web_process failed!` | daemon setup/loop |
| `/logon.cgi`, `Unauth`, `/Index.htm`, `/Logout.htm`, `auth ip:%bu... remote ip:%bu...` | auth/session |

Response side: `HTTP/1.1 200 OK`, `Content-Type`, `Content-Length: %u`,
`Connection: close`, `Set-Cookie: ...;Max-Age=%d`, `Last-Modified`,
`Cache-Control`, `Expires`, `Pragma`.

## 2. Jump/dispatch table (flash `0x011d`)

A table of 6-byte records was found at **flash `0x011d`..`0x028b`** (60 entries;
the app's banked *entry points*, not directly the URL routes):

```
  90 lo hi   mov dptr,#(adj)      ; adj = (hi<<8)|lo
  02 01 00   ljmp 0x0100          ; bank-0 trampoline
  90 lo hi
  02 01 0c   ljmp 0x010c          ; bank-12 trampoline
```
So each entry is `manual_bank_call(adj, bank)`; the real target is
`adj + 0x011d` (base 0x011d), e.g. `0x4a9a -> 0x4bb7`, `0xf851 -> 0xf96e`.
Banks used: 0 and 12.

Trampolines (flash `0x0102` and `0x010e`):
```
0x0102: 85 96 bb    mov 0xbb,0x96    ; save bank
       75 96 NN    mov 0x96,#NN     ; select bank
       31 18       acall 0x0118
       85 bb 96    mov 0x96,0xbb    ; restore
       22          ret
```

## 2b. Finding the app's *real* code (progress)

- The router/jump table at `0x011d` is in the **fixed boot region**, not the app;
  the app's HTTP code is elsewhere and is what we need.
- The app's HTTP layer (`httpd.c`) strings sit at flash `0x58000` (`.bin 0x3F0xx`:
  `GET`/`POST`, `Cookie:`, `Content-Type:`, `Content-Length:`, multipart, then the
  resource lists). The bytes **immediately before** `0x58000` are zeros, so the
  code is not adjacent there — it is placed elsewhere by the linker.
- **Flashing an image does not change the fixed region** (`0x0..0x1BE0E`), so:
  - the bank-0/bank-12 API trampolines, the router table at `0x011d`, and the
    boot region are **fixed** and identical across app builds;
  - the app lives only in segment A/B, addressed via the loader's split mapping.

## 3. Code addressing / banking

The `adj` (16-bit `dptr`) in the fixed region maps to flash as
`flash = bank * 0x10000 + 0x4000 + adj`. This is the **fixed-region** view. The
app (segments A/B) is addressed linearly within its CPU image per the loader
split:
```
segment A:  payload offset P -> flash 0x1002 + P          (CPU linear addr = P)
segment B:  payload offset P -> flash 0x1BE0E + (P-0x2E0C)
```
The banked `0x96` window is the mechanism by which the app calls fixed-region
library routines (lwIP, flash driver); the app's own code runs in its contiguous
logical image (see §3b).

## 3b. Where the app code actually runs — RESOLVED

Per `FIRMWARE_FORMAT.md` §4, segment A and segment B are **contiguous in the
app's logical (CPU) address space** — the fixed `0x18000` runtime is banked *out*
of the app's linear image — so the logical app image equals the `.bin` payload
(`file[0x14:]`). The loader split (`flash 0x1002` / `flash 0x1BE0E`) therefore
describes **storage**; the app runs from the banked window and up-calls the
fixed-region library routines (lwIP, flash driver) through the SFR `0x96` bank
register. This closes the earlier "copied to RAM?" question.

Remaining (see §6): the exact logical address of the app's HTTP router/handlers
so we can point new code at them.

## 4. Two static resource lists

There are **two** parallel lists of resource URL strings:
- List 1 starts ~`.bin 0x3F110` (near the `httpd.c` strings).
- List 2 starts ~`.bin 0x3F258` (`/logon.cgi`, `/arrow.gif`, `/button.gif`,
  `/help_arc_1.gif`, ...).

No parallel pointer/offset array for these has been located yet, so it is unclear
whether the strings are matched by iteration or via a separate table.

## 5. Plan to add a custom "hello world" CGI

1. **Pin the bank mapping** so we know the CPU address our appended code gets and
   how to target it (fix the router entry / trampoline).
2. **Find the router check** (string compare / table walk) and the handler
   invocation convention (how a matched URL calls its handler, and how the
   handler sends a response).
3. **Simplest win:** repoint an existing, safe handler entry to our code. Cheapest
   of all: overwrite an existing static response (or a `Success` CGI string) with
   `hello world` of equal length via `patch_firmware.pl --replace` — no new code.
4. **Real handler:** append a handler into segment B free space (grown image via
   `build_firmware.pl`), matching the calling convention, that emits
   `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world`.

## 6. Status
- Router/jump table located and decoded; trampolines identified; bank register SFR
  `0x96` identified.
- **App addressing resolved:** the app logical image is contiguous and equals the
  `.bin` payload (`FIRMWARE_FORMAT.md` §4), and arbitrary-size append is verified
  live (`FIRMWARE_FORMAT.md` §7) — so a handler can be placed in segment B's free
  space with `tools/build_firmware.pl append --model a`.
- **Remaining blockers:** router string-match logic; handler ABI (request context
  + response send routine); exact logical address of the HTTP router/handlers.
- **Easiest demonstrable custom CGI (already shown):** equal-length replacement of
  an existing static string needs no code and flashes with the same-size tool —
  the live `"Here you can configure"` → `"HERE you can configure"` test
  (`FIRMWARE_FORMAT.md` §5) is exactly this path.
