#!/usr/bin/env bash
# Flash a (patched) TP-Link Easy Smart firmware .bin through the default loader.
# Enters loader mode via the running web UI, uploads, and reports the result.
#
# Usage: flash_via_loader.sh <ip> [user] [pass] <firmware.bin>
set -u

IP="${1:?usage: flash_via_loader.sh <ip> [user] [pass] <firmware.bin>}"
USER="${2:-admin}"
if [ $# -ge 4 ]; then PASS="$3"; FW="$4"; else PASS="admin1"; FW="$3"; fi
[ -n "${FW:-}" ] || { echo "firmware .bin required"; exit 2; }
[ -f "$FW" ] || { echo "no such file: $FW"; exit 2; }

CK="$(mktemp)"
trap 'rm -f "$CK"' EXIT

echo "[*] login to $IP"
curl -s -m 8 -c "$CK" -b "$CK" -d "username=$USER&password=$PASS&logon=Login" \
     "http://$IP/logon.cgi" -o /dev/null

echo "[*] request loader mode"
curl -s -m 10 -b "$CK" -d "reset_op=fwupgrade" "http://$IP/fupgrade0.cgi" -o /dev/null

echo "[*] waiting for loader"
ok=0
for _ in $(seq 1 30); do
    sleep 2
    if curl -s -m 4 "http://$IP/" 2>/dev/null | grep -q upgrade_ds; then ok=1; break; fi
done
[ "$ok" = 1 ] || { echo "[!] loader did not come up"; exit 1; }
echo "[*] loader is up"

echo "[*] uploading $FW"
RESP="$(mktemp)"
trap 'rm -f "$CK" "$RESP"' EXIT
code=$(curl -s -m 240 -o "$RESP" -w "%{http_code}" \
        -F "firmware=@$FW;filename=TL-SG108E.bin" \
        "http://$IP/httpupg.cgi?cmd=fw_upgrade")
if grep -q "OK, please wait for writing" "$RESP"; then
    echo "[+] loader accepted the image (http=$code)"
elif grep -q "Invalid image" "$RESP"; then
    echo "[!] loader REJECTED the image: Invalid image (f8/header checksum wrong)"
    exit 3
else
    echo "[!] unexpected loader response (http=$code):"
    sed 's/<[^>]*>/ /g' "$RESP" | tr -s ' \n' ' ' | head -c 300; echo
fi

echo "[*] waiting for reboot"
for _ in $(seq 1 30); do
    sleep 4
    ping -c1 -W1 "$IP" >/dev/null 2>&1 || continue
    body=$(curl -s -m 4 "http://$IP/" 2>/dev/null)
    if echo "$body" | grep -q logonInfo; then echo "[+] device booted normally"; exit 0; fi
    if echo "$body" | grep -q upgrade_ds; then echo "[.] still in loader"; fi
done
echo "[!] device did not return to normal mode (may need power cycle)"
exit 1
