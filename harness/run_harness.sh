#!/usr/bin/env bash
set -x
export WINEPREFIX=/tmp/opencode/wineprefix
export WINEDLLOVERRIDES="mscoree,mshtml,wine-mono,wine-gecko="
Xvfb :87 -screen 0 1024x768x24 -nolisten tcp >/tmp/opencode/xvfb_h.log 2>&1 &
XVFB=$!
sleep 2
export DISPLAY=:87
JAVA=$(ls -d /tmp/opencode/zulu8fxwin/*/bin/java.exe | head -1)
JAVA_WIN='Z:'"$(echo "$JAVA" | sed 's#/#\\#g')"
CP='Z:\tmp\opencode\escu_inner.jar;Z:\tmp\opencode\harness'
echo "JAVA_WIN=$JAVA_WIN"
wine "$JAVA_WIN" -cp "$CP" Harness
kill $XVFB 2>/dev/null
wait 2>/dev/null
