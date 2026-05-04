#!/bin/bash
# dom_send.sh — write a command to C:\dom_cmd.txt for dom_replay.dll to consume.
# Usage:
#   ./dom_send.sh probe
#   ./dom_send.sh pick_slot 0
#   ./dom_send.sh start_game
#
# Inspect results via:
#   tail -f ~/.wine/dosdevices/c:/dom_replay.log
set -e
WINE_C="/Users/robin/.wine/dosdevices/c:"
if [ -z "$1" ]; then
    echo "Usage: $0 <probe | pick_slot N | start_game>"
    exit 1
fi
echo -n "$*" > "${WINE_C}/dom_cmd.txt"
echo "wrote: $*"
