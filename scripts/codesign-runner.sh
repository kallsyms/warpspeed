#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <binary> [args...]" >&2
    exit 2
fi

binary="$1"
shift

if [ ! -f "$binary" ]; then
    echo "codesign-runner: binary does not exist: $binary" >&2
    exit 1
fi

entitlements="${WARPSPEED_CODESIGN_ENTITLEMENTS:-warpspeed.entitlements}"
identity="${WARPSPEED_CODESIGN_IDENTITY:--}"

codesign --entitlements "$entitlements" --force -s "$identity" "$binary"
exec "$binary" "$@"
