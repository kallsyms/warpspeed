#!/bin/sh
set -eu

host_triple="$(rustc -vV | awk '/^host:/ { print $2 }')"
if [ -z "$host_triple" ]; then
    echo "failed to determine rust host triple" >&2
    exit 1
fi

runner_var="CARGO_TARGET_$(printf '%s' "$host_triple" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
runner_path="${WARPSPEED_TEST_RUNNER:-$(pwd)/scripts/codesign-runner.sh}"

export "$runner_var=$runner_path"
exec cargo test "$@"
