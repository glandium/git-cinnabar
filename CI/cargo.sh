#!/bin/sh

set -x

value=
target=
for arg in "$@"; do
  if [ -n "$value" ]; then
    target=$arg
    break
  fi
  case "$arg" in
  --target=*)
    target=${arg#--target=}
    break
    ;;
  --target)
    value=1
    ;;
  *)
    ;;
  esac
done

if [ -n "$target" ]; then
  TARGET="$(echo $target | tr a-z- A-Z_)"
  target="$(echo $target | tr - _)"
  CFLAGS_VAR=CFLAGS_${target}
  RUSTFLAGS_VAR=CARGO_TARGET_${TARGET}_RUSTFLAGS
else
  CFLAGS_VAR=TARGET_CFLAGS
  RUSTFLAGS_VAR=RUSTFLAGS
fi
env
eval "export $CFLAGS_VAR=\"\$$CFLAGS_VAR -ffile-prefix-map=$PWD=/build -ffile-prefix-map=${CARGO_HOME:-$HOME/.cargo}=/.cargo\""
eval "export $RUSTFLAGS_VAR=\"\$$RUSTFLAGS_VAR --remap-path-prefix $PWD=/build --remap-path-prefix ${CARGO_HOME:-$HOME/.cargo}=/.cargo --remap-path-prefix ${RUSTUP_HOME:-$HOME/.rustup}=/.rustup\""

env
cargo "$@"
