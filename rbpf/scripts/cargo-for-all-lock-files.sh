#!/usr/bin/env bash

here="$(dirname "$0")"
cargo="$(readlink -f "${here}/../cargo")"

set -e

shifted_args=()
while [[ -n $1 ]]; do
  if [[ $1 = -- ]]; then
    escape_marker=found
    shift
    break
  elif [[ $1 = "--ignore-exit-code" ]]; then
    ignore=1
    shift
  else
    shifted_args+=("$1")
    shift
  fi
done

# When "--" appear at the first and shifted_args is empty, consume it here
# to unambiguously pass and use any other "--" for cargo
if [[ -n $escape_marker && ${#shifted_args[@]} -gt 0 ]]; then
  files="${shifted_args[*]}"
  for file in $files; do
    if [[ $file = "${file%Cargo.lock}" ]]; then
      echo "$0: unrecognizable as Cargo.lock path (prepend \"--\"?): $file" >&2
      exit 1
    fi
  done
  shifted_args=()
else
  files="$(git ls-files :**Cargo.lock)"
fi

for lock_file in $files; do
  if [[ -n $CI ]]; then
    echo "--- [$lock_file]: cargo " "${shifted_args[@]}" "$@"
  fi

  if (set -x && cd "$(dirname "$lock_file")" && cargo "${shifted_args[@]}" "$@"); then
    # noop
    true
  else
    failed_exit_code=$?
    if [[ -n $ignore ]]; then
      echo "$0: WARN: ignoring last cargo command failed exit code as requested:" $failed_exit_code
      true
    else
      exit $failed_exit_code
    fi
  fi
done
