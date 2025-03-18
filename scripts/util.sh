#!/usr/bin/env bash
# This script contains general helper functions for bash scripting.
set -Eeuo pipefail

source ./third_party/sh/ansi.sh

util::debug() {
    set -x; "$@"; set +x;
}

util::info() {
    printf \
        "$(ansi::resetColor)$(ansi::blueIntense)💡 %s$(ansi::resetColor)\n" \
        "$@"
}

util::warn() {
    printf \
        "$(ansi::resetColor)$(ansi::yellowIntense)⚠️ %s$(ansi::resetColor)\n" \
        "$@"
}

util::error() {
    printf \
        "$(ansi::resetColor)$(ansi::bold)$(ansi::redIntense)❌ %s$(ansi::resetColor)\n" \
        "$@"
}

util::success() {
  printf "$(ansi::resetColor)$(ansi::greenIntense)✅ %s$(ansi::resetColor)\n" "$@"
}

util::retry() {
    for i in {1..5}; do
      if "${@}"; then
        return
      fi

      sleep "$i"
    done
}

util::prompt() {
  prompt=$(printf "$(ansi::bold)$()❔ %s [y/N]$(ansi::resetColor)\n" "$@")
  read -rp "${prompt}" yn
  case $yn in
      [Yy]* ) ;;
      * ) util::error "Did not receive happy input, exiting."; exit 1;;
  esac
}

util::prompt_skip() {
  prompt=$(printf "$(ansi::bold)$()❔ %s [y/N]$(ansi::resetColor)\n" "$@")
  read -rp "${prompt}" yn
  case $yn in
      [Yy]* ) return 0;;
      * ) util::warn "Did not receive happy input, skipping."; return 1;;
  esac
}
