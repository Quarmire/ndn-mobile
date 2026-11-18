#!/usr/bin/env bash
# Fails when a feature that exists for tests only is on in a shipped build.
#
# Features that must never be on in a shipped build:
#
#   fault-injection   ndn-link's fault layer (drops, duplicates, forges and delays the packets
#                     arriving on links; ndn-rs docs/specs/ndn-link.md §17B). Loud at start and
#                     in `Links::report()`, off by default.
#
# Four checks, none needing a build (`cargo tree` only resolves):
#   1. No Cargo.toml of this repo but the feature's own crate declares or enables it outside
#      `[dev-dependencies]` (a `[features]` line that forwards it, a normal dependency that turns
#      it on). A test that needs it asks for it as a dev-dependency or on its command line.
#   2. No `.cargo/config.toml` of this repo names it.
#   3. No workflow of this repo names it except on a test line (`cargo test`, `cargo nextest`):
#      a build, a release or a run step that turns it on is refused.
#   4. The resolved feature graph of each package given as an argument (the shipped ones), by
#      default features and by `--all-features`, no dev edges, does not hold it.
#
# This file is the same in ndn-ext, ndn-fwd and ndn-mobile, so a repo's CI depends on nothing
# outside it; the shipped packages are the repo's arguments:
#   tools/check-forbidden-features.sh            # manifests, cargo config, workflows
#   tools/check-forbidden-features.sh ndn-fwd    # ... and the feature graph of package ndn-fwd
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

FORBIDDEN_FEATURES=(fault-injection)
# own_manifest <feature>: the one manifest (relative to the repo) that may declare it. Another
# repo's manifest never matches, so it declares it nowhere here.
own_manifest() {
  case "$1" in
    fault-injection) echo "./crates/faces/ndn-link/Cargo.toml" ;;
  esac
}

manifests() { # manifests <feature>
  local feature="$1" own hits
  own=$(own_manifest "$feature")
  hits=$(grep -rl --include=Cargo.toml --exclude-dir=target --exclude-dir=target-shared \
           --exclude-dir=.git --exclude-dir=node_modules -e "$feature" . 2>/dev/null \
         | while read -r toml; do
             awk -v f="$feature" -v file="$toml" -v own="$own" '
               /^\[/ { section = $0 }
               index($0, f) && $0 !~ /^[[:space:]]*#/ && section !~ /dev-dependencies/ \
                 && !(file == own && section == "[features]") {
                 printf "  %s:%d [%s] %s\n", file, FNR, section, $0 }' "$toml"
           done)
  if [ -n "$hits" ]; then
    echo "  FORBIDDEN: \`$feature\` is declared or enabled outside its own crate and dev-dependencies:"
    printf '%s\n' "$hits"
    echo "  A test that needs it asks for it as a dev-dependency or on its own command line."
    fail=1
  else
    echo "  ok: manifests"
  fi
}

cargo_config() { # cargo_config <feature>
  local feature="$1" hits
  hits=$(grep -H -n -e "$feature" .cargo/config.toml .cargo/config 2>/dev/null \
         | grep -v -E '^[^:]*:[0-9]+:[[:space:]]*#')
  if [ -n "$hits" ]; then
    echo "  FORBIDDEN: \`$feature\` is named in the cargo config, which every build here reads:"
    printf '%s\n' "$hits"
    fail=1
  else
    echo "  ok: cargo config"
  fi
}

workflows() { # workflows <feature>
  local feature="$1" hits
  [ -d .github/workflows ] || { echo "  ok: no workflows"; return; }
  hits=$(grep -H -n -e "$feature" .github/workflows/* 2>/dev/null \
         | grep -v -E ':[0-9]+:[[:space:]]*#' \
         | grep -v -E 'cargo (nextest run|test)')
  if [ -n "$hits" ]; then
    echo "  FORBIDDEN: \`$feature\` is named in a workflow step that is not a test run:"
    printf '%s\n' "$hits"
    fail=1
  else
    echo "  ok: workflows (it is named only on test lines, if at all)"
  fi
}

tree_lacks() { # tree_lacks <feature> <label> <cargo tree args...>
  local feature="$1" label="$2"; shift 2
  local out
  if ! out=$(cargo tree --edges features,normal,build "$@" 2>&1); then
    echo "  FAILED to resolve $label:"; printf '%s\n' "$out" | head -5; fail=1; return
  fi
  if printf '%s\n' "$out" | grep -q "feature \"$feature\""; then
    echo "  FORBIDDEN: \`$feature\` is on in $label:"
    printf '%s\n' "$out" | grep -n "feature \"$feature\"" | head -5
    fail=1
  else
    echo "  ok: $label"
  fi
}

for feature in "${FORBIDDEN_FEATURES[@]}"; do
  printf '\n===== forbidden feature `%s` =====\n' "$feature"
  manifests "$feature"
  cargo_config "$feature"
  workflows "$feature"
  for pkg in "$@"; do
    tree_lacks "$feature" "$pkg (default features)" -p "$pkg"
    tree_lacks "$feature" "$pkg (all features)" -p "$pkg" --all-features
  done
done

printf '\n'
if [ "$fail" -eq 0 ]; then
  echo "ok: no forbidden feature in a shipped build"
else
  echo "FAILED: a forbidden feature is on (above)"
fi
exit "$fail"
