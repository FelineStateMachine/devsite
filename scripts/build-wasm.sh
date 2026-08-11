#!/usr/bin/env bash
# Build the browser endpoint to web/pkg/.
#
# `ring` (pulled in by iroh's tls-ring feature) compiles C, and the wasm32 build therefore
# needs a clang with the WebAssembly backend. Apple's system clang does not have one, so we
# locate a suitable toolchain rather than failing deep inside a cc-rs error.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

find_wasm_clang() {
  # An explicit override always wins.
  if [[ -n "${WASM_CLANG:-}" ]]; then
    echo "$WASM_CLANG"
    return
  fi
  local candidates=(
    /opt/homebrew/opt/llvm/bin/clang
    /usr/local/opt/llvm/bin/clang
    "$(command -v clang-22 || true)"
    "$(command -v clang-21 || true)"
    "$(command -v clang || true)"
  )
  for candidate in "${candidates[@]}"; do
    [[ -x "$candidate" ]] || continue
    if "$candidate" --print-targets 2>/dev/null | grep -q 'wasm32'; then
      echo "$candidate"
      return
    fi
  done
  return 1
}

if ! clang_bin="$(find_wasm_clang)"; then
  cat >&2 <<'EOF'
error: no clang with a WebAssembly target was found.

  iroh's tls-ring feature builds C code, and Apple's system clang cannot target wasm32.

  macOS:  brew install llvm
  Linux:  install the distribution's clang (most builds include the wasm32 backend)

  Or point at one explicitly:  WASM_CLANG=/path/to/clang scripts/build-wasm.sh
EOF
  exit 1
fi

clang_bin_dir="$(dirname "$clang_bin")"
ar_bin="$clang_bin_dir/llvm-ar"
[[ -x "$ar_bin" ]] || ar_bin="$(command -v llvm-ar || command -v ar)"

echo "building devsite-web with $clang_bin"

export CC_wasm32_unknown_unknown="$clang_bin"
export AR_wasm32_unknown_unknown="$ar_bin"

staging="$repo_root/web/pkg/.build"
rm -rf "$staging"

wasm-pack build crates/devsite-web \
  --target web \
  --out-dir "$staging" \
  "${@:---dev}"

# Publish under a content hash so the bundle can be cached immutably at the edge.
#
# wasm-pack emits stable filenames, so caching them aggressively would serve a stale
# bundle after every deploy. Versioning the directory instead means the big artifact is
# immutable and only the tiny manifest ever needs revalidating.
version="$(shasum -a 256 "$staging/devsite_web_bg.wasm" | cut -c1-12)"
target_dir="$repo_root/web/pkg/$version"

rm -rf "$target_dir"
mkdir -p "$target_dir"
cp "$staging"/devsite_web*.js "$staging"/devsite_web*.wasm "$target_dir"/ 2>/dev/null || true
rm -rf "$staging"

printf '{"version":"%s"}\n' "$version" > "$repo_root/web/pkg/manifest.json"

# Drop superseded builds so the directory does not grow without bound.
for old in "$repo_root"/web/pkg/*/; do
  name="$(basename "$old")"
  [[ "$name" == "$version" ]] || rm -rf "$old"
done

size="$(du -h "$target_dir/devsite_web_bg.wasm" | cut -f1)"
echo "built $version ($size) → web/pkg/$version/"
