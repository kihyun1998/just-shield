#!/usr/bin/env bash
# just-shield Action 래퍼 실행 스크립트.
# 순서가 곧 보안 모델이다: 다운로드 → 체크섬 검증 → (통과 시에만) 실행.
# 검증 전의 바이너리는 신뢰하지 않는다 — R3가 경고하는 "받자마자 실행" 패턴을 우리가 피한다.
set -euo pipefail

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *)
    echo "지원하지 않는 OS: $(uname -s)" >&2
    exit 2
    ;;
esac
case "${os}-$(uname -m)" in
  linux-x86_64) target=x86_64-unknown-linux-musl ext=tar.gz ;;
  linux-aarch64 | linux-arm64) target=aarch64-unknown-linux-musl ext=tar.gz ;;
  darwin-arm64) target=aarch64-apple-darwin ext=tar.gz ;;
  darwin-x86_64) target=x86_64-apple-darwin ext=tar.gz ;;
  windows-x86_64) target=x86_64-pc-windows-msvc ext=zip ;;
  windows-aarch64 | windows-arm64) target=aarch64-pc-windows-msvc ext=zip ;;
  *)
    echo "지원하지 않는 플랫폼: ${os}/$(uname -m)" >&2
    exit 2
    ;;
esac

name="just-shield-${JS_VERSION}-${target}"
base="https://github.com/kihyun1998/just-shield/releases/download/${JS_VERSION}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
case "$JS_PATH" in
  /*) scan_root="$JS_PATH" ;;
  *) scan_root="$(pwd)/${JS_PATH}" ;;
esac

cd "$work"
curl -fsSL --retry 3 -o "${name}.${ext}" "${base}/${name}.${ext}"
curl -fsSL --retry 3 -o SHA256SUMS "${base}/SHA256SUMS"

# 체크섬 검증 — 항목이 없거나 불일치면 실행 없이 즉시 실패.
expected="$(awk -v f="${name}.${ext}" '$2 == f' SHA256SUMS)"
if [ -z "$expected" ]; then
  echo "SHA256SUMS에 ${name}.${ext} 항목이 없습니다 — 릴리스가 손상됐을 수 있습니다" >&2
  exit 1
fi
if command -v sha256sum > /dev/null 2>&1; then
  echo "$expected" | sha256sum -c -
else
  echo "$expected" | shasum -a 256 -c -
fi

if [ "$ext" = "zip" ]; then
  if command -v unzip > /dev/null 2>&1; then
    unzip -q "${name}.zip"
  else
    powershell.exe -NoProfile -Command "Expand-Archive -Path '${name}.zip' -DestinationPath '.'"
  fi
  bin="${work}/${name}/just-shield.exe"
else
  tar -xzf "${name}.tar.gz"
  bin="${work}/${name}/just-shield"
fi

# `[ 조건 ] && 동작` 단축형은 set -e에서 조건 거짓 시 스크립트를 죽인다 — if문으로.
args=(scan "$scan_root")
if [ "$JS_STRICT" = "true" ]; then args+=(--strict); fi
if [ "$JS_ONLINE" = "true" ]; then args+=(--online); fi
if [ -n "$JS_FORMAT" ]; then args+=(--format "$JS_FORMAT"); fi
if [ -n "$JS_COOLDOWN" ]; then args+=(--cooldown-days "$JS_COOLDOWN"); fi

# scan의 종료 코드가 곧 이 스텝의 결과다 (위반 = 잡 실패).
if [ -n "$JS_OUTPUT" ]; then
  case "$JS_OUTPUT" in
    /*) out_file="$JS_OUTPUT" ;;
    *) out_file="${scan_root}/${JS_OUTPUT}" ;;
  esac
  "$bin" "${args[@]}" > "$out_file"
else
  "$bin" "${args[@]}"
fi
