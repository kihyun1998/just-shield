#!/usr/bin/env bash
# observe 모드 post — 잡의 마지막에 호출된다 (사용자 스텝이 실패해도 실행됨).
# main(observe-start.sh)이 남긴 기록을 판정하고, 잡 요약에 보고서를 붙인다.
# 미등재 목적지(🔴)면 이 스텝이 실패해 잡 결과가 빨간불이 된다.
set -uo pipefail

bin="${RUNNER_TEMP}/just-shield-bin"
record="${RUNNER_TEMP}/just-shield-record.txt"

case "$JS_PATH" in
  /*) scan_root="$JS_PATH" ;;
  *) scan_root="${GITHUB_WORKSPACE:-$(pwd)}/${JS_PATH}" ;;
esac

# 관찰자 종료 — 기록은 새 도메인마다 flush되므로 종료 순서에 안전하다.
sudo pkill -f "observe start" 2> /dev/null || true

if [ ! -f "$record" ]; then
  # 관찰자가 fail-open으로 빠졌거나 기동 실패 — 보고 없이 정상 종료 (도구 장애 ≠ 빌드 장애).
  echo "관찰 기록이 없습니다 — 관찰이 비활성이었습니다 (정상 진행)"
  exit 0
fi

set +e
out="$("$bin" observe report "$scan_root" --record "$record")"
code=$?
set -e

echo "$out"

# 잡 요약에 마크다운으로 표시.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### 🛡 just-shield observe"
    echo ""
    echo '```text'
    echo "$out"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

exit "$code"
