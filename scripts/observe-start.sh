#!/usr/bin/env bash
# observe 모드 main — 릴리스 바이너리를 받아 체크섬 검증 후 관찰자를 백그라운드로 띄운다.
# 바이너리와 기록 파일은 $RUNNER_TEMP의 고정 경로에 둬, post 단계(observe-report.sh)가 찾는다.
# Linux 러너 전용 (ADR-0006). fail-open은 관찰자(observe start)가 자체 처리한다.
set -euo pipefail

case "$(uname -m)" in
  x86_64) target=x86_64-unknown-linux-musl ;;
  aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
  *)
    echo "관찰 비활성: 지원하지 않는 아키텍처 $(uname -m) (정상 진행)" >&2
    exit 0 # fail-open
    ;;
esac
if [ "$(uname -s)" != "Linux" ]; then
  echo "관찰 비활성: observe 모드는 Linux 러너 전용입니다 (정상 진행)" >&2
  exit 0 # fail-open
fi

name="just-shield-${JS_VERSION}-${target}"
base="https://github.com/kihyun1998/just-shield/releases/download/${JS_VERSION}"
bin="${RUNNER_TEMP}/just-shield-bin"
record="${RUNNER_TEMP}/just-shield-record.txt"

dir="$(mktemp -d)"
cd "$dir"
curl -fsSL --retry 3 -o "${name}.tar.gz" "${base}/${name}.tar.gz"
curl -fsSL --retry 3 -o SHA256SUMS "${base}/SHA256SUMS"

# 체크섬 검증 — 통과한 바이너리만 실행한다 (래퍼 전체와 같은 보안 모델).
expected="$(awk -v f="${name}.tar.gz" '$2 == f' SHA256SUMS)"
if [ -z "$expected" ]; then
  echo "SHA256SUMS에 ${name}.tar.gz 항목이 없습니다 — 릴리스가 손상됐을 수 있습니다" >&2
  exit 1
fi
echo "$expected" | sha256sum -c -

tar -xzf "${name}.tar.gz"
cp "${name}/just-shield" "$bin"
chmod +x "$bin"

# 관찰자를 백그라운드로 띄운다 — 이 액션 스텝이 끝나도 이후 사용자 스텝 동안
# 살아 있어야 한다. setsid로 새 세션을 만들어 스텝 정리(프로세스 그룹 종료)에서
# 분리한다 — 그냥 nohup만으로는 스텝 종료 시 함께 죽는다.
# 53번 바인드 + resolv.conf 수정에 sudo가 필요하다(러너는 무암호 sudo).
sudo setsid "$bin" observe start --job "$JS_JOB" --record "$record" \
  < /dev/null > "${RUNNER_TEMP}/just-shield-observer.log" 2>&1 &
disown 2> /dev/null || true

# 관찰자가 기록 파일을 만들 때까지(=serve 진입) 최대 10초 대기 — 못 만들면 fail-open.
for _ in $(seq 1 20); do
  [ -f "$record" ] && break
  sleep 0.5
done
if [ -f "$record" ]; then
  echo "👁 관찰 시작: 잡 '${JS_JOB}'의 DNS 질의를 기록합니다 (잡 끝에 보고)"
else
  echo "관찰 비활성: 관찰자가 기동하지 못했습니다 (정상 진행, fail-open)" >&2
  cat "${RUNNER_TEMP}/just-shield-observer.log" >&2 || true
fi
