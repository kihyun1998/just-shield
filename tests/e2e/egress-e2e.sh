#!/usr/bin/env bash
# V2-S3 e2e — 관찰자(#45)와 판정(#44)을 진짜 러너에서 연결한다 (채점표 ②, 이슈 #43).
# 세 가지를 증명한다:
#   1. 공격 경로: 잠근 잡이 미등재 도메인을 조회하면 observe report가 🔴(exit 1)
#   2. 양성 경로: 등재된 곳만 조회하면 통과(exit 0)
#   3. fail-open: 관찰자를 죽여도 잡의 일반 DNS가 살아 있다
#
# DNS 질의는 nslookup으로 127.0.0.1(우리 관찰자)에 직접 보낸다 — resolv.conf 전파의
# 타이밍/캐시 변수를 빼고 관찰자 자체를 결정적으로 구동한다. FQDN 끝점(`.`)으로
# search 도메인 접미 확장을 막는다.
set -uo pipefail

BIN="$1" # just-shield 바이너리 경로
WORK="$(mktemp -d)"
REC="${WORK}/record.txt"
RESOLV_BACKUP="${WORK}/resolv.backup"

# 잠근 잡 'e2e' — example.com만 허용.
cat > "${WORK}/egress.lock" << 'EOF'
[e2e]
example.com
EOF

sudo cp /etc/resolv.conf "${RESOLV_BACKUP}" 2> /dev/null || true

start_observer() {
  sudo "${BIN}" observe start --job e2e --record "${REC}" > "${WORK}/observer.log" 2>&1 &
  OBSERVER_PID=$!
  # 관찰자가 127.0.0.1:53에 바인드할 때까지 대기.
  for _ in $(seq 1 20); do
    if nslookup example.com. 127.0.0.1 > /dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "관찰자가 기동하지 못했습니다:" >&2
  cat "${WORK}/observer.log" >&2
  return 1
}

stop_observer() {
  sudo kill "${OBSERVER_PID}" 2> /dev/null || true
  wait "${OBSERVER_PID}" 2> /dev/null || true
}

fail() {
  echo "❌ $1" >&2
  sudo cp "${RESOLV_BACKUP}" /etc/resolv.conf 2> /dev/null || true
  exit 1
}

# ── 1. 공격 경로 ────────────────────────────────────────────────
start_observer || fail "관찰자 기동 실패 (공격 경로)"
nslookup example.com. 127.0.0.1 > /dev/null 2>&1 || true
nslookup data-collect.evil.example. 127.0.0.1 > /dev/null 2>&1 || true
sleep 1
stop_observer

echo "── 기록(공격) ──"; cat "${REC}"
if "${BIN}" observe report "${WORK}" --record "${REC}"; then
  fail "공격 경로: 미등재 도메인인데 통과했습니다 (🔴가 나와야 함)"
fi
"${BIN}" observe report "${WORK}" --record "${REC}" | grep -q "data-collect.evil.example" \
  || fail "공격 경로: 보고에 미등재 도메인이 특정되지 않았습니다"
echo "✅ 공격 경로: 미등재 조회가 🔴로 잡혔다"

# ── 2. 양성 경로 ────────────────────────────────────────────────
REC="${WORK}/record-benign.txt"
start_observer || fail "관찰자 기동 실패 (양성 경로)"
nslookup example.com. 127.0.0.1 > /dev/null 2>&1 || true
sleep 1
stop_observer

echo "── 기록(양성) ──"; cat "${REC}"
"${BIN}" observe report "${WORK}" --record "${REC}" \
  || fail "양성 경로: 등재된 곳만 조회했는데 실패했습니다 (통과해야 함)"
echo "✅ 양성 경로: 등재만 조회하니 통과"

# ── 3. fail-open ───────────────────────────────────────────────
# 관찰자는 이미 죽었고 resolv.conf는 127.0.0.1 우선 + 원본 폴백 상태다.
# 일반 경로(getent)로 이름 해석이 여전히 되는지 확인한다.
if getent hosts github.com > /dev/null 2>&1; then
  echo "✅ fail-open: 관찰자 종료 후에도 일반 DNS가 동작한다"
else
  fail "fail-open 실패: 관찰자 종료 후 DNS가 끊겼습니다"
fi

sudo cp "${RESOLV_BACKUP}" /etc/resolv.conf 2> /dev/null || true
echo "🎉 e2e 통과"
