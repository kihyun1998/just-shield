# 사용법 — 단계별 적용 가이드

처음 just-shield를 쓰는 사람을 위해, **빈 저장소에서 시작해 CI에 붙이기까지** 순서대로 따라 하는 문서입니다. 각 명령이 무엇을 왜 하는지도 함께 설명합니다.

옵션 하나하나의 정확한 정의가 필요하면 [CLI 레퍼런스](cli.md)를 보세요. 이 문서는 "어떤 순서로 무엇을 하는가"에 집중합니다.

> 한 줄 요약: **설치 → `scan`으로 현황 파악 → `fix`로 자동 교체 → `lock`으로 신뢰 박제 → GitHub Action으로 PR마다 자동 검사.**

---

## 0. 이 도구가 막는 것 (1분)

CI 파이프라인은 남이 만든 GitHub Action을 받아서 실행합니다. 그 Action이 **가짜이거나 중간에 오염되면**, 파이프라인이 들고 있는 CI 자격증명(토큰·시크릿)이 통째로 털릴 수 있습니다 — 실제로 TeamPCP(UNC6780)가 보안 벤더 도구들을 이렇게 오염시켰습니다.

just-shield는 워크플로 파일(`.github/workflows/*.yml`)을 **실행 전에** 읽어서, 받아 쓰는 Action들이 진짜인지·오염됐을 때 덜 털리는 구조인지 검사합니다. 의존 크레이트 0개, 기본 완전 오프라인입니다.

배경 개념(공급망 공격, 섭취 전 검증, 태그 하이재킹 등)은 [CONTEXT.md](../CONTEXT.md)에 정리돼 있습니다.

---

## 1. 설치 (5분)

가장 간단한 방법은 패키지 매니저입니다 — 체크섬 검증까지 자동입니다.

```bash
# macOS / Linux
brew install kihyun1998/tap/just-shield
```

```powershell
# Windows
scoop bucket add kihyun1998 https://github.com/kihyun1998/scoop-bucket
scoop install just-shield
```

설치가 끝났는지 확인:

```bash
just-shield
# 사용법: just-shield <scan|lock|fix> [저장소 경로] [옵션...] 이 출력되면 정상
```

> 다른 설치 경로(직접 다운로드 + 체크섬·출처 검증, `cargo install`, 컨테이너 이미지)는 [README 설치 절](../README.md#설치)에 있습니다.

---

## 2. 첫 검사 — `scan` (5분)

검사할 프로젝트 폴더로 이동한 뒤:

```bash
just-shield scan
```

- 인자를 안 주면 **현재 디렉터리**를 검사합니다 (`just-shield scan .`와 동일).
- 기본은 **오프라인** — 네트워크 없이 워크플로 파일 텍스트만 보고 판정합니다.
- 다른 폴더를 검사하려면 경로를 붙입니다: `just-shield scan ./my-repo`

출력은 발견 항목(finding) 목록과 요약입니다. 위반이 있으면 **종료 코드 1**, 깨끗하면 `0`으로 끝납니다.

---

## 3. 결과 읽는 법 (5분)

각 발견 항목에는 **심각도 등급**이 붙습니다. 색이 곧 "빌드를 깨뜨리느냐"를 뜻합니다.

| 등급 | 의미 | 기본 동작 |
|------|------|-----------|
| 🔴 높음 | 검증 가능한 사실 위반 | **빌드 실패** (종료 코드 1) |
| 🟡 중간 | 오염됐을 때 피해를 키우는 요인 | 경고 (`--strict` 주면 실패로 승격) |
| 🔵 안내 | 휴리스틱 기반 참고 정보 | 항상 경고만 |
| ⚪ 무시됨 | 사유와 함께 의도적으로 수용 | 리포트에 남되 판정엔 불포함 |

> **왜 등급이 동작을 결정하나?** just-shield는 "사실 기반 판정" 원칙([ADR-0002](adr/0002-fact-based-verdicts.md))을 따릅니다. 추측이 아니라 **검증 가능한 사실**에서 나온 위반만 빌드를 깨뜨립니다(🔴). 그래서 오탐으로 CI가 막히는 일이 줄어듭니다.

각 항목은 "왜 위험한지(evidence)"와 "어떻게 고치는지(fix_hint)"를 함께 보여줍니다. 어떤 규칙(R1~R10, LOCK)이 무엇을 잡는지는 [README의 규칙표](../README.md#검사-규칙-구현-현황)를 참고하세요.

처음 검사에서 가장 흔히 보게 되는 것은 **R1 — 서드파티 Action을 태그/브랜치(가변 참조)로 쓰고 있음**입니다. 다음 단계가 이걸 한 방에 정리합니다.

---

## 4. 자동으로 고치기 — `fix` (5분)

R1의 권장 해법은 "태그를 커밋 SHA로 박제(핀 고정)"하는 것입니다. 손으로 해시를 찾을 필요 없이 `fix`가 대신합니다.

먼저 **무엇이 바뀌는지 미리보기** (파일은 안 건드립니다):

```bash
just-shield fix --dry-run
```

출력 예:

```
.github/workflows/ci.yml:9
  - uses: some/action@v3
  + uses: some/action@1a2b3c... # v3
```

내용이 마음에 들면 실제로 적용:

```bash
just-shield fix
```

- `fix`는 가변 참조를 **커밋 SHA로 교체**하고, 어떤 버전이었는지 `# v3` 주석까지 답니다.
- 어떤 SHA로 박을지 알아내려면 GitHub에 물어봐야 하므로 **네트워크가 필요**합니다.
- 바꾼 뒤 다시 `scan`을 돌려 R1이 사라졌는지 확인하세요.

> **"SHA로 박으면 업데이트가 끊기지 않나?"** 아닙니다. 최초 핀은 `fix`가, 이후 갱신은 GitHub **Dependabot**(`github-actions` 생태계)이 SHA와 버전 주석을 함께 올리는 PR로 처리합니다. 머지만 하면 핀이 *불변이면서 동시에 최신*으로 유지됩니다. 설정 한 블록은 [README](../README.md#sha-핀-손이-많이-가지-않나)에 있습니다.

---

## 5. 신뢰 박제 — `lock` + `--online` (선택, 10분)

여기까지는 오프라인으로 충분합니다. 한 단계 더 강한 방어를 원하면 **shield.lock**을 도입하세요.

```bash
just-shield lock
```

이 명령은 지금 시점의 "태그 → 커밋 SHA" 대응을 저장소 루트의 `shield.lock` 파일에 박제합니다 (네트워크 필요). 이후:

```bash
just-shield scan --online
```

`--online`을 주면 scan이 현재 상태를 박제본과 대조해, 누군가 **태그를 다른 커밋으로 몰래 옮긴 것(태그 하이재킹)**을 잡습니다 — TeamPCP가 Trivy 76개 태그에 쓴 바로 그 수법입니다. `--online`은 이 외에도 임포스터 커밋(R5)·발행 7일 미만 참조(R10) 검사를 켭니다.

`shield.lock`은 **커밋해서 PR 리뷰 대상으로 관리**하세요. 그래야 신뢰가 바뀔 때 코드 리뷰를 통과하게 됩니다 (캐시가 아니라 신뢰의 기준점입니다).

---

## 6. CI에 붙이기 — GitHub Action (10분)

이제 PR마다 자동으로 검사하도록 만듭니다. 워크플로에 한 블록을 추가하면 끝입니다.

```yaml
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      # 우리 액션도 우리 규칙(R1)대로 커밋 SHA로 핀 고정한다.
      # 최신 SHA는 릴리스 노트의 "복붙용 한 줄"을 그대로 쓰세요.
      - uses: kihyun1998/just-shield@<릴리스-노트의-SHA> # vX.Y.Z
        with:
          strict: true
```

- 이 래퍼는 로직 없는 얇은 껍데기입니다. 릴리스 바이너리를 내려받아 **SHA256SUMS 체크섬 검증을 통과한 경우에만** 실행하고, 검증에 실패하면 즉시 실패합니다.
- `scan`의 종료 코드가 그대로 잡 결과가 됩니다 — 위반이면 잡이 빨갛게 됩니다.
- 입력 전체 목록은 [CLI 레퍼런스의 GitHub Action 입력 절](cli.md#github-action-입력)에 있습니다.

### PR 코드 줄에 경고를 직접 띄우려면 (SARIF)

`--format sarif`로 출력해 GitHub 코드 스캐닝에 업로드하면, 경고가 PR의 해당 코드 줄 위에 달립니다.

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # SARIF 업로드에 필요
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      - uses: kihyun1998/just-shield@<릴리스-노트의-SHA> # vX.Y.Z
        with:
          format: sarif
          output-file: results.sarif
      - uses: github/codeql-action/upload-sarif@8aad20d150bbac5944a9f9d289da16a4b0d87c1e # v4.36.2
        if: always() # 위반으로 scan이 실패해도 결과는 업로드
        with:
          sarif_file: results.sarif
```

실제 동작은 [just-shield-demo](https://github.com/kihyun1998/just-shield-demo)에서 볼 수 있습니다.

---

## 7. 경고를 의도적으로 수용하기 — 탈출구

모든 경고를 다 고칠 수는 없습니다. 검사 자체를 꺼버리는 대신, **사유를 남기고 수용**하세요.

경고가 난 줄 위(또는 같은 줄 끝)에 무시 주석을 답니다 — `--` 뒤 **사유는 필수**입니다:

```yaml
# just-shield: ignore R1 -- 내부 보안팀 검증 완료, 2026-07 SHA 핀 예정
- uses: vendor/tool@v2
```

- 사유가 없으면 무시가 적용되지 않고 그 사실이 🔵로 보고됩니다.
- 해당 행·해당 규칙에만 적용됩니다 (여러 규칙은 `ignore R1, R7`).
- 무시된 항목은 사라지지 않습니다 — ⚪ 등급으로 사유와 함께 리포트에 남습니다 (**침묵 ≠ 은폐**).

조직 단위 신뢰나 쿨다운 기준은 저장소 루트의 `.just-shield.conf`에 선언합니다:

```text
# 한 줄에 하나, 해당 org의 액션을 퍼스트파티로 취급
trust-org partner-org
# R10 쿨다운 기준 일수 (기본 7, CLI --cooldown-days가 우선)
cooldown-days 14
```

---

## 자주 막히는 곳

| 증상 | 원인 / 해결 |
|------|-------------|
| `--online` / `lock` / `fix`가 멈추거나 실패 | 이 셋은 네트워크가 필요합니다. 인터넷·GitHub 접근을 확인하세요. |
| CI 잡이 🟡 때문에 실패 | `strict: true`(또는 `--strict`)를 켠 상태입니다. 의도가 아니라면 끄세요. |
| 경고가 너무 많아 막막함 | 먼저 `just-shield fix`로 R1을 한 번에 정리한 뒤 남은 것만 보세요. |
| 무시 주석이 안 먹힘 | `--` 뒤에 사유를 적었는지 확인하세요. 사유 없는 무시는 무효입니다. |
| 종료 코드 `2`가 뜸 | 위반이 아니라 사용법/입출력 오류입니다. 경로·옵션 철자를 확인하세요. |

---

## 다음 단계

- 옵션·종료 코드·출력 형식의 정확한 정의 → [CLI 레퍼런스](cli.md)
- 규칙 10개가 각각 무엇을 잡는지 → [README 규칙표](../README.md#검사-규칙-구현-현황)
- 왜 이런 설계인지 → [CONTEXT.md](../CONTEXT.md) · [docs/adr/](adr/)
