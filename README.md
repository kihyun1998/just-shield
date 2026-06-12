# just-shield

CI 파이프라인이 받아 쓰는 GitHub Action이 **진짜인지, 오염됐을 때 덜 털리는 구조인지**를 실행 전에 검사하는 CLI. 북극성은 CI 자격증명 탈취 방지다 — TeamPCP(UNC6780) 캠페인을 대표 검증 시나리오로 사용한다.

의존 크레이트 0개, 기본 완전 오프라인. 설계 배경은 [CONTEXT.md](CONTEXT.md)와 [docs/adr/](docs/adr/)에 있다.

## 설치

패키지 매니저로 설치하면 체크섬 검증까지 자동이다:

```bash
# macOS / Linux (Homebrew)
brew install kihyun1998/tap/just-shield
```

```powershell
# Windows (Scoop)
scoop bucket add kihyun1998 https://github.com/kihyun1998/scoop-bucket
scoop install just-shield
```

두 채널 모두 formula/manifest에 SHA256이 명시되어 있어 패키지 매니저가 설치 때 강제 검증하며, 새 릴리스가 나오면 자동 갱신된다.

직접 내려받으려면 [릴리스 페이지](https://github.com/kihyun1998/just-shield/releases/latest)에서 플랫폼에 맞는 아카이브를 받는다. Linux 바이너리는 musl 정적 링크라 시스템 라이브러리 의존이 없다.

컨테이너 기반 CI는 ghcr.io 이미지를 쓴다 — `FROM scratch`에 정적 바이너리 하나뿐인 수 MB 이미지다 (linux amd64·arm64). 참조는 반드시 다이제스트로 핀 고정한다(우리 R4 규칙 그대로) — 각 릴리스의 다이제스트는 릴리스 노트에 기록된다:

```bash
docker run --rm -v "$PWD:/work" \
  ghcr.io/kihyun1998/just-shield@sha256:24c53b0f97e704e6c0623d969932922c9f121c3a004540271a89dbf27e339546 scan /work --strict  # v0.1.2
```

| 플랫폼 | 파일 |
|--------|------|
| Linux x86_64 | `just-shield-<버전>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 | `just-shield-<버전>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `just-shield-<버전>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `just-shield-<버전>-x86_64-apple-darwin.tar.gz` |
| Windows x86_64 | `just-shield-<버전>-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `just-shield-<버전>-aarch64-pc-windows-msvc.zip` |

내려받은 파일은 실행 전에 검증한다 — 이 도구가 설파하는 원칙(R3) 그대로다:

```bash
# ① 체크섬: 릴리스의 SHA256SUMS와 대조
sha256sum -c SHA256SUMS --ignore-missing

# ② 빌드 출처 증명: 이 파일이 이 저장소의 릴리스 워크플로에서 만들어졌는지 GitHub이 보증
gh attestation verify just-shield-*.tar.gz --repo kihyun1998/just-shield
```

Rust 툴체인이 있으면 crates.io에서 바로 설치할 수도 있다 — 사전 빌드 바이너리가 없는 플랫폼의 만능 탈출구:

```bash
cargo install just-shield
```

## GitHub Action으로 사용

워크플로에 한 블록 추가하면 끝이다. 래퍼는 로직 없는 얇은 껍데기로, 릴리스 바이너리를 내려받아 **SHA256SUMS 체크섬 검증을 통과한 경우에만** 실행한다 — 검증 실패 시 즉시 실패한다.

```yaml
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      # 우리 액션도 우리 규칙(R1)대로 커밋 SHA로 핀 고정해서 쓰라
      - uses: kihyun1998/just-shield@<40자리 커밋 SHA>  # 릴리스 태그의 커밋
        with:
          strict: true
```

입력: `path`(기본 `.`), `strict`, `online`, `format`(text|json|sarif), `cooldown-days`, `output-file`(출력 저장 경로), `version`(내려받을 릴리스 — 기본값은 핀 고정된 검증 릴리스). scan의 종료 코드가 그대로 잡 결과가 된다 — 위반이면 잡이 실패한다.

## 사용법

```bash
just-shield scan [경로]              # 워크플로 검사 (기본: 현재 디렉터리, 오프라인)
just-shield scan . --strict         # 🟡(중간)도 빌드 실패로 승격
just-shield scan . --online         # shield.lock 대조 등 네트워크 검사 활성화
just-shield scan . --format json    # 기계용 JSON 출력
just-shield scan . --format sarif   # SARIF 2.1.0 — GitHub 코드 스캐닝 업로드용
just-shield lock [경로]              # 태그→SHA를 shield.lock으로 박제 (네트워크 필요)
just-shield fix [경로]               # 가변 참조를 SHA로 자동 교체 + 버전 주석 (네트워크 필요)
just-shield fix [경로] --dry-run     # 교체 내용을 적용 없이 미리보기
```

종료 코드: `0` 통과 · `1` 위반(🔴, `--strict`면 🟡 포함) · `2` 사용법/입출력 오류.

## 검사 규칙 (구현 현황)

| 규칙 | 등급 | 내용 |
|------|------|------|
| R1 | 🔴/🔵 | 서드파티 액션의 가변 참조(태그/브랜치). GitHub 공식은 🔵 완화 |
| R2 | 🔵→🔴 | 유명 액션과 한 글자 차이(전치 포함) — 기본 🔵, `--online` 교차 검증(짝퉁은 태그 ≤2 · 원본 ≥10)으로만 🔴 격상 |
| R3 | 🔵 | `curl \| sh`류 미검증 파이프 설치 (휴리스틱 — 항상 안내만, 체크섬 검증 시 침묵) |
| R4 | 🟡 | 다이제스트 없는 컨테이너 이미지 참조 (`image:`, `container:`, `docker://`) |
| R6 | 🟡 | 시크릿을 쓰는 잡에서 서드파티 액션 실행 |
| R7 | 🟡 | `permissions` 미선언 또는 `write-all` |
| R5 | 🔴 | (`--online`) 핀된 SHA가 저장소 정식 히스토리에서 도달 불가 — 임포스터 커밋 |
| R8 | 🔴 | `pull_request_target`/`workflow_run` + 외부 PR 체크아웃 조합 |
| R9 | 🔴 | 공개 권고에 악성으로 등재된 버전/커밋 사용 (동봉 DB 스냅숏, 오프라인 동작) |
| R10 | 🟡 | (`--online`) 발행 7일 미만 참조 — 미검증 기간(쿨다운) 회피, `--cooldown-days`로 조정 |
| LOCK | 🔴/🔵 | shield.lock 박제본 대비 태그 이동 (정확 버전 이동=🔴, 별칭/브랜치=🔵) |

**규칙 10개 전체 구현 완료.** R9의 권고 DB(`data/advisories.txt`)와 R2의 유명 액션 목록(`data/popular-actions.txt`)은 바이너리에 동봉된다 — 형식·갱신 절차는 각 파일 머리말 참조. 갱신 = 새 릴리스이므로 데이터만 바꿔치기하는 공격면이 없다.

신뢰 분류: 로컬·같은 소유자 = 퍼스트파티(검사 제외), `actions/*`·`github/*` = 공식(완화), 그 외 전부 서드파티(엄격). 판별 실패 시 서드파티 취급(fail-closed).

## shield.lock

`just-shield lock`이 각 액션의 "태그 → 커밋 SHA" 대응을 저장소 루트의 `shield.lock`에 박제한다. 이후 `scan --online`은 현재 대응을 박제본과 대조해 **태그 하이재킹**(TeamPCP가 Trivy 76개 태그에 쓴 수법)을 권고 DB 등재 이전에 탐지한다. 락파일은 커밋해서 PR 리뷰 대상으로 관리하라 — 신뢰 변경이 코드 리뷰를 통과하는 구조다.

## 탈출구 — 경고를 의도적으로 수용하기

경고가 난 줄 위(또는 같은 줄 끝)에 **사유 필수** 무시 주석을 단다:

```yaml
# just-shield: ignore R1 -- 내부 보안팀 검증 완료, 2026-07 SHA 핀 예정
- uses: vendor/tool@v2
```

- `--` 뒤 사유가 없으면 무시가 적용되지 않고 그 사실이 🔵로 보고된다
- 해당 행·해당 규칙에만 적용된다 (여러 규칙은 `ignore R1, R7`)
- 무시된 항목은 사라지지 않는다 — ⚪ 등급으로 사유와 함께 리포트·JSON에 남는다 (침묵 ≠ 은폐)

조직 단위 신뢰는 저장소 루트의 `.just-shield.conf`에 선언한다:

```text
# 한 줄에 하나, 해당 org의 액션은 퍼스트파티로 취급
trust-org partner-org
# R10 쿨다운 기준 일수 (기본 7, CLI --cooldown-days가 우선)
cooldown-days 14
```

## JSON 출력 스키마 (version 1)

```json
{
  "version": 1,
  "workflows_scanned": 1,
  "summary": { "high": 1, "medium": 0, "info": 2, "suppressed": 1 },
  "exit_code": 1,
  "findings": [
    {
      "rule": "R1",
      "severity": "high",
      "file": ".github/workflows/ci.yml",
      "line": 9,
      "uses": "aquasecurity/trivy-action@master",
      "evidence": "왜 위험한지 — 검증 가능한 사실과 출처",
      "fix_hint": "어떻게 고치는지"
    }
  ],
  "suppressed": [
    {
      "rule": "R1",
      "file": ".github/workflows/ci.yml",
      "line": 12,
      "uses": "vendor/tool@v2",
      "reason": "무시 주석의 -- 뒤 사유"
    }
  ]
}
```

- `severity`: `high` | `medium` | `info` (무시된 항목은 `suppressed` 배열에 별도 수록)
- `file`: 플랫폼과 무관하게 `/` 구분자로 정규화
- `exit_code`: 해당 실행의 종료 코드와 동일 (`--strict` 반영)
- `findings`: (file, line, rule) 순 정렬 — 같은 입력이면 같은 순서

## SARIF 출력

`--format sarif`는 [SARIF 2.1.0](https://docs.github.com/en/code-security/code-scanning) 형식으로 출력한다 — GitHub 코드 스캐닝에 업로드하면 경고가 PR의 해당 코드 줄 위에 직접 표시된다.

- 심각도 매핑: 🔴 → `error`, 🟡 → `warning`, 🔵 → `note`
- 무시 주석으로 수용된 발견은 결과에서 사라지지 않고 SARIF `suppressions`(사유 포함)로 표현된다 (침묵 ≠ 은폐)
- 종료 코드는 텍스트/JSON 모드와 동일 — 출력 형식이 판정을 바꾸지 않는다
- 출력 전체가 스냅숏 테스트(`tests/snapshots/violation.sarif`)로 고정된다

```yaml
# GitHub Actions에서 코드 스캐닝으로 업로드하는 예 (Action 래퍼가 이를 내장할 예정)
- run: just-shield scan . --format sarif > results.sarif || true
- uses: github/codeql-action/upload-sarif@<커밋 SHA>  # 버전 주석
  with:
    sarif_file: results.sarif
```

## 개발

```bash
cargo test     # 유닛 + 통합 + 채점표 코퍼스 (릴리스 게이트)
cargo clippy   # 린트
```

**채점표 게이트** (`tests/corpus/`, ADR-0002 원칙 ④): TeamPCP 캠페인을 재현한 공격 코퍼스는 전부 탐지돼야 하고(미탐 0), 실제 워크플로를 본뜬 양성 코퍼스에서 🔴 오탐이 하나도 없어야 한다. CI는 마지막에 just-shield로 자기 저장소를 검사한다(dogfood). 코퍼스 추가 절차는 [tests/corpus/README.md](tests/corpus/README.md).

모든 판정은 사실 기반이어야 한다 — 빌드를 깨뜨리는 🔴는 검증 가능한 사실에서만 나온다 ([ADR-0002](docs/adr/0002-fact-based-verdicts.md)).

## 라이선스

[MIT](LICENSE-MIT) 또는 [Apache-2.0](LICENSE-APACHE) 중 원하는 쪽을 선택해 사용한다 (Rust 생태계 관례의 이중 라이선스).
