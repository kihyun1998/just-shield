# CLI 레퍼런스

just-shield의 모든 명령·옵션·종료 코드·출력 형식을 빠르게 찾기 위한 사전식 문서입니다. 처음 쓰는 경우라면 먼저 [단계별 적용 가이드](usage.md)를 따라 하는 편이 빠릅니다.

이 문서의 1차 출처는 `src/main.rs`의 인자 파서입니다 — 옵션이 바뀌면 여기도 함께 갱신하세요.

## 형식

```
just-shield <명령> [저장소 경로] [옵션...]
```

- **명령**: `scan` | `lock` | `fix` 중 하나. 없거나 알 수 없으면 사용법을 출력하고 종료 코드 `2`.
- **저장소 경로**: 첫 번째 위치 인자. 생략하면 현재 디렉터리(`.`).
- 옵션은 순서 무관하며 경로 앞뒤 어디에 와도 됩니다.

명령을 안 주고 `just-shield`만 실행하면 사용법 한 줄을 stderr로 출력합니다.

---

## 명령

### `scan` — 워크플로 검사

`.github/workflows/`의 워크플로 파일을 읽어 규칙 위반을 판정합니다. 출력 형식·종료 코드는 아래 해당 절 참고.

```bash
just-shield scan                  # 현재 디렉터리, 오프라인, text 출력
just-shield scan ./repo           # 다른 경로 검사
just-shield scan . --strict       # 🟡(중간)도 빌드 실패로 승격
just-shield scan . --online       # 네트워크 검사(R5·R10·LOCK) 활성화
just-shield scan . --format json  # 기계용 JSON
just-shield scan . --format sarif # SARIF 2.1.0 (GitHub 코드 스캐닝)
```

받는 옵션: `--strict`, `--online`, `--format`, `--cooldown-days`. (`--dry-run`은 scan에서 무시됩니다.)

### `lock` — 신뢰 박제

각 액션의 "태그 → 커밋 SHA" 대응을 저장소 루트의 `shield.lock`에 기록합니다. **네트워크가 필요**합니다.

```bash
just-shield lock          # 현재 디렉터리
just-shield lock ./repo
```

- 성공 시: `shield.lock 박제 완료 — N건 기록`을 출력하고 종료 코드 `0`.
- 박제할 수 없는 참조는 `건너뜀: <참조> — <사유>`로 stderr에 보고합니다.
- 이후 `scan --online`이 이 파일과 현재 상태를 대조해 태그 하이재킹(LOCK 규칙)을 잡습니다.
- `shield.lock`은 커밋해서 PR 리뷰 대상으로 관리하세요.

### `fix` — 가변 참조를 SHA로 자동 교체

태그/브랜치 참조를 커밋 SHA로 바꾸고 `# vX.Y.Z` 버전 주석을 답니다. **네트워크가 필요**합니다.

```bash
just-shield fix             # 실제로 파일을 수정
just-shield fix --dry-run   # 미리보기만, 파일 미변경
```

- 교체 항목마다 `파일:줄` 과 `- 이전` / `+ 이후`를 출력합니다.
- 교체할 수 없는 참조는 `건너뜀: <참조> — <사유>`로 보고합니다.
- 끝에 요약: `fix: 교체 N건, 건너뜀 M건 — 적용 완료` (또는 `미리보기 (--dry-run, 파일 미변경)`).
- 정상 종료는 항상 `0`, 내부 오류는 `2`.

---

## 옵션

| 옵션 | 값 | 적용 명령 | 의미 |
|------|-----|-----------|------|
| `--strict` | (없음) | scan | 🟡(중간) 발견도 실패로 승격해 종료 코드에 반영 |
| `--online` | (없음) | scan | 네트워크 검사 활성화 — R5(임포스터 커밋)·R10(쿨다운)·LOCK(태그 대조) |
| `--dry-run` | (없음) | fix | 변경 사항을 적용하지 않고 미리보기만 |
| `--cooldown-days` | 정수 N | scan | R10 쿨다운 기준 일수. 생략 시 기본 7. `.just-shield.conf`보다 우선 |
| `--format` | `text` \| `json` \| `sarif` | scan | 출력 형식. `--format json` 또는 `--format=json` 둘 다 가능. 기본 `text` |

지원하지 않는 형식 값이나 알 수 없는 `--옵션`은 오류 메시지를 내고 종료 코드 `2`.

---

## 종료 코드

| 코드 | 의미 |
|------|------|
| `0` | 통과 — 빌드를 깨뜨릴 발견 없음 |
| `1` | 위반 — 🔴 발견(또는 `--strict`일 때 🟡 포함) |
| `2` | 사용법/입출력 오류 — 잘못된 옵션, 경로 문제, 내부 오류 |

종료 코드는 **출력 형식과 무관**합니다 — text·json·sarif 모두 같은 판정에서 같은 코드를 냅니다. GitHub Action에서는 이 코드가 그대로 잡 결과가 됩니다.

---

## 출력 형식

### `text` (기본)

사람이 읽는 리포트. 각 발견의 등급·위치·근거(evidence)·수정 힌트(fix_hint)와 요약을 보여줍니다.

### `json`

기계가 소비하는 안정 스키마(version 1). 핵심 구조:

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
    { "rule": "R1", "file": ".github/workflows/ci.yml", "line": 12,
      "uses": "vendor/tool@v2", "reason": "무시 주석의 -- 뒤 사유" }
  ]
}
```

- `severity`: `high` | `medium` | `info` (무시된 항목은 별도로 `suppressed` 배열에 수록)
- `file`: 플랫폼과 무관하게 `/` 구분자로 정규화
- `exit_code`: 그 실행의 종료 코드와 동일 (`--strict` 반영)
- `findings`: (file, line, rule) 순 정렬 — 같은 입력이면 항상 같은 순서

전체 스키마 설명은 [README의 JSON 출력 절](../README.md#json-출력-스키마-version-1).

### `sarif`

[SARIF 2.1.0](https://docs.github.com/en/code-security/code-scanning) — GitHub 코드 스캐닝 업로드용. 심각도 매핑: 🔴 → `error`, 🟡 → `warning`, 🔵 → `note`. 무시된 발견은 사라지지 않고 SARIF `suppressions`(사유 포함)로 표현됩니다. `--format sarif`는 보통 `output-file`과 함께 써서 파일로 저장합니다.

---

## 보조 파일

| 파일 | 위치 | 역할 |
|------|------|------|
| `shield.lock` | 저장소 루트 | `lock`이 생성하는 "태그 → SHA" 박제본. `scan --online`이 대조 |
| `.just-shield.conf` | 저장소 루트 | 조직 단위 설정 |

### `.just-shield.conf`

한 줄에 하나씩 선언합니다.

```text
# 해당 org의 액션을 퍼스트파티(검사 제외)로 취급
trust-org partner-org
# R10 쿨다운 기준 일수 (기본 7). CLI --cooldown-days가 이 값보다 우선
cooldown-days 14
```

### 무시 주석 (탈출구)

경고 난 줄 위 또는 같은 줄 끝에 단다. `--` 뒤 사유는 필수.

```yaml
# just-shield: ignore R1 -- 사유를 여기에
- uses: vendor/tool@v2          # just-shield: ignore R1, R7 -- 여러 규칙도 가능
```

사유 없는 무시는 적용되지 않고 🔵로 보고됩니다. 무시된 항목은 ⚪ 등급으로 리포트·JSON·SARIF에 남습니다.

---

## GitHub Action 입력

`uses: kihyun1998/just-shield@<SHA>`로 호출할 때의 `with:` 입력입니다. 각 입력은 동일한 CLI 동작에 매핑됩니다.

| 입력 | 기본값 | 대응 CLI |
|------|--------|----------|
| `path` | `.` | 검사할 저장소 경로 (위치 인자) |
| `strict` | `false` | `'true'`면 `--strict` |
| `online` | `false` | `'true'`면 `--online` |
| `format` | `text` | `--format <값>` (text\|json\|sarif) |
| `cooldown-days` | (빈 값 = 7) | `--cooldown-days <N>` |
| `output-file` | (빈 값 = stdout) | 출력을 저장할 파일 경로 (SARIF 업로드용) |
| `version` | 핀 고정된 검증 릴리스 | 내려받을 just-shield 릴리스 태그 |

래퍼는 릴리스 바이너리를 내려받아 **SHA256SUMS 체크섬 검증을 통과한 경우에만** 실행하며, scan의 종료 코드가 그대로 잡 결과가 됩니다. 워크플로 예시는 [단계별 가이드 6절](usage.md#6-ci에-붙이기--github-action-10분).

---

## 참고

- 처음부터 따라 하기 → [단계별 적용 가이드](usage.md)
- 규칙 R1~R10·LOCK이 각각 무엇을 잡는지 → [README 규칙표](../README.md#검사-규칙-구현-현황)
- 설계 배경·용어 → [CONTEXT.md](../CONTEXT.md) · [docs/adr/](adr/)
