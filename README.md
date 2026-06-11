# just-shield

CI 파이프라인이 받아 쓰는 GitHub Action이 **진짜인지, 오염됐을 때 덜 털리는 구조인지**를 실행 전에 검사하는 CLI. 북극성은 CI 자격증명 탈취 방지다 — TeamPCP(UNC6780) 캠페인을 대표 검증 시나리오로 사용한다.

의존 크레이트 0개, 기본 완전 오프라인. 설계 배경은 [CONTEXT.md](CONTEXT.md)와 [docs/adr/](docs/adr/)에 있다.

## 사용법

```bash
just-shield scan [경로]              # 워크플로 검사 (기본: 현재 디렉터리, 오프라인)
just-shield scan . --strict         # 🟡(중간)도 빌드 실패로 승격
just-shield scan . --online         # shield.lock 대조 등 네트워크 검사 활성화
just-shield scan . --format json    # 기계용 JSON 출력
just-shield lock [경로]              # 태그→SHA를 shield.lock으로 박제 (네트워크 필요)
```

종료 코드: `0` 통과 · `1` 위반(🔴, `--strict`면 🟡 포함) · `2` 사용법/입출력 오류.

## 검사 규칙 (구현 현황)

| 규칙 | 등급 | 내용 |
|------|------|------|
| R1 | 🔴/🔵 | 서드파티 액션의 가변 참조(태그/브랜치). GitHub 공식은 🔵 완화 |
| R6 | 🟡 | 시크릿을 쓰는 잡에서 서드파티 액션 실행 |
| R7 | 🟡 | `permissions` 미선언 또는 `write-all` |
| R8 | 🔴 | `pull_request_target`/`workflow_run` + 외부 PR 체크아웃 조합 |
| LOCK | 🔴/🔵 | shield.lock 박제본 대비 태그 이동 (정확 버전 이동=🔴, 별칭/브랜치=🔵) |
| R2·R3·R4·R5·R9·R10 | — | 예정 ([이슈 트래커](https://github.com/kihyun1998/just-shield/issues) 참조) |

신뢰 분류: 로컬·같은 소유자 = 퍼스트파티(검사 제외), `actions/*`·`github/*` = 공식(완화), 그 외 전부 서드파티(엄격). 판별 실패 시 서드파티 취급(fail-closed).

## shield.lock

`just-shield lock`이 각 액션의 "태그 → 커밋 SHA" 대응을 저장소 루트의 `shield.lock`에 박제한다. 이후 `scan --online`은 현재 대응을 박제본과 대조해 **태그 하이재킹**(TeamPCP가 Trivy 76개 태그에 쓴 수법)을 권고 DB 등재 이전에 탐지한다. 락파일은 커밋해서 PR 리뷰 대상으로 관리하라 — 신뢰 변경이 코드 리뷰를 통과하는 구조다.

## JSON 출력 스키마 (version 1)

```json
{
  "version": 1,
  "workflows_scanned": 1,
  "summary": { "high": 1, "medium": 0, "info": 2 },
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
  ]
}
```

- `severity`: `high` | `medium` | `info`
- `file`: 플랫폼과 무관하게 `/` 구분자로 정규화
- `exit_code`: 해당 실행의 종료 코드와 동일 (`--strict` 반영)
- `findings`: (file, line, rule) 순 정렬 — 같은 입력이면 같은 순서

## 개발

```bash
cargo test     # 유닛 + 통합 테스트
cargo clippy   # 린트
```

모든 판정은 사실 기반이어야 한다 — 빌드를 깨뜨리는 🔴는 검증 가능한 사실에서만 나온다 ([ADR-0002](docs/adr/0002-fact-based-verdicts.md)).
