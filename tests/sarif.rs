//! `--format sarif` 통합 테스트 — GitHub 코드 스캐닝용 SARIF 2.1.0 출력.
//!
//! 스냅숏(tests/snapshots/violation.sarif)으로 출력 전체를 고정한다.
//! 규칙 문구를 바꾸면 스냅숏도 함께 갱신해야 한다 — 출력 변화가 리뷰를 통과하게 하는 장치다.

use std::process::Command;

fn run_sarif(fixture: &str) -> (String, Option<i32>) {
    let bin = env!("CARGO_BIN_EXE_just-shield");
    let out = Command::new(bin)
        .args(["scan", fixture, "--format", "sarif"])
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
        out.status.code(),
    )
}

#[test]
fn violation_sarif_matches_snapshot() {
    let (sarif, code) = run_sarif("tests/fixtures/violation");
    // 종료 코드는 텍스트/JSON 모드와 동일 — 출력 형식이 판정을 바꾸지 않는다.
    assert_eq!(code, Some(1));
    let expected = include_str!("snapshots/violation.sarif")
        .replace("\r\n", "\n")
        .replace("{VERSION}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        sarif, expected,
        "SARIF 스냅숏 불일치 — 의도한 변경이면 tests/snapshots/violation.sarif를 갱신하세요"
    );
}

#[test]
fn sarif_severity_maps_to_levels_and_required_fields_exist() {
    let (sarif, _) = run_sarif("tests/fixtures/violation");
    // SARIF 2.1.0 필수 구조.
    for field in [
        "\"version\": \"2.1.0\"",
        "\"runs\": [",
        "\"driver\": {",
        "\"rules\": [",
        "\"results\": [",
        // High→error, Medium→warning, Info→note.
        "\"level\": \"error\"",
        "\"level\": \"warning\"",
        "\"level\": \"note\"",
        // 경로는 / 구분자로 정규화 (JSON과 동일 원칙).
        "\"uri\": \".github/workflows/ci.yml\"",
        "\"startLine\": 9",
    ] {
        assert!(
            sarif.contains(field),
            "SARIF에 {field} 가 없습니다:\n{sarif}"
        );
    }
    assert!(!sarif.contains("workflows\\"), "경로 정규화 실패");
}

#[test]
fn suppressed_findings_become_sarif_suppressions() {
    let (sarif, code) = run_sarif("tests/fixtures/escape");
    // 사유 있는 무시(10행)는 suppressions로 표현되고, 결과에서 사라지지 않는다 (침묵 ≠ 은폐).
    assert!(sarif.contains("\"suppressions\": [{ \"kind\": \"inSource\""));
    assert!(sarif.contains("내부 보안팀 검증 완료"));
    assert!(sarif.contains("vendor/tool@v2"));
    // 사유 없는 무시(13행)는 무시가 적용되지 않으므로 suppressions 없이 결과로 남는다.
    assert!(sarif.contains("vendor/tool3@v2"));
    // 무시되지 않은 High(11행)가 있으므로 종료 코드는 1.
    assert_eq!(code, Some(1));
}

#[test]
fn clean_repo_sarif_has_empty_results() {
    let (sarif, code) = run_sarif("tests/fixtures/clean");
    assert_eq!(code, Some(0));
    assert!(sarif.contains("\"results\": []"));
    // 규칙 메타데이터는 결과가 없어도 항상 전부 실린다.
    assert!(sarif.contains("\"id\": \"LOCK\""));
}
