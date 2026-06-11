//! S1 수용 기준 검증 — 외부 동작(입력 워크플로 → 판정·근거·종료 코드)만 테스트한다.

use std::path::Path;
use std::process::Command;

#[test]
fn detects_mutable_refs_with_file_and_line() {
    let result = just_shield::scan(Path::new("tests/fixtures/violation")).unwrap();
    assert_eq!(result.workflows_scanned, 1);

    // 가변 참조 4건: @v4, @master, @release, 참조 없음.
    // SHA 핀 2건, 로컬, docker://, 주석 처리 행은 침묵해야 한다.
    let lines: Vec<usize> = result.findings.iter().map(|f| f.line).collect();
    assert_eq!(lines, vec![7, 8, 15, 16]);

    for f in &result.findings {
        assert_eq!(f.rule, "R1");
        assert!(f.file.contains("ci.yml"));
        assert!(!f.evidence.is_empty(), "모든 발견에는 근거가 붙어야 한다");
        assert!(
            !f.fix_hint.is_empty(),
            "모든 발견에는 해결 힌트가 붙어야 한다"
        );
    }

    // 따옴표로 감싼 참조도 값이 정확히 추출돼야 한다.
    assert_eq!(result.findings[1].uses, "aquasecurity/trivy-action@master");
}

#[test]
fn clean_workflows_pass_silently() {
    let result = just_shield::scan(Path::new("tests/fixtures/clean")).unwrap();
    assert_eq!(result.workflows_scanned, 1);
    assert!(result.findings.is_empty());
}

#[test]
fn missing_workflows_dir_is_not_an_error() {
    let result = just_shield::scan(Path::new("tests/fixtures")).unwrap();
    assert_eq!(result.workflows_scanned, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn exit_code_one_on_violation_zero_on_clean() {
    let bin = env!("CARGO_BIN_EXE_just-shield");

    let bad = Command::new(bin)
        .args(["scan", "tests/fixtures/violation"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&bad.stdout);
    assert!(stdout.contains("R1"));
    assert!(stdout.contains("ci.yml"));

    let good = Command::new(bin)
        .args(["scan", "tests/fixtures/clean"])
        .output()
        .unwrap();
    assert_eq!(good.status.code(), Some(0));

    let usage = Command::new(bin).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
}
