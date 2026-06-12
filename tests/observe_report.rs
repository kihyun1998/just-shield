//! `observe report` 통합 테스트 — 판정 코어의 오프라인 재현 (채점표 ①, 이슈 #44).
//!
//! 관찰과 판정이 기록 파일로 분리되므로(ADR-0006), 모든 판정 경로가
//! 네트워크·러너 없이 손으로 쓴 기록으로 재현된다 (facts.txt 패턴).

use std::process::Command;

fn run(args: &[&str]) -> (String, Option<i32>) {
    let bin = env!("CARGO_BIN_EXE_just-shield");
    let out = Command::new(bin).args(args).output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
        out.status.code(),
    )
}

#[test]
fn locked_job_unlisted_destination_fails_with_rotation_advice() {
    let (text, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress/locked",
        "--record",
        "tests/fixtures/egress/records/release-exfil.txt",
    ]);
    assert_eq!(
        code,
        Some(1),
        "미등재 목적지는 빌드 실패여야 합니다:\n{text}"
    );
    for needle in [
        "EGRESS",
        "release",
        "data-collect.evil.net", // 어느 도메인인지 특정
        "회전",                  // 토큰 회전 권고
        "다음 한 줄을 추가",     // 복붙용 락 diff
    ] {
        assert!(
            text.contains(needle),
            "보고에 {needle} 가 없습니다:\n{text}"
        );
    }
}

#[test]
fn locked_job_all_listed_is_silent_pass() {
    let (text, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress/locked",
        "--record",
        "tests/fixtures/egress/records/release-clean.txt",
    ]);
    assert_eq!(code, Some(0), "등재만 조회했으면 통과여야 합니다:\n{text}");
    assert!(text.contains("일치"));
}

#[test]
fn unlocked_job_never_fails_and_proposes_draft() {
    // 락이 있어도 그 잡이 없으면 — 잠금은 선택제.
    let (text, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress/locked",
        "--record",
        "tests/fixtures/egress/records/build-unlocked.txt",
    ]);
    assert_eq!(code, Some(0));
    assert!(
        text.contains("[build]"),
        "초안에 잡 구획이 없습니다:\n{text}"
    );
    assert!(text.contains("totally-new-domain.example"));
    assert!(text.contains("실패하지 않음"));

    // 락 파일 자체가 없어도 동일 — 보고 + 초안.
    let (text, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress", // egress.lock 없는 디렉터리
        "--record",
        "tests/fixtures/egress/records/build-unlocked.txt",
    ]);
    assert_eq!(code, Some(0));
    assert!(text.contains("[build]"));
}

#[test]
fn egress_verdict_flows_into_json_and_sarif() {
    let (json, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress/locked",
        "--record",
        "tests/fixtures/egress/records/release-exfil.txt",
        "--format",
        "json",
    ]);
    assert_eq!(code, Some(1));
    assert!(json.contains("\"rule\": \"EGRESS\""));
    assert!(json.contains("\"severity\": \"high\""));
    assert!(json.contains("data-collect.evil.net"));

    let (sarif, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress/locked",
        "--record",
        "tests/fixtures/egress/records/release-exfil.txt",
        "--format",
        "sarif",
    ]);
    assert_eq!(code, Some(1));
    assert!(sarif.contains("\"ruleId\": \"EGRESS\""));
    assert!(sarif.contains("\"level\": \"error\""));
}

#[test]
fn broken_lock_is_usage_error_not_silence() {
    // 정책 파일이 깨졌으면 침묵 통과가 아니라 입출력 오류(2)다.
    let (_, code) = run(&[
        "observe",
        "report",
        "tests/fixtures/egress/broken",
        "--record",
        "tests/fixtures/egress/records/release-clean.txt",
    ]);
    assert_eq!(code, Some(2));
}

#[test]
fn missing_record_flag_is_usage_error() {
    let (_, code) = run(&["observe", "report", "tests/fixtures/egress/locked"]);
    assert_eq!(code, Some(2));
}
