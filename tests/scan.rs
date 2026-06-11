//! S1·S2 수용 기준 검증 — 외부 동작(입력 워크플로 → 판정·등급·종료 코드)만 테스트한다.

use just_shield::rules::Severity;
use std::path::Path;
use std::process::Command;

#[test]
fn detects_mutable_refs_with_file_and_line() {
    let result = just_shield::scan(Path::new("tests/fixtures/violation")).unwrap();
    assert_eq!(result.workflows_scanned, 1);

    // 가변 참조 4건: @v4, @master, @release, 참조 없음.
    // SHA 핀 2건, 로컬, docker://, 주석 처리 행은 침묵해야 한다.
    let lines: Vec<usize> = result.findings.iter().map(|f| f.line).collect();
    assert_eq!(lines, vec![9, 10, 17, 18]);

    for f in &result.findings {
        assert_eq!(f.rule, "R1");
        assert!(f.file.contains("ci.yml"));
        assert!(!f.evidence.is_empty(), "모든 발견에는 근거가 붙어야 한다");
        assert!(
            !f.fix_hint.is_empty(),
            "모든 발견에는 해결 힌트가 붙어야 한다"
        );
    }

    // 신뢰 차등: GitHub 공식(actions/*)은 🔵, 그 외 서드파티는 🔴.
    assert_eq!(result.findings[0].severity, Severity::Info);
    assert_eq!(result.findings[1].severity, Severity::High);
    assert_eq!(result.findings[2].severity, Severity::High);
    assert_eq!(result.findings[3].severity, Severity::High);

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
fn official_actions_are_info_and_never_fail() {
    let result = just_shield::scan(Path::new("tests/fixtures/official")).unwrap();
    assert_eq!(result.findings.len(), 2);
    assert!(result.findings.iter().all(|f| f.severity == Severity::Info));
    // 🔵은 strict 모드에서도 빌드를 깨뜨리지 않는다.
    assert_eq!(just_shield::report::exit_code(&result, false), 0);
    assert_eq!(just_shield::report::exit_code(&result, true), 0);
}

#[test]
fn same_owner_actions_are_first_party_and_silent() {
    // .git 디렉터리는 저장소에 커밋할 수 없으므로 임시 디렉터리에 구성한다.
    let root = std::env::temp_dir().join(format!("just-shield-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join(".github").join("workflows")).unwrap();
    std::fs::write(
        root.join(".git").join("config"),
        "[remote \"origin\"]\n\turl = https://github.com/myorg/myrepo.git\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".github").join("workflows").join("ci.yml"),
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: myorg/internal-action@v1\n      - uses: evil/other-action@v1\n",
    )
    .unwrap();

    let result = just_shield::scan(&root).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    // 같은 소유자(myorg)는 침묵, 남(evil)은 🔴 한 건만.
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0].uses.starts_with("evil/"));
    assert_eq!(result.findings[0].severity, Severity::High);
}

#[test]
fn blast_radius_rules_fire_together() {
    let result = just_shield::scan(Path::new("tests/fixtures/blast")).unwrap();
    let by_rule = |r: &str| -> Vec<_> { result.findings.iter().filter(|f| f.rule == r).collect() };

    // R1: 전부 SHA 핀이라 침묵.
    assert!(by_rule("R1").is_empty());

    // R8 🔴: pull_request_target + 외부 PR head 체크아웃 조합.
    let r8 = by_rule("R8");
    assert_eq!(r8.len(), 1);
    assert_eq!(r8[0].severity, Severity::High);

    // R6 🟡: 시크릿 쓰는 잡의 서드파티 액션 (공식 checkout은 대상 아님).
    let r6 = by_rule("R6");
    assert_eq!(r6.len(), 1);
    assert_eq!(r6[0].severity, Severity::Medium);
    assert!(r6[0].uses.starts_with("evil/"));

    // R7 🟡: permissions 미선언.
    let r7 = by_rule("R7");
    assert_eq!(r7.len(), 1);
    assert_eq!(r7[0].severity, Severity::Medium);

    for f in &result.findings {
        assert!(!f.evidence.is_empty());
        assert!(!f.fix_hint.is_empty());
    }

    // 🔴(R8)이 있으므로 기본 모드에서도 빌드 실패.
    assert_eq!(just_shield::report::exit_code(&result, false), 1);
}

#[test]
fn write_all_permissions_is_flagged() {
    let result = just_shield::scan(Path::new("tests/fixtures/writeall")).unwrap();
    let r7: Vec<_> = result.findings.iter().filter(|f| f.rule == "R7").collect();
    assert_eq!(r7.len(), 1);
    assert_eq!(r7[0].severity, Severity::Medium);
    assert!(r7[0].evidence.contains("write-all"));
    // 🟡뿐이므로 기본 통과, --strict에서 실패.
    assert_eq!(just_shield::report::exit_code(&result, false), 0);
    assert_eq!(just_shield::report::exit_code(&result, true), 1);
}

#[test]
fn declared_minimal_permissions_silence_r7() {
    // clean 픽스처는 워크플로 수준 contents: read 선언 — R6·R7·R8 모두 침묵해야 한다.
    let result = just_shield::scan(Path::new("tests/fixtures/clean")).unwrap();
    assert!(result.findings.is_empty());
}

#[test]
fn strict_promotes_medium_to_failure() {
    // 🟡 규칙은 S3에서 들어오므로, 종료 코드 정책은 합성 결과로 검증한다.
    let medium_only = just_shield::ScanResult {
        workflows_scanned: 1,
        findings: vec![just_shield::rules::Finding {
            rule: "R7",
            severity: Severity::Medium,
            file: "x.yml".into(),
            line: 1,
            uses: String::new(),
            evidence: "합성 픽스처".into(),
            fix_hint: "합성 픽스처".into(),
        }],
    };
    assert_eq!(just_shield::report::exit_code(&medium_only, false), 0);
    assert_eq!(just_shield::report::exit_code(&medium_only, true), 1);
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

    // 공식 액션만 있는 저장소: 🔵뿐이므로 strict에서도 통과.
    let official = Command::new(bin)
        .args(["scan", "tests/fixtures/official", "--strict"])
        .output()
        .unwrap();
    assert_eq!(official.status.code(), Some(0));

    let usage = Command::new(bin).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
}
