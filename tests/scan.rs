//! S1·S2 수용 기준 검증 — 외부 동작(입력 워크플로 → 판정·등급·종료 코드)만 테스트한다.

use just_shield::rules::Severity;
use std::path::Path;
use std::process::Command;

#[test]
fn detects_mutable_refs_with_file_and_line() {
    let result = just_shield::scan(Path::new("tests/fixtures/violation")).unwrap();
    assert_eq!(result.workflows_scanned, 1);

    // 가변 참조 4건: @v4, @master, @release, 참조 없음.
    // SHA 핀 2건, 로컬, docker://(R1 대상 아님), 주석 처리 행은 침묵해야 한다.
    let r1: Vec<_> = result.findings.iter().filter(|f| f.rule == "R1").collect();
    let lines: Vec<usize> = r1.iter().map(|f| f.line).collect();
    assert_eq!(lines, vec![9, 10, 17, 18]);

    for f in &result.findings {
        assert!(f.file.contains("ci.yml"));
        assert!(!f.evidence.is_empty(), "모든 발견에는 근거가 붙어야 한다");
        assert!(
            !f.fix_hint.is_empty(),
            "모든 발견에는 해결 힌트가 붙어야 한다"
        );
    }

    // 신뢰 차등: GitHub 공식(actions/*)은 🔵, 그 외 서드파티는 🔴.
    assert_eq!(r1[0].severity, Severity::Info);
    assert_eq!(r1[1].severity, Severity::High);
    assert_eq!(r1[2].severity, Severity::High);
    assert_eq!(r1[3].severity, Severity::High);

    // 따옴표로 감싼 참조도 값이 정확히 추출돼야 한다.
    assert_eq!(r1[1].uses, "aquasecurity/trivy-action@master");
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
        suppressed: vec![],
        online_rules_skipped: false,
    };
    assert_eq!(just_shield::report::exit_code(&medium_only, false), 0);
    assert_eq!(just_shield::report::exit_code(&medium_only, true), 1);
}

#[test]
fn ignore_comment_with_reason_suppresses_only_that_line_and_rule() {
    let result = just_shield::scan(Path::new("tests/fixtures/escape")).unwrap();

    // 사유 있는 주석 → 다음 행(vendor/tool@v2)의 R1만 무시됨, 사유 보존.
    assert_eq!(result.suppressed.len(), 1);
    assert!(result.suppressed[0].finding.uses.contains("vendor/tool@v2"));
    assert!(result.suppressed[0].reason.contains("2026-07"));

    // 다른 행(tool2, tool3)에는 영향 없음 — 여전히 활성 🔴.
    let r1: Vec<_> = result.findings.iter().filter(|f| f.rule == "R1").collect();
    assert_eq!(r1.len(), 2);
    assert!(r1.iter().any(|f| f.uses.contains("tool2")));
    assert!(r1.iter().any(|f| f.uses.contains("tool3")));

    // 사유 없는 주석 → 무시 미적용 + 그 사실이 보고됨.
    let ignore: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule == "IGNORE")
        .collect();
    assert_eq!(ignore.len(), 1);
    assert_eq!(ignore[0].severity, Severity::Info);

    assert_eq!(just_shield::report::exit_code(&result, false), 1);
}

#[test]
fn suppressed_findings_appear_in_reports_with_reason() {
    let result = just_shield::scan(Path::new("tests/fixtures/escape")).unwrap();
    let text = just_shield::report::render(&result, false);
    assert!(text.contains("⚪ R1"));
    assert!(text.contains("사유: 내부 보안팀 검증 완료"));
    assert!(text.contains("⚪ 무시 1건"));

    let json = just_shield::report::render_json(&result, false);
    assert!(json.contains("\"suppressed\": 1"));
    assert!(json.contains("\"reason\": \"내부 보안팀 검증 완료, 2026-07 SHA 핀 예정\""));
}

#[test]
fn trusted_org_from_config_is_first_party() {
    let result = just_shield::scan(Path::new("tests/fixtures/trusted")).unwrap();
    // vendor는 .just-shield.conf의 trust-org → 침묵, stranger만 🔴.
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0].uses.starts_with("stranger/"));
    assert_eq!(result.findings[0].severity, Severity::High);
}

#[test]
fn pipe_install_is_info_only_and_never_fails() {
    let result = just_shield::scan(Path::new("tests/fixtures/pipe")).unwrap();
    let r3: Vec<_> = result.findings.iter().filter(|f| f.rule == "R3").collect();

    // curl | bash 한 건만 — 체크섬 검증 동반(wget+sha256sum)과 `| shasum`은 침묵.
    assert_eq!(r3.len(), 1);
    assert_eq!(r3[0].line, 9);
    assert_eq!(r3[0].severity, Severity::Info);

    // ADR-0002 회귀: 휴리스틱(R3)은 단독으로 빌드를 깨뜨릴 수 없다 — strict에서도.
    assert_eq!(just_shield::report::exit_code(&result, false), 0);
    assert_eq!(just_shield::report::exit_code(&result, true), 0);
}

#[test]
fn images_without_digest_are_medium() {
    let result = just_shield::scan(Path::new("tests/fixtures/images")).unwrap();
    let r4: Vec<_> = result.findings.iter().filter(|f| f.rule == "R4").collect();

    // container: node:18 + image: postgres:16 두 건.
    // redis@sha256(다이제스트)과 ${{ matrix.img }}(표현식 — 판정 불가)는 침묵.
    assert_eq!(r4.len(), 2);
    assert!(r4.iter().all(|f| f.severity == Severity::Medium));
    assert!(r4.iter().any(|f| f.uses.contains("node:18")));
    assert!(r4.iter().any(|f| f.uses.contains("postgres:16")));

    // 🟡뿐이므로 기본 통과, --strict에서 실패.
    assert_eq!(just_shield::report::exit_code(&result, false), 0);
    assert_eq!(just_shield::report::exit_code(&result, true), 1);
}

#[test]
fn known_compromised_version_is_flagged_offline_from_bundled_db() {
    // 완전 오프라인 scan() — 동봉 스냅숏만으로 알려진 악성 버전을 잡아야 한다.
    let result = just_shield::scan(Path::new("tests/fixtures/advisory")).unwrap();
    let r9: Vec<_> = result.findings.iter().filter(|f| f.rule == "R9").collect();

    assert_eq!(r9.len(), 1, "등재된 SHA만 — 등재 안 된 SHA는 침묵");
    assert_eq!(r9[0].line, 10);
    assert_eq!(r9[0].severity, Severity::High);
    assert!(
        r9[0].evidence.contains("CVE-2025-30066"),
        "근거에 권고 출처가 표시돼야 한다"
    );
    assert_eq!(just_shield::report::exit_code(&result, false), 1);
}

#[test]
fn teampcp_style_advisory_entries_match_tags_and_shas() {
    // TeamPCP 사례를 본뜬 권고 항목 — KICS(태그 하이재킹), Trivy(임포스터 커밋) 형태.
    let db = just_shield::advisory::AdvisoryDb::parse(
        "checkmarx/kics-github-action@aaaa000000000000000000000000000000000000 GHSA-fake-kics 2026-03 태그 하이재킹 오염 커밋\n\
         aquasecurity/trivy-action@v0.99.0 GHSA-fake-trivy 오염된 릴리스 태그\n",
    );
    let entries = just_shield::workflow::extract_uses_entries(
        "      - uses: checkmarx/kics-github-action@aaaa000000000000000000000000000000000000\n      - uses: aquasecurity/trivy-action@v0.99.0\n      - uses: aquasecurity/trivy-action@v0.28.0\n",
    );
    let findings = just_shield::rules::check_r9(Path::new("ci.yml"), &entries, &db);

    // SHA 등재·태그 등재 모두 매칭, 미등재 버전은 침묵.
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(
        findings
            .iter()
            .any(|f| f.evidence.contains("GHSA-fake-kics"))
    );
    assert!(
        findings
            .iter()
            .any(|f| f.evidence.contains("GHSA-fake-trivy"))
    );
}

#[test]
fn json_output_for_clean_repo_is_pinned_snapshot() {
    // 스키마 고정: 이 스냅숏이 깨지면 의도적 스키마 변경인지 확인하고 version을 올릴 것.
    let result = just_shield::scan(Path::new("tests/fixtures/clean")).unwrap();
    let json = just_shield::report::render_json(&result, false);
    let expected = "{\n  \"version\": 1,\n  \"workflows_scanned\": 1,\n  \"summary\": { \"high\": 0, \"medium\": 0, \"info\": 0, \"suppressed\": 0 },\n  \"exit_code\": 0,\n  \"findings\": [],\n  \"suppressed\": []\n}\n";
    assert_eq!(json, expected);
}

#[test]
fn json_output_contains_all_finding_fields() {
    let bin = env!("CARGO_BIN_EXE_just-shield");
    let out = Command::new(bin)
        .args(["scan", "tests/fixtures/violation", "--format", "json"])
        .output()
        .unwrap();
    // 종료 코드는 텍스트 모드와 동일.
    assert_eq!(out.status.code(), Some(1));
    let json = String::from_utf8_lossy(&out.stdout);
    for field in [
        "\"rule\": \"R1\"",
        "\"severity\": \"high\"",
        "\"severity\": \"info\"",
        // 경로는 OS와 무관하게 / 구분자로 정규화된다.
        "\"file\": \".github/workflows/ci.yml\"",
        "\"line\": 9",
        "\"uses\": \"aquasecurity/trivy-action@master\"",
        "\"evidence\": ",
        "\"fix_hint\": ",
        // docker://alpine:3.19가 R4 🟡로 잡힌다.
        "\"summary\": { \"high\": 3, \"medium\": 1, \"info\": 1, \"suppressed\": 0 }",
        "\"exit_code\": 1",
    ] {
        assert!(json.contains(field), "JSON에 {field} 가 없습니다:\n{json}");
    }
    assert!(
        !json.contains('\\') || !json.contains("workflows\\"),
        "경로 정규화 실패"
    );
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
