//! S8(R5 임포스터 커밋)·S9(R10 쿨다운) 수용 기준 — 가짜 GitHub 구현으로 검증한다.

use just_shield::ScanOptions;
use just_shield::github_facts::GithubFacts;
use just_shield::rules::Severity;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

const GOOD_SHA: &str = "aaaa000000000000000000000000000000000000";
const IMPOSTOR_SHA: &str = "bbbb000000000000000000000000000000000000";
const ERROR_SHA: &str = "cccc000000000000000000000000000000000000";

/// 도달 가능성·타임스탬프를 제어할 수 있는 가짜 GitHub.
#[derive(Default)]
struct FakeGithub {
    reachable: HashMap<String, bool>,
    /// 키: "repo@ref" → 커미터 시각 (unix 초).
    timestamps: HashMap<String, i64>,
}

impl GithubFacts for FakeGithub {
    fn resolve_ref(&self, _owner_repo: &str, _git_ref: &str) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn commit_reachable(&self, _owner_repo: &str, sha: &str) -> io::Result<Option<bool>> {
        if sha == ERROR_SHA {
            return Err(io::Error::other("네트워크 오류 시뮬레이션"));
        }
        Ok(self.reachable.get(sha).copied())
    }

    fn ref_timestamp(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<i64>> {
        Ok(self
            .timestamps
            .get(&format!("{owner_repo}@{git_ref}"))
            .copied())
    }
}

fn make_repo(name: &str, workflow: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("just-shield-online-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".github").join("workflows")).unwrap();
    std::fs::write(
        root.join(".github").join("workflows").join("ci.yml"),
        workflow,
    )
    .unwrap();
    root
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn r5_impostor_commit_is_high_real_commit_silent_error_is_info() {
    let workflow = format!(
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: good/action@{GOOD_SHA}\n      - uses: evil/action@{IMPOSTOR_SHA}\n      - uses: flaky/action@{ERROR_SHA}\n"
    );
    let root = make_repo("r5", &workflow);
    let facts = FakeGithub {
        reachable: HashMap::from([
            (GOOD_SHA.to_string(), true),
            (IMPOSTOR_SHA.to_string(), false),
        ]),
        ..Default::default()
    };
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let r5: Vec<_> = result.findings.iter().filter(|f| f.rule == "R5").collect();
    assert_eq!(r5.len(), 2);

    // 임포스터: 🔴, 근거에 SHA와 저장소 명시.
    let impostor = r5.iter().find(|f| f.uses.contains("evil/")).unwrap();
    assert_eq!(impostor.severity, Severity::High);
    assert!(impostor.evidence.contains(IMPOSTOR_SHA));

    // 조회 실패: 🔵 확인 불가 — 오탐을 만들지 않는다.
    let flaky = r5.iter().find(|f| f.uses.contains("flaky/")).unwrap();
    assert_eq!(flaky.severity, Severity::Info);

    // 실재 커밋은 침묵.
    assert!(!r5.iter().any(|f| f.uses.contains("good/")));
}

#[test]
fn r10_fresh_ref_is_medium_aged_ref_silent_boundary_exact() {
    let workflow = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: fresh/action@v1.2.3\n      - uses: aged/action@v2.0.0\n      - uses: exact/action@v3.0.0\n";
    let root = make_repo("r10", workflow);
    let t = now();
    let facts = FakeGithub {
        timestamps: HashMap::from([
            ("fresh/action@v1.2.3".to_string(), t - 3 * 86_400), // 3일 전 → 🟡
            ("aged/action@v2.0.0".to_string(), t - 30 * 86_400), // 30일 전 → 침묵
            ("exact/action@v3.0.0".to_string(), t - 7 * 86_400), // 정확히 7일 → 침묵 (>= 기준)
        ]),
        ..Default::default()
    };
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let r10: Vec<_> = result.findings.iter().filter(|f| f.rule == "R10").collect();
    assert_eq!(r10.len(), 1);
    assert!(r10[0].uses.contains("fresh/"));
    assert_eq!(r10[0].severity, Severity::Medium);
    assert!(
        r10[0].evidence.contains("미검증"),
        "근거가 미검증 기간 회피 취지를 설명해야 한다"
    );
}

#[test]
fn r10_cooldown_days_is_configurable() {
    let workflow = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: fresh/action@v1.2.3\n";
    let t = now();
    let facts = FakeGithub {
        timestamps: HashMap::from([("fresh/action@v1.2.3".to_string(), t - 10 * 86_400)]),
        ..Default::default()
    };

    // 기본 7일: 10일 된 참조는 침묵.
    let root = make_repo("cd-default", workflow);
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    assert!(result.findings.iter().all(|f| f.rule != "R10"));
    let _ = std::fs::remove_dir_all(&root);

    // CLI 옵션으로 30일: 같은 참조가 🟡.
    let root = make_repo("cd-cli", workflow);
    let result = just_shield::scan_with_options(
        &root,
        &ScanOptions {
            facts: Some(&facts),
            cooldown_days: Some(30),
        },
    )
    .unwrap();
    assert!(result.findings.iter().any(|f| f.rule == "R10"));
    let _ = std::fs::remove_dir_all(&root);

    // 설정 파일로 30일: 같은 효과.
    let root = make_repo("cd-conf", workflow);
    std::fs::write(root.join(".just-shield.conf"), "cooldown-days 30\n").unwrap();
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    assert!(result.findings.iter().any(|f| f.rule == "R10"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn offline_scan_skips_online_rules_and_says_so() {
    let workflow = format!(
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: evil/action@{IMPOSTOR_SHA}\n"
    );
    let root = make_repo("offline", &workflow);
    let result = just_shield::scan(&root).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    // 오프라인: R5/R10 발견 없음 + 건너뛴 사실이 리포트에 안내된다.
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.rule != "R5" && f.rule != "R10")
    );
    assert!(result.online_rules_skipped);
    let text = just_shield::report::render(&result, false);
    assert!(text.contains("--online"));
}
