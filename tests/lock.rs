//! S7 수용 기준 검증 — shield.lock 박제·대조를 가짜 GitHub 구현으로 재현한다.

use just_shield::github_facts::GithubFacts;
use just_shield::rules::Severity;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

/// 테스트용 가짜 GitHub — (repo, ref) → SHA 맵.
struct FakeGithub(HashMap<(String, String), String>);

impl FakeGithub {
    fn new(entries: &[(&str, &str, &str)]) -> Self {
        Self(
            entries
                .iter()
                .map(|(repo, r, sha)| ((repo.to_string(), r.to_string()), sha.to_string()))
                .collect(),
        )
    }
}

impl GithubFacts for FakeGithub {
    fn resolve_ref(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<String>> {
        Ok(self
            .0
            .get(&(owner_repo.to_string(), git_ref.to_string()))
            .cloned())
    }
}

/// 워크플로 하나를 가진 임시 저장소를 만든다.
fn make_repo(name: &str, workflow: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("just-shield-lock-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".github").join("workflows")).unwrap();
    std::fs::write(
        root.join(".github").join("workflows").join("ci.yml"),
        workflow,
    )
    .unwrap();
    root
}

const WORKFLOW: &str = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: aquasecurity/trivy-action@0.28.0\n      - uses: actions/checkout@v4\n";

#[test]
fn lock_is_deterministic_and_sorted() {
    let root = make_repo("det", WORKFLOW);
    let fake = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "aaaa000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "bbbb000000000000000000000000000000000000",
        ),
    ]);

    let outcome = just_shield::lock(&root, &fake).unwrap();
    assert_eq!(outcome.written, 2);
    assert!(outcome.skipped.is_empty());
    let first = std::fs::read(root.join("shield.lock")).unwrap();

    just_shield::lock(&root, &fake).unwrap();
    let second = std::fs::read(root.join("shield.lock")).unwrap();
    assert_eq!(first, second, "같은 입력 → 같은 바이트 (diff 친화)");

    // 정렬: actions/checkout이 aquasecurity보다 먼저.
    let text = String::from_utf8(first).unwrap();
    let a = text.find("actions/checkout@v4").unwrap();
    let b = text.find("aquasecurity/trivy-action@0.28.0").unwrap();
    assert!(a < b);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn moved_exact_version_tag_is_high_with_both_shas() {
    let root = make_repo("hijack", WORKFLOW);
    let before = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "aaaa000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "bbbb000000000000000000000000000000000000",
        ),
    ]);
    just_shield::lock(&root, &before).unwrap();

    // 박제 후 공격자가 정확 버전 태그를 옮겨 꽂은 상황.
    let after = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "ffff000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "bbbb000000000000000000000000000000000000",
        ),
    ]);
    let result = just_shield::scan_with_facts(&root, Some(&after)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let lock_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule == "LOCK")
        .collect();
    assert_eq!(lock_findings.len(), 1, "이동한 태그만 보고돼야 한다");
    let f = lock_findings[0];
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.evidence
            .contains("aaaa000000000000000000000000000000000000")
    );
    assert!(
        f.evidence
            .contains("ffff000000000000000000000000000000000000")
    );
    assert_eq!(just_shield::report::exit_code(&result, false), 1);
}

#[test]
fn moved_major_alias_is_info_not_failure() {
    let root = make_repo("alias", WORKFLOW);
    let before = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "aaaa000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "bbbb000000000000000000000000000000000000",
        ),
    ]);
    just_shield::lock(&root, &before).unwrap();

    // v4 같은 메이저 별칭은 정상 릴리스로도 이동한다 → 🔵 안내까지만.
    let after = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "aaaa000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "cccc000000000000000000000000000000000000",
        ),
    ]);
    let result = just_shield::scan_with_facts(&root, Some(&after)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let lock_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule == "LOCK")
        .collect();
    assert_eq!(lock_findings.len(), 1);
    assert_eq!(lock_findings[0].severity, Severity::Info);
}

#[test]
fn unmoved_tags_are_silent() {
    let root = make_repo("calm", WORKFLOW);
    let fake = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "aaaa000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "bbbb000000000000000000000000000000000000",
        ),
    ]);
    just_shield::lock(&root, &fake).unwrap();
    let result = just_shield::scan_with_facts(&root, Some(&fake)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    assert!(result.findings.iter().all(|f| f.rule != "LOCK"));
}

#[test]
fn unlocked_mutable_ref_is_reported_offline() {
    let root = make_repo("partial", WORKFLOW);
    // trivy만 박제하고 checkout@v4는 빠진 상태로 만든다.
    let fake = FakeGithub::new(&[(
        "aquasecurity/trivy-action",
        "0.28.0",
        "aaaa000000000000000000000000000000000000",
    )]);
    let outcome = just_shield::lock(&root, &fake).unwrap();
    assert_eq!(outcome.written, 1);
    assert_eq!(outcome.skipped.len(), 1, "해석 실패는 건너뛰고 보고");

    // 오프라인 scan: 박제 안 된 가변 참조는 🔵로 안내된다 (네트워크 불필요).
    let result = just_shield::scan(&root).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let lock_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule == "LOCK")
        .collect();
    assert_eq!(lock_findings.len(), 1);
    assert_eq!(lock_findings[0].severity, Severity::Info);
    assert!(lock_findings[0].uses.contains("actions/checkout"));
}

#[test]
fn missing_lockfile_changes_nothing() {
    // 기존 픽스처에는 shield.lock이 없다 — LOCK 발견이 없어야 하고 오류도 없어야 한다.
    let result = just_shield::scan(Path::new("tests/fixtures/violation")).unwrap();
    assert!(result.findings.iter().all(|f| f.rule != "LOCK"));
}

#[test]
fn resolution_failure_is_reported_not_guessed() {
    let root = make_repo("offline-ish", WORKFLOW);
    let fake = FakeGithub::new(&[
        (
            "aquasecurity/trivy-action",
            "0.28.0",
            "aaaa000000000000000000000000000000000000",
        ),
        (
            "actions/checkout",
            "v4",
            "bbbb000000000000000000000000000000000000",
        ),
    ]);
    just_shield::lock(&root, &fake).unwrap();

    // 박제 후 조회가 아무것도 못 찾는 상황(네트워크 장애 등) → 판정 보류 🔵, 오탐 없음.
    let empty = FakeGithub::new(&[]);
    let result = just_shield::scan_with_facts(&root, Some(&empty)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let lock_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule == "LOCK")
        .collect();
    assert_eq!(lock_findings.len(), 2);
    // 확인 불가가 🔴로 둔갑하지 않는다 — LOCK은 전부 안내에 머문다.
    assert!(lock_findings.iter().all(|f| f.severity == Severity::Info));
}
