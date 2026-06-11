//! S12 수용 기준 검증 — fix의 교체·보존·멱등성을 가짜 GitHub 구현으로 검증한다.

use just_shield::github_facts::GithubFacts;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

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

fn make_repo(name: &str, workflow: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("just-shield-fix-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".github").join("workflows")).unwrap();
    std::fs::write(
        root.join(".github").join("workflows").join("ci.yml"),
        workflow,
    )
    .unwrap();
    root
}

const SHA_A: &str = "aaaa000000000000000000000000000000000000";
const SHA_B: &str = "bbbb000000000000000000000000000000000000";
const SHA_C: &str = "cccc000000000000000000000000000000000000";

fn fake() -> FakeGithub {
    FakeGithub::new(&[
        ("aquasecurity/trivy-action", "v0.28.0", SHA_A),
        ("quoted/action", "v1", SHA_B),
        ("commented/action", "v2", SHA_C),
    ])
}

const WORKFLOW: &str = "name: CI\non: push # 트리거 주석\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: aquasecurity/trivy-action@v0.28.0\n      - uses: \"quoted/action@v1\"\n      - uses: commented/action@v2 # 기존 주석\n      - uses: ./local/action\n      - uses: docker://alpine:3.19\n      - uses: pinned/action@0123456789abcdef0123456789abcdef01234567 # v9\n      - uses: unknown/action@v3\n";

#[test]
fn replaces_mutable_refs_and_preserves_everything_else() {
    let root = make_repo("replace", WORKFLOW);
    let outcome = just_shield::fix::fix(&root, &fake(), false).unwrap();
    let content =
        std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml")).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    assert!(outcome.applied);
    assert_eq!(outcome.changes.len(), 3);

    // 교체: SHA + 사람용 버전 주석.
    assert!(content.contains(&format!(
        "- uses: aquasecurity/trivy-action@{SHA_A} # v0.28.0"
    )));
    // 따옴표 보존, 주석은 따옴표 밖에.
    assert!(content.contains(&format!("- uses: \"quoted/action@{SHA_B}\" # v1")));
    // 기존 행 끝 주석은 보존하고 중복 주석을 덧붙이지 않는다.
    assert!(content.contains(&format!("- uses: commented/action@{SHA_C} # 기존 주석")));
    assert!(!content.contains("# 기존 주석 # v2"));

    // 건드리지 않는 것들: 로컬, docker, 이미 SHA 핀, 그리고 무관한 행 전부.
    assert!(content.contains("- uses: ./local/action"));
    assert!(content.contains("- uses: docker://alpine:3.19"));
    assert!(
        content.contains("- uses: pinned/action@0123456789abcdef0123456789abcdef01234567 # v9")
    );
    assert!(content.contains("on: push # 트리거 주석"));

    // 해석 실패는 변경하지 않고 사유 보고.
    assert!(content.contains("- uses: unknown/action@v3"));
    assert_eq!(outcome.skipped.len(), 1);
    assert!(outcome.skipped[0].0.contains("unknown/action@v3"));
}

#[test]
fn fix_is_idempotent() {
    let root = make_repo("idem", WORKFLOW);
    just_shield::fix::fix(&root, &fake(), false).unwrap();
    let first =
        std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml")).unwrap();

    let second_outcome = just_shield::fix::fix(&root, &fake(), false).unwrap();
    let second =
        std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml")).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    // 두 번째 실행: SHA로 핀된 참조는 가변이 아니므로 변경 0건, 파일 동일.
    assert_eq!(second_outcome.changes.len(), 0);
    assert_eq!(first, second);
}

#[test]
fn dry_run_reports_but_does_not_write() {
    let root = make_repo("dry", WORKFLOW);
    let outcome = just_shield::fix::fix(&root, &fake(), true).unwrap();
    let content =
        std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml")).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    assert!(!outcome.applied);
    assert_eq!(outcome.changes.len(), 3, "미리보기에도 변경 목록은 나온다");
    assert_eq!(content, WORKFLOW, "파일은 바이트 단위로 그대로여야 한다");
}

#[test]
fn crlf_line_endings_are_preserved() {
    let crlf_workflow = WORKFLOW.replace('\n', "\r\n");
    let root = make_repo("crlf", &crlf_workflow);
    just_shield::fix::fix(&root, &fake(), false).unwrap();
    let content =
        std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml")).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    assert!(!content.contains("\n\n") || crlf_workflow.contains("\r\n\r\n"));
    // 모든 행이 여전히 CRLF — LF 단독 행이 생기지 않았다.
    assert_eq!(
        content.matches('\n').count(),
        content.matches("\r\n").count()
    );
    assert!(content.contains(&format!(
        "- uses: aquasecurity/trivy-action@{SHA_A} # v0.28.0\r\n"
    )));
}

#[test]
fn first_party_refs_are_left_alone() {
    let root = make_repo(
        "firstparty",
        "on: push\njobs:\n  b:\n    steps:\n      - uses: myorg/tool@v1\n      - uses: other/tool@v1\n",
    );
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(
        root.join(".git").join("config"),
        "[remote \"origin\"]\n\turl = https://github.com/myorg/myrepo.git\n",
    )
    .unwrap();
    let facts = FakeGithub::new(&[("myorg/tool", "v1", SHA_A), ("other/tool", "v1", SHA_B)]);
    let outcome = just_shield::fix::fix(&root, &facts, false).unwrap();
    let content =
        std::fs::read_to_string(root.join(".github").join("workflows").join("ci.yml")).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    // 퍼스트파티(myorg)는 그대로, 서드파티만 교체.
    assert_eq!(outcome.changes.len(), 1);
    assert!(content.contains("- uses: myorg/tool@v1"));
    assert!(content.contains(&format!("- uses: other/tool@{SHA_B} # v1")));
}
