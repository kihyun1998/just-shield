//! S11(R2 타이포스쿼팅) 수용 기준 — 오프라인 🔵 상한과 교차 검증 격상을 검증한다.

use just_shield::github_facts::GithubFacts;
use just_shield::rules::Severity;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

/// 저장소별 태그 개수를 제어하는 가짜 GitHub.
#[derive(Default)]
struct FakeGithub {
    tag_counts: HashMap<String, usize>,
}

impl GithubFacts for FakeGithub {
    fn resolve_ref(&self, _owner_repo: &str, _git_ref: &str) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn ref_count(&self, owner_repo: &str) -> io::Result<Option<usize>> {
        Ok(self.tag_counts.get(owner_repo).copied())
    }
}

fn make_repo(name: &str, workflow: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("just-shield-r2-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".github").join("workflows")).unwrap();
    std::fs::write(
        root.join(".github").join("workflows").join("ci.yml"),
        workflow,
    )
    .unwrap();
    root
}

// 전치(aquasecurtiy)와 추가 글자(checkoutt) — 둘 다 SHA 핀이라 R1은 침묵, R2만 검증.
const WORKFLOW: &str = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: aquasecurtiy/trivy-action@0123456789abcdef0123456789abcdef01234567\n      - uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567\n      - uses: totally/unrelated-action@0123456789abcdef0123456789abcdef01234567\n";

#[test]
fn offline_typosquat_is_info_and_never_fails() {
    let root = make_repo("offline", WORKFLOW);
    let result = just_shield::scan(&root).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let r2: Vec<_> = result.findings.iter().filter(|f| f.rule == "R2").collect();
    // 짝퉁 1건만 — 본체(aquasecurity)와 무관한 이름은 침묵.
    assert_eq!(r2.len(), 1);
    assert!(r2[0].uses.starts_with("aquasecurtiy/"));
    assert_eq!(r2[0].severity, Severity::Info);
    assert!(r2[0].evidence.contains("aquasecurity/trivy-action"));

    // ADR-0002 회귀: 오프라인에서는 어떤 경우에도 🔵를 넘지 않는다.
    assert_eq!(just_shield::report::exit_code(&result, false), 0);
    assert_eq!(just_shield::report::exit_code(&result, true), 0);
}

#[test]
fn corroborated_typosquat_is_promoted_to_high() {
    let root = make_repo("promote", WORKFLOW);
    let facts = FakeGithub {
        tag_counts: HashMap::from([
            ("aquasecurtiy/trivy-action".to_string(), 1), // 급조 짝퉁: 태그 1개
            ("aquasecurity/trivy-action".to_string(), 48), // 원본: 풍부
        ]),
    };
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let r2: Vec<_> = result.findings.iter().filter(|f| f.rule == "R2").collect();
    assert_eq!(r2.len(), 1);
    assert_eq!(r2[0].severity, Severity::High);
    assert!(r2[0].evidence.contains("교차 검증"));
    assert_eq!(just_shield::report::exit_code(&result, false), 1);
}

#[test]
fn active_lookalike_fork_is_not_promoted() {
    // 반례: 이름은 비슷하지만 태그가 많은(활발한) 정상 포크 — 격상 금지.
    let root = make_repo("fork", WORKFLOW);
    let facts = FakeGithub {
        tag_counts: HashMap::from([
            ("aquasecurtiy/trivy-action".to_string(), 30),
            ("aquasecurity/trivy-action".to_string(), 48),
        ]),
    };
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let r2: Vec<_> = result.findings.iter().filter(|f| f.rule == "R2").collect();
    assert_eq!(r2.len(), 1);
    assert_eq!(
        r2[0].severity,
        Severity::Info,
        "증거 불충분이면 🔵에 머문다"
    );
}

#[test]
fn unknown_tag_counts_stay_info() {
    // 조회 불가(None)는 격상 근거가 될 수 없다 — 추측 금지.
    let root = make_repo("unknown", WORKFLOW);
    let facts = FakeGithub::default();
    let result = just_shield::scan_with_facts(&root, Some(&facts)).unwrap();
    let _ = std::fs::remove_dir_all(&root);

    let r2: Vec<_> = result.findings.iter().filter(|f| f.rule == "R2").collect();
    assert_eq!(r2.len(), 1);
    assert_eq!(r2[0].severity, Severity::Info);
}
