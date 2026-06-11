//! S13 채점표 게이트 (ADR-0002 원칙 ④) — 이 두 테스트가 곧 릴리스 게이트다.
//!
//! - attacks/: 재현된 공격이 하나라도 미탐이면 실패
//! - benign/: 양성 워크플로에서 🔴 오탐이 하나라도 나오면 실패
//!
//! 코퍼스 형식과 추가 절차는 tests/corpus/README.md 참조.

use just_shield::github_facts::GithubFacts;
use just_shield::rules::Severity;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

/// facts.txt 기반의 가짜 GitHub — 온라인 공격(임포스터·태그 이동)을 오프라인 재현한다.
#[derive(Default)]
struct FileFacts {
    resolve: HashMap<String, String>,
    reachable: HashMap<String, bool>,
    tags: HashMap<String, usize>,
    time: HashMap<String, i64>,
}

impl FileFacts {
    fn load(path: &Path) -> Self {
        let mut facts = Self::default();
        for line in std::fs::read_to_string(path).unwrap().lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut p = line.split_whitespace();
            match (p.next(), p.next(), p.next()) {
                (Some("resolve"), Some(k), Some(v)) => {
                    facts.resolve.insert(k.into(), v.into());
                }
                (Some("reachable"), Some(k), Some(v)) => {
                    facts.reachable.insert(k.into(), v == "true");
                }
                (Some("tags"), Some(k), Some(v)) => {
                    facts.tags.insert(k.into(), v.parse().unwrap());
                }
                (Some("time"), Some(k), Some(v)) => {
                    facts.time.insert(k.into(), v.parse().unwrap());
                }
                _ => panic!("facts.txt 형식 오류: {line}"),
            }
        }
        facts
    }
}

impl GithubFacts for FileFacts {
    fn resolve_ref(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<String>> {
        Ok(self
            .resolve
            .get(&format!("{owner_repo}@{git_ref}"))
            .cloned())
    }

    fn commit_reachable(&self, _owner_repo: &str, sha: &str) -> io::Result<Option<bool>> {
        Ok(self.reachable.get(sha).copied())
    }

    fn ref_timestamp(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<i64>> {
        Ok(self.time.get(&format!("{owner_repo}@{git_ref}")).copied())
    }

    fn ref_count(&self, owner_repo: &str) -> io::Result<Option<usize>> {
        Ok(self.tags.get(owner_repo).copied())
    }
}

fn subdirs(base: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(base)
        .unwrap_or_else(|_| panic!("코퍼스 디렉터리 없음: {}", base.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

#[test]
fn attack_corpus_must_all_be_detected() {
    let dirs = subdirs(Path::new("tests/corpus/attacks"));
    assert!(!dirs.is_empty(), "미탐 코퍼스가 비어 있다");

    for dir in dirs {
        let expected = std::fs::read_to_string(dir.join("expected.txt"))
            .unwrap_or_else(|_| panic!("{} 에 expected.txt가 없다", dir.display()));
        let facts_path = dir.join("facts.txt");
        let file_facts = facts_path.is_file().then(|| FileFacts::load(&facts_path));
        let facts: Option<&dyn GithubFacts> = file_facts.as_ref().map(|f| f as &dyn GithubFacts);

        let result = just_shield::scan_with_facts(&dir, facts).unwrap();
        for rule in expected
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            assert!(
                result.findings.iter().any(|f| f.rule == rule),
                "미탐: {} 에서 {rule}이 탐지되지 않았다 (릴리스 불가)",
                dir.display()
            );
        }
    }
}

#[test]
fn benign_corpus_must_have_zero_high_findings() {
    let dirs = subdirs(Path::new("tests/corpus/benign"));
    assert!(!dirs.is_empty(), "오탐 코퍼스가 비어 있다");

    for dir in dirs {
        let result = just_shield::scan(&dir).unwrap();
        let highs: Vec<String> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .map(|f| format!("{} {}:{} {}", f.rule, f.file, f.line, f.uses))
            .collect();
        assert!(
            highs.is_empty(),
            "🔴 오탐: {} — {:?} (릴리스 불가)",
            dir.display(),
            highs
        );
    }
}
