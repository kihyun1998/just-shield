//! shield.lock — 신뢰를 결정한 시점의 태그→SHA 박제 (ADR-0003).
//!
//! 상태는 도구가 아니라 저장소의 이 파일에 산다. 정렬된 텍스트라 diff 친화적이고,
//! 변경(신뢰 변경)이 PR 리뷰를 통과해야 하는 구조가 된다.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

pub const FILE_NAME: &str = "shield.lock";

const HEADER: &str = "\
# shield.lock — just-shield가 박제한 태그→SHA 대응. 직접 수정하지 말 것.
# 갱신: just-shield lock
";

/// 박제본. 키는 `owner/repo@ref`, 값은 박제 시점의 커밋 SHA.
#[derive(Default)]
pub struct Lockfile {
    pub entries: BTreeMap<String, String>,
}

impl Lockfile {
    pub fn key(repo: &str, git_ref: &str) -> String {
        format!("{repo}@{git_ref}")
    }

    pub fn get(&self, repo: &str, git_ref: &str) -> Option<&str> {
        self.entries
            .get(&Self::key(repo, git_ref))
            .map(|s| s.as_str())
    }
}

/// `<root>/shield.lock`을 읽는다. 없으면 `Ok(None)` — 오류가 아니다.
pub fn load(root: &Path) -> io::Result<Option<Lockfile>> {
    let path = root.join(FILE_NAME);
    if !path.is_file() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    let mut entries = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, sha)) = line.split_once(' ') {
            entries.insert(key.to_string(), sha.trim().to_string());
        }
    }
    Ok(Some(Lockfile { entries }))
}

/// 박제본을 기록한다. BTreeMap이라 같은 입력이면 항상 같은 바이트가 나온다.
pub fn save(root: &Path, lockfile: &Lockfile) -> io::Result<()> {
    let mut out = String::from(HEADER);
    for (key, sha) in &lockfile.entries {
        out.push_str(&format!("{key} {sha}\n"));
    }
    std::fs::write(root.join(FILE_NAME), out)
}
