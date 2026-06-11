//! 알려진 감염 버전 권고 DB (R9).
//!
//! 스냅숏은 컴파일 시점에 바이너리에 동봉된다(`include_str!`) — 런타임 파일/네트워크
//! 의존이 없고, DB 갱신은 곧 새 릴리스이므로 DB만 바꿔치기하는 공격면이 없다.
//! 형식과 갱신 절차는 `data/advisories.txt` 머리말 참조.

use std::collections::HashMap;

const BUNDLED: &str = include_str!("../data/advisories.txt");

/// 권고 항목 — 출처와 설명.
pub struct Advisory {
    pub source: String,
    pub note: String,
}

/// 참조(`owner/repo@ref`, 소문자) → 권고.
pub struct AdvisoryDb {
    entries: HashMap<String, Advisory>,
}

impl AdvisoryDb {
    /// 동봉 스냅숏을 파싱한다.
    pub fn bundled() -> Self {
        Self::parse(BUNDLED)
    }

    pub fn parse(content: &str) -> Self {
        let mut entries = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, char::is_whitespace);
            let (Some(reference), Some(source)) = (parts.next(), parts.next()) else {
                continue;
            };
            entries.insert(
                reference.to_lowercase(),
                Advisory {
                    source: source.to_string(),
                    note: parts.next().unwrap_or("").trim().to_string(),
                },
            );
        }
        Self { entries }
    }

    /// `repo@ref`가 권고에 등재되어 있는가.
    pub fn lookup(&self, repo: &str, git_ref: &str) -> Option<&Advisory> {
        self.entries
            .get(&format!("{repo}@{git_ref}").to_lowercase())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::AdvisoryDb;

    #[test]
    fn bundled_snapshot_parses_and_contains_real_world_entry() {
        let db = AdvisoryDb::bundled();
        assert!(!db.is_empty());
        let advisory = db
            .lookup(
                "tj-actions/changed-files",
                "0e58ed8671d6b60d0890c21b07f8835ace038e67",
            )
            .expect("실세계 권고(CVE-2025-30066)가 동봉돼야 한다");
        assert_eq!(advisory.source, "CVE-2025-30066");
    }

    #[test]
    fn lookup_is_case_insensitive_and_misses_are_none() {
        let db = AdvisoryDb::parse("Evil/Action@V1.0.0 GHSA-test 설명 텍스트\n# 주석\n");
        assert!(db.lookup("evil/action", "v1.0.0").is_some());
        assert!(db.lookup("evil/action", "v1.0.1").is_none());
        assert!(db.lookup("good/action", "v1.0.0").is_none());
    }
}
