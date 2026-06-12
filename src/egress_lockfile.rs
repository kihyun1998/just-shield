//! egress.lock — 잡별 허용 통신 목적지의 박제 (ADR-0006, shield.lock의 자매).
//!
//! 상태는 도구가 아니라 저장소의 이 파일에 산다. 잠금은 잡 단위 선택제 —
//! 여기 적힌 잡만 대조 대상이고, 안 적힌 잡은 관찰 보고만 받는다.
//! 와일드카드는 사람이 명시적으로만 쓴다 — 도구는 절대 자동 생성하지 않는다.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

pub const FILE_NAME: &str = "egress.lock";

/// 락의 잡 구획 하나 — `[이름]` 헤더의 행 번호와 허용 패턴들.
pub struct JobSection {
    pub line: usize,
    pub patterns: BTreeSet<String>,
}

/// 박제본. 키는 잡 이름.
#[derive(Default)]
pub struct EgressLock {
    pub jobs: BTreeMap<String, JobSection>,
}

impl EgressLock {
    /// 엄격 파싱 — 정책 파일이므로 모르는 줄은 조용히 넘기지 않고 오류를 낸다.
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut jobs: BTreeMap<String, JobSection> = BTreeMap::new();
        let mut current: Option<String> = None;
        for (idx, raw) in content.lines().enumerate() {
            let line_no = idx + 1;
            // 행 끝 주석 제거 후 정리.
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let name = name.trim();
                if name.is_empty() {
                    return Err(format!("{line_no}행: 잡 이름이 빈 구획입니다"));
                }
                if jobs.contains_key(name) {
                    return Err(format!("{line_no}행: 잡 '{name}' 구획이 중복됩니다"));
                }
                jobs.insert(
                    name.to_string(),
                    JobSection {
                        line: line_no,
                        patterns: BTreeSet::new(),
                    },
                );
                current = Some(name.to_string());
                continue;
            }
            let Some(job) = &current else {
                return Err(format!(
                    "{line_no}행: 잡 구획(`[이름]`) 앞에 도메인이 나왔습니다"
                ));
            };
            let pattern = normalize(line);
            validate_pattern(&pattern).map_err(|e| format!("{line_no}행: {e}"))?;
            jobs.get_mut(job)
                .expect("current는 항상 jobs에 존재")
                .patterns
                .insert(pattern);
        }
        Ok(EgressLock { jobs })
    }

    /// BTreeMap/BTreeSet이라 같은 입력이면 항상 같은 바이트가 나온다.
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# egress.lock — 잡별 허용 통신 목적지 (just-shield 층 ⓒ, ADR-0006).\n\
             # 여기 적힌 잡만 대조 대상 — 미등재 목적지 관찰 = 🔴. 와일드카드는 사람이 명시적으로만.\n",
        );
        for (job, section) in &self.jobs {
            out.push_str(&format!("\n[{job}]\n"));
            for p in &section.patterns {
                out.push_str(p);
                out.push('\n');
            }
        }
        out
    }

    pub fn job(&self, name: &str) -> Option<&JobSection> {
        self.jobs.get(name)
    }
}

/// 도메인 정규화 — 소문자, 끝점 제거.
pub fn normalize(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// 패턴 검증. 허용: 일반 도메인 또는 선행 라벨 1개 와일드카드(`*.example.com`).
fn validate_pattern(p: &str) -> Result<(), String> {
    let rest = p.strip_prefix("*.").unwrap_or(p);
    if rest.contains('*') {
        return Err(format!(
            "'{p}' — 와일드카드는 선행 라벨 1개(`*.example.com`)만 허용됩니다"
        ));
    }
    if rest.is_empty()
        || rest
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'))
    {
        return Err(format!("'{p}' — 도메인으로 보이지 않습니다"));
    }
    Ok(())
}

/// 관찰된 도메인이 패턴과 맞는가. 와일드카드는 정확히 한 라벨만 대신한다 —
/// `*.example.com`은 `a.example.com`과 맞고 `a.b.example.com`·`example.com`과는 안 맞는다.
pub fn matches(pattern: &str, domain: &str) -> bool {
    let domain = normalize(domain);
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let Some(head) = domain.strip_suffix(suffix) else {
            return false;
        };
        let Some(label) = head.strip_suffix('.') else {
            return false;
        };
        !label.is_empty() && !label.contains('.')
    } else {
        domain == pattern
    }
}

/// `<root>/egress.lock`을 읽는다. 없으면 `Ok(None)` — 오류가 아니다(잠금은 선택제).
/// 파싱 실패는 오류다 — 정책 파일이 깨진 채 침묵하면 안 된다.
pub fn load(root: &Path) -> io::Result<Option<EgressLock>> {
    let path = root.join(FILE_NAME);
    if !path.is_file() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    EgressLock::parse(&content)
        .map(Some)
        .map_err(|e| io::Error::other(format!("egress.lock 파싱 실패 — {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_render_roundtrip_is_deterministic() {
        let text = "[release]\nghcr.io\ncrates.io # 발행\n\n[build]\n*.blob.core.windows.net\n";
        let lock = EgressLock::parse(text).unwrap();
        let rendered = lock.render();
        let reparsed = EgressLock::parse(&rendered).unwrap();
        assert_eq!(rendered, reparsed.render());
        // 정렬: build가 release보다 먼저.
        assert!(rendered.find("[build]").unwrap() < rendered.find("[release]").unwrap());
        // 행 끝 주석은 패턴에 포함되지 않는다.
        assert!(lock.job("release").unwrap().patterns.contains("crates.io"));
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        assert!(matches("*.example.com", "a.example.com"));
        assert!(matches("*.example.com", "A.EXAMPLE.COM."));
        assert!(!matches("*.example.com", "a.b.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", "aexample.com"));
        assert!(matches("ghcr.io", "GHCR.IO"));
        assert!(!matches("ghcr.io", "evil-ghcr.io"));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in [
            "[j]\n*.*.example.com",
            "[j]\na.*.b",
            "[j]\n**",
            "[j]\nhas space.com",
            "orphan.com",
            "[]\n",
        ] {
            assert!(EgressLock::parse(bad).is_err(), "통과되면 안 됨: {bad}");
        }
    }

    #[test]
    fn missing_job_is_none() {
        let lock = EgressLock::parse("[release]\nghcr.io\n").unwrap();
        assert!(lock.job("build").is_none());
        assert!(lock.job("release").is_some());
    }
}
