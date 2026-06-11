//! 신뢰 분류 — CONTEXT.md의 퍼스트파티/공식/서드파티 경계.
//!
//! 판별 불가(원격 없음, GitHub 아님)면 서드파티로 취급한다 — 분류 실패는
//! 경고 누락이 아니라 과잉 경고 쪽으로 넘어진다 (fail-closed).

use std::path::Path;

/// 액션 소유자에 대한 신뢰 등급.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// 이 저장소와 같은 소유자 — 자기 코드의 연장, 섭취 검증 대상 아님.
    FirstParty,
    /// GitHub이 직접 관리하는 액션 — 서드파티지만 완화된 등급으로 보고.
    Official,
    /// 그 외 전부 — 평판과 무관하게 엄격 적용 (TeamPCP의 교훈).
    ThirdParty,
}

const OFFICIAL_OWNERS: &[&str] = &["actions", "github"];

/// 신뢰 판정에 필요한 문맥 — 저장소 소유자 + 설정으로 선언된 신뢰 org.
pub struct TrustContext {
    repo_owner: Option<String>,
    trusted_owners: Vec<String>,
}

impl TrustContext {
    pub fn new(repo_owner: Option<String>, trusted_owners: Vec<String>) -> Self {
        Self {
            repo_owner,
            trusted_owners,
        }
    }

    /// `owner/repo(/sub)` 참조의 소유자를 분류한다.
    pub fn classify(&self, owner_repo: &str) -> Trust {
        let owner = owner_repo.split('/').next().unwrap_or("");
        if let Some(mine) = &self.repo_owner
            && owner.eq_ignore_ascii_case(mine)
        {
            return Trust::FirstParty;
        }
        if self
            .trusted_owners
            .iter()
            .any(|t| owner.eq_ignore_ascii_case(t))
        {
            return Trust::FirstParty;
        }
        if OFFICIAL_OWNERS
            .iter()
            .any(|o| owner.eq_ignore_ascii_case(o))
        {
            return Trust::Official;
        }
        Trust::ThirdParty
    }
}

/// `.git/config`의 origin URL에서 GitHub 소유자를 읽는다. 실패하면 None.
pub fn detect_repo_owner(root: &Path) -> Option<String> {
    let config = std::fs::read_to_string(root.join(".git").join("config")).ok()?;
    owner_from_git_config(&config)
}

fn owner_from_git_config(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t == r#"[remote "origin"]"#;
            continue;
        }
        if !in_origin {
            continue;
        }
        if let Some(url) = t
            .strip_prefix("url")
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix('='))
        {
            return owner_from_url(url.trim());
        }
    }
    None
}

/// `https://github.com/owner/repo.git` 또는 `git@github.com:owner/repo.git`에서 owner 추출.
fn owner_from_url(url: &str) -> Option<String> {
    let rest = url.split("github.com").nth(1)?;
    let rest = rest.strip_prefix(':').or_else(|| rest.strip_prefix('/'))?;
    let owner = rest.split('/').next()?;
    if owner.is_empty() {
        None
    } else {
        Some(owner.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{Trust, TrustContext, owner_from_git_config};

    fn ctx(repo_owner: Option<&str>, trusted: &[&str]) -> TrustContext {
        TrustContext::new(
            repo_owner.map(str::to_string),
            trusted.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn same_owner_is_first_party_case_insensitive() {
        assert_eq!(
            ctx(Some("myorg"), &[]).classify("MyOrg/tool"),
            Trust::FirstParty
        );
    }

    #[test]
    fn configured_trusted_org_is_first_party() {
        let c = ctx(Some("myorg"), &["partner-org"]);
        assert_eq!(c.classify("Partner-Org/tool"), Trust::FirstParty);
        assert_eq!(c.classify("stranger/tool"), Trust::ThirdParty);
    }

    #[test]
    fn github_owned_actions_are_official() {
        assert_eq!(
            ctx(Some("myorg"), &[]).classify("actions/checkout"),
            Trust::Official
        );
        assert_eq!(
            ctx(None, &[]).classify("github/codeql-action"),
            Trust::Official
        );
    }

    #[test]
    fn everyone_else_is_third_party_even_security_vendors() {
        assert_eq!(
            ctx(Some("myorg"), &[]).classify("aquasecurity/trivy-action"),
            Trust::ThirdParty
        );
        // 소유자 판별 불가 → 안전한 쪽: 서드파티
        assert_eq!(ctx(None, &[]).classify("myorg/tool"), Trust::ThirdParty);
    }

    #[test]
    fn extracts_owner_from_https_and_ssh_urls() {
        let https = "[remote \"origin\"]\n\turl = https://github.com/kihyun1998/just-shield.git\n";
        assert_eq!(owner_from_git_config(https).as_deref(), Some("kihyun1998"));
        let ssh = "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:someorg/repo.git\n";
        assert_eq!(owner_from_git_config(ssh).as_deref(), Some("someorg"));
    }

    #[test]
    fn non_github_or_missing_origin_yields_none() {
        let gitlab = "[remote \"origin\"]\n\turl = https://gitlab.com/o/r.git\n";
        assert_eq!(owner_from_git_config(gitlab), None);
        assert_eq!(owner_from_git_config("[core]\n\tbare = false\n"), None);
    }
}
