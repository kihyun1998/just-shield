//! 외부(GitHub) 조회의 격리 인터페이스.
//!
//! 모든 온라인 규칙은 이 trait에만 의존한다 — 테스트는 가짜 구현으로
//! 하이재킹 상황을 오프라인 재현하고, 실제 구현은 `git ls-remote` 서브프로세스를
//! 사용해 HTTP 클라이언트 의존성 없이 동작한다.

use std::io;

/// GitHub에 대한 사실 조회.
pub trait GithubFacts {
    /// `owner/repo`의 `git_ref`(태그/브랜치)가 현재 가리키는 커밋 SHA.
    /// 참조가 존재하지 않으면 `Ok(None)`.
    fn resolve_ref(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<String>>;
}

/// `git ls-remote` 기반의 실제 구현.
pub struct GitRemote;

impl GithubFacts for GitRemote {
    fn resolve_ref(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<String>> {
        let url = format!("https://github.com/{owner_repo}.git");
        // 주석 태그(annotated tag)는 태그 객체 SHA와 커밋 SHA가 다르다 —
        // `ref^{}`(peeled)가 실제 커밋이므로 함께 조회해 우선한다.
        let peeled = format!("{git_ref}^{{}}");
        let out = std::process::Command::new("git")
            .args(["ls-remote", &url, git_ref, &peeled])
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "git ls-remote 실패 ({owner_repo}): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(pick_best(&String::from_utf8_lossy(&out.stdout)))
    }
}

/// ls-remote 출력에서 가장 정확한 SHA를 고른다: peeled(^{}) > tags > 그 외.
fn pick_best(output: &str) -> Option<String> {
    let mut tag = None;
    let mut other = None;
    for line in output.lines() {
        let Some((sha, name)) = line.split_once('\t') else {
            continue;
        };
        if name.ends_with("^{}") {
            return Some(sha.to_string());
        }
        if name.starts_with("refs/tags/") {
            tag.get_or_insert_with(|| sha.to_string());
        } else {
            other.get_or_insert_with(|| sha.to_string());
        }
    }
    tag.or(other)
}

#[cfg(test)]
mod tests {
    use super::pick_best;

    #[test]
    fn prefers_peeled_then_tag_then_branch() {
        let out = "aaa\trefs/heads/v4\nbbb\trefs/tags/v4\nccc\trefs/tags/v4^{}\n";
        assert_eq!(pick_best(out).as_deref(), Some("ccc"));
        let out = "aaa\trefs/heads/v4\nbbb\trefs/tags/v4\n";
        assert_eq!(pick_best(out).as_deref(), Some("bbb"));
        assert_eq!(pick_best(""), None);
    }
}
