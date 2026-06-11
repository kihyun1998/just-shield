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

    /// 커밋이 저장소의 정식 히스토리에서 도달 가능한가 (R5 임포스터 커밋 판정).
    /// `Ok(None)` = 판정 불가(미지원) — 규칙은 조용히 건너뛴다.
    fn commit_reachable(&self, _owner_repo: &str, _sha: &str) -> io::Result<Option<bool>> {
        Ok(None)
    }

    /// 참조가 가리키는 커밋의 커미터 시각, unix epoch 초 (R10 쿨다운 판정).
    /// `Ok(None)` = 참조 없음 또는 판정 불가 — 규칙은 조용히 건너뛴다.
    fn ref_timestamp(&self, _owner_repo: &str, _git_ref: &str) -> io::Result<Option<i64>> {
        Ok(None)
    }
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

    fn commit_reachable(&self, owner_repo: &str, sha: &str) -> io::Result<Option<bool>> {
        Self::commit_reachable_impl(owner_repo, sha)
    }

    fn ref_timestamp(&self, owner_repo: &str, git_ref: &str) -> io::Result<Option<i64>> {
        Self::ref_timestamp_impl(owner_repo, git_ref)
    }
}

impl GitRemote {
    /// 임시 저장소에 해당 객체만 fetch해 본다. 도달 불가 객체는 GitHub이 거부한다.
    fn shallow_fetch(
        owner_repo: &str,
        want: &str,
    ) -> io::Result<(bool, String, std::path::PathBuf)> {
        let url = format!("https://github.com/{owner_repo}.git");
        let key = want
            .bytes()
            .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
        let tmp =
            std::env::temp_dir().join(format!("just-shield-fetch-{}-{key:x}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let init = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&tmp)
            .output()?;
        if !init.status.success() {
            return Err(io::Error::other("git init 실패"));
        }
        let fetch = std::process::Command::new("git")
            .args(["fetch", "--quiet", "--depth=1", &url, want])
            .current_dir(&tmp)
            .output()?;
        let stderr = String::from_utf8_lossy(&fetch.stderr).to_lowercase();
        Ok((fetch.status.success(), stderr, tmp))
    }

    /// API 조회와 달리 git 프로토콜은 포크에 숨긴 커밋(임포스터)을 내주지 않는다 —
    /// 정식 참조에서 도달 가능한 객체만 fetch된다.
    fn commit_reachable_impl(owner_repo: &str, sha: &str) -> io::Result<Option<bool>> {
        let (ok, stderr, tmp) = Self::shallow_fetch(owner_repo, sha)?;
        let _ = std::fs::remove_dir_all(&tmp);
        if ok {
            return Ok(Some(true));
        }
        // 도달 불가/미공개 객체 거부는 "임포스터" 신호, 그 외(네트워크 등)는 판정 보류.
        if stderr.contains("not our ref") || stderr.contains("unadvertised object") {
            return Ok(Some(false));
        }
        Err(io::Error::other(format!(
            "git fetch 실패 ({owner_repo}@{sha}): {}",
            stderr.trim()
        )))
    }

    fn ref_timestamp_impl(owner_repo: &str, git_ref: &str) -> io::Result<Option<i64>> {
        let (ok, stderr, tmp) = Self::shallow_fetch(owner_repo, git_ref)?;
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            if stderr.contains("couldn't find remote ref") {
                return Ok(None);
            }
            return Err(io::Error::other(format!(
                "git fetch 실패 ({owner_repo}@{git_ref}): {}",
                stderr.trim()
            )));
        }
        let log = std::process::Command::new("git")
            .args(["log", "-1", "--format=%ct", "FETCH_HEAD"])
            .current_dir(&tmp)
            .output()?;
        let _ = std::fs::remove_dir_all(&tmp);
        if !log.status.success() {
            return Ok(None);
        }
        Ok(String::from_utf8_lossy(&log.stdout).trim().parse().ok())
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
