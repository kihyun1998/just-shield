//! `uses:` 참조 문자열의 분해.
//!
//! 참조가 가변(태그/브랜치)인지 불변(40자리 커밋 SHA)인지는 문법적 사실이며,
//! R1은 이 사실만으로 판정한다 (ADR-0002).

/// `uses:` 값이 가리키는 대상의 종류.
pub enum UsesRef {
    /// 이 저장소 안의 로컬 액션 (`./...`) — 퍼스트파티, 섭취 검증 대상 아님.
    Local,
    /// 컨테이너 이미지 참조 (`docker://...`) — R4(이미지 다이제스트)의 영역, R1 대상 아님.
    DockerImage,
    /// 다른 저장소의 액션.
    Repository {
        owner_repo: String,
        git_ref: Option<RefKind>,
    },
}

/// 저장소 액션 참조의 종류.
pub enum RefKind {
    /// 40자리 16진수 커밋 SHA — 불변 참조.
    CommitSha(String),
    /// 태그/브랜치 — 공격자가 옮겨 꽂을 수 있는 가변 참조.
    Mutable(String),
}

/// `uses:` 값을 분해한다.
pub fn parse(value: &str) -> UsesRef {
    if value.starts_with("./") || value.starts_with(".\\") {
        return UsesRef::Local;
    }
    if value.starts_with("docker://") {
        return UsesRef::DockerImage;
    }
    match value.split_once('@') {
        None => UsesRef::Repository {
            owner_repo: value.to_string(),
            git_ref: None,
        },
        Some((path, r)) => {
            let kind = if is_commit_sha(r) {
                RefKind::CommitSha(r.to_string())
            } else {
                RefKind::Mutable(r.to_string())
            };
            UsesRef::Repository {
                owner_repo: path.to_string(),
                git_ref: Some(kind),
            }
        }
    }
}

fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// `owner/repo/subpath`에서 저장소 부분(`owner/repo`)만 — 태그는 저장소에 속한다.
pub fn repo_root(owner_repo: &str) -> &str {
    match owner_repo.match_indices('/').nth(1) {
        Some((idx, _)) => &owner_repo[..idx],
        None => owner_repo,
    }
}

#[cfg(test)]
mod tests {
    use super::{RefKind, UsesRef, parse};

    #[test]
    fn classifies_local_and_docker() {
        assert!(matches!(parse("./.github/actions/x"), UsesRef::Local));
        assert!(matches!(
            parse("docker://alpine:3.19"),
            UsesRef::DockerImage
        ));
    }

    #[test]
    fn full_sha_is_immutable() {
        let r = parse("owner/repo@0123456789abcdef0123456789abcdef01234567");
        assert!(matches!(
            r,
            UsesRef::Repository {
                git_ref: Some(RefKind::CommitSha(_)),
                ..
            }
        ));
    }

    #[test]
    fn tag_branch_and_short_sha_are_mutable() {
        for v in ["owner/repo@v4", "owner/repo@main", "owner/repo@abc1234"] {
            assert!(matches!(
                parse(v),
                UsesRef::Repository {
                    git_ref: Some(RefKind::Mutable(_)),
                    ..
                }
            ));
        }
    }

    #[test]
    fn missing_ref_is_detected() {
        assert!(matches!(
            parse("owner/repo"),
            UsesRef::Repository { git_ref: None, .. }
        ));
    }
}
