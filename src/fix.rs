//! `fix` — 가변 참조를 커밋 SHA로 자동 교체 (탈출구 ③).
//!
//! 이 도구가 사용자 파일을 고쳐 쓰는 유일한 지점이므로 가장 보수적으로 동작한다:
//! YAML을 재직렬화하지 않고 해당 행의 참조 부분 문자열만 치환해 주석·서식·키 순서를
//! 바이트 단위로 보존하며, 각 행의 원래 줄바꿈(CRLF/LF)도 그대로 유지한다.
//! 해석에 실패한 참조는 절대 건드리지 않고 사유를 보고한다.

use crate::github_facts::GithubFacts;
use crate::trust::{Trust, TrustContext};
use crate::uses_ref::{self, RefKind, UsesRef};
use crate::{config, trust, workflow};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;

/// 교체 한 건.
pub struct FixChange {
    pub file: String,
    pub line: usize,
    pub from: String,
    pub to: String,
}

/// `fix` 실행 결과.
pub struct FixOutcome {
    pub changes: Vec<FixChange>,
    /// 해석 실패로 건드리지 않은 참조와 사유.
    pub skipped: Vec<(String, String)>,
    /// false면 dry-run — 파일은 변경되지 않았다.
    pub applied: bool,
}

/// 모든 워크플로의 가변 참조를 현재 SHA로 핀 고정한다.
/// 이미 SHA인 참조·로컬 액션·docker 이미지·퍼스트파티는 건드리지 않는다 → 멱등.
pub fn fix(root: &Path, facts: &dyn GithubFacts, dry_run: bool) -> io::Result<FixOutcome> {
    let ctx = TrustContext::new(
        trust::detect_repo_owner(root),
        config::load(root)?.trusted_owners,
    );
    // 같은 (저장소, 태그)는 한 번만 해석한다.
    let mut cache: HashMap<(String, String), Option<String>> = HashMap::new();
    let mut skipped: BTreeMap<String, String> = BTreeMap::new();
    let mut changes = Vec::new();

    for wf in workflow::find_workflows(root)? {
        let content = std::fs::read_to_string(&wf)?;
        let rel = wf.strip_prefix(root).unwrap_or(&wf).display().to_string();
        let mut new_content = String::with_capacity(content.len() + 64);
        let mut changed = false;

        for (idx, segment) in content.split_inclusive('\n').enumerate() {
            let (body, ending) = split_ending(segment);
            match try_fix_line(body, &ctx, facts, &mut cache, &mut skipped) {
                Some((new_body, from, to)) => {
                    changes.push(FixChange {
                        file: rel.clone(),
                        line: idx + 1,
                        from,
                        to,
                    });
                    new_content.push_str(&new_body);
                    changed = true;
                }
                None => new_content.push_str(body),
            }
            new_content.push_str(ending);
        }

        if changed && !dry_run {
            std::fs::write(&wf, new_content)?;
        }
    }

    Ok(FixOutcome {
        changes,
        skipped: skipped.into_iter().collect(),
        applied: !dry_run,
    })
}

/// 행 본문과 줄바꿈 문자를 분리한다 — 원래의 CRLF/LF를 보존하기 위해.
fn split_ending(segment: &str) -> (&str, &str) {
    if let Some(body) = segment.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = segment.strip_suffix('\n') {
        (body, "\n")
    } else {
        (segment, "")
    }
}

/// 교체 대상 행이면 (새 행, 이전 참조, 새 참조)를 반환한다.
fn try_fix_line(
    line: &str,
    ctx: &TrustContext,
    facts: &dyn GithubFacts,
    cache: &mut HashMap<(String, String), Option<String>>,
    skipped: &mut BTreeMap<String, String>,
) -> Option<(String, String, String)> {
    let value = workflow::extract_uses_value(line)?;
    let UsesRef::Repository {
        owner_repo,
        git_ref: Some(RefKind::Mutable(git_ref)),
    } = uses_ref::parse(&value)
    else {
        return None;
    };
    if ctx.classify(&owner_repo) == Trust::FirstParty {
        return None;
    }
    let repo = uses_ref::repo_root(&owner_repo).to_string();
    let key = (repo.clone(), git_ref.clone());
    let sha = match cache.get(&key) {
        Some(cached) => cached.clone(),
        None => {
            let resolved = match facts.resolve_ref(&repo, &git_ref) {
                Ok(Some(sha)) => Some(sha),
                Ok(None) => {
                    skipped.insert(
                        format!("{repo}@{git_ref}"),
                        "참조를 찾을 수 없음 — 변경하지 않음".to_string(),
                    );
                    None
                }
                Err(e) => {
                    skipped.insert(
                        format!("{repo}@{git_ref}"),
                        format!("해석 실패 — 변경하지 않음: {e}"),
                    );
                    None
                }
            };
            cache.insert(key, resolved.clone());
            resolved
        }
    }?;

    let new_value = format!("{owner_repo}@{sha}");
    let pos = line.find(&value)?;
    let rest = &line[pos + value.len()..];
    let mut new_line = String::with_capacity(line.len() + 48);
    new_line.push_str(&line[..pos]);
    new_line.push_str(&new_value);
    new_line.push_str(rest);
    // 사람이 읽을 버전 주석 — 이미 행 끝 주석이 있으면 보존하고 덧붙이지 않는다.
    if !rest.contains('#') {
        new_line.push_str(&format!(" # {git_ref}"));
    }
    Some((new_line, value, new_value))
}
