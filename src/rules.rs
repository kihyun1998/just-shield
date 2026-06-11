//! 검사 규칙. S1: R1(가변 참조). S2: 신뢰 분류와 심각도 차등 적용.

use crate::trust::{self, Trust};
use crate::uses_ref::{self, RefKind, UsesRef};
use crate::workflow::UsesEntry;
use std::path::Path;

/// 심각도 등급 (CONTEXT.md). 🔴는 사실 규칙만 낼 수 있다 (ADR-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// 🔴 실제 공격 경로가 열려 있음 — 빌드 실패.
    High,
    /// 🟡 피해 확대 요인 — 경고, `--strict`에서 실패.
    Medium,
    /// 🔵 안내 — 항상 경고만. 휴리스틱 단독 판정의 상한.
    Info,
}

/// 규칙 위반 한 건. 모든 발견에는 근거와 해결 힌트가 붙는다 (ADR-0002 원칙 ③).
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub uses: String,
    pub evidence: String,
    pub fix_hint: String,
}

/// R1 — 액션의 가변 참조(태그/브랜치/참조 없음) 탐지.
///
/// 신뢰 차등: 퍼스트파티(로컬·같은 소유자)는 침묵, GitHub 공식은 🔵 안내,
/// 그 외 서드파티는 🔴 — 보안 벤더라는 평판도 예외가 아니다 (TeamPCP의 교훈).
pub fn check_r1(file: &Path, entries: &[UsesEntry], repo_owner: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let UsesRef::Repository {
            owner_repo,
            git_ref,
        } = uses_ref::parse(&e.value)
        else {
            // 로컬 액션은 퍼스트파티, docker://는 R4(이미지)의 영역.
            continue;
        };
        let trust = trust::classify(&owner_repo, repo_owner);
        if trust == Trust::FirstParty {
            continue;
        }
        let ref_problem = match git_ref {
            Some(RefKind::CommitSha(_)) => continue,
            Some(RefKind::Mutable(r)) => format!(
                "`@{r}`은(는) 태그/브랜치 — 공격자가 다른 커밋으로 옮겨 꽂을 수 있는 가변 참조입니다"
            ),
            None => {
                "참조(@버전)가 없습니다 — 기본 브랜치를 그대로 따라가는 가변 참조입니다".to_string()
            }
        };
        let (severity, evidence) = match trust {
            Trust::Official => (
                Severity::Info,
                format!(
                    "{ref_problem} (GitHub 공식 액션이라 완화 등급 — 그래도 SHA 핀 고정을 권고합니다)"
                ),
            ),
            _ => (
                Severity::High,
                format!("{ref_problem} (TeamPCP는 이 방식으로 Trivy 태그 76개를 하이재킹했습니다)"),
            ),
        };
        out.push(Finding {
            rule: "R1",
            severity,
            file: file.display().to_string(),
            line: e.line,
            uses: e.value.clone(),
            evidence,
            fix_hint: format!(
                "커밋 SHA로 핀 고정 — uses: {owner_repo}@<40자리 커밋 SHA>  # 원래 버전을 주석으로"
            ),
        });
    }
    out
}
