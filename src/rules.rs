//! 검사 규칙. S1에서는 R1(가변 참조)만 구현한다.
//!
//! S1의 단순 정책: 로컬/도커 외 전부 서드파티 취급, 위반은 빌드 실패.
//! 신뢰 분류(퍼스트파티/공식/서드파티)와 심각도 차등은 S2(#3)에서 들어온다.

use crate::uses_ref::{self, RefKind, UsesRef};
use crate::workflow::UsesEntry;
use std::path::Path;

/// 규칙 위반 한 건. 모든 발견에는 근거와 해결 힌트가 붙는다 (ADR-0002 원칙 ③).
pub struct Finding {
    pub rule: &'static str,
    pub file: String,
    pub line: usize,
    pub uses: String,
    pub evidence: String,
    pub fix_hint: String,
}

/// R1 — 서드파티 액션의 가변 참조(태그/브랜치/참조 없음) 탐지.
pub fn check_r1(file: &Path, entries: &[UsesEntry]) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let evidence = match uses_ref::parse(&e.value) {
            UsesRef::Local | UsesRef::DockerImage => None,
            UsesRef::Repository {
                git_ref: Some(RefKind::CommitSha(_)),
                ..
            } => None,
            UsesRef::Repository {
                git_ref: Some(RefKind::Mutable(r)),
                ..
            } => Some(format!(
                "`@{r}`은(는) 태그/브랜치 — 공격자가 다른 커밋으로 옮겨 꽂을 수 있는 가변 참조입니다 \
                 (TeamPCP는 이 방식으로 Trivy 태그 76개를 하이재킹했습니다)"
            )),
            UsesRef::Repository { git_ref: None, .. } => Some(
                "참조(@버전)가 없습니다 — 기본 브랜치를 그대로 따라가는 가변 참조입니다"
                    .to_string(),
            ),
        };
        if let Some(evidence) = evidence {
            let owner_repo = e.value.split('@').next().unwrap_or(&e.value).to_string();
            out.push(Finding {
                rule: "R1",
                file: file.display().to_string(),
                line: e.line,
                uses: e.value.clone(),
                evidence,
                fix_hint: format!(
                    "커밋 SHA로 핀 고정 — uses: {owner_repo}@<40자리 커밋 SHA>  # 원래 버전을 주석으로"
                ),
            });
        }
    }
    out
}
