//! 검사 규칙. R1(가변 참조) + 피해 반경 R6(시크릿 노출)·R7(권한 과잉)·R8(위험 트리거).

use crate::trust::{self, Trust};
use crate::uses_ref::{self, RefKind, UsesRef};
use crate::workflow::{UsesEntry, WorkflowDoc};
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
    /// 관련 `uses:` 값. 참조와 무관한 규칙(R7 등)은 빈 문자열.
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

/// R6 — 시크릿을 사용하는 잡에서 서드파티 액션 실행 (🟡).
///
/// 액션 코드는 같은 잡의 시크릿에 접근 가능한 환경에서 돈다 — 오염되면 함께 털린다.
pub fn check_r6(file: &Path, doc: &WorkflowDoc, repo_owner: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();
    for job in &doc.jobs {
        if !job.uses_secrets {
            continue;
        }
        for step in &job.steps {
            let Some(uses) = &step.uses else { continue };
            let UsesRef::Repository { owner_repo, .. } = uses_ref::parse(uses) else {
                continue;
            };
            if trust::classify(&owner_repo, repo_owner) != Trust::ThirdParty {
                continue;
            }
            out.push(Finding {
                rule: "R6",
                severity: Severity::Medium,
                file: file.display().to_string(),
                line: step.line,
                uses: uses.clone(),
                evidence: format!(
                    "잡 '{}'은(는) 시크릿을 사용하는데 같은 잡에서 서드파티 액션이 실행됩니다 — \
                     액션이 오염되면 시크릿이 함께 털립니다 (TeamPCP의 자격증명 수확 방식)",
                    job.name
                ),
                fix_hint: "시크릿이 필요한 스텝과 서드파티 액션을 별도 잡으로 분리하세요".into(),
            });
        }
    }
    out
}

/// R7 — `permissions` 미선언 또는 광범위 권한 (🟡).
///
/// 기본 GITHUB_TOKEN은 권한이 넓다 — 탈취 시 피해 반경을 키운다.
pub fn check_r7(file: &Path, doc: &WorkflowDoc) -> Vec<Finding> {
    let mut out = Vec::new();
    let file = file.display().to_string();
    let broad_hint = "워크플로 상단에 `permissions: contents: read`를 선언하고, 필요한 잡에만 추가 권한을 부여하세요";

    if let Some((line, value)) = &doc.workflow_permissions {
        if value.contains("write-all") {
            out.push(Finding {
                rule: "R7",
                severity: Severity::Medium,
                file,
                line: *line,
                uses: String::new(),
                evidence: "`permissions: write-all` — 토큰이 모든 쓰기 권한을 가집니다. \
                           탈취 시 저장소 변조·2차 감염까지 가능해집니다"
                    .into(),
                fix_hint: broad_hint.into(),
            });
        }
        return out;
    }

    for job in &doc.jobs {
        match &job.permissions {
            Some((line, value)) if value.contains("write-all") => out.push(Finding {
                rule: "R7",
                severity: Severity::Medium,
                file: file.clone(),
                line: *line,
                uses: String::new(),
                evidence: format!(
                    "잡 '{}'의 `permissions: write-all` — 토큰이 모든 쓰기 권한을 가집니다",
                    job.name
                ),
                fix_hint: broad_hint.into(),
            }),
            Some(_) => {}
            None => out.push(Finding {
                rule: "R7",
                severity: Severity::Medium,
                file: file.clone(),
                line: job.line,
                uses: String::new(),
                evidence: format!(
                    "잡 '{}'에 `permissions` 선언이 없습니다 — 기본 GITHUB_TOKEN은 권한이 넓어 \
                     탈취 시 피해 반경을 키웁니다 (TeamPCP는 과잉 권한 토큰으로 48개 패키지를 2차 감염시켰습니다)",
                    job.name
                ),
                fix_hint: broad_hint.into(),
            }),
        }
    }
    out
}

/// R8 — 위험 트리거(`pull_request_target`/`workflow_run`) + 외부 PR 코드 체크아웃 (🔴).
///
/// 두 설정의 조합이 파일에 존재하는가라는 사실 판정 (ADR-0002).
pub fn check_r8(file: &Path, doc: &WorkflowDoc) -> Vec<Finding> {
    let dangerous_trigger =
        doc.on_text.contains("pull_request_target") || doc.on_text.contains("workflow_run");
    if !dangerous_trigger {
        return Vec::new();
    }
    let mut out = Vec::new();
    for job in &doc.jobs {
        for step in &job.steps {
            let checks_out_pr = step.text.contains("github.event.pull_request.head")
                || step.text.contains("github.head_ref");
            if !checks_out_pr {
                continue;
            }
            out.push(Finding {
                rule: "R8",
                severity: Severity::High,
                file: file.display().to_string(),
                line: step.line,
                uses: step.uses.clone().unwrap_or_default(),
                evidence: "위험 트리거는 시크릿 접근 권한으로 실행되는데, 이 스텝이 외부 PR의 \
                           코드를 체크아웃합니다 — 외부인이 시크릿 있는 환경에서 코드를 실행할 수 \
                           있게 됩니다"
                    .into(),
                fix_hint: "`pull_request` 트리거로 바꾸거나, 외부 PR head 체크아웃을 제거하세요"
                    .into(),
            });
        }
    }
    out
}
