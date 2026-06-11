//! 검사 규칙. R1(가변 참조) + 피해 반경 R6(시크릿 노출)·R7(권한 과잉)·R8(위험 트리거).

use crate::github_facts::GithubFacts;
use crate::lockfile::Lockfile;
use crate::trust::{Trust, TrustContext};
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

/// 무시 주석으로 수용된 발견 — 결과에서 지우지 않고 사유와 함께 남긴다 (침묵 ≠ 은폐).
pub struct Suppressed {
    pub finding: Finding,
    pub reason: String,
}

/// R1 — 액션의 가변 참조(태그/브랜치/참조 없음) 탐지.
///
/// 신뢰 차등: 퍼스트파티(로컬·같은 소유자)는 침묵, GitHub 공식은 🔵 안내,
/// 그 외 서드파티는 🔴 — 보안 벤더라는 평판도 예외가 아니다 (TeamPCP의 교훈).
pub fn check_r1(file: &Path, entries: &[UsesEntry], ctx: &TrustContext) -> Vec<Finding> {
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
        let trust = ctx.classify(&owner_repo);
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

/// R2 — 타이포스쿼팅 의심 (기본 🔵, `--online` 교차 검증으로만 격상).
///
/// 이름 유사도는 휴리스틱이므로 오프라인 단독 판정은 🔵 상한 (ADR-0002).
/// 격상 조건은 보수적이다: 의심 저장소는 태그가 거의 없고(≤2) 원본은 풍부(≥10)할 때만.
/// 애매하면 🔵에 머문다.
pub fn check_r2(
    file: &Path,
    entries: &[UsesEntry],
    ctx: &TrustContext,
    facts: Option<&dyn GithubFacts>,
) -> Vec<Finding> {
    let popular = crate::typosquat::bundled_popular();
    let mut out = Vec::new();
    for e in entries {
        let UsesRef::Repository { owner_repo, .. } = uses_ref::parse(&e.value) else {
            continue;
        };
        if ctx.classify(&owner_repo) == Trust::FirstParty {
            continue;
        }
        let repo = uses_ref::repo_root(&owner_repo).to_string();
        let Some(original) = crate::typosquat::similar_popular(&repo, &popular) else {
            continue;
        };
        let base_evidence = format!(
            "`{repo}`은(는) 유명 액션 `{original}`과(와) 한 글자 차이입니다 —              타이포스쿼팅 위장의 흔한 형태 (TeamPCP는 aquasecurtiy.org 도메인을 썼습니다)"
        );
        // 교차 검증: 의심본이 무명(태그 ≤2)이고 원본이 유명(태그 ≥10)할 때만 격상.
        let corroborated = facts.and_then(|f| {
            let suspect = f.ref_count(&repo).ok()??;
            let orig = f.ref_count(&original).ok()??;
            (suspect <= 2 && orig >= 10).then_some((suspect, orig))
        });
        let (severity, evidence) = match corroborated {
            Some((suspect, orig)) => (
                Severity::High,
                format!(
                    "{base_evidence}. 교차 검증: 의심 저장소는 버전 태그 {suspect}개(무명),                      `{original}`은 {orig}개 — 증거가 모여 격상"
                ),
            ),
            None => (
                Severity::Info,
                format!("{base_evidence}. 이름 유사도는 휴리스틱이므로 안내 등급입니다"),
            ),
        };
        out.push(Finding {
            rule: "R2",
            severity,
            file: file.display().to_string(),
            line: e.line,
            uses: e.value.clone(),
            evidence,
            fix_hint: format!("의도한 액션이 `{original}`인지 철자를 확인하세요"),
        });
    }
    out
}

/// R3 — 무결성 검증 없는 파이프 설치(`curl ... | sh`) 탐지.
///
/// 셸 명령 해석은 본질적으로 휴리스틱이므로 ADR-0002에 따라 단독 판정은 🔵 상한.
/// 체크섬 검증(sha256sum 등)이 동반된 스텝은 침묵한다.
pub fn check_r3(file: &Path, doc: &WorkflowDoc) -> Vec<Finding> {
    let mut out = Vec::new();
    for job in &doc.jobs {
        for step in &job.steps {
            let pipe_install = step
                .text
                .lines()
                .any(|l| (l.contains("curl") || l.contains("wget")) && pipes_to_shell(l));
            if !pipe_install {
                continue;
            }
            let verified = step.text.contains("sha256sum") || step.text.contains("shasum");
            if verified {
                continue;
            }
            out.push(Finding {
                rule: "R3",
                severity: Severity::Info,
                file: file.display().to_string(),
                line: step.line,
                uses: String::new(),
                evidence: "다운로드한 스크립트를 검증 없이 바로 실행하는 패턴으로 보입니다 —                            배포 서버가 오염되면 그대로 악성 코드가 실행됩니다 (Trivy식 바이너리 교체 통로).                            셸 해석은 휴리스틱이므로 안내 등급에 머뭅니다"
                    .into(),
                fix_hint: "다운로드 후 sha256sum 등으로 체크섬을 검증하고 실행하세요".into(),
            });
        }
    }
    out
}

/// `|` 뒤의 첫 명령이 셸인가 — `| shasum`(검증)을 `| sh`로 오인하지 않도록 토큰 단위로 본다.
fn pipes_to_shell(line: &str) -> bool {
    line.split('|').skip(1).any(|seg| {
        let cmd = seg.split_whitespace().next().unwrap_or("");
        matches!(cmd, "sh" | "bash" | "sudo") || cmd.ends_with("/sh") || cmd.ends_with("/bash")
    })
}

/// R4 — 다이제스트 없는 컨테이너 이미지 참조 (🟡).
///
/// 다이제스트(`@sha256:`)의 유무는 문법적 사실이다. 태그는 내용물이 바뀔 수 있다.
pub fn check_r4(file: &Path, entries: &[UsesEntry], images: &[UsesEntry]) -> Vec<Finding> {
    let mut out = Vec::new();
    let docker_uses = entries.iter().filter_map(|e| {
        e.value
            .strip_prefix("docker://")
            .map(|img| (e.line, img.to_string(), e.value.clone()))
    });
    let image_keys = images
        .iter()
        .map(|e| (e.line, e.value.clone(), e.value.clone()));
    for (line, image, raw) in docker_uses.chain(image_keys) {
        if image.contains("@sha256:") {
            continue;
        }
        out.push(Finding {
            rule: "R4",
            severity: Severity::Medium,
            file: file.display().to_string(),
            line,
            uses: raw,
            evidence: format!(
                "`{image}`은(는) 다이제스트 없는 이미지 참조 — 태그는 같은 이름으로 내용물이                  바뀔 수 있는 가변 참조입니다"
            ),
            fix_hint: format!("다이제스트로 고정 — {image}@sha256:<다이제스트>"),
        });
    }
    out
}

/// R6 — 시크릿을 사용하는 잡에서 서드파티 액션 실행 (🟡).
///
/// 액션 코드는 같은 잡의 시크릿에 접근 가능한 환경에서 돈다 — 오염되면 함께 털린다.
pub fn check_r6(file: &Path, doc: &WorkflowDoc, ctx: &TrustContext) -> Vec<Finding> {
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
            if ctx.classify(&owner_repo) != Trust::ThirdParty {
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

/// R9 — 알려진 감염 버전 대조 (동봉 권고 DB, 오프라인, 🔴).
///
/// 공개 권고 등재 여부는 사실이다. 알려진 악성 버전은 소유자 신뢰와 무관하게
/// 절대적으로 위험하므로 신뢰 분류를 적용하지 않는다.
pub fn check_r9(
    file: &Path,
    entries: &[UsesEntry],
    db: &crate::advisory::AdvisoryDb,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let UsesRef::Repository {
            owner_repo,
            git_ref: Some(git_ref),
        } = uses_ref::parse(&e.value)
        else {
            continue;
        };
        let git_ref = match &git_ref {
            RefKind::CommitSha(s) => s.as_str(),
            RefKind::Mutable(r) => r.as_str(),
        };
        let repo = uses_ref::repo_root(&owner_repo);
        let Some(advisory) = db.lookup(repo, git_ref) else {
            continue;
        };
        out.push(Finding {
            rule: "R9",
            severity: Severity::High,
            file: file.display().to_string(),
            line: e.line,
            uses: e.value.clone(),
            evidence: format!(
                "이 버전은 공개 보안 권고에 악성으로 등재되어 있습니다 — {}: {}",
                advisory.source, advisory.note
            ),
            fix_hint: "즉시 제거/교체하고, 이 버전이 실행된 기간의 CI 로그와 시크릿 노출을 점검하세요 (이미 실행됐다면 사후 대응 필요)".into(),
        });
    }
    out
}

/// R5 — 임포스터 커밋 검증 (`--online`, 🔴).
///
/// 핀된 SHA가 그 저장소의 정식 히스토리에서 도달 가능한가는 조회 가능한 사실이다.
/// 도달 불가 = 포크 등에 숨긴 커밋을 핀에 꽂은 임포스터 신호 (TeamPCP Trivy 수법).
pub fn check_r5(
    file: &Path,
    entries: &[UsesEntry],
    facts: &dyn GithubFacts,
    ctx: &TrustContext,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let UsesRef::Repository {
            owner_repo,
            git_ref: Some(RefKind::CommitSha(sha)),
        } = uses_ref::parse(&e.value)
        else {
            continue;
        };
        if ctx.classify(&owner_repo) == Trust::FirstParty {
            continue;
        }
        let repo = uses_ref::repo_root(&owner_repo);
        match facts.commit_reachable(repo, &sha) {
            Ok(Some(true)) | Ok(None) => {}
            Ok(Some(false)) => out.push(Finding {
                rule: "R5",
                severity: Severity::High,
                file: file.display().to_string(),
                line: e.line,
                uses: e.value.clone(),
                evidence: format!(
                    "핀된 커밋 {sha}이(가) `{repo}`의 정식 히스토리에서 도달 불가합니다 — \
                     포크에 숨긴 커밋을 꽂은 임포스터 커밋 신호 (TeamPCP의 Trivy 공격이 이 수법)"
                ),
                fix_hint: "이 SHA의 출처를 확인하고, 업스트림 정식 릴리스의 SHA로 교체하세요"
                    .into(),
            }),
            Err(_) => out.push(Finding {
                rule: "R5",
                severity: Severity::Info,
                file: file.display().to_string(),
                line: e.line,
                uses: e.value.clone(),
                evidence: format!(
                    "`{repo}@{sha}`의 도달 가능성을 확인하지 못했습니다 — 판정 보류 \
                     (확인 불가는 오탐을 만들지 않습니다)"
                ),
                fix_hint: "네트워크 상태를 확인하고 다시 시도하세요".into(),
            }),
        }
    }
    out
}

/// R10 — 쿨다운: 발행된 지 기준 일수가 안 된 참조 경고 (`--online`, 🟡).
///
/// 제로데이를 탐지하는 게 아니라 미검증 기간을 회피하는 전략이다 (CONTEXT.md).
/// 시각을 알 수 없는 참조는 판정하지 않는다 (추측 금지).
pub fn check_r10(
    file: &Path,
    entries: &[UsesEntry],
    facts: &dyn GithubFacts,
    ctx: &TrustContext,
    cooldown_days: u32,
    now: i64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let threshold = i64::from(cooldown_days) * 86_400;
    for e in entries {
        let UsesRef::Repository {
            owner_repo,
            git_ref: Some(_),
        } = uses_ref::parse(&e.value)
        else {
            continue;
        };
        if ctx.classify(&owner_repo) == Trust::FirstParty {
            continue;
        }
        let repo = uses_ref::repo_root(&owner_repo);
        let git_ref = e.value.split_once('@').map(|(_, r)| r).unwrap_or_default();
        let Ok(Some(ts)) = facts.ref_timestamp(repo, git_ref) else {
            continue;
        };
        let age = now - ts;
        if age >= threshold {
            continue;
        }
        let age_days = age / 86_400;
        out.push(Finding {
            rule: "R10",
            severity: Severity::Medium,
            file: file.display().to_string(),
            line: e.line,
            uses: e.value.clone(),
            evidence: format!(
                "이 참조는 발행된 지 {age_days}일밖에 안 됐습니다 (기준 {cooldown_days}일) — \
                 갓 나온 버전은 아직 아무도 검증하지 않은 버전입니다. 오염은 보통 며칠 내 \
                 발각되므로, 숙성 기간은 미검증 창(제로데이 창)을 회피하는 전략입니다"
            ),
            fix_hint: format!(
                "{cooldown_days}일이 지난 뒤 도입하거나, 검증된 이전 버전을 사용하세요 \
                 (기준 조정: --cooldown-days)"
            ),
        });
    }
    out
}

/// LOCK — shield.lock 박제본 대비 태그 이동 탐지 (ADR-0003).
///
/// 박제 SHA ≠ 현재 SHA는 조회 가능한 사실이다. 단 `v4` 같은 메이저 별칭과 브랜치는
/// 정상적으로도 이동하므로 🔵 안내에 머물고, 점이 포함된 정확 버전 태그의 이동만
/// 🔴다 — 이것이 TeamPCP가 Trivy 76개 태그에 쓴 하이재킹의 형태다.
pub fn check_lock(
    file: &Path,
    entries: &[UsesEntry],
    lockfile: &Lockfile,
    facts: Option<&dyn GithubFacts>,
    ctx: &TrustContext,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let UsesRef::Repository {
            owner_repo,
            git_ref: Some(RefKind::Mutable(git_ref)),
        } = uses_ref::parse(&e.value)
        else {
            continue;
        };
        // 퍼스트파티는 섭취 검증 대상이 아니다 (CONTEXT.md) — LOCK도 Tier 1 규칙.
        if ctx.classify(&owner_repo) == Trust::FirstParty {
            continue;
        }
        let repo = uses_ref::repo_root(&owner_repo).to_string();
        let Some(locked_sha) = lockfile.get(&repo, &git_ref) else {
            out.push(Finding {
                rule: "LOCK",
                severity: Severity::Info,
                file: file.display().to_string(),
                line: e.line,
                uses: e.value.clone(),
                evidence: format!(
                    "가변 참조 `{repo}@{git_ref}`이(가) shield.lock에 박제되어 있지 않습니다 — \
                     이동 감시 대상에서 빠져 있습니다"
                ),
                fix_hint: "`just-shield lock`을 실행해 박제본을 갱신하세요".into(),
            });
            continue;
        };
        let Some(facts) = facts else {
            // 오프라인: 현재 SHA를 조회할 수 없으므로 대조는 건너뛴다 (오탐 금지).
            continue;
        };
        let current = match facts.resolve_ref(&repo, &git_ref) {
            Ok(Some(sha)) => sha,
            Ok(None) | Err(_) => {
                out.push(Finding {
                    rule: "LOCK",
                    severity: Severity::Info,
                    file: file.display().to_string(),
                    line: e.line,
                    uses: e.value.clone(),
                    evidence: format!(
                        "`{repo}@{git_ref}`의 현재 SHA를 확인하지 못했습니다 — 판정 보류 (확인 불가는 오탐을 만들지 않습니다)"
                    ),
                    fix_hint: "네트워크 상태를 확인하고 다시 시도하세요".into(),
                });
                continue;
            }
        };
        if current == locked_sha {
            continue;
        }
        // 정확 버전 태그(점 포함)는 정상 상황에서 움직이지 않는다 → 이동 = 🔴.
        // 메이저 별칭(v4)·브랜치는 릴리스마다 합법적으로 이동할 수 있다 → 🔵.
        let exact_version = git_ref.contains('.');
        let (severity, label) = if exact_version {
            (Severity::High, "태그 하이재킹 신호")
        } else {
            (
                Severity::Info,
                "이동 감지 — 메이저 별칭/브랜치는 정상 릴리스로도 이동합니다",
            )
        };
        out.push(Finding {
            rule: "LOCK",
            severity,
            file: file.display().to_string(),
            line: e.line,
            uses: e.value.clone(),
            evidence: format!(
                "박제 시점의 `{repo}@{git_ref}`은(는) {locked_sha}였는데 지금은 {current}를 \
                 가리킵니다 — {label} (TeamPCP가 Trivy/KICS에 쓴 수법)"
            ),
            fix_hint: "업스트림 릴리스 노트로 의도된 변경인지 확인하고, 맞다면 `just-shield lock`을 재실행하세요"
                .into(),
        });
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
