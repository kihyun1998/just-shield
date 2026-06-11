//! just-shield 검사 엔진.
//!
//! CLI(`main.rs`)는 이 라이브러리를 호출하는 얇은 껍데기다 (ADR-0004, 엔진/포장 분리).
//! 모든 판정은 사실 기반이어야 한다 (ADR-0002) — 추측으로 빌드를 깨뜨리지 않는다.

pub mod config;
pub mod fix;
pub mod github_facts;
pub mod lockfile;
pub mod report;
pub mod rules;
pub mod suppress;
pub mod trust;
pub mod uses_ref;
pub mod workflow;

use github_facts::GithubFacts;
use std::collections::BTreeMap;
use std::path::Path;

/// 한 저장소에 대한 스캔 결과.
pub struct ScanResult {
    pub workflows_scanned: usize,
    /// 활성 발견 — 종료 코드와 집계는 이것만 본다.
    pub findings: Vec<rules::Finding>,
    /// 무시 주석으로 수용된 발견 — 사유와 함께 보존된다.
    pub suppressed: Vec<rules::Suppressed>,
    /// 오프라인 실행이라 온라인 규칙(R5·R10·LOCK 대조)을 건너뛰었는가 — 리포트에 안내.
    pub online_rules_skipped: bool,
}

/// 스캔 동작 옵션.
#[derive(Default)]
pub struct ScanOptions<'a> {
    pub facts: Option<&'a dyn GithubFacts>,
    /// 쿨다운 기준 일수 — None이면 설정 파일, 그것도 없으면 7일.
    pub cooldown_days: Option<u32>,
}

/// `lock` 실행 결과.
pub struct LockOutcome {
    /// 박제된 항목 수.
    pub written: usize,
    /// 해석하지 못해 건너뛴 참조와 사유.
    pub skipped: Vec<(String, String)>,
}

/// 저장소 루트를 받아 `.github/workflows`의 모든 워크플로를 검사한다.
/// 완전 오프라인 — 파일만 읽는다.
pub fn scan(root: &Path) -> std::io::Result<ScanResult> {
    scan_with_facts(root, None)
}

/// 외부 조회(`facts`)가 주어지면 온라인 규칙(R5·R10·LOCK 대조)을 수행한다.
pub fn scan_with_facts(
    root: &Path,
    facts: Option<&dyn GithubFacts>,
) -> std::io::Result<ScanResult> {
    scan_with_options(
        root,
        &ScanOptions {
            facts,
            ..Default::default()
        },
    )
}

/// 모든 옵션을 받는 스캔 진입점.
pub fn scan_with_options(root: &Path, options: &ScanOptions) -> std::io::Result<ScanResult> {
    let facts = options.facts;
    let loaded = config::load(root)?;
    let cooldown_days = options.cooldown_days.or(loaded.cooldown_days).unwrap_or(7);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ctx = trust::TrustContext::new(trust::detect_repo_owner(root), loaded.trusted_owners);
    let lockfile = lockfile::load(root)?;
    let workflows = workflow::find_workflows(root)?;
    let mut findings = Vec::new();
    let mut suppressed = Vec::new();
    for wf in &workflows {
        let content = std::fs::read_to_string(wf)?;
        let rel = wf.strip_prefix(root).unwrap_or(wf);
        let entries = workflow::extract_uses_entries(&content);
        let doc = workflow::parse_workflow(&content);

        let images = workflow::extract_image_refs(&content);

        let mut file_findings = Vec::new();
        file_findings.extend(rules::check_r1(rel, &entries, &ctx));
        file_findings.extend(rules::check_r3(rel, &doc));
        file_findings.extend(rules::check_r4(rel, &entries, &images));
        file_findings.extend(rules::check_r6(rel, &doc, &ctx));
        file_findings.extend(rules::check_r7(rel, &doc));
        file_findings.extend(rules::check_r8(rel, &doc));
        if let Some(lf) = &lockfile {
            file_findings.extend(rules::check_lock(rel, &entries, lf, facts, &ctx));
        }
        if let Some(facts) = facts {
            file_findings.extend(rules::check_r5(rel, &entries, facts, &ctx));
            file_findings.extend(rules::check_r10(
                rel,
                &entries,
                facts,
                &ctx,
                cooldown_days,
                now,
            ));
        }

        // 탈출구 ①: 무시 주석 적용. 사유 없는 주석은 적용되지 않고 그 사실이 보고된다.
        let directives = suppress::parse(&content);
        for d in &directives {
            if d.reason.is_none() {
                file_findings.push(rules::Finding {
                    rule: "IGNORE",
                    severity: rules::Severity::Info,
                    file: rel.display().to_string(),
                    line: d.comment_line,
                    uses: String::new(),
                    evidence: "무시 주석에 사유가 없습니다 — `--` 뒤에 사유를 적지 않으면 무시가 적용되지 않습니다"
                        .into(),
                    fix_hint: "`# just-shield: ignore R1 -- <왜 수용하는지>` 형식으로 사유를 적으세요"
                        .into(),
                });
            }
        }
        for f in file_findings {
            let matched = directives.iter().find(|d| {
                d.reason.is_some()
                    && d.target_line == Some(f.line)
                    && d.rules.iter().any(|r| r == f.rule)
            });
            match matched {
                Some(d) => suppressed.push(rules::Suppressed {
                    finding: f,
                    reason: d.reason.clone().expect("reason은 위에서 확인됨"),
                }),
                None => findings.push(f),
            }
        }
    }
    findings.sort_by(|a, b| (&a.file, a.line, a.rule).cmp(&(&b.file, b.line, b.rule)));
    suppressed.sort_by(|a, b| {
        (&a.finding.file, a.finding.line, a.finding.rule).cmp(&(
            &b.finding.file,
            b.finding.line,
            b.finding.rule,
        ))
    });
    Ok(ScanResult {
        workflows_scanned: workflows.len(),
        findings,
        suppressed,
        online_rules_skipped: facts.is_none(),
    })
}

/// 워크플로의 모든 가변 참조를 해석해 shield.lock으로 박제한다 (ADR-0003).
pub fn lock(root: &Path, facts: &dyn GithubFacts) -> std::io::Result<LockOutcome> {
    let workflows = workflow::find_workflows(root)?;
    // BTreeSet 효과: 정렬 + 중복 제거 → 같은 입력이면 항상 같은 락파일.
    let mut wanted: BTreeMap<(String, String), ()> = BTreeMap::new();
    for wf in &workflows {
        let content = std::fs::read_to_string(wf)?;
        for e in workflow::extract_uses_entries(&content) {
            if let uses_ref::UsesRef::Repository {
                owner_repo,
                git_ref: Some(uses_ref::RefKind::Mutable(r)),
            } = uses_ref::parse(&e.value)
            {
                wanted.insert((uses_ref::repo_root(&owner_repo).to_string(), r), ());
            }
        }
    }

    let mut lf = lockfile::Lockfile::default();
    let mut skipped = Vec::new();
    for (repo, git_ref) in wanted.into_keys() {
        match facts.resolve_ref(&repo, &git_ref) {
            Ok(Some(sha)) => {
                lf.entries
                    .insert(lockfile::Lockfile::key(&repo, &git_ref), sha);
            }
            Ok(None) => skipped.push((
                format!("{repo}@{git_ref}"),
                "참조를 찾을 수 없음".to_string(),
            )),
            Err(e) => skipped.push((format!("{repo}@{git_ref}"), e.to_string())),
        }
    }
    let written = lf.entries.len();
    lockfile::save(root, &lf)?;
    Ok(LockOutcome { written, skipped })
}
