//! just-shield 검사 엔진.
//!
//! CLI(`main.rs`)는 이 라이브러리를 호출하는 얇은 껍데기다 (ADR-0004, 엔진/포장 분리).
//! 모든 판정은 사실 기반이어야 한다 (ADR-0002) — 추측으로 빌드를 깨뜨리지 않는다.

pub mod report;
pub mod rules;
pub mod trust;
pub mod uses_ref;
pub mod workflow;

use std::path::Path;

/// 한 저장소에 대한 스캔 결과.
pub struct ScanResult {
    pub workflows_scanned: usize,
    pub findings: Vec<rules::Finding>,
}

/// 저장소 루트를 받아 `.github/workflows`의 모든 워크플로를 검사한다.
/// 네트워크 접근 없음 — 파일만 읽는다.
pub fn scan(root: &Path) -> std::io::Result<ScanResult> {
    let repo_owner = trust::detect_repo_owner(root);
    let workflows = workflow::find_workflows(root)?;
    let mut findings = Vec::new();
    for wf in &workflows {
        let content = std::fs::read_to_string(wf)?;
        let rel = wf.strip_prefix(root).unwrap_or(wf);
        let entries = workflow::extract_uses_entries(&content);
        let doc = workflow::parse_workflow(&content);
        findings.extend(rules::check_r1(rel, &entries, repo_owner.as_deref()));
        findings.extend(rules::check_r6(rel, &doc, repo_owner.as_deref()));
        findings.extend(rules::check_r7(rel, &doc));
        findings.extend(rules::check_r8(rel, &doc));
    }
    findings.sort_by(|a, b| (&a.file, a.line, a.rule).cmp(&(&b.file, b.line, b.rule)));
    Ok(ScanResult {
        workflows_scanned: workflows.len(),
        findings,
    })
}
