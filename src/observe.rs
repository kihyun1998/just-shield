//! 관찰 기록 → 판정 (층 ⓒ 유출 정책층의 판정 코어, ADR-0006).
//!
//! 관찰자(DNS 중계)와 판정은 기록 파일 하나로 분리된다 — 그래서 이 모듈의 모든
//! 판정은 네트워크 없이 손으로 쓴 기록으로 테스트된다 (v1의 facts.txt 패턴).
//!
//! 판정 정책: 락에 없는 잡 = 보고 + 초안 제안, 절대 실패 없음.
//! 락에 있는 잡 = 미등재 목적지 관찰 시 🔴 — "조회했다 + 락에 없다"는 둘 다
//! 검증 가능한 사실이다 (ADR-0002). 탈출구는 락 편집 그 자체.

use crate::egress_lockfile::{self, EgressLock};
use crate::rules::{Finding, Severity};
use std::collections::BTreeSet;

/// 관찰 기록 — 관찰자가 남기는 "잡 이름 + 조회된 도메인 집합".
pub struct Record {
    pub job: String,
    pub domains: BTreeSet<String>,
}

/// 기록 파일 파싱. 첫 유효 줄은 `job <이름>`, 이후는 한 줄 한 도메인.
pub fn parse_record(content: &str) -> Result<Record, String> {
    let mut job: Option<String> = None;
    let mut domains = BTreeSet::new();
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("job ") {
            if job.is_some() {
                return Err(format!("{line_no}행: job 줄이 중복됩니다"));
            }
            let name = name.trim();
            if name.is_empty() {
                return Err(format!("{line_no}행: 잡 이름이 비었습니다"));
            }
            job = Some(name.to_string());
            continue;
        }
        if job.is_none() {
            return Err(format!(
                "{line_no}행: 첫 유효 줄은 `job <이름>`이어야 합니다"
            ));
        }
        if line.split_whitespace().count() != 1 {
            return Err(format!("{line_no}행: 도메인은 한 줄에 하나입니다"));
        }
        domains.insert(egress_lockfile::normalize(line));
    }
    let job = job.ok_or("기록에 `job <이름>` 줄이 없습니다")?;
    Ok(Record { job, domains })
}

/// 판정 결과.
pub struct ObserveOutcome {
    pub job: String,
    pub observed: BTreeSet<String>,
    /// 잡이 egress.lock에 있었는가 (잠금 선택제).
    pub locked: bool,
    /// 잠근 잡의 미등재 목적지 — 🔴 EGRESS.
    pub findings: Vec<Finding>,
    /// 락에 없는 잡에게 제안하는 복붙용 초안.
    pub draft: Option<String>,
}

/// 기록 + (있다면) 락 → 판정.
pub fn verdict(record: &Record, lock: Option<&EgressLock>) -> ObserveOutcome {
    let section = lock.and_then(|l| l.job(&record.job));
    match section {
        None => {
            // 잠그지 않은 잡 — 어떤 입력에도 실패하지 않는다.
            let mut draft = format!("[{}]\n", record.job);
            for d in &record.domains {
                draft.push_str(d);
                draft.push('\n');
            }
            ObserveOutcome {
                job: record.job.clone(),
                observed: record.domains.clone(),
                locked: false,
                findings: Vec::new(),
                draft: Some(draft),
            }
        }
        Some(section) => {
            let mut findings = Vec::new();
            for domain in &record.domains {
                let allowed = section
                    .patterns
                    .iter()
                    .any(|p| egress_lockfile::matches(p, domain));
                if allowed {
                    continue;
                }
                findings.push(Finding {
                    rule: "EGRESS",
                    severity: Severity::High,
                    file: egress_lockfile::FILE_NAME.to_string(),
                    line: section.line,
                    uses: domain.clone(),
                    evidence: format!(
                        "잡 '{}'이(가) egress.lock [{}] 구획에 없는 '{}'을(를) 조회했습니다 — \
                         유출 신호일 수 있습니다. 이 잡이 쓰는 시크릿·토큰을 회전하고 통신 경위를 확인하세요 \
                         (TeamPCP류 사건의 피해자들은 유출을 몇 주 뒤에야 알았습니다)",
                        record.job, record.job, domain
                    ),
                    fix_hint: format!(
                        "의도된 통신이라면 egress.lock [{}] 구획에 다음 한 줄을 추가하세요: {}",
                        record.job, domain
                    ),
                });
            }
            ObserveOutcome {
                job: record.job.clone(),
                observed: record.domains.clone(),
                locked: true,
                findings,
                draft: None,
            }
        }
    }
}

/// 사람용 관찰 보고서.
pub fn render_text(outcome: &ObserveOutcome) -> String {
    let mut s = format!(
        "just-shield observe — 잡 '{}'의 통신 기록 (도메인 {}개)\n\n",
        outcome.job,
        outcome.observed.len()
    );
    for d in &outcome.observed {
        s.push_str(&format!("  {d}\n"));
    }
    s.push('\n');
    if !outcome.locked {
        s.push_str(
            "이 잡은 egress.lock에 없습니다 — 관찰 보고만 합니다 (실패하지 않음)\n\
             잠그려면 아래 초안을 검토해 egress.lock에 추가하세요:\n\n",
        );
        if let Some(draft) = &outcome.draft {
            s.push_str(draft);
        }
        return s;
    }
    if outcome.findings.is_empty() {
        s.push_str(&format!(
            "✅ egress.lock [{}] 박제본과 일치 — 평소와 같은 통신입니다\n",
            outcome.job
        ));
        return s;
    }
    for f in &outcome.findings {
        s.push_str(&format!("🔴 {}  {}:{}\n", f.rule, f.file, f.line));
        s.push_str(&format!("   목적지: {}\n", f.uses));
        s.push_str(&format!("   근거: {}\n", f.evidence));
        s.push_str(&format!("   해결: {}\n\n", f.fix_hint));
    }
    s.push_str(&format!(
        "요약: 🔴 미등재 목적지 {}건 — 빌드 실패\n",
        outcome.findings.len()
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(text: &str) -> EgressLock {
        EgressLock::parse(text).unwrap()
    }

    #[test]
    fn unlocked_job_never_fails_and_gets_draft() {
        let record = parse_record("job build\ncrates.io\nGITHUB.COM.\n").unwrap();
        let out = verdict(&record, Some(&lock("[release]\nghcr.io\n")));
        assert!(!out.locked);
        assert!(out.findings.is_empty());
        let draft = out.draft.unwrap();
        assert!(draft.starts_with("[build]\n"));
        // 정규화: 소문자·끝점 제거.
        assert!(draft.contains("github.com\n"));
    }

    #[test]
    fn no_lock_at_all_gets_draft() {
        let record = parse_record("job release\nghcr.io\n").unwrap();
        let out = verdict(&record, None);
        assert!(!out.locked);
        assert!(out.draft.is_some());
    }

    #[test]
    fn locked_job_unlisted_domain_is_high() {
        let record = parse_record("job release\nghcr.io\nevil.net\n").unwrap();
        let out = verdict(&record, Some(&lock("[release]\nghcr.io\n")));
        assert!(out.locked);
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule, "EGRESS");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.uses, "evil.net");
        assert!(f.evidence.contains("회전"));
        assert!(f.fix_hint.contains("evil.net"));
    }

    #[test]
    fn locked_job_all_listed_including_wildcard_is_silent() {
        let record = parse_record("job release\nghcr.io\nabc123.blob.core.windows.net\n").unwrap();
        let out = verdict(
            &record,
            Some(&lock("[release]\nghcr.io\n*.blob.core.windows.net\n")),
        );
        assert!(out.locked);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn record_parse_rejects_malformed_input() {
        assert!(parse_record("crates.io\n").is_err()); // job 줄 없음
        assert!(parse_record("job a\njob b\n").is_err()); // 중복
        assert!(parse_record("job a\ntwo tokens\n").is_err());
    }
}
