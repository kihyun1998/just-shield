//! 터미널 리포트 출력과 종료 코드 정책.
//!
//! 기본: 🔴만 빌드 실패. `--strict`: 🟡도 실패로 승격. 🔵는 어떤 모드에서도 실패하지 않는다.

use crate::ScanResult;
use crate::rules::Severity;

fn marker(s: Severity) -> &'static str {
    match s {
        Severity::High => "🔴",
        Severity::Medium => "🟡",
        Severity::Info => "🔵",
    }
}

/// 사람용 터미널 리포트를 렌더링한다.
pub fn render(result: &ScanResult, strict: bool) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "just-shield scan — 워크플로 {}개 검사\n\n",
        result.workflows_scanned
    ));
    if result.findings.is_empty() {
        s.push_str("✅ 위반 없음 — 모든 액션 참조가 안전하게 핀 고정되어 있습니다\n");
        return s;
    }
    for f in &result.findings {
        s.push_str(&format!(
            "{} {}  {}:{}\n",
            marker(f.severity),
            f.rule,
            f.file,
            f.line
        ));
        if !f.uses.is_empty() {
            s.push_str(&format!("   uses: {}\n", f.uses));
        }
        s.push_str(&format!("   근거: {}\n", f.evidence));
        s.push_str(&format!("   해결: {}\n\n", f.fix_hint));
    }
    let (high, medium, info) = tier_counts(result);
    let status = if exit_code(result, strict) == 0 {
        "통과"
    } else {
        "빌드 실패"
    };
    s.push_str(&format!(
        "요약: 🔴 {high}건 · 🟡 {medium}건 · 🔵 {info}건 — {status}\n"
    ));
    s
}

/// 기계용 JSON 리포트. 스키마는 README에 문서화되어 있으며 스냅숏 테스트로 고정된다.
/// 경로 구분자는 플랫폼과 무관하게 `/`로 정규화한다 — 파싱 스크립트가 OS를 타지 않도록.
pub fn render_json(result: &ScanResult, strict: bool) -> String {
    let (high, medium, info) = tier_counts(result);
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"version\": 1,\n");
    s.push_str(&format!(
        "  \"workflows_scanned\": {},\n",
        result.workflows_scanned
    ));
    s.push_str(&format!(
        "  \"summary\": {{ \"high\": {high}, \"medium\": {medium}, \"info\": {info} }},\n"
    ));
    s.push_str(&format!(
        "  \"exit_code\": {},\n",
        exit_code(result, strict)
    ));
    s.push_str("  \"findings\": [");
    for (i, f) in result.findings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("\n    {\n");
        s.push_str(&format!("      \"rule\": \"{}\",\n", esc(f.rule)));
        s.push_str(&format!(
            "      \"severity\": \"{}\",\n",
            severity_name(f.severity)
        ));
        s.push_str(&format!(
            "      \"file\": \"{}\",\n",
            esc(&f.file.replace('\\', "/"))
        ));
        s.push_str(&format!("      \"line\": {},\n", f.line));
        s.push_str(&format!("      \"uses\": \"{}\",\n", esc(&f.uses)));
        s.push_str(&format!("      \"evidence\": \"{}\",\n", esc(&f.evidence)));
        s.push_str(&format!("      \"fix_hint\": \"{}\"\n", esc(&f.fix_hint)));
        s.push_str("    }");
    }
    if result.findings.is_empty() {
        s.push_str("]\n");
    } else {
        s.push_str("\n  ]\n");
    }
    s.push_str("}\n");
    s
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Info => "info",
    }
}

/// JSON 문자열 이스케이프 — 따옴표·역슬래시·제어 문자.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 종료 코드: 🔴 있으면 1, `--strict`면 🟡도 1, 그 외 0. (사용법 오류는 main에서 2.)
pub fn exit_code(result: &ScanResult, strict: bool) -> u8 {
    let (high, medium, _) = tier_counts(result);
    if high > 0 || (strict && medium > 0) {
        1
    } else {
        0
    }
}

fn tier_counts(result: &ScanResult) -> (usize, usize, usize) {
    let count = |sev| result.findings.iter().filter(|f| f.severity == sev).count();
    (
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Info),
    )
}
