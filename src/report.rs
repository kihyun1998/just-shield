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
        if result.online_rules_skipped {
            s.push_str(
                "참고: 온라인 검사(R5 임포스터 커밋 · R10 쿨다운 · LOCK 태그 대조)는 --online 옵션에서 수행됩니다\n",
            );
        }
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
    if !result.suppressed.is_empty() {
        s.push_str("무시됨 (사유 필수 주석으로 수용):\n");
        for sp in &result.suppressed {
            let f = &sp.finding;
            s.push_str(&format!("⚪ {}  {}:{}\n", f.rule, f.file, f.line));
            if !f.uses.is_empty() {
                s.push_str(&format!("   uses: {}\n", f.uses));
            }
            s.push_str(&format!("   사유: {}\n\n", sp.reason));
        }
    }
    let (high, medium, info) = tier_counts(result);
    let status = if exit_code(result, strict) == 0 {
        "통과"
    } else {
        "빌드 실패"
    };
    let suppressed = result.suppressed.len();
    s.push_str(&format!(
        "요약: 🔴 {high}건 · 🟡 {medium}건 · 🔵 {info}건 · ⚪ 무시 {suppressed}건 — {status}\n"
    ));
    if result.online_rules_skipped {
        s.push_str(
            "참고: 온라인 검사(R5 임포스터 커밋 · R10 쿨다운 · LOCK 태그 대조)는 --online 옵션에서 수행됩니다\n",
        );
    }
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
        "  \"summary\": {{ \"high\": {high}, \"medium\": {medium}, \"info\": {info}, \"suppressed\": {} }},\n",
        result.suppressed.len()
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
        s.push_str("],\n");
    } else {
        s.push_str("\n  ],\n");
    }
    s.push_str("  \"suppressed\": [");
    for (i, sp) in result.suppressed.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let f = &sp.finding;
        s.push_str("\n    {\n");
        s.push_str(&format!("      \"rule\": \"{}\",\n", esc(f.rule)));
        s.push_str(&format!(
            "      \"file\": \"{}\",\n",
            esc(&f.file.replace('\\', "/"))
        ));
        s.push_str(&format!("      \"line\": {},\n", f.line));
        s.push_str(&format!("      \"uses\": \"{}\",\n", esc(&f.uses)));
        s.push_str(&format!("      \"reason\": \"{}\"\n", esc(&sp.reason)));
        s.push_str("    }");
    }
    if result.suppressed.is_empty() {
        s.push_str("]\n");
    } else {
        s.push_str("\n  ]\n");
    }
    s.push_str("}\n");
    s
}

/// SARIF 규칙 메타데이터 — id와 짧은 설명. `ruleIndex`는 이 배열의 위치다.
/// 결과에 등장하지 않는 규칙도 항상 전부 싣는다 — 출력이 입력에 따라 흔들리지 않도록.
const RULE_METADATA: &[(&str, &str)] = &[
    (
        "R1",
        "서드파티 액션의 가변 참조(태그/브랜치) — 태그 하이재킹에 노출",
    ),
    ("R2", "유명 액션과 한 글자 차이 — 타이포스쿼팅 의심"),
    ("R3", "curl | sh류 미검증 파이프 설치"),
    ("R4", "다이제스트 없는 컨테이너 이미지 참조"),
    (
        "R5",
        "핀된 SHA가 저장소 정식 히스토리에서 도달 불가 — 임포스터 커밋",
    ),
    ("R6", "시크릿을 쓰는 잡에서 서드파티 액션 실행"),
    ("R7", "permissions 미선언 또는 write-all"),
    (
        "R8",
        "위험 트리거(pull_request_target 등)와 외부 PR 체크아웃 조합",
    ),
    ("R9", "공개 권고에 악성으로 등재된 버전/커밋 사용"),
    ("R10", "발행 후 쿨다운(검증 기간) 미경과 참조"),
    ("LOCK", "shield.lock 박제본 대비 태그 이동"),
    (
        "EGRESS",
        "잠근 잡이 egress.lock에 없는 목적지를 조회 — 유출 신호",
    ),
];

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Info => "note",
    }
}

fn rule_index(rule: &str) -> usize {
    RULE_METADATA
        .iter()
        .position(|(id, _)| *id == rule)
        .unwrap_or(0)
}

/// SARIF 2.1.0 리포트 — GitHub 코드 스캐닝 업로드용.
/// 무시된 발견은 결과에서 빠지지 않고 `suppressions`로 표시된다 (침묵 ≠ 은폐).
pub fn render_sarif(result: &ScanResult) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    s.push_str("  \"version\": \"2.1.0\",\n");
    s.push_str("  \"runs\": [\n    {\n");
    s.push_str("      \"tool\": {\n        \"driver\": {\n");
    s.push_str("          \"name\": \"just-shield\",\n");
    s.push_str(&format!(
        "          \"version\": \"{}\",\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str("          \"informationUri\": \"https://github.com/kihyun1998/just-shield\",\n");
    s.push_str("          \"rules\": [");
    for (i, (id, desc)) in RULE_METADATA.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "\n            {{ \"id\": \"{}\", \"shortDescription\": {{ \"text\": \"{}\" }} }}",
            esc(id),
            esc(desc)
        ));
    }
    s.push_str("\n          ]\n        }\n      },\n");
    s.push_str("      \"results\": [");
    let mut first = true;
    let mut push_result = |s: &mut String, f: &crate::rules::Finding, reason: Option<&str>| {
        if !first {
            s.push(',');
        }
        first = false;
        let message = if f.uses.is_empty() {
            format!("{} — 해결: {}", f.evidence, f.fix_hint)
        } else {
            format!("uses: {} — {} — 해결: {}", f.uses, f.evidence, f.fix_hint)
        };
        s.push_str("\n        {\n");
        s.push_str(&format!("          \"ruleId\": \"{}\",\n", esc(f.rule)));
        s.push_str(&format!(
            "          \"ruleIndex\": {},\n",
            rule_index(f.rule)
        ));
        s.push_str(&format!(
            "          \"level\": \"{}\",\n",
            sarif_level(f.severity)
        ));
        s.push_str(&format!(
            "          \"message\": {{ \"text\": \"{}\" }},\n",
            esc(&message)
        ));
        s.push_str(&format!(
            "          \"locations\": [{{ \"physicalLocation\": {{ \"artifactLocation\": {{ \"uri\": \"{}\" }}, \"region\": {{ \"startLine\": {} }} }} }}]",
            esc(&f.file.replace('\\', "/")),
            f.line.max(1)
        ));
        if let Some(reason) = reason {
            s.push_str(&format!(
                ",\n          \"suppressions\": [{{ \"kind\": \"inSource\", \"justification\": \"{}\" }}]",
                esc(reason)
            ));
        }
        s.push_str("\n        }");
    };
    for f in &result.findings {
        push_result(&mut s, f, None);
    }
    for sp in &result.suppressed {
        push_result(&mut s, &sp.finding, Some(&sp.reason));
    }
    if first {
        s.push_str("]\n");
    } else {
        s.push_str("\n      ]\n");
    }
    s.push_str("    }\n  ]\n}\n");
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
