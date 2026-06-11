//! 터미널 리포트 출력과 종료 코드 정책.
//!
//! S1에는 🔴(빌드 실패)만 존재한다. 심각도 3단계와 `--strict`는 S2(#3)에서.

use crate::ScanResult;

/// 사람용 터미널 리포트를 렌더링한다.
pub fn render(result: &ScanResult) -> String {
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
        s.push_str(&format!("🔴 {}  {}:{}\n", f.rule, f.file, f.line));
        s.push_str(&format!("   uses: {}\n", f.uses));
        s.push_str(&format!("   근거: {}\n", f.evidence));
        s.push_str(&format!("   해결: {}\n\n", f.fix_hint));
    }
    s.push_str(&format!(
        "요약: 🔴 {}건 — 빌드 실패\n",
        result.findings.len()
    ));
    s
}

/// 종료 코드: 위반 있으면 1, 깨끗하면 0. (사용법 오류는 main에서 2.)
pub fn exit_code(result: &ScanResult) -> u8 {
    if result.findings.is_empty() { 0 } else { 1 }
}
