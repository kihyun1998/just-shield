//! 워크플로 파일 발견과 `uses:` 참조 추출.
//!
//! S1에서는 YAML 전체 구조를 해석하지 않고 `uses:` 행만 추출한다.
//! R1 판정에 필요한 것은 참조 문자열과 행 번호뿐이며, 의존 크레이트 0개를 유지한다.
//! 잡/권한/트리거 구조가 필요해지는 S3에서 내부를 교체하되 이 모듈의 인터페이스는 유지한다.

use std::path::{Path, PathBuf};

/// 워크플로 파일에서 발견된 `uses:` 한 건.
pub struct UsesEntry {
    /// 1부터 시작하는 행 번호.
    pub line: usize,
    /// 따옴표·주석이 제거된 참조 값 (예: `actions/checkout@v4`).
    pub value: String,
}

/// `<root>/.github/workflows`의 `*.yml`/`*.yaml` 파일 목록 (정렬됨).
pub fn find_workflows(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let dir = root.join(".github").join("workflows");
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"));
        if is_yaml {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// 파일 내용에서 모든 `uses:` 참조를 행 번호와 함께 추출한다.
pub fn extract_uses_entries(content: &str) -> Vec<UsesEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            extract_uses_value(line).map(|value| UsesEntry {
                line: idx + 1,
                value,
            })
        })
        .collect()
}

/// 한 행에서 `uses:` 값을 추출한다. 주석 행과 `uses:`가 아닌 행은 None.
fn extract_uses_value(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    // 주석 처리된 행 (`# uses: ...`)은 실행되지 않으므로 검사 대상이 아니다.
    if trimmed.starts_with('#') {
        return None;
    }
    let rest = match trimmed.strip_prefix('-') {
        Some(r) => r.trim_start(),
        None => trimmed,
    };
    let rest = rest.strip_prefix("uses:")?;
    // YAML 블록 매핑에서 키 뒤에는 공백이 와야 한다 — `uses:foo`는 키가 아니라 스칼라.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    let value = if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()?
    } else if let Some(q) = rest.strip_prefix('\'') {
        q.split('\'').next()?
    } else {
        // 따옴표 없는 값: 공백 또는 행 끝 주석(#) 앞까지.
        rest.split(|c: char| c.is_whitespace() || c == '#').next()?
    };
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::extract_uses_value;

    #[test]
    fn extracts_plain_and_list_item() {
        assert_eq!(
            extract_uses_value("      - uses: actions/checkout@v4"),
            Some("actions/checkout@v4".to_string())
        );
        assert_eq!(
            extract_uses_value("        uses: owner/repo@main"),
            Some("owner/repo@main".to_string())
        );
    }

    #[test]
    fn extracts_quoted_values() {
        assert_eq!(
            extract_uses_value(r#"      - uses: "owner/repo@v1""#),
            Some("owner/repo@v1".to_string())
        );
        assert_eq!(
            extract_uses_value("      - uses: 'owner/repo@v1'"),
            Some("owner/repo@v1".to_string())
        );
    }

    #[test]
    fn drops_trailing_comment() {
        assert_eq!(
            extract_uses_value("      - uses: owner/repo@abc123 # v2"),
            Some("owner/repo@abc123".to_string())
        );
    }

    #[test]
    fn ignores_commented_lines_and_non_uses() {
        assert_eq!(extract_uses_value("      # uses: owner/repo@v1"), None);
        assert_eq!(extract_uses_value("      - run: echo uses: nothing"), None);
        assert_eq!(extract_uses_value("      uses:foo"), None);
    }
}
