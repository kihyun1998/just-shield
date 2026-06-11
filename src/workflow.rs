//! 워크플로 파일 발견과 구조 추출.
//!
//! 의존 크레이트 0개를 유지하기 위해 워크플로 YAML의 관용적 형태(블록 매핑 +
//! 들여쓰기)만 해석하는 전용 파서를 쓴다. R1은 `uses:` 행 추출로, R6~R8은
//! `parse_workflow`의 구조(트리거/권한/잡/스텝)로 판정한다.

use std::path::{Path, PathBuf};

/// 워크플로 파일에서 발견된 `uses:` 한 건.
pub struct UsesEntry {
    /// 1부터 시작하는 행 번호.
    pub line: usize,
    /// 따옴표·주석이 제거된 참조 값 (예: `actions/checkout@v4`).
    pub value: String,
}

/// R6~R8 판정에 필요한 워크플로 구조.
pub struct WorkflowDoc {
    /// `on:` 값 전체를 이어붙인 텍스트 — 트리거 토큰 검사용.
    pub on_text: String,
    /// 워크플로 수준 `permissions:` (행 번호, 값 텍스트). 없으면 None.
    pub workflow_permissions: Option<(usize, String)>,
    pub jobs: Vec<Job>,
}

/// 잡 하나의 구조.
pub struct Job {
    pub name: String,
    pub line: usize,
    /// 잡 수준 `permissions:` (행 번호, 값 텍스트). 없으면 None.
    pub permissions: Option<(usize, String)>,
    /// 잡 블록 어딘가에서 `${{ secrets.* }}` 또는 `secrets:`를 참조하는가.
    pub uses_secrets: bool,
    pub steps: Vec<Step>,
}

/// 스텝 하나.
pub struct Step {
    pub line: usize,
    pub uses: Option<String>,
    /// 스텝 블록 원문(트림된 행들의 결합) — `ref:` 패턴 검사용.
    pub text: String,
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

/// 의미 있는 행 하나 (빈 행·주석 제외).
#[derive(Clone, Copy)]
struct Line<'a> {
    no: usize,
    indent: usize,
    text: &'a str,
}

/// 워크플로의 구조(트리거/권한/잡/스텝)를 추출한다.
pub fn parse_workflow(content: &str) -> WorkflowDoc {
    let lines: Vec<Line> = content
        .lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let text = raw.trim_start();
            if text.is_empty() || text.starts_with('#') {
                return None;
            }
            Some(Line {
                no: i + 1,
                indent: raw.len() - text.len(),
                text,
            })
        })
        .collect();

    let mut on_text = String::new();
    let mut workflow_permissions = None;
    let mut jobs = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.indent != 0 {
            i += 1;
            continue;
        }
        if l.text.strip_prefix("on:").is_some() {
            let (text, next) = collect_block_text(&lines, i, "on:");
            on_text = text;
            i = next;
        } else if l.text.strip_prefix("permissions:").is_some() {
            let (text, next) = collect_block_text(&lines, i, "permissions:");
            workflow_permissions = Some((l.no, text));
            i = next;
        } else if l.text.starts_with("jobs:") {
            let block_end = block_end(&lines, i + 1, 0);
            jobs = parse_jobs(&lines[i + 1..block_end]);
            i = block_end;
        } else {
            i += 1;
        }
    }

    WorkflowDoc {
        on_text,
        workflow_permissions,
        jobs,
    }
}

/// `lines[start]`의 키 인라인 값 + 더 깊은 들여쓰기의 자식 행들을 한 문자열로 모은다.
/// 반환: (모은 텍스트, 다음으로 처리할 인덱스).
fn collect_block_text(lines: &[Line], start: usize, key: &str) -> (String, usize) {
    let base_indent = lines[start].indent;
    let mut text = lines[start].text[key.len()..].trim().to_string();
    let mut j = start + 1;
    while j < lines.len() && lines[j].indent > base_indent {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(lines[j].text);
        j += 1;
    }
    (text, j)
}

/// `lines[from..]`에서 indent가 `parent_indent` 이하로 돌아오는 첫 인덱스.
fn block_end(lines: &[Line], from: usize, parent_indent: usize) -> usize {
    let mut k = from;
    while k < lines.len() && lines[k].indent > parent_indent {
        k += 1;
    }
    k
}

fn parse_jobs(lines: &[Line]) -> Vec<Job> {
    let Some(job_indent) = lines.first().map(|l| l.indent) else {
        return Vec::new();
    };
    let mut jobs = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.indent == job_indent && l.text.ends_with(':') {
            let end = block_end(lines, i + 1, job_indent);
            jobs.push(parse_job(
                l.text.trim_end_matches(':').to_string(),
                l.no,
                &lines[i + 1..end],
            ));
            i = end;
        } else {
            i += 1;
        }
    }
    jobs
}

fn parse_job(name: String, line: usize, lines: &[Line]) -> Job {
    let uses_secrets = lines.iter().any(|l| {
        (l.text.contains("${{") && l.text.contains("secrets.")) || l.text.starts_with("secrets:")
    });
    let child_indent = lines.iter().map(|l| l.indent).min().unwrap_or(0);
    let mut permissions = None;
    let mut steps = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.indent == child_indent && l.text.strip_prefix("permissions:").is_some() {
            let (text, next) = collect_block_text(lines, i, "permissions:");
            permissions = Some((l.no, text));
            i = next;
        } else if l.indent == child_indent && l.text.starts_with("steps:") {
            let end = block_end(lines, i + 1, child_indent);
            steps = parse_steps(&lines[i + 1..end]);
            i = end;
        } else {
            i += 1;
        }
    }

    Job {
        name,
        line,
        permissions,
        uses_secrets,
        steps,
    }
}

fn parse_steps(lines: &[Line]) -> Vec<Step> {
    let Some(item_indent) = lines
        .iter()
        .filter(|l| l.text.starts_with('-'))
        .map(|l| l.indent)
        .min()
    else {
        return Vec::new();
    };
    let mut steps = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.indent == item_indent && l.text.starts_with('-') {
            let mut end = i + 1;
            while end < lines.len()
                && !(lines[end].indent == item_indent && lines[end].text.starts_with('-'))
                && lines[end].indent >= item_indent
            {
                end += 1;
            }
            let block = &lines[i..end];
            let uses = block.iter().find_map(|b| extract_uses_value(b.text));
            let text = block.iter().map(|b| b.text).collect::<Vec<_>>().join("\n");
            steps.push(Step {
                line: l.no,
                uses,
                text,
            });
            i = end;
        } else {
            i += 1;
        }
    }
    steps
}

/// 컨테이너 이미지 참조(`image:` 값, 인라인 `container:` 값)를 행 번호와 함께 추출한다.
/// `${{ ... }}` 표현식은 값을 알 수 없으므로 판정 대상에서 제외한다 (추측 금지).
pub fn extract_image_refs(content: &str) -> Vec<UsesEntry> {
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let t = line.trim_start();
            if t.starts_with('#') {
                return None;
            }
            let rest = match t.strip_prefix('-') {
                Some(r) => r.trim_start(),
                None => t,
            };
            let rest = rest
                .strip_prefix("image:")
                .or_else(|| rest.strip_prefix("container:"))?;
            if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                return None;
            }
            if rest.contains("${{") {
                return None;
            }
            let value = scalar_value(rest.trim_start())?;
            Some(UsesEntry {
                line: idx + 1,
                value,
            })
        })
        .collect()
}

/// 한 행에서 `uses:` 값을 추출한다. 주석 행과 `uses:`가 아닌 행은 None.
pub fn extract_uses_value(line: &str) -> Option<String> {
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
    scalar_value(rest.trim_start())
}

/// 따옴표·행 끝 주석을 처리해 스칼라 값만 꺼낸다.
fn scalar_value(rest: &str) -> Option<String> {
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
    use super::{extract_uses_value, parse_workflow};

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

    const SAMPLE: &str = "name: CI\non: pull_request_target\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: cargo test\n  deploy:\n    permissions:\n      contents: read\n    steps:\n      - uses: evil/tool@v1\n        env:\n          T: ${{ secrets.TOKEN }}\n";

    #[test]
    fn parses_triggers_permissions_jobs_steps() {
        let doc = parse_workflow(SAMPLE);
        assert!(doc.on_text.contains("pull_request_target"));
        assert!(
            doc.workflow_permissions
                .as_ref()
                .is_some_and(|(_, v)| v.contains("write-all"))
        );
        assert_eq!(doc.jobs.len(), 2);

        let build = &doc.jobs[0];
        assert_eq!(build.name, "build");
        assert!(build.permissions.is_none());
        assert!(!build.uses_secrets);
        assert_eq!(build.steps.len(), 2);
        assert_eq!(build.steps[0].uses.as_deref(), Some("actions/checkout@v4"));
        assert!(
            build.steps[0]
                .text
                .contains("github.event.pull_request.head")
        );

        let deploy = &doc.jobs[1];
        assert!(deploy.permissions.is_some());
        assert!(deploy.uses_secrets);
        assert_eq!(deploy.steps[0].uses.as_deref(), Some("evil/tool@v1"));
    }
}
