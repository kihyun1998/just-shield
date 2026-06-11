//! 무시 주석 — 탈출구 ①: 경고의 의도적 수용.
//!
//! 형식: `# just-shield: ignore R1 -- 사유`
//! 단독 주석 행이면 다음 의미 행에, 행 끝 주석이면 같은 행에 적용된다.
//! `--` 뒤 사유가 없으면 무시는 적용되지 않는다 — 미래의 동료(와 미래의 나)가
//! "왜 무시했지?"를 알 수 있어야 하기 때문이다.

const MARKER: &str = "just-shield:";

/// 무시 주석 한 건.
pub struct Directive {
    /// 무시할 규칙 ID들 (예: ["R1", "R7"]).
    pub rules: Vec<String>,
    /// `--` 뒤의 사유. 없으면 무시가 적용되지 않는다.
    pub reason: Option<String>,
    /// 주석이 있는 행 (1부터).
    pub comment_line: usize,
    /// 무시가 적용될 행. 단독 주석인데 뒤에 의미 행이 없으면 None.
    pub target_line: Option<usize>,
}

/// 파일 내용에서 모든 무시 주석을 찾는다.
pub fn parse(content: &str) -> Vec<Directive> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let Some(pos) = raw.find(MARKER) else {
            continue;
        };
        // 마커가 주석 안에 있어야 한다 — 마커 앞에 '#'이 존재해야.
        if !raw[..pos].contains('#') {
            continue;
        }
        let after = raw[pos + MARKER.len()..].trim_start();
        let Some(rest) = after.strip_prefix("ignore") else {
            continue;
        };
        let (rules_part, reason) = match rest.split_once("--") {
            Some((r, why)) => {
                let why = why.trim();
                (
                    r.trim(),
                    if why.is_empty() {
                        None
                    } else {
                        Some(why.to_string())
                    },
                )
            }
            None => (rest.trim(), None),
        };
        let rules: Vec<String> = rules_part
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if rules.is_empty() {
            continue;
        }
        // 단독 주석 행 → 다음 의미 행에 적용, 행 끝 주석 → 같은 행에 적용.
        let whole_line_comment = raw.trim_start().starts_with('#');
        let target_line = if whole_line_comment {
            lines[i + 1..]
                .iter()
                .position(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .map(|j| i + 1 + j + 1)
        } else {
            Some(i + 1)
        };
        out.push(Directive {
            rules,
            reason,
            comment_line: i + 1,
            target_line,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn standalone_comment_targets_next_meaningful_line() {
        let d =
            parse("a: 1\n# just-shield: ignore R1 -- 검토 완료\n\n# 다른 주석\n- uses: x/y@v1\n");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rules, vec!["R1"]);
        assert_eq!(d[0].reason.as_deref(), Some("검토 완료"));
        assert_eq!(d[0].target_line, Some(5));
    }

    #[test]
    fn trailing_comment_targets_same_line() {
        let d = parse("permissions: write-all  # just-shield: ignore R7 -- 배포 잡\n");
        assert_eq!(d[0].target_line, Some(1));
        assert_eq!(d[0].rules, vec!["R7"]);
    }

    #[test]
    fn missing_reason_is_kept_but_marked() {
        let d = parse("# just-shield: ignore R1\n- uses: x/y@v1\n");
        assert_eq!(d.len(), 1);
        assert!(d[0].reason.is_none());
    }

    #[test]
    fn multiple_rules_and_non_directives() {
        let d = parse(
            "# just-shield: ignore R1, R7 -- 둘 다 수용\nx: 1\n# 그냥 주석\njust-shield: ignore R9 (주석 아님)\n",
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rules, vec!["R1", "R7"]);
    }
}
