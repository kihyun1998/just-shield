//! CLI 껍데기 — 인자를 해석해 엔진(lib)을 호출하고 종료 코드를 반환한다.

use just_shield::github_facts::{GitRemote, GithubFacts};
use std::path::Path;
use std::process::ExitCode;

struct Cli {
    command: Option<String>,
    root: String,
    strict: bool,
    online: bool,
    format: String,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        command: None,
        root: ".".to_string(),
        strict: false,
        online: false,
        format: "text".to_string(),
    };
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" => cli.strict = true,
            "--online" => cli.online = true,
            "--format" => {
                i += 1;
                cli.format = args
                    .get(i)
                    .ok_or("--format 뒤에 값이 필요합니다 (text|json)")?
                    .clone();
            }
            a if a.starts_with("--format=") => cli.format = a["--format=".len()..].to_string(),
            a if a.starts_with("--") => return Err(format!("알 수 없는 옵션: {a}")),
            a => positional.push(a.to_string()),
        }
        i += 1;
    }
    if !matches!(cli.format.as_str(), "text" | "json") {
        return Err(format!("지원하지 않는 형식: {} (text|json)", cli.format));
    }
    cli.command = positional.first().cloned();
    if let Some(p) = positional.get(1) {
        cli.root = p.clone();
    }
    Ok(cli)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("오류: {e}");
            return usage();
        }
    };

    match cli.command.as_deref() {
        Some("scan") => {
            let remote = GitRemote;
            let facts: Option<&dyn GithubFacts> = if cli.online { Some(&remote) } else { None };
            match just_shield::scan_with_facts(Path::new(&cli.root), facts) {
                Ok(result) => {
                    let output = match cli.format.as_str() {
                        "json" => just_shield::report::render_json(&result, cli.strict),
                        _ => just_shield::report::render(&result, cli.strict),
                    };
                    print!("{output}");
                    ExitCode::from(just_shield::report::exit_code(&result, cli.strict))
                }
                Err(e) => {
                    eprintln!("오류: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Some("lock") => match just_shield::lock(Path::new(&cli.root), &GitRemote) {
            Ok(outcome) => {
                println!("shield.lock 박제 완료 — {}건 기록", outcome.written);
                for (reference, reason) in &outcome.skipped {
                    eprintln!("건너뜀: {reference} — {reason}");
                }
                ExitCode::from(0)
            }
            Err(e) => {
                eprintln!("오류: {e}");
                ExitCode::from(2)
            }
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "사용법: just-shield <scan|lock> [저장소 경로] [--strict] [--online] [--format text|json]"
    );
    ExitCode::from(2)
}
