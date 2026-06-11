//! CLI 껍데기 — 인자를 해석해 엔진(lib)을 호출하고 종료 코드를 반환한다.

use just_shield::github_facts::{GitRemote, GithubFacts};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let strict = args.iter().any(|a| a == "--strict");
    let online = args.iter().any(|a| a == "--online");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let root = positional.get(1).map(|s| s.as_str()).unwrap_or(".");

    match positional.first().map(|s| s.as_str()) {
        Some("scan") => {
            let remote = GitRemote;
            let facts: Option<&dyn GithubFacts> = if online { Some(&remote) } else { None };
            match just_shield::scan_with_facts(Path::new(root), facts) {
                Ok(result) => {
                    print!("{}", just_shield::report::render(&result, strict));
                    ExitCode::from(just_shield::report::exit_code(&result, strict))
                }
                Err(e) => {
                    eprintln!("오류: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Some("lock") => match just_shield::lock(Path::new(root), &GitRemote) {
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
        _ => {
            eprintln!("사용법: just-shield <scan|lock> [저장소 경로] [--strict] [--online]");
            ExitCode::from(2)
        }
    }
}
