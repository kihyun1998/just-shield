//! CLI 껍데기 — 인자를 해석해 엔진(lib)을 호출하고 종료 코드를 반환한다.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let strict = args.iter().any(|a| a == "--strict");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    match positional.first().map(|s| s.as_str()) {
        Some("scan") => {
            let root = positional.get(1).map(|s| s.as_str()).unwrap_or(".");
            match just_shield::scan(Path::new(root)) {
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
        _ => {
            eprintln!("사용법: just-shield scan [저장소 경로] [--strict]");
            ExitCode::from(2)
        }
    }
}
