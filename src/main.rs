//! CLI 껍데기 — 인자를 해석해 엔진(lib)을 호출하고 종료 코드를 반환한다.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => {
            let root = args.get(1).map(String::as_str).unwrap_or(".");
            match just_shield::scan(Path::new(root)) {
                Ok(result) => {
                    print!("{}", just_shield::report::render(&result));
                    ExitCode::from(just_shield::report::exit_code(&result))
                }
                Err(e) => {
                    eprintln!("오류: {e}");
                    ExitCode::from(2)
                }
            }
        }
        _ => {
            eprintln!("사용법: just-shield scan [저장소 경로]");
            ExitCode::from(2)
        }
    }
}
