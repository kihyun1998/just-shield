//! CLI 껍데기 — 인자를 해석해 엔진(lib)을 호출하고 종료 코드를 반환한다.

use just_shield::github_facts::{GitRemote, GithubFacts};
use std::path::Path;
use std::process::ExitCode;

struct Cli {
    command: Option<String>,
    /// `observe`의 하위 동작 (예: report).
    subaction: Option<String>,
    root: String,
    strict: bool,
    online: bool,
    dry_run: bool,
    cooldown_days: Option<u32>,
    format: String,
    /// `observe report`가 읽을 / `observe start`가 쓸 관찰 기록 파일.
    record: Option<String>,
    /// `observe start`의 잡 이름·resolv.conf 경로 (Linux 러너).
    job: Option<String>,
    resolv: String,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        command: None,
        subaction: None,
        root: ".".to_string(),
        strict: false,
        online: false,
        dry_run: false,
        cooldown_days: None,
        format: "text".to_string(),
        record: None,
        job: None,
        resolv: "/etc/resolv.conf".to_string(),
    };
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" => cli.strict = true,
            "--online" => cli.online = true,
            "--dry-run" => cli.dry_run = true,
            "--cooldown-days" => {
                i += 1;
                cli.cooldown_days = Some(
                    args.get(i)
                        .and_then(|v| v.parse().ok())
                        .ok_or("--cooldown-days 뒤에 일수가 필요합니다")?,
                );
            }
            "--format" => {
                i += 1;
                cli.format = args
                    .get(i)
                    .ok_or("--format 뒤에 값이 필요합니다 (text|json|sarif)")?
                    .clone();
            }
            "--record" => {
                i += 1;
                cli.record = Some(
                    args.get(i)
                        .ok_or("--record 뒤에 기록 파일 경로가 필요합니다")?
                        .clone(),
                );
            }
            "--job" => {
                i += 1;
                cli.job = Some(
                    args.get(i)
                        .ok_or("--job 뒤에 잡 이름이 필요합니다")?
                        .clone(),
                );
            }
            "--resolv" => {
                i += 1;
                cli.resolv = args
                    .get(i)
                    .ok_or("--resolv 뒤에 경로가 필요합니다")?
                    .clone();
            }
            a if a.starts_with("--format=") => cli.format = a["--format=".len()..].to_string(),
            a if a.starts_with("--") => return Err(format!("알 수 없는 옵션: {a}")),
            a => positional.push(a.to_string()),
        }
        i += 1;
    }
    if !matches!(cli.format.as_str(), "text" | "json" | "sarif") {
        return Err(format!(
            "지원하지 않는 형식: {} (text|json|sarif)",
            cli.format
        ));
    }
    cli.command = positional.first().cloned();
    // observe는 하위 동작을 하나 더 받는다: observe report [경로]
    let root_index = if cli.command.as_deref() == Some("observe") {
        cli.subaction = positional.get(1).cloned();
        2
    } else {
        1
    };
    if let Some(p) = positional.get(root_index) {
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
            let options = just_shield::ScanOptions {
                facts,
                cooldown_days: cli.cooldown_days,
            };
            match just_shield::scan_with_options(Path::new(&cli.root), &options) {
                Ok(result) => {
                    let output = match cli.format.as_str() {
                        "json" => just_shield::report::render_json(&result, cli.strict),
                        "sarif" => just_shield::report::render_sarif(&result),
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
        Some("observe") => match cli.subaction.as_deref() {
            // DNS 관찰자 기동 — 러너의 리졸버 경로에 끼어들어 질의 이름을 기록한다.
            // 포그라운드로 돈다(워크플로가 `&`로 백그라운드화). fail-open: 못 끼어들면 경고만 하고 정상 종료.
            Some("start") => observe_start(&cli),
            // 기록 + (있다면) egress.lock → 판정. 관찰과 판정은 기록 파일로 분리된다 (ADR-0006).
            Some("report") => {
                let Some(record_path) = &cli.record else {
                    eprintln!("오류: observe report에는 --record <기록 파일>이 필요합니다");
                    return usage();
                };
                let content = match std::fs::read_to_string(record_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("오류: 기록 파일을 읽을 수 없습니다 — {e}");
                        return ExitCode::from(2);
                    }
                };
                let record = match just_shield::observe::parse_record(&content) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("오류: 기록 파싱 실패 — {e}");
                        return ExitCode::from(2);
                    }
                };
                let lock = match just_shield::egress_lockfile::load(Path::new(&cli.root)) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("오류: {e}");
                        return ExitCode::from(2);
                    }
                };
                let outcome = just_shield::observe::verdict(&record, lock.as_ref());
                // 판정은 기존 보고 경로로 합류한다 — json/sarif·종료 코드가 그대로 동작.
                let result = just_shield::ScanResult {
                    workflows_scanned: 0,
                    findings: outcome.findings.clone(),
                    suppressed: Vec::new(),
                    online_rules_skipped: false,
                };
                let output = match cli.format.as_str() {
                    "json" => just_shield::report::render_json(&result, cli.strict),
                    "sarif" => just_shield::report::render_sarif(&result),
                    _ => just_shield::observe::render_text(&outcome),
                };
                print!("{output}");
                ExitCode::from(just_shield::report::exit_code(&result, cli.strict))
            }
            _ => usage(),
        },
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
        Some("fix") => match just_shield::fix::fix(Path::new(&cli.root), &GitRemote, cli.dry_run) {
            Ok(outcome) => {
                for c in &outcome.changes {
                    println!("{}:{}", c.file, c.line);
                    println!("  - {}", c.from);
                    println!("  + {}", c.to);
                }
                for (reference, reason) in &outcome.skipped {
                    eprintln!("건너뜀: {reference} — {reason}");
                }
                let mode = if outcome.applied {
                    "적용 완료"
                } else {
                    "미리보기 (--dry-run, 파일 미변경)"
                };
                println!(
                    "fix: 교체 {}건, 건너뜀 {}건 — {mode}",
                    outcome.changes.len(),
                    outcome.skipped.len()
                );
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

/// `observe start` — 관찰자를 기동한다 (Linux 러너).
/// fail-open: 리졸버를 못 찾거나 포트를 못 잡으면 resolv.conf를 건드리지 않고 정상 종료(0)한다 —
/// 도구 장애가 빌드 장애로 번지지 않는다.
fn observe_start(cli: &Cli) -> ExitCode {
    use just_shield::dns_observer as dns;

    let Some(record) = &cli.record else {
        eprintln!("오류: observe start에는 --record <기록 파일>이 필요합니다");
        return usage();
    };
    let Some(job) = &cli.job else {
        eprintln!("오류: observe start에는 --job <잡 이름>이 필요합니다");
        return usage();
    };

    let original = std::fs::read_to_string(&cli.resolv).unwrap_or_default();
    let Some(upstream_ip) = dns::first_nameserver(&original) else {
        eprintln!("관찰 비활성: resolv.conf에서 업스트림 리졸버를 찾지 못했습니다 (정상 진행)");
        return ExitCode::from(0); // fail-open
    };
    let upstream = format!("{upstream_ip}:53");

    // 끼어들 수 있는지 먼저 확인 — 53번을 못 잡으면 resolv.conf를 건드리지 않고 빠진다.
    match std::net::UdpSocket::bind("127.0.0.1:53") {
        Ok(probe) => drop(probe),
        Err(e) => {
            eprintln!("관찰 비활성: 127.0.0.1:53을 열 수 없습니다 ({e}) — 정상 진행 (fail-open)");
            return ExitCode::from(0);
        }
    }

    // 관찰을 켜는 resolv.conf 작성. 127.0.0.1을 우선하되 원본을 폴백으로 남긴다 —
    // 관찰자가 죽어도 잡의 이름 해석이 끊기지 않는다.
    if let Err(e) = std::fs::write(&cli.resolv, dns::observing_resolv(&original)) {
        eprintln!("관찰 비활성: resolv.conf를 쓸 수 없습니다 ({e}) — 정상 진행 (fail-open)");
        return ExitCode::from(0);
    }

    let config = dns::RelayConfig {
        listen: "127.0.0.1:53".to_string(),
        upstream,
        job: job.clone(),
        record_path: std::path::PathBuf::from(record),
        stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    eprintln!("관찰 활성: 잡 '{job}'의 DNS 질의를 기록합니다 → {record}");
    // 포그라운드 서브. 워크플로가 백그라운드로 돌리고, 잡 종료 시 프로세스가 정리된다.
    // 기록은 새 도메인마다 디스크에 flush되므로 강제 종료에도 보존된다.
    if let Err(e) = dns::serve(&config) {
        eprintln!("관찰 중단: {e} (기록은 그때까지 보존됨)");
    }
    ExitCode::from(0)
}

fn usage() -> ExitCode {
    eprintln!(
        "사용법: just-shield <scan|lock|fix> [저장소 경로] [--strict] [--online] [--dry-run] [--cooldown-days N] [--format text|json|sarif]\n\
         \u{20}      just-shield observe start --job <잡 이름> --record <기록 파일> [--resolv <경로>]  (Linux 러너)\n\
         \u{20}      just-shield observe report [저장소 경로] --record <기록 파일> [--format text|json|sarif]"
    );
    ExitCode::from(2)
}
