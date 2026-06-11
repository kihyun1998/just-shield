//! 저장소 설정 파일 (`.just-shield.conf`) — 탈출구 ②: 신뢰 org 선언.
//!
//! 의도적으로 단순한 행 기반 형식이다. 한 줄 = 한 선언, `#`은 주석.
//!
//! ```text
//! # 파트너 조직의 액션은 퍼스트파티로 취급
//! trust-org partner-org
//! ```

use std::io;
use std::path::Path;

pub const FILE_NAME: &str = ".just-shield.conf";

#[derive(Default)]
pub struct Config {
    /// 퍼스트파티로 취급할 액션 소유자(org/계정) 목록.
    pub trusted_owners: Vec<String>,
}

/// 설정을 읽는다. 파일이 없으면 기본값 — 오류가 아니다.
pub fn load(root: &Path) -> io::Result<Config> {
    let path = root.join(FILE_NAME);
    if !path.is_file() {
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(path)?;
    let mut config = Config::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(owner) = line.strip_prefix("trust-org") {
            let owner = owner.trim();
            if !owner.is_empty() {
                config.trusted_owners.push(owner.to_string());
            }
        }
        // 알 수 없는 선언은 미래 버전과의 호환을 위해 조용히 무시한다.
    }
    Ok(config)
}
