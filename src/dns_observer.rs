//! 초소형 DNS 관찰자 (층 ⓒ의 눈, ADR-0006) — Linux 러너 전용, 의존 크레이트 0.
//!
//! 잡의 DNS 질의를 업스트림으로 그대로 중계하고, 질의된 이름(QNAME)만 기록 파일에
//! 남긴다. 차단하지 않는다 — 관찰은 정책 작성을 위한 가시성 도구이지 보안 경계가 아니다.
//!
//! 관찰자와 판정은 이 기록 파일로 분리된다(PRD 결정): 여기서 만든 파일을
//! `observe report`(S1)가 읽는다. 그래서 QNAME 추출이라는 테스트할 가치가 있는
//! 부분은 순수 함수로, 소켓을 만지는 부분은 최대한 얇게 둔다.

use std::collections::BTreeSet;
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// DNS 질의 메시지에서 첫 질문의 QNAME을 추출한다.
///
/// 헤더 12바이트 뒤부터 라벨 시퀀스(`<len><bytes>...0x00`)를 읽는다. 질의 패킷의
/// 질문 섹션에는 압축 포인터가 쓰이지 않으므로(RFC 1035) 포인터는 거부한다 —
/// 관찰 대상은 우리가 받는 아웃바운드 질의뿐이다.
pub fn extract_qname(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    // QDCOUNT(질문 수)가 0이면 추출할 이름이 없다.
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            break; // 루트 라벨 — 이름 끝.
        }
        // 상위 2비트가 켜져 있으면 압축 포인터 — 질의에는 없어야 한다.
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        let end = pos.checked_add(len)?;
        let label = packet.get(pos..end)?;
        // 라벨은 호스트네임 문자만 — 이상하면 거부(잘린 패킷 등).
        if !label
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos = end;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

/// resolv.conf에서 첫 `nameserver` 주소를 찾는다 — 우리의 업스트림이 된다.
pub fn first_nameserver(resolv: &str) -> Option<String> {
    for line in resolv.lines() {
        if let Some(addr) = line.trim().strip_prefix("nameserver ") {
            let addr = addr.trim();
            if !addr.is_empty() && addr != "127.0.0.1" {
                return Some(addr.to_string());
            }
        }
    }
    None
}

/// 관찰을 켜는 resolv.conf를 만든다 — 127.0.0.1을 첫 리졸버로 두되 **기존
/// nameserver들을 폴백으로 남긴다**. 이것이 fail-open의 핵심: 관찰자가 죽으면
/// 127.0.0.1 질의가 즉시 거부되고 리졸버가 다음 줄(진짜 리졸버)로 넘어가, 잡의
/// 이름 해석이 끊기지 않는다.
pub fn observing_resolv(original: &str) -> String {
    let mut out = String::from("# just-shield observe — 127.0.0.1 우선, 원본은 폴백.\n");
    out.push_str("nameserver 127.0.0.1\n");
    for line in original.lines() {
        let trimmed = line.trim();
        // 원본의 nameserver는 폴백으로 보존(중복 127.0.0.1만 제외), 그 외 지시어도 보존.
        if trimmed == "nameserver 127.0.0.1" {
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// 관찰자가 모은 도메인 집합을 S1이 읽는 기록 파일 형식으로 직렬화한다.
pub fn render_record(job: &str, domains: &BTreeSet<String>) -> String {
    let mut out = format!("# just-shield observe 기록 — 잡 '{job}'이 조회한 도메인.\njob {job}\n");
    for d in domains {
        out.push_str(d);
        out.push('\n');
    }
    out
}

/// 중계기 설정.
pub struct RelayConfig {
    /// 우리가 들을 주소 (예: 127.0.0.1:53).
    pub listen: String,
    /// 질의를 전달할 진짜 리졸버 (예: 8.8.8.8:53).
    pub upstream: String,
    /// 기록 파일 경로 — 잡 이름과 함께.
    pub job: String,
    pub record_path: std::path::PathBuf,
    /// 종료 신호.
    pub stop: Arc<AtomicBool>,
}

/// 중계 루프. 질의를 받으면 ① QNAME을 기록하고 ② 업스트림에 그대로 전달해
/// 응답을 돌려준다. **새 도메인이 보일 때마다 기록 파일을 즉시 갱신한다** —
/// `kill -9`로 관찰자가 죽어도 그때까지의 기록은 디스크에 남는다.
/// 어떤 단계가 실패해도 루프는 계속된다 — fail-open.
pub fn serve(config: &RelayConfig) -> io::Result<()> {
    let sock = UdpSocket::bind(&config.listen)?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    // 시작 즉시 빈 기록을 한 번 쓴다 — 질의가 0건이어도 보고가 파일을 찾도록.
    let _ = std::fs::write(
        &config.record_path,
        render_record(&config.job, &seen.lock().unwrap()),
    );
    let mut buf = [0u8; 1500];
    while !config.stop.load(Ordering::Relaxed) {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => continue, // fail-open: 수신 오류는 무시하고 계속.
        };
        let query = &buf[..n];
        if let Some(name) = extract_qname(query)
            && let Ok(mut set) = seen.lock()
            && set.insert(name)
        {
            // 새 도메인 — 기록 파일을 즉시 갱신(flush-on-update).
            let _ = std::fs::write(&config.record_path, render_record(&config.job, &set));
        }
        // 업스트림으로 전달하고 응답을 질의자에게 돌려준다. 우리가 리졸버 경로에
        // 끼어든 이상 전달은 해줘야 한다 — 실패 시 그 질의만 포기한다(fail-open).
        let _ = forward(&sock, query, &config.upstream, from);
    }
    Ok(())
}

/// 한 질의를 업스트림에 전달하고 응답을 원 질의자에게 돌려준다.
fn forward(
    listen_sock: &UdpSocket,
    query: &[u8],
    upstream: &str,
    reply_to: std::net::SocketAddr,
) -> io::Result<()> {
    let up = UdpSocket::bind("0.0.0.0:0")?;
    up.set_read_timeout(Some(Duration::from_secs(3)))?;
    up.send_to(query, upstream)?;
    let mut resp = [0u8; 1500];
    let n = up.recv(&mut resp)?;
    listen_sock.send_to(&resp[..n], reply_to)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 헤더(12B) + QNAME 라벨들 + 0x00 + QTYPE/QCLASS로 질의 패킷을 만든다.
    fn query_packet(name: &str) -> Vec<u8> {
        let mut p = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: 표준 질의
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0x00); // 루트
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        p
    }

    #[test]
    fn extracts_simple_and_multi_label_names() {
        assert_eq!(
            extract_qname(&query_packet("ghcr.io")).as_deref(),
            Some("ghcr.io")
        );
        assert_eq!(
            extract_qname(&query_packet("abc123.blob.core.windows.net")).as_deref(),
            Some("abc123.blob.core.windows.net")
        );
    }

    #[test]
    fn lowercases_names() {
        assert_eq!(
            extract_qname(&query_packet("GHCR.IO")).as_deref(),
            Some("ghcr.io")
        );
    }

    #[test]
    fn rejects_compression_pointer_in_question() {
        let mut p = query_packet("evil.net");
        // 첫 라벨 길이 바이트를 압축 포인터(0xC0..)로 오염.
        p[12] = 0xC0;
        assert_eq!(extract_qname(&p), None);
    }

    #[test]
    fn rejects_truncated_and_empty() {
        assert_eq!(extract_qname(&[0u8; 5]), None); // 헤더보다 짧음
        // QDCOUNT=0
        let mut p = query_packet("x.com");
        p[4] = 0;
        p[5] = 0;
        assert_eq!(extract_qname(&p), None);
        // 길이가 패킷을 넘어가는 라벨.
        let mut bad = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        bad.push(0x40); // 64바이트 라벨이라 주장하지만 데이터 없음
        assert_eq!(extract_qname(&bad), None);
    }

    #[test]
    fn first_nameserver_skips_localhost() {
        let resolv = "# comment\nnameserver 127.0.0.1\nnameserver 8.8.8.8\noptions edns0\n";
        assert_eq!(first_nameserver(resolv).as_deref(), Some("8.8.8.8"));
        assert_eq!(first_nameserver("options edns0\n"), None);
    }

    #[test]
    fn observing_resolv_keeps_original_as_fallback() {
        let original = "nameserver 8.8.8.8\nnameserver 1.1.1.1\noptions edns0\n";
        let out = observing_resolv(original);
        let lines: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("nameserver"))
            .collect();
        // 127.0.0.1이 첫 줄, 원본 리졸버들이 폴백으로 뒤따른다.
        assert_eq!(lines[0], "nameserver 127.0.0.1");
        assert!(lines.contains(&"nameserver 8.8.8.8"));
        assert!(lines.contains(&"nameserver 1.1.1.1"));
        // options 같은 비-nameserver 지시어도 보존.
        assert!(out.contains("options edns0"));
    }

    #[test]
    fn record_format_matches_observe_reader() {
        let mut set = BTreeSet::new();
        set.insert("ghcr.io".to_string());
        set.insert("crates.io".to_string());
        let text = render_record("release", &set);
        // S1의 parse_record가 읽을 수 있어야 한다 — 같은 형식.
        let parsed = crate::observe::parse_record(&text).unwrap();
        assert_eq!(parsed.job, "release");
        assert!(parsed.domains.contains("ghcr.io"));
        assert!(parsed.domains.contains("crates.io"));
    }
}
