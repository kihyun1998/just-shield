//! DNS 관찰자 중계 루프의 실제 소켓 통합 테스트 (이슈 #45).
//!
//! 가짜 업스트림(질의를 받으면 정해진 응답을 돌려줌)을 세워 hermetic하게 검증한다 —
//! 진짜 8.8.8.8에 의존하지 않는다. 관찰자가 질의를 받아 ① 도메인을 기록 파일에 쓰고
//! ② 업스트림 응답을 질의자에게 돌려주는지 확인한다.

use just_shield::dns_observer::{RelayConfig, serve};
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn query_packet(name: &str) -> Vec<u8> {
    let mut p = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    p
}

#[test]
fn relay_records_domain_and_forwards_response() {
    let stop = Arc::new(AtomicBool::new(false));

    // 가짜 업스트림: 질의를 받을 때마다 0xCAFE를 붙여 응답한다 (재전송 대비 루프).
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let upstream_addr = upstream.local_addr().unwrap().to_string();
    let up_stop = stop.clone();
    let upstream_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while !up_stop.load(Ordering::Relaxed) {
            if let Ok((n, from)) = upstream.recv_from(&mut buf) {
                let mut resp = buf[..n].to_vec();
                resp.extend_from_slice(&[0xCA, 0xFE]);
                let _ = upstream.send_to(&resp, from);
            }
        }
    });

    // listen 포트를 :0으로 잡아 빈 포트를 알아낸 뒤 넘긴다 (53은 root 필요).
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen_addr = probe.local_addr().unwrap().to_string();
    drop(probe);

    let record = std::env::temp_dir().join(format!("js-dns-test-{}.txt", std::process::id()));
    let config = RelayConfig {
        listen: listen_addr.clone(),
        upstream: upstream_addr,
        job: "build".to_string(),
        record_path: record.clone(),
        stop: stop.clone(),
    };
    let relay = std::thread::spawn(move || {
        let _ = serve(&config);
    });

    // 관찰자에게 질의를 보낸다. UDP라 릴레이가 아직 바인드 전이면 패킷이 유실되므로,
    // 응답이 올 때까지 짧은 간격으로 재전송한다.
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let query = query_packet("crates.io");
    let mut buf = [0u8; 1500];
    let mut got = None;
    let send_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < send_deadline {
        client.send_to(&query, &listen_addr).unwrap();
        if let Ok((n, _)) = client.recv_from(&mut buf) {
            got = Some(n);
            break;
        }
    }
    let n = got.expect("업스트림 응답이 돌아와야 한다");
    // 업스트림이 붙인 마커가 보이면 전달이 동작한 것.
    assert_eq!(
        &buf[n - 2..n],
        &[0xCA, 0xFE],
        "업스트림 응답이 전달되지 않음"
    );

    // 기록 파일에 도메인이 flush될 때까지 잠시 대기.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut content = String::new();
    while Instant::now() < deadline {
        if let Ok(c) = std::fs::read_to_string(&record) {
            if c.contains("crates.io") {
                content = c;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::Relaxed);
    let _ = relay.join();
    let _ = upstream_thread.join();
    let _ = std::fs::remove_file(&record);

    assert!(
        content.contains("job build"),
        "기록에 잡 이름이 없음:\n{content}"
    );
    assert!(
        content.contains("crates.io"),
        "기록에 도메인이 없음:\n{content}"
    );
}
