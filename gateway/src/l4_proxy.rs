use std::net::{IpAddr, SocketAddr};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info, warn};

use crate::config::L4ProxyEntry;

/// Start all L4 proxy listeners. Each entry gets its own task.
pub fn spawn_l4_proxies(entries: &[L4ProxyEntry]) {
    for entry in entries {
        let entry = entry.clone();
        let allowlist = entry.ip_allowlist_nets();
        tokio::spawn(async move {
            match entry.protocol.as_str() {
                "tcp" => serve_tcp(entry.listen_port, &entry.backend, allowlist).await,
                "udp" => serve_udp(entry.listen_port, &entry.backend, allowlist).await,
                other => error!(protocol = other, "unsupported L4 protocol"),
            }
        });
    }
}

/// GW-41: L4 proxy has no auth (DD-002), so a source-IP allowlist is its only
/// access control. `None` allowlist means unrestricted (backward compatible).
fn ip_allowed(ip: IpAddr, allowlist: &Option<Vec<ipnet::IpNet>>) -> bool {
    match allowlist {
        None => true,
        Some(nets) => nets.iter().any(|net| net.contains(&ip)),
    }
}

async fn serve_tcp(listen_port: u16, backend: &str, allowlist: Option<Vec<ipnet::IpNet>>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(port = listen_port, "L4/TCP bind failed: {e}");
            return;
        }
    };

    info!(
        port = listen_port,
        backend = backend,
        "L4/TCP proxy listening"
    );

    serve_tcp_on(listener, backend, allowlist).await;
}

async fn serve_tcp_on(listener: TcpListener, backend: &str, allowlist: Option<Vec<ipnet::IpNet>>) {
    let listen_port = listener.local_addr().unwrap().port();
    let backend_addr: String = backend.to_string();
    loop {
        let (client_stream, client_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!(port = listen_port, "L4/TCP accept error: {e}");
                continue;
            }
        };

        if !ip_allowed(client_addr.ip(), &allowlist) {
            warn!(
                port = listen_port,
                client = %client_addr,
                "L4/TCP connection rejected: source IP not in allowlist"
            );
            continue;
        }

        let backend_addr = backend_addr.clone();
        tokio::spawn(async move {
            let backend_stream = match TcpStream::connect(&backend_addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        port = listen_port,
                        client = %client_addr,
                        backend = %backend_addr,
                        "L4/TCP backend connect failed: {e}"
                    );
                    return;
                }
            };

            let mut client = client_stream;
            let mut backend = backend_stream;

            match copy_bidirectional(&mut client, &mut backend).await {
                Ok((c2b, b2c)) => {
                    info!(
                        port = listen_port,
                        client = %client_addr,
                        client_to_backend = c2b,
                        backend_to_client = b2c,
                        "L4/TCP connection closed"
                    );
                }
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("reset") && !msg.contains("broken pipe") {
                        warn!(port = listen_port, client = %client_addr, "L4/TCP error: {msg}");
                    }
                }
            }
        });
    }
}

async fn serve_udp(listen_port: u16, backend: &str, allowlist: Option<Vec<ipnet::IpNet>>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let socket = match UdpSocket::bind(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(port = listen_port, "L4/UDP bind failed: {e}");
            return;
        }
    };

    info!(
        port = listen_port,
        backend = backend,
        "L4/UDP proxy listening"
    );

    let backend_addr: SocketAddr = match backend.parse() {
        Ok(a) => a,
        Err(e) => {
            error!(backend = backend, "L4/UDP invalid backend address: {e}");
            return;
        }
    };

    serve_udp_on(socket, backend_addr, allowlist).await;
}

async fn serve_udp_on(
    socket: UdpSocket,
    backend_addr: SocketAddr,
    allowlist: Option<Vec<ipnet::IpNet>>,
) {
    let listen_port = socket.local_addr().unwrap().port();
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!(port = listen_port, "L4/UDP recv error: {e}");
                continue;
            }
        };

        if !ip_allowed(src.ip(), &allowlist) {
            warn!(
                port = listen_port,
                client = %src,
                "L4/UDP packet rejected: source IP not in allowlist"
            );
            continue;
        }

        // Forward to backend
        if let Err(e) = socket.send_to(&buf[..len], backend_addr).await {
            warn!(port = listen_port, "L4/UDP send to backend failed: {e}");
            continue;
        }

        // Only the configured backend IP and port may answer. Rejected packets
        // must not reset the overall response deadline.
        match tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let (resp_len, peer) = socket.recv_from(&mut buf).await?;
                if peer == backend_addr {
                    return Ok::<usize, std::io::Error>(resp_len);
                }
                warn!(
                    port = listen_port,
                    source = %peer,
                    "L4/UDP response rejected: source is not the configured backend"
                );
            }
        })
        .await
        {
            Ok(Ok(resp_len)) => {
                if let Err(e) = socket.send_to(&buf[..resp_len], src).await {
                    warn!(port = listen_port, "L4/UDP send to client failed: {e}");
                }
            }
            Ok(Err(e)) => warn!(port = listen_port, "L4/UDP backend recv error: {e}"),
            Err(_) => {} // timeout — no response from backend, common for UDP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(cidrs: &[&str]) -> Option<Vec<ipnet::IpNet>> {
        Some(cidrs.iter().map(|c| c.parse().unwrap()).collect())
    }

    #[test]
    fn no_allowlist_allows_any_ip() {
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(ip_allowed(ip, &None));
    }

    #[test]
    fn allowlist_allows_matching_ip() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(ip_allowed(ip, &nets(&["10.0.0.0/24"])));
    }

    #[test]
    fn allowlist_rejects_non_matching_ip() {
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(!ip_allowed(ip, &nets(&["10.0.0.0/24"])));
    }

    #[test]
    fn allowlist_checks_all_entries() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(ip_allowed(ip, &nets(&["10.0.0.0/24", "192.168.1.0/24"])));
    }

    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    const IO_TIMEOUT: Duration = Duration::from_secs(2);
    const REJECTION_WINDOW: Duration = Duration::from_millis(100);

    // Abort long-running listeners even when a test assertion fails.
    struct ProxyTask(tokio::task::JoinHandle<()>);

    impl Drop for ProxyTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn tcp_roundtrip(allowlist: Option<Vec<ipnet::IpNet>>) {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        let _proxy = ProxyTask(tokio::spawn(async move {
            serve_tcp_on(listener, &backend_addr, allowlist).await;
        }));
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"request").await.unwrap();
        let (mut peer, _) = timeout(IO_TIMEOUT, backend.accept())
            .await
            .unwrap()
            .unwrap();
        let mut buf = [0; 7];
        timeout(IO_TIMEOUT, peer.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"request");
        peer.write_all(b"reply").await.unwrap();
        let mut response = [0; 5];
        timeout(IO_TIMEOUT, client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"reply");
    }

    #[tokio::test]
    async fn tcp_allowlist_permits_roundtrip() {
        tcp_roundtrip(nets(&["127.0.0.1/32"])).await;
    }

    #[tokio::test]
    async fn tcp_empty_allowlist_preserves_roundtrip() {
        tcp_roundtrip(empty_allowlist()).await;
    }

    fn empty_allowlist() -> Option<Vec<ipnet::IpNet>> {
        L4ProxyEntry {
            listen_port: 1234,
            protocol: "udp".into(),
            backend: "127.0.0.1:5678".into(),
            ip_allowlist: vec![],
        }
        .ip_allowlist_nets()
    }

    #[tokio::test]
    async fn tcp_allowlist_rejects_before_backend_connect() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        let _proxy = ProxyTask(tokio::spawn(async move {
            serve_tcp_on(listener, &backend_addr, nets(&["192.0.2.0/24"])).await;
        }));
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0; 1];
        let result = timeout(IO_TIMEOUT, client.read(&mut buf)).await.unwrap();
        assert!(matches!(result, Ok(0)) || result.is_err());
        assert!(timeout(REJECTION_WINDOW, backend.accept()).await.is_err());
    }

    async fn udp_proxy(allowlist: Option<Vec<ipnet::IpNet>>) -> (UdpSocket, SocketAddr, ProxyTask) {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = socket.local_addr().unwrap();
        let proxy = ProxyTask(tokio::spawn(serve_udp_on(socket, backend_addr, allowlist)));
        (backend, proxy_addr, proxy)
    }

    async fn udp_roundtrip(allowlist: Option<Vec<ipnet::IpNet>>) {
        let (backend, proxy_addr, _proxy) = udp_proxy(allowlist).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"request", proxy_addr).await.unwrap();
        let mut buf = [0; 64];
        let (len, peer) = timeout(IO_TIMEOUT, backend.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"request");
        backend.send_to(b"reply", peer).await.unwrap();
        let (len, peer) = timeout(IO_TIMEOUT, client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"reply");
        assert_eq!(peer, proxy_addr);
    }

    #[tokio::test]
    async fn udp_allowlist_permits_roundtrip() {
        udp_roundtrip(nets(&["127.0.0.1/32"])).await;
    }

    #[tokio::test]
    async fn udp_empty_allowlist_preserves_roundtrip() {
        udp_roundtrip(empty_allowlist()).await;
    }

    #[tokio::test]
    async fn udp_allowlist_rejects_before_backend_forward() {
        let (backend, proxy_addr, _proxy) = udp_proxy(nets(&["127.0.0.1/32"])).await;
        let denied = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        denied.send_to(b"denied", proxy_addr).await.unwrap();
        let mut buf = [0; 64];
        assert!(timeout(REJECTION_WINDOW, backend.recv_from(&mut buf))
            .await
            .is_err());
        // The listener must still serve permitted clients after rejection.
        let allowed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        allowed.send_to(b"allowed", proxy_addr).await.unwrap();
        let (len, peer) = timeout(IO_TIMEOUT, backend.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"allowed");
        backend.send_to(b"reply", peer).await.unwrap();
        let (len, _) = timeout(IO_TIMEOUT, allowed.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"reply");
    }

    async fn rejects_injected_response(attacker_ip: &str, allowlist: Option<Vec<ipnet::IpNet>>) {
        let (backend, proxy_addr, _proxy) = udp_proxy(allowlist).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind((attacker_ip, 0)).await.unwrap();
        client.send_to(b"request", proxy_addr).await.unwrap();
        let mut buf = [0; 64];
        // Seeing the request at the backend proves the proxy is awaiting its response.
        let (len, peer) = timeout(IO_TIMEOUT, backend.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"request");
        attacker.send_to(b"injected", peer).await.unwrap();
        assert!(
            timeout(REJECTION_WINDOW, client.recv_from(&mut buf))
                .await
                .is_err(),
            "a packet from a different backend address reached the client"
        );
        backend.send_to(b"real response", peer).await.unwrap();
        let (len, peer) = timeout(IO_TIMEOUT, client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"real response");
        assert_eq!(peer, proxy_addr);
        assert!(timeout(REJECTION_WINDOW, backend.recv_from(&mut buf))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn udp_response_rejects_ip_outside_allowlist() {
        rejects_injected_response("127.0.0.2", nets(&["127.0.0.1/32"])).await;
    }

    #[tokio::test]
    async fn udp_response_rejects_backend_ip_with_wrong_port() {
        rejects_injected_response("127.0.0.1", nets(&["127.0.0.1/32"])).await;
    }

    #[tokio::test]
    async fn udp_response_rejects_injection_with_empty_allowlist() {
        rejects_injected_response("127.0.0.2", empty_allowlist()).await;
    }
}
