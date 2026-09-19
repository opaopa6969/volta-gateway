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

        // Wait for response from backend (with timeout)
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((resp_len, _))) => {
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
}
