use std::net::SocketAddr;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info, warn};

use crate::config::L4ProxyEntry;

/// Start all L4 proxy listeners. Each entry gets its own task.
pub fn spawn_l4_proxies(entries: &[L4ProxyEntry]) {
    for entry in entries {
        let entry = entry.clone();
        tokio::spawn(async move {
            match entry.protocol.as_str() {
                "tcp" => serve_tcp(entry.listen_port, &entry.backend).await,
                "udp" => serve_udp(entry.listen_port, &entry.backend).await,
                other => error!(protocol = other, "unsupported L4 protocol"),
            }
        });
    }
}

async fn serve_tcp(listen_port: u16, backend: &str) {
    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(port = listen_port, "L4/TCP bind failed: {e}");
            return;
        }
    };

    info!(port = listen_port, backend = backend, "L4/TCP proxy listening");

    let backend_addr: String = backend.to_string();
    loop {
        let (client_stream, client_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!(port = listen_port, "L4/TCP accept error: {e}");
                continue;
            }
        };

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

async fn serve_udp(listen_port: u16, backend: &str) {
    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let socket = match UdpSocket::bind(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(port = listen_port, "L4/UDP bind failed: {e}");
            return;
        }
    };

    info!(port = listen_port, backend = backend, "L4/UDP proxy listening");

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

        // Forward to backend
        if let Err(e) = socket.send_to(&buf[..len], backend_addr).await {
            warn!(port = listen_port, "L4/UDP send to backend failed: {e}");
            continue;
        }

        // Wait for response from backend (with timeout)
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        ).await {
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
