#[allow(dead_code)]
pub mod protocol {
    pub const VERSION: u8 = 0;
    pub const RESPONSE: [u8; 2] = [0u8; 2];
    pub const NETWORK_TYPE_TCP: u8 = 1;
    pub const NETWORK_TYPE_UDP: u8 = 2;
    pub const ADDRESS_TYPE_IPV4: u8 = 1;
    pub const ADDRESS_TYPE_DOMAIN: u8 = 2;
    pub const ADDRESS_TYPE_IPV6: u8 = 3;
}

pub mod lib {
    use std::io::{Error, ErrorKind, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    use crate::common::conn::socket::{process_tcp_outbound, process_udp_outbound};
    use crate::ext::StreamExt;
    use crate::proxy::vless::protocol;
    use crate::websocket::WebSocketStream;
    use tokio::io::AsyncReadExt;
    use regex::Regex;

    pub async fn run_tunnel(
        mut client_socket: WebSocketStream<'_>,
        proxy_ip: Vec<String>,
    ) -> Result<()> {
        // ignore version and user_id
        let _ = client_socket.read_u8().await?;
        let _ = client_socket.read_bytes(16).await?;

        // ignore addons
        let length = client_socket.read_u8().await?;
        _ = client_socket.read_bytes(length as usize).await?;

        // read network type
        let network_type = client_socket.read_u8().await?;

        // read remote port
        let remote_port = client_socket.read_u16().await?;

        // read remote address
        let remote_addr = match client_socket.read_u8().await? {
            protocol::ADDRESS_TYPE_DOMAIN => {
                let length = client_socket.read_u8().await?;
                client_socket.read_string(length as usize).await?
            }
            protocol::ADDRESS_TYPE_IPV4 => {
                Ipv4Addr::from_bits(client_socket.read_u32().await?).to_string()
            }
            protocol::ADDRESS_TYPE_IPV6 => format!(
                "[{}]",
                Ipv6Addr::from_bits(client_socket.read_u128().await?)
            ),
            _ => {
                return Err(Error::new(ErrorKind::InvalidData, "invalid address type"));
            }
        };

        // process outbound
        match network_type {
            protocol::NETWORK_TYPE_TCP => {
                // try to connect to remote
                let proxy_ip_pattern = Regex::new(r"^.+-\d+$").unwrap();
                let all_targets = [vec![remote_addr], proxy_ip].concat();

                for mut target_addr in all_targets {
                    let target = target_addr.clone();
                    let mut target_port = remote_port;
                    
                    if proxy_ip_pattern.is_match(&target) {
                        let proxy_and_port: Vec<&str> = target.split("-").collect();

                        // reassign new proxy address and port
                        target_addr = proxy_and_port[0].to_string();
                        target_port = proxy_and_port[1].parse().unwrap_or(443);
                    }

                    match process_tcp_outbound(&mut client_socket, &target_addr, target_port).await {
                        Ok(_) => return Ok(()),
                        Err(e) => {
                            if e.kind() != ErrorKind::ConnectionReset {
                                return Err(e);
                            }
                            continue;
                        }
                    }
                }

                Err(Error::new(ErrorKind::InvalidData, "no target to connect"))
            }
            protocol::NETWORK_TYPE_UDP => {
                let _ = process_udp_outbound(&mut client_socket, &remote_addr, remote_port).await;
                Ok(())
            }
            unknown => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unsupported network type: {}", unknown),
            )),
        }
    }
}