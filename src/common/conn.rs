pub mod socket {
    use crate::ext::StreamExt;
    use std::io::{Error, ErrorKind, Result};
    use crate::proxy::vless::protocol;
    use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
    use worker::*;

    use crate::websocket::WebSocketStream;

    pub async fn process_tcp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        target: &str,
        port: u16,
    ) -> Result<()> {
        // connect to remote socket
        let mut remote_socket = Socket::builder().connect(target, port).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionAborted,
                format!("connect to remote failed: {}", e),
            )
        })?;

        // check remote socket
        remote_socket.opened().await.map_err(|e| {
            Error::new(
                ErrorKind::ConnectionReset,
                format!("remote socket not opened: {}", e),
            )
        })?;

        // send response header
        client_socket
            .write(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;

        // forward data
        copy_bidirectional(client_socket, &mut remote_socket)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("forward data between client and remote failed: {}", e),
                )
            })?;

        Ok(())
    }

    pub async fn process_udp_outbound(
        client_socket: &mut WebSocketStream<'_>,
        _: &str,
        port: u16,
    ) -> Result<()> {
        // check port (only support dns query)
        if port != 53 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "not supported udp proxy yet",
            ));
        }

        // send response header
        client_socket
            .write(&protocol::RESPONSE)
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send response header failed: {}", e),
                )
            })?;

        // forward data
        loop {
            // read packet length
            let length = client_socket.read_u16().await;
            if length.is_err() {
                return Ok(());
            }

            // read dns packet
            let packet = client_socket.read_bytes(length.unwrap() as usize).await?;

            // create request
            let request = Request::new_with_init("https://8.8.8.8/dns-query", &{
                // create request
                let mut init = RequestInit::new();
                init.method = Method::Post;
                init.headers = Headers::new();
                init.body = Some(packet.into());

                // set headers
                _ = init.headers.set("Content-Type", "application/dns-message");

                init
            })
            .unwrap();

            // invoke dns-over-http resolver
            let mut response = Fetch::Request(request).send().await.map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("send DNS-over-HTTP request failed: {}", e),
                )
            })?;

            // read response
            let data = response.bytes().await.map_err(|e| {
                Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("DNS-over-HTTP response body error: {}", e),
                )
            })?;

            // write response
            client_socket.write_u16(data.len() as u16).await?;
            client_socket.write_all(&data).await?;
        }
    }
}