mod proxy;
mod common;

use crate::proxy::vless::lib::run_tunnel as handle_vless;
use crate::proxy::{parse_early_data, parse_user_id, protocol_sniffer};
use crate::websocket::WebSocketStream;
use proxy::seek_protocol;
use wasm_bindgen::JsValue;
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // get user id
    let user_id = env.var("USER_ID")?.to_string();
    let _user_id = parse_user_id(&user_id);

    // better disguising;
    let fallback_site = env
        .var("FALLBACK_SITE")
        .unwrap_or(JsValue::from_str("").into())
        .to_string();
    let should_fallback = req
        .headers()
        .get("Upgrade")?
        .map(|up| up != *"websocket")
        .unwrap_or(true);

    let request_path = req.path().to_string();
    let uuid_str = env.var("USER_ID")?.to_string();
    let host_str = req.url()?.host_str().unwrap().to_string();
    
    // get proxy ip
    let proxy_ip = request_path.replace("/", "");
    let proxy_ip = proxy_ip
        .split_ascii_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    if should_fallback && !fallback_site.is_empty() {
        let req = Fetch::Url(Url::parse(&fallback_site)?);
        return req.send().await;
    } else if should_fallback {
        let vless_uri = format!(
            "vless://{uuid}@{host}:443?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=ws#workers-tunnel",
            uuid = uuid_str,
            host = host_str
        );
        return Response::ok(vless_uri);
    }


    // ready early data
    let early_data = req.headers().get("sec-websocket-protocol")?;
    let early_data = parse_early_data(early_data)?;

    // Accept / handle a websocket connection
    let WebSocketPair { client, server } = WebSocketPair::new()?;
    server.accept()?;

    wasm_bindgen_futures::spawn_local(async move {
        // create websocket stream
        let mut socket = WebSocketStream::new(
            &server,
            server.events().expect("could not open stream"),
            early_data,
        );

        // protocol hijacking
        if let Err(err) = socket.fill_buffer_until(56).await {
            console_error!("error filling buffer: {}", err);
        }

        // into tunnel
        match protocol_sniffer(socket.peek_buffer(56)) {
            seek_protocol::PROTOCOL_VLESS => {
                if let Err(err) = handle_vless(socket, proxy_ip).await {
                    console_error!("error: {}", err);
                    _ = server.close(Some(1003), Some("invalid request"));
                }
            }
            unknown => {
                console_error!("unsupported protocol: {}", unknown)
            }
        }
    });

    Response::from_websocket(client)
}

mod ext {
    use std::io::Result;
    use tokio::io::AsyncReadExt;
    #[allow(dead_code)]
    pub trait StreamExt {
        async fn read_string(&mut self, n: usize) -> Result<String>;
        async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>>;
    }

    impl<T: AsyncReadExt + Unpin + ?Sized> StreamExt for T {
        async fn read_string(&mut self, n: usize) -> Result<String> {
            self.read_bytes(n).await.map(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid string: {}", e),
                    )
                })
            })?
        }

        async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
            let mut buffer = vec![0u8; n];
            self.read_exact(&mut buffer).await?;

            Ok(buffer)
        }
    }
}

pub mod websocket {
    use futures_util::Stream;
    use std::{
        io::{Error, ErrorKind, Result},
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::{BufMut, BytesMut};
    use pin_project::pin_project;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use worker::{EventStream, WebSocket, WebsocketEvent};

    #[pin_project]
    pub struct WebSocketStream<'a> {
        ws: &'a WebSocket,
        #[pin]
        stream: EventStream<'a>,
        buffer: BytesMut,
    }

    impl<'a> WebSocketStream<'a> {
        pub fn new(
            ws: &'a WebSocket,
            stream: EventStream<'a>,
            early_data: Option<Vec<u8>>,
        ) -> Self {
            let mut buffer = BytesMut::new();
            if let Some(data) = early_data {
                buffer.put_slice(&data)
            }

            Self { ws, stream, buffer }
        }

        pub async fn fill_buffer_until(&mut self, n: usize) -> Result<()> {
            use futures_util::stream::StreamExt;

            while self.buffer.len() < n {
                match self.stream.next().await {
                    Some(Ok(WebsocketEvent::Message(msg))) => {
                        if let Some(data) = msg.bytes() {
                            self.buffer.put_slice(&data);
                        }
                    }
                    Some(Err(e)) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                    }
                    _ => break, // Connection closed
                }
            }

            Ok(())
        }

        pub fn peek_buffer(&self, n: usize) -> &[u8] {
            let len = std::cmp::min(n, self.buffer.len());
            &self.buffer[..len]
        }
    }

    impl AsyncRead for WebSocketStream<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            let mut this = self.project();

            loop {
                let amt = std::cmp::min(this.buffer.len(), buf.remaining());
                if amt > 0 {
                    buf.put_slice(&this.buffer.split_to(amt));
                    return Poll::Ready(Ok(()));
                }

                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                        if let Some(data) = msg.bytes() {
                            this.buffer.put_slice(&data);
                        };
                        continue;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())))
                    }
                    _ => return Poll::Ready(Ok(())), // None or Close event, return Ok to indicate stream end
                }
            }
        }
    }

    impl AsyncWrite for WebSocketStream<'_> {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            if let Err(e) = self.ws.send_with_bytes(buf) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            if let Err(e) = self.ws.close(None, Some("normal close")) {
                return Poll::Ready(Err(Error::new(ErrorKind::Other, e.to_string())));
            }

            Poll::Ready(Ok(()))
        }
    }
}
