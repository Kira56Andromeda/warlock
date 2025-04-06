pub mod vless;

use std::io::{Error, ErrorKind, Result};
use base64::{decode_config, URL_SAFE_NO_PAD};

pub fn parse_early_data(data: Option<String>) -> Result<Option<Vec<u8>>> {
    if let Some(data) = data {
        if !data.is_empty() {
            let s = data.replace('+', "-").replace('/', "_").replace("=", "");
            match decode_config(s, URL_SAFE_NO_PAD) {
                Ok(early_data) => return Ok(Some(early_data)),
                Err(err) => return Err(Error::new(ErrorKind::Other, err.to_string())),
            }
        }
    }
    Ok(None)
}

pub fn parse_user_id(user_id: &str) -> Vec<u8> {
    let mut hex_bytes = user_id
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push((h << 4) | l)
    }
    bytes
}

pub mod seek_protocol {
    pub const PROTOCOL_VLESS: u8 = 1;

    pub const VERSION_VLESS: u8 = 0;
}

pub fn protocol_sniffer(buf: &[u8]) -> u8 {
    if buf[0] == seek_protocol::VERSION_VLESS {
        return seek_protocol::PROTOCOL_VLESS;
    }

    return 0;
}