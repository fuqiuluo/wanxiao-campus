use base64::Engine;
use log::{error, info};
use serde_json::{json, Value};
use crate::request::request_no_encrypt;
use crate::cryptor::{create_key_pair, des_encrypt, rsa_decrypt};
use crate::login::LoginError;

const URL_EXCHANGE_SECRET: &str = "https://app.17wanxiao.com:443/campus/cam_iface46/exchangeSecretkey.action";

/// 完美校园会话
pub struct SessionInfo {
    pub session_id: String,
    pub app_key: String,
    pub token: String,
    pub device_id: String,
}

impl SessionInfo {
    /// 合成加密请求参数
    pub fn generate_encrypted_data(&self, data: &[u8]) -> (String, Value) {
        let des_key = &self.app_key.as_bytes()[..24];
        let encrypted_data = des_encrypt(data, des_key);
        let data = base64::prelude::BASE64_STANDARD.encode(&encrypted_data);
        let data = json!({
            "session": self.session_id,
            "data": data
        });
        (sha256::digest(data.to_string()), data)
    }
}

/// 新建一个会话
///
/// 将会自动发起公钥交换请求
pub async fn new_session(
    device_id: &str,
) -> Option<SessionInfo> {
    let mut session = SessionInfo {
        session_id: "".to_string(),
        app_key: "".to_string(),
        token: "".to_string(),
        device_id: device_id.to_string(),
    };

    pub async fn exchange_secret(public_key: String, private_key: String) -> Option<(String, String)> {
        info!("Exchange public key with server");
        let params = json!({ "key": public_key });
        let response_text = match request_no_encrypt(URL_EXCHANGE_SECRET, &params, None).await {
            Some(result) => result,
            None => {
                error!("Public key exchange request failed");
                return None;
            }
        };
        let json_str = match rsa_decrypt(response_text, &private_key) {
            None => return None,
            Some(result) => String::from_utf8(result).unwrap()
        };
        let v: Value = serde_json::from_str(&json_str).unwrap();
        let session_id = String::from(v["session"].as_str().unwrap());
        let app_key = String::from(v["key"].as_str().unwrap());
        Some((session_id, app_key))
    }

    let server_secret = match create_key_pair(1024) {
        Some((pub_key, pri_key)) => exchange_secret(pub_key, pri_key).await,
        None => return None
    };
    let (session_id, app_key) = match server_secret {
        None => return None,
        Some(result) => result
    };

    session.session_id = session_id;
    session.app_key = app_key;

    return Some(session)
}