use core::fmt;
use base64::Engine;
use log::error;
use serde_json::{json, Value};
use crate::cryptor::aes_encrypt;
use crate::keychain::KeyChainError::{NetworkError, ParseError};
use crate::login::LoginError;
use crate::request::USER_AGENT;
use crate::wanxiao::SessionInfo;

const URL_KEY_CHAIN: &str = "https://xqh5.17wanxiao.com/keychain/Api";
const AES_KEY: &[u8; 16] = b"wanmeiqiyewmqywx";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyChainError {
    NetworkError,
    RequestFailed(String),
    ParseError(String),
}

impl fmt::Display for KeyChainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyChainError::RequestFailed(ref msg) => {
                write!(f, "Request failed: {}", msg)
            }
            KeyChainError::NetworkError => {
                write!(f, "Network error")
            }
            KeyChainError::ParseError(ref msg) => {
                write!(f, "Parse error: {}", msg)
            }
        }
    }
}

#[cfg(any(feature = "std", test))]
impl error::Error for KeyChainError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            KeyChainError::RequestFailed(_) => None,
            KeyChainError::NetworkError => None,
            KeyChainError::ParseError(_) => None,
        }
    }
}


macro_rules! parse_code {
    ($expression:expr) => {
        match $expression.as_i64() {
            Some(result) => result,
            None => match $expression.as_str() {
                Some(result) => result.parse::<i64>().unwrap(),
                None => {
                    return Err(KeyChainError::RequestFailed("无法解析返回值".to_string()));
                }
            }
        }
    };
}

#[derive(Debug, Clone)]
pub struct SCard {
    grant_id: i32,
    snr: String,
    name: String,
    area: String,
    status: i32,
    card_type: String,
    ter_mid: String,
    ex_ter_mid: String,
    ex_pos_code: String,
}

impl SessionInfo {
    pub async fn get_lock_key_list(&self) -> Result<Vec<SCard>, KeyChainError> {
        let json_args = json!({
            "customerid": self.ecard_customer_id,
            "beginIndex":0,
            "count":20,
            "extendtypes":"2,3,4,7"
        });
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let json_args = json_args.to_string() + time.to_string().as_str();
        let json_args = base64::prelude::BASE64_STANDARD.encode(aes_encrypt(json_args.as_bytes(), AES_KEY));

        let referer = format!("https://xqh5.17wanxiao.com/keychain/html/index.html?customreId={}&systemType=Android&UAinfo=wanxiao&versioncode=10583101&token={}", self.customer_id, self.token);

        let mut params = std::collections::HashMap::new();
        params.insert("token", self.session_id.as_str());
        params.insert("method", "LOCK_KEY_LIST");
        params.insert("param", json_args.as_str());

        let client = reqwest::Client::new();
        let mut builder = client.post(URL_KEY_CHAIN);
        let resp = match builder
            .header("User-Agent", USER_AGENT)
            .header("refer", referer)
            .header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
            .form(&params)
            .send().await {
            Ok(result) => result,
            Err(e) => {
                error!("network request failed: {}", e);
                return Err(NetworkError);
            }
        };
        let response_text = match resp.text().await {
            Ok(result) => result,
            Err(e) => {
                error!("network failed to receive: {}", e);
                return Err(NetworkError);
            }
        };
        let response: Value = match serde_json::from_str(&response_text) {
            Ok(result) => result,
            Err(e) => {
                error!("无法解析返回值: {}", e);
                return Err(ParseError(e.to_string()));
            }
        };
        let code = parse_code!(response["code_"]);
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(KeyChainError::RequestFailed(msg.to_string()));
        }
        let data = response["body"].as_str().unwrap();
        let data: Value = serde_json::from_str(data).unwrap();
        let scard_list = data["data"].as_array().unwrap();

        let mut result = Vec::<SCard>::new();

        for scard in scard_list {
            result.push(SCard {
                grant_id: scard["grantid"].as_i64().unwrap() as i32,
                snr: scard["scardsnr"].as_str().unwrap().to_string(),
                area: scard["area"].as_str().unwrap().to_string(),
                status: scard["status"].as_i64().unwrap() as i32,
                card_type: scard["extendtype"].as_str().unwrap().to_string(),
                ter_mid: scard["termid"].as_str().unwrap().to_string(),
                ex_ter_mid: scard["extendtermid"].as_str().unwrap().to_string(),
                ex_pos_code: scard["extendposcode"].as_str().unwrap().to_string(),
                name: scard["note"].as_str().unwrap().to_string(),
            })
        }

        Ok(result)
    }

    pub async fn open_lock(&self, card: &SCard) -> Result<(), KeyChainError> {
        let json_args = json!({
            "postCode":"null",
            "name":card.name.as_str(),
            "termtype":card.card_type.as_str(),
            "dpcode":"00000000",
            "customerid":self.ecard_customer_id,
            "termid":card.ter_mid.as_str(),
            "lockcode":"null",
            "systemid":"48",
            "iotype":"0",
            "extendposcode":card.ex_pos_code.as_str(),
            "extendtermid":card.ex_ter_mid.as_str(),
        });
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let json_args = json_args.to_string() + time.to_string().as_str();
        let json_args = base64::prelude::BASE64_STANDARD.encode(aes_encrypt(json_args.as_bytes(), AES_KEY));

        let referer = format!("https://xqh5.17wanxiao.com/keychain/html/index.html?customreId={}&systemType=Android&UAinfo=wanxiao&versioncode=10583101&token={}", self.customer_id, self.token);

        let mut params = std::collections::HashMap::new();
        params.insert("token", self.session_id.as_str());
        params.insert("method", "LOCK_OPEN");
        params.insert("param", json_args.as_str());

        let client = reqwest::Client::new();
        let mut builder = client.post(URL_KEY_CHAIN);
        let resp = match builder
            .header("User-Agent", USER_AGENT)
            .header("refer", referer)
            .header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
            .form(&params)
            .send().await {
            Ok(result) => result,
            Err(e) => {
                error!("network request failed: {}", e);
                return Err(NetworkError);
            }
        };
        let response_text = match resp.text().await {
            Ok(result) => result,
            Err(e) => {
                error!("network failed to receive: {}", e);
                return Err(NetworkError);
            }
        };
        let response: Value = match serde_json::from_str(&response_text) {
            Ok(result) => result,
            Err(e) => {
                error!("无法解析返回值: {}", e);
                return Err(ParseError(e.to_string()));
            }
        };
        let code = parse_code!(response["code_"]);
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(KeyChainError::RequestFailed(msg.to_string()));
        }
        Ok(())
    }
}