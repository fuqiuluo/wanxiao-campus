use core::fmt;
use log::{error, info, warn};
use reqwest::{Response, StatusCode};
use serde_json::{json, Value};
use crate::wanxiao::SessionInfo;

const URL_LOGIN: &str = "https://app.17wanxiao.com/campus/cam_iface46/loginnew.action";
const URL_CHECK_BEFORE_LOGIN: &str = "https://app.59wanmei.com/campus/cam_iface46/checkBeforeSendRegisterCode.action";
const URL_REQUEST_SEND_CODE: &str = "https://app.59wanmei.com/campus/cam_iface46/gainMatrixCaptcha543.action";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginError {
    /// 服务器错误
    ServerError(StatusCode),
    /// 未注册手机号
    RequestFailed(String),

}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LoginError::ServerError(_) => {
                write!(f, "Server error")
            }
            LoginError::RequestFailed(ref s) => {
                write!(f, "Request failed: {}", s)
            }
        }
    }
}
#[cfg(any(feature = "std", test))]
impl error::Error for LoginError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LoginError::ServerError(_) => None,
            LoginError::RequestFailed(_) => None,
        }
    }
}

impl SessionInfo {
    /// 检查手机号状态（是否注册）
    pub async fn check_phone_state(&self, phone: &str) -> Result<(), LoginError> {
        let params = json!({
            "action": "registAndLogin",
            "confirm": false,
            "deviceId": self.device_id,
            "mobile": phone,
            "requestMethod": "cam_iface46/gainMatrixCaptcha543.action",
            "type": "sms"
        });
        let response_text = self.request(URL_CHECK_BEFORE_LOGIN, &params).await.unwrap();
        let response: Value = serde_json::from_str(&response_text).unwrap();
        let code = match response["code_"].as_i64() {
            Some(result) => result,
            None => match response["code_"].as_str() {
                Some(result) => result.parse::<i64>().unwrap(),
                None => {
                    return Err(LoginError::RequestFailed("无法解析返回值".to_string()));
                }
            }
        };
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(LoginError::RequestFailed(
                msg.to_string()
            ));
        }
        return Ok(());
    }

    /// 请求发送验证码
    pub async fn request_send_code(&self, phone: &str) -> Result<(), LoginError> {
        let params = json!({
            "action": "registAndLogin",
            "confirm": false,
            "deviceId": self.device_id,
            "mobile": phone,
            "requestMethod": "cam_iface46/gainMatrixCaptcha543.action",
            "type": "sms"
        });
        let response_text = self.request(URL_REQUEST_SEND_CODE, &params).await.unwrap();
        let response: Value = serde_json::from_str(&response_text).unwrap();
        let code = match response["code_"].as_i64() {
            Some(result) => result,
            None => match response["code_"].as_str() {
                Some(result) => result.parse::<i64>().unwrap(),
                None => {
                    return Err(LoginError::RequestFailed("无法解析返回值".to_string()));
                }
            }
        };
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(LoginError::RequestFailed(
                msg.to_string()
            ));
        }
        return Ok(());
    }
}


/*
/// 登录完美校园
pub async fn login_campus(
    phone: &str,
    password: &str,
    device_id: &str,
    device_brand: &str,
    device_name: &str,
    device_ver: &str,
) -> Result<(), LoginError> {
    let server_secret = match create_key_pair(1024) {
        Some((pub_key, pri_key)) => exchange_secret(pub_key, pri_key).await,
        None => return Err(LoginError::GetAppKeyFailed)
    };
    let (session_id, app_key) = match server_secret {
        None => return Err(LoginError::GetAppKeyFailed),
        Some(result) => result
    };

    info!("交换公钥成功, session_id: {}, app_key: {}", session_id, app_key);

    let mut password_list = Vec::<String>::new();
    let des_key = &app_key.as_bytes()[..24];
    let mut data = [0u8; 1];

    for c in password.as_bytes() {
        data[0] = *c;
        let result = des_encrypt(&data, des_key);
        let base64 = base64::prelude::BASE64_STANDARD.encode(&result);
        password_list.push(base64);
    }

    let params = json!({
        "appCode": "M002",
        "deviceId": device_id,
        "netWork": "wifi",
        "password": password_list,
        "qudao": "guanwang",
        "requestMethod": "cam_iface46/loginnew.action",
        "shebeixinghao": device_brand,
        "systemType": "android",
        "telephoneInfo": device_ver,
        "telephoneModel": device_name,
        "type": "1",
        "userName": phone,
        "wanxiaoVersion": 10462101,
        "yunyingshang": "07"
    }).to_string();
    let encrypted_data = des_encrypt(params.as_bytes(), des_key);
    let args = json!({
        "session": session_id,
        "data": base64::prelude::BASE64_STANDARD.encode(&encrypted_data)
    });

    let client = reqwest::Client::new();
    let resp = match client
        .post(URL_LOGIN)
        .header("User-Agent", USER_AGENT)
        .header("campusSign", sha256::digest(args.to_string()))
        .json(&args).send().await {
        Ok(result) => result,
        Err(e) => {
            error!("登录请求发起失败: {}", e);
            return Err(LoginError::DesError);
        }
    };

    if resp.status().as_u16() != 200 {
        error!("登录请求失败: {}", resp.status());
        return Err(LoginError::ServerError(resp.status()));
    }
    let response_text = match resp.text().await {
        Ok(result) => result,
        Err(e) => {
            error!("登录请求接收失败: {}", e);
            return Err(LoginError::DesError);
        }
    };

    println!("{}", response_text);

    let response: Value = serde_json::from_str(&response_text).unwrap();

    let code = response["code_"].as_str().unwrap();

    Ok(())
}*/