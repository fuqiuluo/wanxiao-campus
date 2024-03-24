use core::fmt;
use base64::Engine;
use log::{error, info, warn};
use reqwest::{Response, StatusCode};
use serde_json::{json, Value};
use crate::cryptor::{des_decrypt, des_encrypt};
use crate::wanxiao::SessionInfo;

const URL_LOGIN: &str = "https://app.59wanmei.com/campus/cam_iface46/loginnew.action";
const URL_CHECK_BEFORE_LOGIN: &str = "https://app.59wanmei.com/campus/cam_iface46/checkBeforeSendRegisterCode.action";
const URL_REQUEST_SEND_CODE: &str = "https://app.59wanmei.com/campus/cam_iface46/gainMatrixCaptcha543.action";
const URL_SUBMIT_CODE: &str = "https://app.59wanmei.com/campus/cam_iface46/registerUsersByTelAndLoginNew.action";

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

macro_rules! parse_code {
    ($expression:expr) => {
        match $expression.as_i64() {
            Some(result) => result,
            None => match $expression.as_str() {
                Some(result) => result.parse::<i64>().unwrap(),
                None => {
                    return Err(LoginError::RequestFailed("无法解析返回值".to_string()));
                }
            }
        }
    };
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
        let code = parse_code!(response["code_"]);
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
        let code = parse_code!(response["code_"]);
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(LoginError::RequestFailed(
                msg.to_string()
            ));
        }
        return Ok(());
    }

    /// 提交验证码
    pub async fn login_with_sms(&mut self, phone: &str, code: &str) -> Result<(), LoginError> {
        let params = json!({
            "appCode": "M002",
            "deviceId": self.device_id,
            "mobile": phone,
            "netWork": "wifi",
            "qudao": "tencent",
            "requestMethod": "cam_iface46/registerUsersByTelAndLoginNew.action",
            "shebeixinghao": "LGE-AN10",
            "sms": code,
            "systemType": "android",
            "telephoneInfo": "12",
            "telephoneModel": "LGE-AN10",
            "wanxiaoVersion": 10552101
        });
        let response_text = self.request(URL_SUBMIT_CODE, &params).await.unwrap();
        let response: Value = serde_json::from_str(&response_text).unwrap();
        let code = parse_code!(response["code_"]);
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(LoginError::RequestFailed(msg.to_string()));
        }
        let data = response["data"].as_str().unwrap();
        let data = base64::prelude::BASE64_STANDARD.decode(data.as_bytes()).unwrap();
        let des_key = &self.app_key.as_bytes()[..24];
        let data = des_decrypt(data.as_slice(), des_key);

        let user_info: Value = serde_json::from_slice(data.as_slice()).unwrap();
        let user_info = user_info["user"].as_object().unwrap();

        let mobile_sm3 = user_info["mobileSm3"].as_str().unwrap();
        let mobile_sm4 = user_info["mobileSm4"].as_str().unwrap();
        //let stu_no = user_info["authStuNo"].as_str().unwrap();
        let ecard_id = user_info["ecardCustomerid"].as_str().unwrap();
        let sm3 = user_info["sm3"].as_str().unwrap();
        let id = user_info["id"].as_i64().unwrap();
        let token = user_info["token"].as_str().unwrap();
        let customer_id = user_info["customId"].as_i64().unwrap();

        self.token = token[..36].to_string();
        self.ecard_customer_id = ecard_id.to_string();
        self.customer_id = customer_id.to_string();

        info!("登录成功：sm3={}", mobile_sm3);

        return Ok(());
    }

    /// 发起密码登录请求
    ///
    /// 该方法会自动处理密码加密
    pub async fn login_with_pwd(&mut self, phone: &str, pwd: &str) -> Result<(), LoginError> {
        let mut password_list = Vec::<String>::new();
        let des_key = &self.app_key.as_bytes()[..24];
        let mut data = [0u8; 1];
        for c in pwd.as_bytes() {
            data[0] = *c;
            let result = des_encrypt(&data, des_key);
            let base64 = base64::prelude::BASE64_STANDARD.encode(&result);
            password_list.push(base64);
        }

        let params = json!({
            "appCode": "M002",
            "deviceId": self.device_id,
            "netWork": "wifi",
            "password": password_list,
            "qudao": "tencent",
            "requestMethod": "cam_iface46/loginnew.action",
            "shebeixinghao": "LGE-AN10",
            "systemType": "android",
            "telephoneInfo": "12",
            "telephoneModel": "LGE-AN10",
            "type": "1",
            "userName": phone,
            "wanxiaoVersion": 10552101,
            "yunyingshang": "07"
        });
        let response_text = self.request(URL_LOGIN, &params).await.unwrap();
        let response: Value = serde_json::from_str(&response_text).unwrap();
        let code = parse_code!(response["code_"]);
        let msg = response["message_"].as_str().unwrap();
        if code != 0 {
            return Err(LoginError::RequestFailed(msg.to_string()));
        }
        let data = response["data"].as_str().unwrap();
        let data = base64::prelude::BASE64_STANDARD.decode(data.as_bytes()).unwrap();
        let data = des_decrypt(data.as_slice(), des_key);

        let mut data = String::from_utf8(data).unwrap();
        data = data.replace("\x0d", "");

        let user_info: Value = serde_json::from_slice(data.as_bytes()).unwrap();
        let user_info = user_info["user"].as_object().unwrap();

        let token = user_info["token"].as_str().unwrap();
        let ecard_id = user_info["ecardCustomerid"].as_str().unwrap();

        self.token = token[..36].to_string();
        self.ecard_customer_id = ecard_id.to_string();

        info!("登录成功：session={}", self.session_id);

        return Ok(());
    }
}