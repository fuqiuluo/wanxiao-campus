use log::error;
use crate::wanxiao::SessionInfo;

const USER_AGENT: &str = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; HUAWEI MLA-AL10 Build/HUAWEIMLA-AL10)";

impl SessionInfo {
    /// 加密的请求
    pub async fn request(&self, url: &str, json: &serde_json::Value) -> Option<String> {
        let (sign, data) = self.generate_encrypted_data(json.to_string().as_bytes());
        return request_no_encrypt(url, &data, Some(sign)).await;
    }
}

/// 不采用加密的请求
pub async fn request_no_encrypt(
    url: &str,
    json: &serde_json::Value,
    sign: Option<String>
) -> Option<String> {
    let client = reqwest::Client::new();
    let mut builder = client.post(url);
    if let Some(sign) = sign {
        builder = builder.header("campusSign", sign);
    }
    let resp = match builder
        .header("User-Agent", USER_AGENT)
        .json(json)
        .send().await {
        Ok(result) => result,
        Err(e) => {
            error!("network request failed: {}", e);
            return None;
        }
    };
    let response_text = match resp.text().await {
        Ok(result) => result,
        Err(e) => {
            error!("network failed to receive: {}", e);
            return None;
        }
    };
    return Some(response_text);
}