extern crate core;

mod login;
mod cryptor;
mod request;
mod wanxiao;

use env_logger::Env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::default().filter_or("MY_LOG_LEVEL", "info");
    env_logger::init_from_env(env);

    let device_id = "00000000-6dea-68c9-0000-000000000000";
    let mut session = wanxiao::new_session(
        device_id
    ).await.unwrap();
    let phone = "110";
    if let Ok(()) = session.check_phone_state(phone).await {
        if let Err(e) = session.request_send_code(phone).await {
            println!("发送验证码失败: {}", e);
        }
    }

    Ok(())
}
