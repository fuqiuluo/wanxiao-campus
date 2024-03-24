# 完校接口

学习测试与交流使用。

## 声明

本项目仅供学习测试与交流使用，不得用于商业用途，如有侵权请联系删除。

## Example

```rust
mod login;
mod wanxiao;

let device_id = "00000000-6dea-68c9-0000-000000000000";
let mut session = wanxiao::new_session(
    device_id
).await.unwrap();

let phone = "18133267317";
if let Ok(()) = session.check_phone_state(phone).await {
    if let Err(e) = session.request_send_code(phone).await {
        println!("发送验证码失败: {}", e);
    }
}
```