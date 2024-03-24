use std::iter;
use std::time::Instant;
use base64::Engine;
use cbc::cipher::BlockEncryptMut;
use cbc::cipher::generic_array::GenericArray;
use des::cipher::KeyIvInit;
use des::TdesEde3;
use log::{error, info, warn};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::EncodePublicKey;

/// 创建密钥对
pub fn create_key_pair(size: usize) -> Option<(String, String)> {
    let start = Instant::now();
    let mut rng = rand::thread_rng();
    let priv_key = match RsaPrivateKey::new(&mut rng, size) {
        Ok(result) => result,
        Err(e) => {
            error!("无法合成密钥对: {}", e);
            return None;
        }
    };
    let pub_key = RsaPublicKey::from(&priv_key);
    let pub_key_str = base64::prelude::BASE64_STANDARD.encode(pub_key.to_public_key_der().unwrap());
    let pri_key_str = base64::prelude::BASE64_STANDARD.encode(priv_key.to_pkcs1_der().unwrap().as_bytes());
    let duration = start.elapsed();
    info!("密钥对合成成功, 耗时: {:?}", duration);
    return Some((pub_key_str, pri_key_str))
}


/// RSA解密
pub fn rsa_decrypt(input_text: String, private_key: &str) -> Option<Vec<u8>> {
    return match base64::prelude::BASE64_STANDARD.decode(input_text) {
        Ok(input_bytes) => {
            let pri_bytes = match base64::prelude::BASE64_STANDARD.decode(private_key) {
                Ok(result) => result,
                Err(e) => {
                    error!("无法解析私钥: {}", e);
                    return None;
                }
            };
            let pri_key = match RsaPrivateKey::from_pkcs1_der(pri_bytes.as_slice()) {
                Ok(result) => result,
                Err(e) => {
                    error!("无法解析私钥: {}", e);
                    return None;
                }
            };
            match pri_key.decrypt(Pkcs1v15Encrypt, input_bytes.as_slice()) {
                Ok(result) => Some(result),
                Err(e) => {
                    error!("RSA解密失败: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            error!("RSA解密输入数据异常: {}", e);
            None
        }
    }
}

/// DES加密
pub fn des_encrypt(input_text: &[u8], des_key: &[u8]) -> Vec<u8> {
    const IV: &[u8; 8] = b"66666666";
    let mut encryptor = cbc::Encryptor::<TdesEde3>::new_from_slices(des_key, IV)
        .unwrap();

    fn pkcs5_padding(text: &mut Vec<u8>, block_size: usize) {
        let padding_length = 8 - text.len() % block_size;
        if padding_length != 0 {
            let padding_byte = padding_length as u8;
            text.extend(iter::repeat(padding_byte).take(padding_length));
        }
    }

    let mut result = Vec::new();
    let mut text = input_text.to_vec();
    pkcs5_padding(&mut text, 8);

    if text.len() == 0 || text.len() % 8 != 0 {
        warn!("des failed! text length is not a multiple of 8! len: {}", text.len());
    }

    for chunk in text.chunks_exact(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        encryptor.encrypt_block_mut(&mut block);
        result.extend_from_slice(block.as_slice());
    }

    return result;
}