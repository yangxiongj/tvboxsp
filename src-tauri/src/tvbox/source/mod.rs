use std::sync::Arc;

use anyhow::Result;
use indicatif::ProgressBar;
pub mod ijk;
pub mod live;
pub mod parse;
pub mod rule;
pub mod vod;
use ijk::Ijk;
use live::Live;
use parse::Parse;
use rule::Rule;
use vod::Vod;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::seq::SliceRandom;
type AesCbc = Cbc<Aes256, Pkcs7>;
use hex::{decode, encode};
use base64::{Engine as _};
use aes::Aes128;

use std::error::Error;
use std::ops::Deref;
use regex::Regex;

/// 视频源结构
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Source {
    pub sites: Vec<Vod>,
    pub lives: Vec<Live>,
    /// 解析地址
    pub parses: Option<Vec<Parse>>,
    /// 需要使用vip解析的flag
    pub flags: Option<Vec<String>>,
    pub ijk: Option<Vec<Ijk>>,
    pub rules: Option<Vec<Rule>>,
    pub ads: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallpaper: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spider: Option<String>,
    #[serde(rename = "warningText")]
    pub warning_text: Option<String>,
}

impl Source {

    pub fn base(&mut self, base: &str) -> Result<()> {
        self.sites.iter_mut().for_each(|item| item.base(base));
        self.lives.iter_mut().for_each(|item| item.base(base));
        if let Some(spider) = self.spider.as_mut() {
            let mut s = spider.split(";").collect::<Vec<_>>();
            let p = s.first_mut().unwrap();
            let n = base_url(base, p);
            *p = n.as_str();
            *spider = s.join(";");
        }
        Ok(())
    }

    pub fn parse(i: &str, illegal_comment: char) -> Result<Self> {
        let mut i = String::from(i);
        // 假設 i 是可變的，例如：let mut i = ...;
        if i.starts_with("2423") {
            match Source::decrypt_aes_bcb(&i) { // 傳遞引用以避免所有權移動
                Ok(decrypted) => {
                    println!("Decrypted text: {}", decrypted);
                    i = decrypted; // 將解密後的值賦給外部的 i
                }
                Err(e) => eprintln!("Failed to decrypt: {}", e),
            }
        }
        // 过滤[#]
        let r = regex::Regex::new(&format!("^{}.*", illegal_comment))?;
        let i = r.replace_all(&i, "").to_string();
        let r = regex::Regex::new(&format!("\n{}.*", illegal_comment)).unwrap();
        let i = r.replace_all(&i, "").to_string();

        let doc = json5::from_str::<Self>(&i);
        if doc.is_ok() {
            // debug!("json5 解析成功!");
            return Ok(doc.unwrap());
        }
        // 匹配行首或行内注释，并删除换行符
        let r = regex::Regex::new(r"(?m)^//.*|[\r\n]+|\s+//.").unwrap();
        let i = r.replace_all(&i, "").to_string();
        let doc = serde_json::from_str::<Self>(&i).map_err(|e| {
            println!("json5.parse.error: {:?}", e);
            println!("数据: {:?}", i);
            anyhow!("解析失败, 不是有效的 json/json5 文件.")
        })?;
        // debug!("json 解析成功!");
        Ok(doc)
    }
    

    /// 解密函数：对应 JS 中的 decryptAesBCB
    pub fn decrypt_aes_bcb(encrypted_data: &str) -> Result<String, Box<dyn Error>> {
        // 1. 拆分字符数组
        let mut data_arr: Vec<char> = encrypted_data.trim().chars().collect();

        // 2. 计算前后缀的 hex 编码
        let prefix_code = encode("$#");  // JS: Buffer.from("$#", "utf-8").toString("hex")
        let suffix_code = encode("#$");  // JS: Buffer.from("#$", "utf-8").toString("hex")

        // 3. 找到 suffix_code 在原串中的索引，截取 pwdMix
        let suffix_pos = encrypted_data
            .find(&suffix_code)
            .ok_or("无法找到后缀代码")?;
        // JS 中 +4 是因为 suffix_code 16 进制长度固定为 4 字符
        let pwd_mix: String = data_arr.drain(..=suffix_pos + 3).collect();

        // 4. 从尾部取出 26 个字符作为 roundtimeInHax
        let round_hex: String = data_arr.drain(data_arr.len().saturating_sub(26)..).collect();

        // 5. 剩余部分即为真正的加密文本
        let encrypted_hex: String = data_arr.iter().collect();

        // 6. 从 pwdMix 中提取 pwdInHax，并 hex 解码为密码
        let pwd_hex = &pwd_mix[prefix_code.len()..pwd_mix.len() - suffix_code.len()];
        let pwd_bytes = decode(pwd_hex)?;
        let pwd = String::from_utf8(pwd_bytes)?;

        // 7. 还原 IV：hex 解码后 utf-8，再右侧 pad 到 16 字节
        let round_bytes = decode(&round_hex)?;
        let mut iv = String::from_utf8(round_bytes)?;
        iv.extend(std::iter::repeat('0').take(16 - iv.len()));
        let iv_bytes = iv.as_bytes();

        // 8. 构造密钥：右侧 pad 密码到 16 字节
        let mut key = pwd.clone();
        key.extend(std::iter::repeat('0').take(16 - key.len()));
        let key_bytes = key.as_bytes();

        type Aes128Cbc = Cbc<Aes128, Pkcs7>;

        // 9. AES-128-CBC 解密
        let cipher = Aes128Cbc::new_from_slices(key_bytes, iv_bytes)?;
        let ciphertext = decode(encrypted_hex)?;
        let decrypted_bytes = cipher.decrypt_vec(&ciphertext)?;

        // 10. 转成 UTF-8 字符串返回
        let decrypted = String::from_utf8(decrypted_bytes)?;
        Ok(decrypted)
    }

}

///
/// let pb = progress_bar(self.sites.len() as u64);+
/// pb.inc(1);
/// pb.finish();
///
pub fn progress_bar(count: u64) -> Arc<ProgressBar> {
    let len = format!("{}", count).len();
    let template = format!(
        "[{{elapsed_precise}}] {{wide_bar:.white/white}} {{pos:>{}}}/{{len:{}}}",
        len, len
    );
    let pb = ProgressBar::new(count as u64);
    let style = indicatif::ProgressStyle::with_template(&template)
        .unwrap()
        .progress_chars("█░");
    pb.enable_steady_tick(std::time::Duration::from_secs(1));
    pb.set_style(style);
    Arc::new(pb)
}

fn base_url(base: &str, path: &str) -> String {
    if path.starts_with(".") || path.starts_with("/") {
        if let Ok(base) = url::Url::parse(base) {
            return base
                .join(path)
                .and_then(|new| Ok(new.to_string()))
                .unwrap_or(path.to_string());
        }
    }
    path.to_string()
}

#[tokio::test]
async fn test_d() {
    let _i = "https://毒盒.com/tv";
    let i = "http://我不是.摸鱼儿.top";
    let content = crate::utils::read_content(_i).await;
    assert!(content.is_ok());
    let content = content.unwrap();
    let src = Source::parse(&content, '#');
    println!("{:?}", src);
    assert!(src.is_ok());
    let src = src.unwrap();
    println!("live: {}", src.lives.len());
    println!("sites: {}", src.sites.len());
    println!("spider: {:?}", src.spider);
    println!("parses: {}", src.parses.is_some());
    println!("ads: {:?}", src.ads.and_then(|s| Some(s.len())));
    println!("flags: {:?}", src.flags.and_then(|s| Some(s.len())));
    println!("rules: {:?}", src.rules.and_then(|r| Some(r.len())));
    println!("wallpaper: {:?}", src.wallpaper);
    println!("warning_text: {:?}", src.warning_text);
    src.sites.iter().for_each(|i| {
        if i.key == "csp_xBPQ_奇优" {
            println!("{:?}", i)
        }
    });
    assert_eq!(1, 1)
}
