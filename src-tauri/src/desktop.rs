// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command

use crate::{
    tvbox::{
        self,
        check::ConnectionStatus,
        source::{live::Live, parse::Parse, vod::Vod},
    },
    utils,
};
use tauri::{Result, Runtime, Window};

#[tauri::command]
pub async fn parse_playlist(
    uri: String,
    threads: Option<u16>,
    skip_ipv6: Option<bool>,
) -> Result<tvbox::playlist::PlaylistCheckResult> {
    let content = utils::read_content(&uri).await.map_err(|e| {
        println!("utils::read_content:{:?}", e);
        tauri::Error::AssetNotFound(e.to_string())
    })?;
    let source = tvbox::playlist::PlaylistSource {
        threads,
        skip_ipv6,
        content,
    };
    let res = source
        .check()
        .await
        .map_err(|e| tauri::Error::ApiNotAllowlisted(e.to_string()))?;
    Ok(res)
}


#[tauri::command]
pub async fn parse_tvbox(uri: String, base: Option<String>) -> Result<tvbox::source::Source> {
    async fn fetch_encoded(uri: &str) -> Result<String> {
        let encoded = urlencoding::encode(uri);
        let new_url = format!("https://ua.fongmi.eu.org/box.php?url={encoded}");
        utils::read_content(&new_url).await.map_err(|e| {
            println!("[ERROR] 转码失败: {e:?}");
            tauri::Error::AssetNotFound(e.to_string())
        })
    }

    async fn get_source(uri: &str) -> Result<tvbox::source::Source> {
        let content = fetch_encoded(uri).await?;
        tvbox::source::Source::parse(&content, '#').map_err(|e| {
            println!("解析失败: {e:?}");
            tauri::Error::ApiNotAllowlisted(e.to_string())
        })
    }

    // 第一阶段：尝试原始请求和解析
    let mut source = match utils::read_content(&uri).await {
        Ok(c) if !c.is_empty() => match tvbox::source::Source::parse(&c, '#') {
            Ok(s) => s,
            Err(e) => {
                println!("[WARN] 原始内容解析失败: {e:?}，触发转码");
                get_source(&uri).await?
            }
        },
        Ok(_) => {
            println!("[WARN] 内容为空，触发转码");
            get_source(&uri).await?
        }
        Err(e) => {
            println!("[ERROR] 原始请求失败: {e:?}，触发转码");
            get_source(&uri).await?
        }
    };
    // 第二阶段：设置base路径
    let base_uri = if uri.starts_with("http://") || uri.starts_with("https://") {
        &uri
    } else {
        base.as_deref().unwrap_or_default()
    };
    source.base(base_uri).ok();

    Ok(source)
}

#[tauri::command]
pub async fn get_content(uri: String) -> String {
    utils::read_content(&uri).await.unwrap_or_default()
}

#[tauri::command]
pub async fn urls_accessibility<R: Runtime>(
    window: Window<R>,
    urls: Vec<String>,
    quick_mode: Option<bool>,
    skip_ipv6: Option<bool>,
    check_m3u8: Option<bool>,
) -> Vec<String> {
    tvbox::urls_accessibility(window, urls, quick_mode.unwrap_or_default(), skip_ipv6,check_m3u8).await
}

/// 执行
#[tauri::command]
pub async fn exec(args: String) -> String {
    inline_exec(args).await
}

#[tauri::command]
pub async fn vods_connectivity<R: Runtime>(
    window: Window<R>,
    items: Vec<Vod>,
    quick_mode: Option<bool>,
    skip_ipv6: Option<bool>,
) -> Vec<ConnectionStatus<Vod>>
where
{
    let items =
        tvbox::check::check_connections(window, items, quick_mode.unwrap_or_default(), skip_ipv6)
            .await;
    items
}
#[tauri::command]
pub async fn live_connectivity<R: Runtime>(
    window: Window<R>,
    items: Vec<Live>,
    quick_mode: Option<bool>,
    skip_ipv6: Option<bool>,
) -> Vec<ConnectionStatus<Live>>
where
{
    let items =
        tvbox::check::check_connections(window, items, quick_mode.unwrap_or_default(), skip_ipv6)
            .await;
    items
}

#[tauri::command]
pub async fn parses_connectivity<R: Runtime>(
    window: Window<R>,
    items: Vec<Parse>,
    quick_mode: Option<bool>,
    skip_ipv6: Option<bool>,
) -> Vec<ConnectionStatus<Parse>>
where
{
    let items =
        tvbox::check::check_connections(window, items, quick_mode.unwrap_or_default(), skip_ipv6)
            .await;
    items
}

#[tauri::command]
pub async fn save(path: String, content: String) -> bool {
    std::fs::write(path, content).is_ok()
}

#[tauri::command]
pub async fn cache(key: String, value: String) {
    crate::server::updata_cache(&key, value).await;
}

#[tauri::command]
pub async fn lan_ip() -> Option<Vec<String>> {
    crate::utils::lan_ip()
}

#[tauri::command]
pub async fn is_install(application: String) -> bool {
    crate::utils::is_installed(&application)
}

pub async fn inline_exec(args: String) -> String {
    if args.is_empty() {
        return args;
    }
    let (shell, first) = if cfg!(windows) {
        ("cmd", "/c")
    } else {
        ("sh", "-c")
    };
    println!("args: {}", args);
    let child = tokio::process::Command::new(shell)
        .args([first])
        .args(&[args])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    if let Ok(child) = child {
        let one_minute = std::time::Duration::from_secs(60);
        tokio::time::timeout(one_minute, child.wait_with_output())
            .await
            .ok()
            .and_then(|out| out.map_err(|e| println!("shell.error: {:?}", e)).ok())
            .and_then(|out| {
                println!("out: {:?}", out);
                String::from_utf8(out.stdout).ok()
            })
            .unwrap_or_default()
    } else {
        println!("shell.err2: {:?}", child);
        String::default()
    }
}

#[tauri::command]
pub async fn download(url: String, path: String) -> bool {
    if let Ok(resp) = reqwest::get(url).await {
        if let Ok(buff) = resp.bytes().await {
            return std::fs::write(path, buff).is_ok();
        }
    }
    false
}

#[tauri::command]
pub async fn hash(content: String) -> String {
    let value = xxhash_rust::xxh3::xxh3_64_with_seed(content.as_bytes(), 42);
    format!("{:0>16X}", value)
}


#[tokio::test]
async fn test_exec() {
    let args = r#"start  /d D:\"Program Files"\mpv mpv http://39.134.24.162/dbiptv.sn.chinamobile.com/PLTV/88888888/224/3221226395/1.m3u8"#;
    inline_exec(args.to_string()).await;
    assert_eq!(1, 1)
}
