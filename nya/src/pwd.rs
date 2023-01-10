use std::{collections::HashMap, env, fs, os::unix::prelude::PermissionsExt, time::Duration};

use debug::debug;
use libc::{getgid, getpid, getppid, getuid, gid_t, uid_t};
use libnss::{group::Group, passwd::Passwd, shadow::Shadow};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
pub enum PasswdResponse {
    Success(Passwd),
    Retry,
    NotFound,
}
pub enum PasswdVectorResponse {
    Success(Vec<Passwd>),
    Retry,
    NotFound,
}
pub enum GroupResponse {
    Success(Group),
    Retry,
    NotFound,
}
pub enum GroupVectorResponse {
    Success(Vec<Group>),
    Retry,
    NotFound,
}

pub enum ShadowResponse {
    Success(Shadow),
    Retry,
    NotFound,
}
pub enum ShadowVectorResponse {
    Success(Vec<Shadow>),
    Retry,
    NotFound,
}
pub enum NetworkReqResponse {
    Success(Value),
    NotFound,
    Error(String),
    TimeOut,
}

lazy_static! {
    static ref HTTP_API_ENDPOINT: Option<String> = {
        match env::var("NSS_HTTP_API_ENDPOINT") {
            Ok(val) => Some(val),
            Err(_) => None,
        }
    };
    static ref NSS_HTTP_API_DEBUG: bool = {
        env::var("NSS_HTTP_API_DEBUG")
            .unwrap_or(false.to_string())
            .parse::<bool>()
            .unwrap()
    };
    static ref NSS_HTTP_API_REQUEST_TIMEOUT: u64 = {
        env::var("NSS_HTTP_API_REQUEST_TIMEOUT")
            .unwrap_or(30.to_string())
            .parse::<u64>()
            .unwrap()
    };
}

pub fn getpwent() -> PasswdVectorResponse {
    let passwd = match request_entry(
        "passwd".to_string(),
        Option::None,
        Option::None,
        "getpwent".to_string(),
    ) {
        NetworkReqResponse::Success(passwd) => serde_json::from_value(passwd).unwrap(),
        NetworkReqResponse::NotFound => return PasswdVectorResponse::NotFound,
        NetworkReqResponse::TimeOut => return PasswdVectorResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getpwent() got error => {}", err);
            return PasswdVectorResponse::NotFound;
        }
    };
    PasswdVectorResponse::Success(passwd)
}

pub fn getpwuid(uid: uid_t) -> PasswdResponse {
    let passwd = match request_entry(
        "passwd".to_string(),
        Some(String::from("uid")),
        Some(uid.to_string()),
        "getpwuid".to_string(),
    ) {
        NetworkReqResponse::Success(passwd) => serde_json::from_value(passwd).unwrap(),
        NetworkReqResponse::NotFound => return PasswdResponse::NotFound,
        NetworkReqResponse::TimeOut => return PasswdResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getpwuid({}) got error => {}", uid, err);
            return PasswdResponse::NotFound;
        }
    };
    return PasswdResponse::Success(passwd);
}

pub fn getpwnam(name: String) -> PasswdResponse {
    let passwd = match request_entry(
        "passwd".to_string(),
        Some(String::from("name")),
        Some(name.clone()),
        "getpwnam".to_string(),
    ) {
        NetworkReqResponse::Success(passwd) => serde_json::from_value(passwd).unwrap(),
        NetworkReqResponse::NotFound => return PasswdResponse::NotFound,
        NetworkReqResponse::TimeOut => return PasswdResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getpwnam({}) got error => {}", name, err);
            return PasswdResponse::NotFound;
        }
    };
    return PasswdResponse::Success(passwd);
}

pub fn getgrent() -> GroupVectorResponse {
    let group = match request_entry(
        "group".to_string(),
        Option::None,
        Option::None,
        "getgrent".to_string(),
    ) {
        NetworkReqResponse::Success(group) => serde_json::from_value(group).unwrap(),
        NetworkReqResponse::NotFound => return GroupVectorResponse::NotFound,
        NetworkReqResponse::TimeOut => return GroupVectorResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getgrent() got error => {}", err);
            return GroupVectorResponse::NotFound;
        }
    };
    GroupVectorResponse::Success(group)
}

pub fn getgrgid(gid: gid_t) -> GroupResponse {
    let group = match request_entry(
        "group".to_string(),
        Some(String::from("gid")),
        Some(gid.to_string()),
        "getgrgid".to_string(),
    ) {
        NetworkReqResponse::Success(group) => serde_json::from_value(group).unwrap(),
        NetworkReqResponse::NotFound => return GroupResponse::NotFound,
        NetworkReqResponse::TimeOut => return GroupResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getgrgid({}) got error => {}", gid, err);
            return GroupResponse::NotFound;
        }
    };
    GroupResponse::Success(group)
}

pub fn getgrnam(name: String) -> GroupResponse {
    let group = match request_entry(
        "group".to_string(),
        Some(String::from("name")),
        Some(name.clone()),
        "getgrnam".to_string(),
    ) {
        NetworkReqResponse::Success(group) => serde_json::from_value(group).unwrap(),
        NetworkReqResponse::NotFound => return GroupResponse::NotFound,
        NetworkReqResponse::TimeOut => return GroupResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getgrnam({}) got error => {}", name, err);
            return GroupResponse::NotFound;
        }
    };
    GroupResponse::Success(group)
}
pub fn check_suid_bit() -> bool {
    match fs::read_link("/proc/self/exe") {
        Ok(path) => {
            debug!(
                "check_suid_bit() real executable file path => {}",
                path.display()
            );
            let metadata = match fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    debug!("check_suid_bit() got metadata error => {}", err);
                    return false;
                }
            };
            let permissions = metadata.permissions().mode();
            let suid_bit = permissions & 0o4000 != 0;
            debug!(
                "check_suid_bit() permissions => {:o}, {}",
                permissions,
                if suid_bit {
                    "suid bit is set"
                } else {
                    "suid bit is not set"
                }
            );
            suid_bit
        }
        Err(err) => {
            debug!("check_suid_bit() got readlink error => {}", err);
            false
        }
    }
}
pub fn getspent() -> ShadowVectorResponse {
    if !check_suid_bit() {
        return ShadowVectorResponse::NotFound;
    }
    let shadow = match request_entry(
        "shadow".to_string(),
        Option::None,
        Option::None,
        "getspent".to_string(),
    ) {
        NetworkReqResponse::Success(shadow) => serde_json::from_value(shadow).unwrap(),
        NetworkReqResponse::NotFound => return ShadowVectorResponse::NotFound,
        NetworkReqResponse::TimeOut => return ShadowVectorResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getspent() got error => {}", err);
            return ShadowVectorResponse::NotFound;
        }
    };
    ShadowVectorResponse::Success(shadow)
}

pub fn getspnam(name: String) -> ShadowResponse {
    if !check_suid_bit() {
        return ShadowResponse::NotFound;
    }
    let shadow = match request_entry(
        "shadow".to_string(),
        Some(String::from("name")),
        Some(name.clone()),
        "getspnam".to_string(),
    ) {
        NetworkReqResponse::Success(shadow) => serde_json::from_value(shadow).unwrap(),
        NetworkReqResponse::NotFound => return ShadowResponse::NotFound,
        NetworkReqResponse::TimeOut => return ShadowResponse::Retry,
        NetworkReqResponse::Error(err) => {
            debug!("getspnam({}) got error => {}", name, err);
            return ShadowResponse::NotFound;
        }
    };
    ShadowResponse::Success(shadow)
}

fn request_entry(
    file: String,
    key: Option<String>,
    value: Option<String>,
    fn_name: String,
) -> NetworkReqResponse {
    let api_url = match &*HTTP_API_ENDPOINT {
        Some(api_url) => api_url,
        None => {
            debug!(
                "{}({}) got error => {}",
                fn_name,
                value.unwrap_or(String::from("")),
                "environment variable NSS_HTTP_API_ENDPOINT is not set"
            );
            return NetworkReqResponse::NotFound;
        }
    };
    let info = unsafe {
        let mut map = HashMap::new();
        map.insert("uid", getuid().to_string());
        map.insert("gid", getgid().to_string());
        map.insert("pid", getpid().to_string());
        map.insert("ppid", getppid().to_string());
        map
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(*NSS_HTTP_API_REQUEST_TIMEOUT))
        .default_headers({
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-UID",
                HeaderValue::from_str(&info["uid"]).expect("failed to set X-UID header"),
            );
            headers.insert(
                "X-GID",
                HeaderValue::from_str(&info["gid"]).expect("failed to set X-GID header"),
            );
            headers.insert(
                "X-PID",
                HeaderValue::from_str(&info["pid"]).expect("failed to set X-PID header"),
            );
            headers.insert(
                "X-PPID",
                HeaderValue::from_str(&info["ppid"]).expect("failed to set X-PPID header"),
            );
            debug!("request headers => {:?}", headers);
            headers
        })
        .build()
        .unwrap();
    let value = match value {
        Some(value) => value,
        None => "".to_string(),
    };
    let url = match key {
        Some(key) => format!("{}/{}?{}={}", api_url, file, key, value),
        None => format!("{}/{}", api_url, file),
    };
    debug!("requesting url => {}", url);
    let response = match client.get(&url).send() {
        Ok(client) => client,
        Err(err) => {
            if err.is_timeout() {
                debug!("{}({}) got timeout error => {:?}", fn_name, value, err);
                return NetworkReqResponse::TimeOut;
            }
            debug!("{}({}) got request error => {:?}", fn_name, value, err);
            return NetworkReqResponse::Error(err.to_string());
        }
    };
    if response.status() == 404 {
        debug!("{}({}) got 404", fn_name, value);
        return NetworkReqResponse::NotFound;
    }
    match response.json::<Value>() {
        Ok(passwd) => {
            debug!(
                "{}({}) got json => {:?}",
                fn_name,
                value,
                passwd.to_string()
            );
            return NetworkReqResponse::Success(passwd);
        }
        Err(err) => {
            debug!("{}({}) got json parse error => {:?}", fn_name, value, err);
            return NetworkReqResponse::Error(err.to_string());
        }
    };
}
