use std::{env, time::Duration};

use debug::debug;
use libc::{gid_t, uid_t};
use libnss::{group::Group, passwd::Passwd, shadow::Shadow};
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
    TimeOut
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

pub fn getspent() -> ShadowVectorResponse {
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
            debug!("{}({}) got error => {}", fn_name, value.unwrap_or(String::from("")), "environment variable NSS_HTTP_API_ENDPOINT is not set");
            return NetworkReqResponse::NotFound
        }
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(*NSS_HTTP_API_REQUEST_TIMEOUT))
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
