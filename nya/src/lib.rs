extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

mod pwd;

use libnss::group::{Group, GroupHooks};
// use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::initgroups::InitgroupsHooks;
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::shadow::{Shadow, ShadowHooks};
use pwd::*;
// use debug::debug;

struct HardcodedPasswd;
libnss_passwd_hooks!(nya, HardcodedPasswd);

// Creates an account with username "test", and password "pass"
// Ensure the home directory "/home/test" exists, and is owned by 1007:1007
impl PasswdHooks for HardcodedPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        match pwd::getpwent() {
            PasswdVectorResponse::Success(passwd) => {
                return Response::Success(passwd);
            }
            PasswdVectorResponse::NotFound => {
                return Response::NotFound;
            }
            PasswdVectorResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        match pwd::getpwuid(uid) {
            PasswdResponse::Success(passwd) => {
                return Response::Success(passwd);
            }
            PasswdResponse::NotFound => {
                return Response::NotFound;
            }
            PasswdResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        match pwd::getpwnam(name) {
            PasswdResponse::Success(passwd) => {
                return Response::Success(passwd);
            }
            PasswdResponse::NotFound => {
                return Response::NotFound;
            }
            PasswdResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }
}

struct HardcodedGroup;
libnss_group_hooks!(nya, HardcodedGroup);

impl GroupHooks for HardcodedGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        match pwd::getgrent() {
            GroupVectorResponse::Success(group) => {
                return Response::Success(group);
            }
            GroupVectorResponse::NotFound => {
                return Response::NotFound;
            }
            GroupVectorResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        match pwd::getgrgid(gid) {
            GroupResponse::Success(group) => {
                return Response::Success(group);
            }
            GroupResponse::NotFound => {
                return Response::NotFound;
            }
            GroupResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        match pwd::getgrnam(name) {
            GroupResponse::Success(group) => {
                return Response::Success(group);
            }
            GroupResponse::NotFound => {
                return Response::NotFound;
            }
            GroupResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }
}

struct HardcodedShadow;
libnss_shadow_hooks!(nya, HardcodedShadow);

impl ShadowHooks for HardcodedShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        match pwd::getspent() {
            ShadowVectorResponse::Success(shadow) => {
                return Response::Success(shadow);
            }
            ShadowVectorResponse::NotFound => {
                return Response::NotFound;
            }
            ShadowVectorResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }

    fn get_entry_by_name(name: String) -> Response<Shadow> {
        match pwd::getspnam(name) {
            ShadowResponse::Success(shadow) => {
                return Response::Success(shadow);
            }
            ShadowResponse::NotFound => {
                return Response::NotFound;
            }
            ShadowResponse::Retry => {
                return Response::TryAgain;
            }
        }
    }
}

// use std::net::{IpAddr, Ipv4Addr};

// struct HardcodedHost;
// libnss_host_hooks!(nya, HardcodedHost);

// impl HostHooks for HardcodedHost {
//     fn get_all_entries() -> Response<Vec<Host>> {
//         Response::Success(vec![Host {
//             name: "test.example".to_string(),
//             addresses: Addresses::V4(vec![Ipv4Addr::new(177, 42, 42, 42)]),
//             aliases: vec!["other.example".to_string()],
//         }])
//     }

//     fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
//         match addr {
//             IpAddr::V4(addr) => {
//                 if addr.octets() == [177, 42, 42, 42] {
//                     Response::Success(Host {
//                         name: "test.example".to_string(),
//                         addresses: Addresses::V4(vec![Ipv4Addr::new(177, 42, 42, 42)]),
//                         aliases: vec!["other.example".to_string()],
//                     })
//                 } else {
//                     Response::NotFound
//                 }
//             }
//             _ => Response::NotFound,
//         }
//     }

//     fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
//         if name.ends_with(".example") && family == AddressFamily::IPv4 {
//             Response::Success(Host {
//                 name: name.to_string(),
//                 addresses: Addresses::V4(vec![Ipv4Addr::new(177, 42, 42, 42)]),
//                 aliases: vec!["test.example".to_string(), "other.example".to_string()],
//             })
//         } else {
//             Response::NotFound
//         }
//     }
// }

struct HardcodedInitgroups;
libnss_initgroups_hooks!(nya, HardcodedInitgroups);

impl InitgroupsHooks for HardcodedInitgroups {
    fn get_entries_by_user(user: String) -> Response<Vec<Group>> {
        let _ = user;
        // Response::Success(vec![Group {
        //     name: "initgroup1".to_string(),
        //     passwd: "".to_string(),
        //     gid: 3005,
        //     members: vec!["someone".to_string()],
        // }, Group {
        //     name: "initgroup2".to_string(),
        //     passwd: "".to_string(),
        //     gid: 3006,
        //     members: vec!["someone".to_string()],
        // }, Group {
        //     name: "initgroup3".to_string(),
        //     passwd: "".to_string(),
        //     gid: 3007,
        //     members: vec!["someone".to_string()],
        // }])
        Response::Success(vec![])
    }
}
