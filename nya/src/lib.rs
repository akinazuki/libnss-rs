extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use std::fs;

use libnss::group::{Group, GroupHooks};
use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::initgroups::InitgroupsHooks;
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::shadow::{Shadow, ShadowHooks};

struct HardcodedPasswd;
libnss_passwd_hooks!(nya, HardcodedPasswd);

// Creates an account with username "test", and password "pass"
// Ensure the home directory "/home/test" exists, and is owned by 1007:1007
impl PasswdHooks for HardcodedPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        println!(
            "passwd::get_all_entries() id: {},gid: {}",
            unsafe { libc::getuid() },
            unsafe { libc::getgid() }
        );
        Response::Success(vec![
            Passwd {
                name: "test".to_string(),
                passwd: "x".to_string(),
                uid: 1005,
                gid: 1005,
                gecos: "Test Account".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            },
            Passwd {
                name: "test2".to_string(),
                passwd: "x".to_string(),
                uid: 1006,
                gid: 1006,
                gecos: "Test Account".to_string(),
                dir: "/home/test2".to_string(),
                shell: "/bin/bash".to_string(),
            },
        ])
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        println!(
            "passwd::get_entry_by_uid({}) id: {},gid: {}",
            uid,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        );
        if uid == 1005 {
            return Response::Success(Passwd {
                name: "test".to_string(),
                passwd: "x".to_string(),
                uid: 1005,
                gid: 1005,
                gecos: "Test Account".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }
        if uid == 1006 {
            return Response::Success(Passwd {
                name: "test2".to_string(),
                passwd: "x".to_string(),
                uid: 1006,
                gid: 1006,
                gecos: "Test Account".to_string(),
                dir: "/home/test2".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }
        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        println!(
            "passwd::get_entry_by_name({}) id: {},gid: {}, pid: {}",
            name,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
            unsafe { libc::getpid() }
        );
        if name == "test" {
            return Response::Success(Passwd {
                name: "test".to_string(),
                passwd: "x".to_string(),
                uid: 1005,
                gid: 1005,
                gecos: "Test Account".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }
        if name == "test2" {
            return Response::Success(Passwd {
                name: "test2".to_string(),
                passwd: "x".to_string(),
                uid: 1006,
                gid: 1006,
                gecos: "Test Account".to_string(),
                dir: "/home/test2".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }

        Response::NotFound
    }
}

struct HardcodedGroup;
libnss_group_hooks!(nya, HardcodedGroup);

impl GroupHooks for HardcodedGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        println!(
            "group::get_all_entries() id: {},gid: {}",
            unsafe { libc::getuid() },
            unsafe { libc::getgid() }
        );
        Response::Success(vec![
            Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            },
            Group {
                name: "test2".to_string(),
                passwd: "".to_string(),
                gid: 1006,
                members: vec!["someone".to_string()],
            },
        ])
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        println!(
            "group::get_entry_by_gid({}) id: {},gid: {}",
            gid,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        );
        if gid == 1005 {
            return Response::Success(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            });
        }
        if gid == 1006 {
            return Response::Success(Group {
                name: "test2".to_string(),
                passwd: "".to_string(),
                gid: 1006,
                members: vec!["someone".to_string()],
            });
        }

        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        println!(
            "group::get_entry_by_name({}) id: {},gid: {}",
            name,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        );
        if name == "test" {
            return Response::Success(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            });
        }
        if name == "test2" {
            return Response::Success(Group {
                name: "test2".to_string(),
                passwd: "".to_string(),
                gid: 1006,
                members: vec!["someone".to_string()],
            });
        }

        Response::NotFound
    }
}

struct HardcodedShadow;
libnss_shadow_hooks!(nya, HardcodedShadow);

impl ShadowHooks for HardcodedShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        println!(
            "shadow::get_all_entries() id: {},gid: {}",
            unsafe { libc::getuid() },
            unsafe { libc::getgid() }
        );
        // TODO: Ensure we are a privileged user before returning results
        Response::Success(vec![
            Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9ZQ2wUM4fr9CluB.65MLVhLxhjv1jVluZphzY1J6EBtxEa5/n4IDqamJ5cvvek3CtXNYSm1".to_string(),
                last_change: 12345,
                change_min_days:0,
                change_max_days: 99999,
                change_warn_days: 0,
                change_inactive_days: -1,
                expire_date: 99999,
                reserved: 0,
            },
            Shadow {
                name: "test2".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9ZQ2wUM4fr9CluB.65MLVhLxhjv1jVluZphzY1J6EBtxEa5/n4IDqamJ5cvvek3CtXNYSm1".to_string(),
                last_change: 12345,
                change_min_days:0,
                change_max_days: 99999,
                change_warn_days: 0,
                change_inactive_days: -1,
                expire_date: 99999,
                reserved: 0,
            }
        ]
    )
    }

    fn get_entry_by_name(name: String) -> Response<Shadow> {
        // TODO: Ensure we are a privileged user before returning results
        println!(
            "shadow::get_entry_by_name({}) id: {},gid: {}",
            name,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        );
        if name == "test" {
            return Response::Success(Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9ZQ2wUM4fr9CluB.65MLVhLxhjv1jVluZphzY1J6EBtxEa5/n4IDqamJ5cvvek3CtXNYSm1".to_string(),
                last_change: 12345,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 0,
                change_inactive_days: -1,
                expire_date: 99999,
                reserved: 0,
            });
        }
        if name == "test2" {
            return Response::Success(Shadow {
                name: "test2".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9ZQ2wUM4fr9CluB.65MLVhLxhjv1jVluZphzY1J6EBtxEa5/n4IDqamJ5cvvek3CtXNYSm1".to_string(),
                last_change: 12345,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 0,
                change_inactive_days: -1,
                expire_date: 99999,
                reserved: 0,
            });
        }
        Response::NotFound
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
