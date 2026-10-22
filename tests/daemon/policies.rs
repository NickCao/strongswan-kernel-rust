// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use charon_kernel_daemon::{
    linux::{
        netlink::{Message, Netlink, NlFamily, NlmF},
        policy::LinuxPolicies,
    },
    policy::{PolicyHandle, PolicyKernel, PolicyKey},
};
use netlink_packet_core::Parseable;
use netlink_packet_xfrm::{self as packet, XfrmMessage, XFRM_MSG_GETPOLICY};
use std::collections::HashMap;

fn inventory() -> HashMap<PolicyKey, charon_kernel_daemon::policy::PolicyConfig> {
    LinuxPolicies::new()
        .unwrap()
        .list()
        .unwrap()
        .into_iter()
        .map(|p| {
            (
                p.handle.id().expect("representable identity").clone(),
                p.config.expect("representable config"),
            )
        })
        .collect()
}

fn native_inventory() -> Vec<packet::policy::ModifyMessage> {
    let mut policies: Vec<_> = Netlink::new(NlFamily::Xfrm)
        .unwrap()
        .request(&Message::new(
            XFRM_MSG_GETPOLICY,
            NlmF::DUMP,
            &XfrmMessage::GetPolicy(Default::default()),
        ))
        .unwrap()
        .into_iter()
        .map(|r| packet::policy::ModifyMessage::parse(r.payload.as_slice()).unwrap())
        .collect();
    policies.sort_by_key(|p| p.user_policy_info.index);
    policies
}

fn install_policy_set(rpc: &Rpc, outer: Family) {
    for inner in [Family::V4, Family::V6] {
        assert_eq!(
            rpc.call(rpc.kernel.bypass_port(ctx(), inner.af(), 500)),
            Err(Error::Kernel(libc::EINVAL))
        );
        rpc.call(rpc.kernel.bypass_port(ctx(), inner.af(), 13000))
            .unwrap();
        for direction in [
            PolicyDirection::Inbound,
            PolicyDirection::Outbound,
            PolicyDirection::Forward,
        ] {
            rpc.call(rpc.kernel.install_policy(
                ctx(),
                inner.policy(direction),
                policy_config(outer, 0x10001),
            ))
            .unwrap();
        }
    }
    assert_eq!(inventory().len(), 10, "six tunnel and four bypass policies");
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn rejects_unsupported_modes(
    daemon: Fixture,
    #[values(IpsecMode::Transport, IpsecMode::Other(u32::MAX))] mode: IpsecMode,
) {
    let rpc = daemon.session();
    let mut config = policy_config(Family::V4, 0x10001);
    config.sa.as_mut().unwrap().mode = mode;
    assert_eq!(
        rpc.call(rpc.kernel.install_policy(
            ctx(),
            Family::V4.policy(PolicyDirection::Outbound),
            config
        )),
        Err(Error::Kernel(libc::EOPNOTSUPP))
    );
    assert!(inventory().is_empty() && owned_links().is_empty());
    rpc.close();
}

#[rstest]
#[case::wildcard(0, 0, (0, u16::MAX))]
#[case::tcp_host_port(32, libc::IPPROTO_TCP as u8, (443, 443))]
#[case::udp_port_range(24, libc::IPPROTO_UDP as u8, (1024, 2047))]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn policy_selectors_and_flags(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] inner: Family,
    #[values(Family::V4, Family::V6)] outer: Family,
    #[values(
        PolicyDirection::Inbound,
        PolicyDirection::Outbound,
        PolicyDirection::Forward
    )]
    direction: PolicyDirection,
    #[case] prefix: u8,
    #[case] protocol: u8,
    #[case] ports: (u16, u16),
) {
    let rpc = daemon.session();
    let prefix = if matches!(inner, Family::V6) && prefix != 0 {
        prefix + 96
    } else {
        prefix
    };
    let id = || {
        let mut id = inner.policy(direction);
        id.src = inner.selector(prefix, ports, protocol);
        id
    };
    let config = || {
        let mut c = policy_config(outer, 0x10001);
        c.forward_icmp = true;
        c
    };
    rpc.call(rpc.kernel.install_policy(ctx(), id(), config()))
        .unwrap();
    let native = inventory();
    assert_eq!(native.len(), 1);
    let (key, config_native) = native.iter().next().unwrap();
    assert_eq!(
        (key.src.prefix_len(), key.protocol, key.dir),
        (prefix, protocol, direction)
    );
    assert_eq!(key.src_port, ports.0);
    assert_eq!(key.src_port | !key.src_port_mask, ports.1);
    assert_eq!(
        config_native.forward_icmp,
        direction != PolicyDirection::Inbound
    );
    let template = config_native.template.as_ref().unwrap();
    assert_eq!(
        (template.src, template.dst),
        (outer.local().address, outer.peer().address)
    );
    assert_eq!(
        template.spi,
        if direction == PolicyDirection::Outbound {
            0x10001
        } else {
            0
        }
    );
    assert_eq!(rpc.call(rpc.kernel.query_policy(ctx(), id())).unwrap(), 0);
    assert!(
        owned_links().is_empty(),
        "policies alone must not create interfaces"
    );
    rpc.call(rpc.kernel.remove_policy(ctx(), id(), config()))
        .unwrap();
    assert!(inventory().is_empty());
    rpc.close();
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn icmp_code_specificity_controls_priority(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
) {
    let rpc = daemon.session();
    let (protocol, icmp_type) = match family {
        Family::V4 => (libc::IPPROTO_ICMP, 3),
        Family::V6 => (libc::IPPROTO_ICMPV6, 128),
    };
    let mut priorities = Vec::new();
    for code in [0, 1] {
        let id = || {
            let mut id = family.policy(PolicyDirection::Outbound);
            id.src.protocol = protocol as u8;
            id.src.from_port = icmp_type << 8 | code;
            id.src.to_port = id.src.from_port;
            id
        };
        rpc.call(
            rpc.kernel
                .install_policy(ctx(), id(), policy_config(family, 0x10001)),
        )
        .unwrap();
        let (key, config) = inventory().into_iter().next().unwrap();
        assert_eq!((key.src_port, key.dst_port), (icmp_type, code));
        assert_eq!(key.dst_port_mask != 0, code != 0);
        priorities.push(config.priority);
        rpc.call(
            rpc.kernel
                .remove_policy(ctx(), id(), policy_config(family, 0x10001)),
        )
        .unwrap();
    }
    assert!(priorities[1] < priorities[0]);
    rpc.close();
}

#[derive(Debug, Clone, Copy)]
enum Mutation {
    Delete,
    Flush,
    Block,
    UnsupportedFlag,
}
#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn policy_repair_preserves_sas_and_bypasses(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
    #[values(
        Mutation::Delete,
        Mutation::Flush,
        Mutation::Block,
        Mutation::UnsupportedFlag
    )]
    mutation: Mutation,
) {
    let rpc = daemon.session();
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        family.sa(0x10001),
        sa_config(Cipher::Gcm, false, true),
    ))
    .unwrap();
    install_policy_set(&rpc, family);
    let expected = inventory();
    let states_before = states();
    let index = owned_links()[0].index;
    let subnet = match family {
        Family::V4 => "0.0.0.0/0",
        Family::V6 => "::/0",
    };
    let mut args = vec![
        "xfrm", "policy", "update", "src", subnet, "dst", subnet, "dir", "out", "if_id", "41",
    ];
    let priority = expected
        .iter()
        .find(|(key, _)| {
            key.if_id == 41
                && key.dir == PolicyDirection::Outbound
                && key.src.addr().is_ipv4() == matches!(family, Family::V4)
        })
        .unwrap()
        .1
        .priority
        .to_string();
    let source = family.local().address.to_string();
    let destination = family.peer().address.to_string();
    match mutation {
        Mutation::Delete => {
            args[2] = "delete";
        }
        Mutation::Flush => {
            args = vec!["xfrm", "policy", "flush"];
        }
        Mutation::Block => {
            args.extend(["priority", "7", "action", "block"]);
        }
        Mutation::UnsupportedFlag => {
            // Keep every supported field unchanged so this only detects drift
            // in flags that cannot be represented by the shared configuration.
            args.extend([
                "priority",
                &priority,
                "flag",
                "localok",
                "tmpl",
                "src",
                &source,
                "dst",
                &destination,
                "proto",
                "esp",
                "spi",
                "0x10001",
                "mode",
                "tunnel",
                "reqid",
                "42",
            ]);
        }
    }
    ip(&args);
    eventually(|| {
        let native = LinuxPolicies::new().unwrap().list().unwrap();
        native.len() == expected.len()
            && native.iter().all(|p| {
                p.handle
                    .id()
                    .and_then(|id| expected.get(id))
                    .is_some_and(|config| p.config.as_ref() == Some(config))
            })
    });
    assert_eq!(states(), states_before);
    assert_eq!(owned_links()[0].index, index);
    rpc.call(rpc.kernel.remove_sa(ctx(), family.sa(0x10001), 0))
        .unwrap();
    assert!(
        owned_links().is_empty(),
        "policies must not retain interfaces"
    );
    rpc.call(rpc.kernel.flush_policies(ctx())).unwrap();
    let bypasses = inventory();
    assert_eq!(bypasses.len(), 4);
    assert!(bypasses.keys().all(|key| key.if_id == 0));
    rpc.close();
    assert!(inventory().is_empty());
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn periodic_policy_audits_do_not_rewrite_or_resurrect_objects(
    daemon: Fixture,
    #[values(false, true)] with_sa: bool,
) {
    let rpc = daemon.session();
    if with_sa {
        rpc.call(rpc.kernel.install_sa(
            ctx(),
            Family::V4.sa(0x10001),
            sa_config(Cipher::Gcm, false, true),
        ))
        .unwrap();
        // Stop background traffic before XFRM so native SA counters stay stable.
        for args in [
            vec!["qdisc", "add", "dev", "ranet00000029", "clsact"],
            vec![
                "filter",
                "add",
                "dev",
                "ranet00000029",
                "egress",
                "matchall",
                "action",
                "drop",
            ],
        ] {
            assert!(std::process::Command::new("tc")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
    }
    install_policy_set(&rpc, Family::V4);
    let before = native_inventory();
    let states_before = states();
    std::thread::sleep(std::time::Duration::from_millis(5300));
    assert_eq!(
        native_inventory(),
        before,
        "unchanged policies, including indices and add times, must survive an audit"
    );
    assert_eq!(states(), states_before);
    // Flush while a repair is pending. Only the bypass desires may survive.
    ip(&[
        "xfrm",
        "policy",
        "delete",
        "src",
        "0.0.0.0/0",
        "dst",
        "0.0.0.0/0",
        "dir",
        "out",
        "if_id",
        "41",
    ]);
    rpc.call(rpc.kernel.flush_policies(ctx())).unwrap();
    let bypasses = native_inventory();
    assert_eq!(bypasses.len(), 4);
    assert!(bypasses.iter().all(|p| p.user_policy_info.priority == 32));
    std::thread::sleep(std::time::Duration::from_millis(5300));
    assert_eq!(
        native_inventory(),
        bypasses,
        "flushed desires must not return"
    );
    assert_eq!(states(), states_before);
    rpc.call(rpc.kernel.flush_sas(ctx())).unwrap();
    rpc.close();
}

#[rstest]
#[case::one_reference(1)]
#[case::repeated_rekey_races(20)]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn repair_uses_surviving_rekey_reference(daemon: Fixture, #[case] count: u32) {
    let rpc = daemon.session();
    let family = Family::V4;
    rpc.call(rpc.kernel.install_policy(
        ctx(),
        family.policy(PolicyDirection::Outbound),
        policy_config(family, 0x10001),
    ))
    .unwrap();
    let expected = inventory();
    for n in 0..count {
        rpc.call(rpc.kernel.install_policy(
            ctx(),
            family.policy(PolicyDirection::Outbound),
            policy_config(family, 0x20000 + n),
        ))
        .unwrap();
        ip(&[
            "xfrm",
            "policy",
            "delete",
            "src",
            "0.0.0.0/0",
            "dst",
            "0.0.0.0/0",
            "dir",
            "out",
            "if_id",
            "41",
        ]);
        rpc.call(rpc.kernel.remove_policy(
            ctx(),
            family.policy(PolicyDirection::Outbound),
            policy_config(family, 0x20000 + n),
        ))
        .unwrap();
    }
    eventually(|| inventory() == expected);
    rpc.call(rpc.kernel.flush_policies(ctx())).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5200));
    assert!(
        inventory().is_empty(),
        "removed desires must not return during the next audit"
    );
    rpc.close();
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn acquire_events_preserve_packet_selectors(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
) {
    let rpc = daemon.session();
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        family.sa(0x10001),
        sa_config(Cipher::Gcm, false, true),
    ))
    .unwrap();
    // A different reqid ensures traffic triggers acquisition instead of using the installed SA.
    let mut config = policy_config(family, 0);
    config.sa.as_mut().unwrap().reqid = 43;
    rpc.call(
        rpc.kernel
            .install_policy(ctx(), family.policy(PolicyDirection::Outbound), config),
    )
    .unwrap();
    let dst = family.destination();
    ip(&[
        "route",
        "add",
        &dst.address.to_string(),
        "dev",
        "ranet00000029",
        "src",
        &family.local().address.to_string(),
    ]);
    let udp =
        std::net::UdpSocket::bind(std::net::SocketAddr::new(family.local().address, 0)).unwrap();
    let destination = std::net::SocketAddr::new(dst.address, 32123);
    let sent = udp.send_to(b"acquire", destination);
    assert!(
        sent.is_ok()
            || sent
                .as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
        "{sent:?}"
    );
    let mut received = None;
    eventually(|| {
        received = rpc.events().into_iter().find_map(|e| e.acquire);
        received.is_some()
    });
    let acquire = received.unwrap();
    assert_eq!(acquire.reqid, 43);
    assert_ne!(acquire.sequence, 0);
    for (selector, address, port) in [
        (
            acquire.src,
            udp.local_addr().unwrap().ip(),
            udp.local_addr().unwrap().port(),
        ),
        (acquire.dst, destination.ip(), destination.port()),
    ] {
        assert_eq!(
            (
                selector.from,
                selector.to,
                selector.protocol,
                selector.from_port,
                selector.to_port
            ),
            (address, address, libc::IPPROTO_UDP as u8, port, port)
        );
    }
    rpc.call(rpc.kernel.flush_policies(ctx())).unwrap();
    rpc.call(rpc.kernel.flush_sas(ctx())).unwrap();
    rpc.close();
}
