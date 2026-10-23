// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn fib_lookups_follow_route_changes(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
    #[values(false, true)] explicit_source: bool,
) {
    let rpc = daemon.session().await;
    let destination = family.destination();
    let source = explicit_source.then(|| {
        let mut s = family.local();
        s.port = 32123;
        s
    });
    let gateway = family.gateway();
    ip(&[
        "route",
        "add",
        &destination.address.to_string(),
        "via",
        &gateway.address.to_string(),
        "dev",
        "underlay",
    ]);
    let selected = rpc
        .call(rpc.kernel.get_source_address(ctx(), destination, source))
        .await
        .unwrap();
    assert_eq!(selected.address, family.local().address);
    if let Some(source) = source {
        assert_eq!(selected, source);
    }
    let route = rpc
        .call(rpc.kernel.get_next_hop(ctx(), destination, source, None))
        .await
        .unwrap();
    assert_eq!(
        (route.gateway.address, route.interface.as_str()),
        (gateway.address, "underlay")
    );
    let replacement = family.host("192.0.2.253", "2001:db8:1::fd");
    ip(&[
        "route",
        "replace",
        &destination.address.to_string(),
        "via",
        &replacement.address.to_string(),
        "dev",
        "underlay",
    ]);
    assert_eq!(
        rpc.call(rpc.kernel.get_next_hop(ctx(), destination, source, None))
            .await
            .unwrap()
            .gateway
            .address,
        replacement.address
    );
    assert!(matches!(
        rpc.call(rpc.kernel.get_next_hop(ctx(), destination, None, Some(24)))
            .await,
        Err(Error::Kernel(libc::EOPNOTSUPP))
    ));
    rpc.close().await;
}

#[rstest]
#[case::excluded("", "underlay", libc::ENETUNREACH)]
#[case::allowlist("spare", "", libc::ENETUNREACH)]
#[case::allowlist_wins("underlay", "underlay", 0)]
#[case::exact_names("", "under*", 0)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn route_interface_filters(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
    #[case] allow: &str,
    #[case] ignore: &str,
    #[case] errno: i32,
) {
    let rpc = daemon.connect().await;
    rpc.open(SessionConfig {
        interfaces_use: allow.into(),
        interfaces_ignore: ignore.into(),
        ..Default::default()
    })
    .await;
    ip(&[
        "route",
        "add",
        &family.destination().address.to_string(),
        "via",
        &family.gateway().address.to_string(),
        "dev",
        "underlay",
    ]);
    let result = rpc
        .call(
            rpc.kernel
                .get_source_address(ctx(), family.destination(), None),
        )
        .await;
    if errno == 0 {
        assert_eq!(result.unwrap().address, family.local().address);
    } else {
        assert_eq!(result, Err(Error::Kernel(errno)));
    }
    rpc.close().await;
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn xfrm_egress_and_policy_rules_are_honored(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
) {
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    ip(&["link", "set", "foreign", "up"]);
    let rpc = daemon.session().await;
    ip(&[
        "route",
        "add",
        &family.destination().address.to_string(),
        "dev",
        "foreign",
    ]);
    assert_eq!(
        rpc.call(
            rpc.kernel
                .get_source_address(ctx(), family.destination(), None)
        )
        .await,
        Err(Error::Kernel(libc::ENETUNREACH))
    );
    assert_eq!(
        rpc.call(
            rpc.kernel
                .get_next_hop(ctx(), family.destination(), Some(family.local()), None)
        )
        .await,
        Err(Error::Kernel(libc::ENETUNREACH))
    );
    ip(&["route", "del", &family.destination().address.to_string()]);
    ip(&[
        "route",
        "add",
        &family.destination().address.to_string(),
        "via",
        &family.gateway().address.to_string(),
        "dev",
        "underlay",
    ]);
    // `ip` needs an explicit family when an unreachable default contains no IP literal.
    let flag = match family {
        Family::V4 => "-4",
        Family::V6 => "-6",
    };
    ip(&[
        flag,
        "route",
        "add",
        "unreachable",
        "default",
        "table",
        "100",
    ]);
    ip(&[
        flag,
        "rule",
        "add",
        "to",
        &family.destination().address.to_string(),
        "table",
        "100",
        "priority",
        "100",
    ]);
    assert_eq!(
        rpc.call(
            rpc.kernel
                .get_source_address(ctx(), family.destination(), None)
        )
        .await,
        Err(Error::Kernel(libc::EHOSTUNREACH))
    );
    rpc.close().await;
}

#[rstest]
#[case::regular(AddressTypes::REGULAR, false, false)]
#[case::include_down(AddressTypes::REGULAR | AddressTypes::DOWN, true, false)]
#[case::include_ignored(AddressTypes::REGULAR | AddressTypes::IGNORED, false, true)]
#[case::include_both(AddressTypes::REGULAR | AddressTypes::IGNORED | AddressTypes::DOWN, true, true)]
#[case::modifier_only(AddressTypes::IGNORED, false, false)]
#[case::all(AddressTypes::all(), true, true)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn address_enumeration_flags(
    daemon: Fixture,
    #[case] which: AddressTypes,
    #[case] down: bool,
    #[case] ignored: bool,
) {
    for (name, address, up) in [
        ("spare", "198.18.1.1/24", false),
        ("ignored", "198.18.2.1/24", true),
    ] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["addr", "add", address, "dev", name]);
        if up {
            ip(&["link", "set", name, "up"]);
        }
    }
    ip(&["addr", "add", "169.254.1.1/16", "dev", "underlay"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "fe80::123/64",
        "dev",
        "underlay",
        "nodad",
    ]);
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    ip(&["link", "set", "foreign", "up"]);
    ip(&["addr", "add", "198.51.100.1/24", "dev", "foreign"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:77::1/64",
        "dev",
        "foreign",
        "nodad",
    ]);
    let rpc = daemon.connect().await;
    rpc.open(SessionConfig {
        interfaces_ignore: "ignored".into(),
        ..Default::default()
    })
    .await;
    let addresses = rpc
        .call(rpc.kernel.list_addresses(ctx(), which))
        .await
        .unwrap();
    let contains = |s: &str| addresses.iter().any(|e| e.address.to_string() == s);
    assert_eq!(contains("198.18.1.1"), down);
    assert_eq!(contains("198.18.2.1"), ignored);
    assert_eq!(contains("192.0.2.1"), which.contains(AddressTypes::REGULAR));
    assert_eq!(
        contains("2001:db8:1::1"),
        which.contains(AddressTypes::REGULAR)
    );
    assert!(!addresses
        .iter()
        .any(|e| e.is_link_local() || e.address.is_loopback()));
    for address in ["198.51.100.1", "2001:db8:77::1"] {
        assert!(!contains(address));
        assert_eq!(
            rpc.call(
                rpc.kernel
                    .get_interface(ctx(), Endpoint::new(address.parse().unwrap(), 0))
            )
            .await,
            Err(Error::Kernel(libc::ENOENT))
        );
    }
    let subnets = rpc.call(rpc.kernel.list_subnets(ctx())).await.unwrap();
    assert!(subnets.iter().all(|s| s.interface == "underlay"));
    rpc.close().await;
}

#[rstest]
#[case::ignored_dummy(false)]
#[case::xfrm(true)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn multihomed_sources_are_independent_of_egress_filters(
    daemon: Fixture,
    #[case] xfrm: bool,
    #[values(Family::V4, Family::V6)] family: Family,
    #[values(false, true)] source_up: bool,
    #[values(false, true)] explicit_source: bool,
) {
    if xfrm {
        ip(&["link", "add", "spare", "type", "xfrm", "if_id", "77"]);
    } else {
        ip(&["link", "add", "spare", "type", "dummy"]);
    }
    let source = family.host("198.18.1.1", "2001:db8:3::1");
    let cidr = format!("{}/{}", source.address, source.bits());
    ip(&["addr", "add", &cidr, "dev", "spare", "nodad"]);
    if source_up {
        ip(&["link", "set", "spare", "up"]);
    }
    let rpc = daemon.connect().await;
    rpc.open(SessionConfig {
        interfaces_ignore: "spare".into(),
        ..Default::default()
    })
    .await;
    ip(&[
        "route",
        "add",
        &family.destination().address.to_string(),
        "via",
        &family.gateway().address.to_string(),
        "dev",
        "underlay",
        "src",
        &source.address.to_string(),
    ]);
    let explicit = explicit_source.then_some(source);
    assert_eq!(
        rpc.call(
            rpc.kernel
                .get_source_address(ctx(), family.destination(), explicit)
        )
        .await
        .unwrap()
        .address,
        source.address
    );
    assert_eq!(
        rpc.call(
            rpc.kernel
                .get_next_hop(ctx(), family.destination(), explicit, None)
        )
        .await
        .unwrap()
        .interface,
        "underlay"
    );
    assert!(!rpc
        .call(rpc.kernel.list_addresses(ctx(), AddressTypes::REGULAR))
        .await
        .unwrap()
        .iter()
        .any(|e| e.address == source.address));
    rpc.close().await;
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn discovery_cache_tracks_link_state_changes(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
) {
    ip(&["link", "add", "spare", "type", "dummy"]);
    // Keep the address present when administratively down, as for IPv4.
    std::fs::write("/proc/sys/net/ipv6/conf/spare/keep_addr_on_down", "1").unwrap();
    let source = family.host("198.18.1.1", "2001:db8:3::1");
    ip(&[
        "addr",
        "add",
        &format!("{}/{}", source.address, source.bits()),
        "dev",
        "spare",
        "nodad",
    ]);
    let rpc = daemon.connect().await;
    rpc.open(SessionConfig {
        interfaces_ignore: "spare".into(),
        ..Default::default()
    })
    .await;
    let listed = async |which| {
        rpc.call(rpc.kernel.list_addresses(ctx(), which))
            .await
            .unwrap()
            .iter()
            .any(|e| e.address == source.address)
    };
    assert!(!listed(AddressTypes::REGULAR | AddressTypes::IGNORED).await);
    assert!(listed(AddressTypes::REGULAR | AddressTypes::IGNORED | AddressTypes::DOWN).await);
    ip(&["link", "set", "spare", "up"]);
    eventually(async || listed(AddressTypes::REGULAR | AddressTypes::IGNORED).await).await;
    assert!(!listed(AddressTypes::REGULAR).await);
    ip(&["link", "set", "spare", "down"]);
    eventually(async || !listed(AddressTypes::REGULAR | AddressTypes::IGNORED).await).await;
    assert!(listed(AddressTypes::REGULAR | AddressTypes::IGNORED | AddressTypes::DOWN).await);
    rpc.close().await;
}

#[rstest]
#[case::single_route(1)]
#[case::route_burst(1000)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn route_events_coalesce_without_losing_address_changes(
    daemon: Fixture,
    #[case] routes: u32,
) {
    let rpc = daemon.session().await;
    // Populate discovery's cache, then mutate after subscribing.
    rpc.call(rpc.kernel.list_addresses(ctx(), AddressTypes::REGULAR))
        .await
        .unwrap();
    ip(&["addr", "add", "192.0.2.3/24", "dev", "underlay"]);
    for n in 0..routes {
        ip(&[
            "route",
            "add",
            &format!("172.17.{}.{}/32", n / 256, n % 256),
            "dev",
            "underlay",
            "table",
            "1234",
        ]);
    }
    let mut events = Vec::new();
    eventually(async || {
        events.extend(rpc.events().await);
        events.iter().any(|e| {
            matches!(
                e,
                Event::Roam {
                    address_changed: true
                }
            )
        })
    })
    .await;
    assert!(
        events.len() < 50,
        "one event per route would overwhelm charon"
    );
    assert_eq!(
        rpc.call(
            rpc.kernel
                .get_interface(ctx(), Endpoint::new("192.0.2.3".parse().unwrap(), 0))
        )
        .await
        .unwrap(),
        "underlay"
    );
    // No polling RPC is needed to wake an otherwise idle client.
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    rpc.notification.drain().unwrap();
    while !rpc.events().await.is_empty() {}
    ip(&["addr", "add", "192.0.2.4/24", "dev", "underlay"]);
    assert_eq!(
        poll(
            &mut [PollFd::new(&rpc.notification, PollFlags::IN)],
            Some(&Timespec {
                tv_sec: 2,
                tv_nsec: 0
            })
        )
        .unwrap(),
        1
    );
    assert!(rpc.notification.drain().unwrap());
    rpc.close().await;
}
