// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use netlink_packet_route::link::LinkFlags;

#[rstest]
#[case::mtu(&["link", "set", "ranet00000029", "mtu", "1280"], false)]
#[case::down(&["link", "set", "ranet00000029", "down"], false)]
#[case::multicast(&["link", "set", "ranet00000029", "multicast", "off"], false)]
#[case::master(&["link", "set", "ranet00000029", "master", "accidental"], false)]
#[case::native_id(&["link", "set", "ranet00000029", "type", "xfrm", "if_id", "66"], false)]
#[case::unknown_name(&["link", "set", "ranet00000029", "name", "renamed"], true)]
#[case::other_logical_id(&["link", "set", "ranet00000029", "name", "ranet00000063"], true)]
#[case::deleted(&["link", "del", "ranet00000029"], true)]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn reconciles_managed_attributes(
    daemon: Fixture,
    #[case] mutation: &[&str],
    #[case] replacement: bool,
) {
    ip(&["link", "add", "accidental", "type", "vrf", "table", "5678"]);
    let rpc = daemon.session();
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        Family::V4.sa(0x10001),
        sa_config(Cipher::Gcm, false, true),
    ))
    .unwrap();
    let index = owned_links()[0].index;
    let states_before = states();
    ip(&[
        "link",
        "set",
        "ranet00000029",
        "alias",
        "user-managed",
        "txqueuelen",
        "123",
        "promisc",
        "on",
        "allmulticast",
        "on",
    ]);
    ip(&["addr", "add", "198.18.41.1/32", "dev", "ranet00000029"]);
    ip(mutation);
    eventually(|| {
        let links = owned_links();
        links.len() == 1
            && links[0].name == "ranet00000029"
            && links[0].mtu == 1400
            && links[0].master == 0
            && links[0].xfrm_if_id == Some(41)
            && links[0]
                .flags
                .contains(LinkFlags::Up | LinkFlags::Multicast)
    });
    let link = owned_links().pop().unwrap();
    assert_eq!(link.index != index, replacement);
    let details = ip(&["-d", "link", "show", "dev", "ranet00000029"]);
    let addresses = ip(&["addr", "show", "dev", "ranet00000029"]);
    assert_eq!(details.contains("user-managed"), !replacement);
    assert_eq!(addresses.contains("198.18.41.1/32"), !replacement);
    if !replacement {
        assert!(details.contains("qlen 123"), "{details}");
        assert!(link
            .flags
            .contains(LinkFlags::Promisc | LinkFlags::Allmulti));
    }
    assert_eq!(
        states(),
        states_before,
        "interface repair must not modify SAs"
    );
    rpc.call(rpc.kernel.remove_sa(ctx(), Family::V4.sa(0x10001), 0))
        .unwrap();
    assert!(owned_links().is_empty());
    rpc.close();
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn overlap_and_failed_installs_follow_sa_ownership(daemon: Fixture) {
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    let rpc = daemon.session();
    for spi in [0x10001, 0x10002] {
        rpc.call(rpc.kernel.install_sa(
            ctx(),
            Family::V4.sa(spi),
            sa_config(Cipher::Gcm, false, true),
        ))
        .unwrap();
    }
    let index = owned_links()[0].index;
    rpc.call(rpc.kernel.remove_sa(ctx(), Family::V4.sa(0x10001), 0))
        .unwrap();
    assert_eq!(owned_links()[0].index, index);
    let mut conflict = Family::V4.sa(0x10003);
    conflict.interface_id = 77;
    assert_eq!(
        rpc.call(
            rpc.kernel
                .install_sa(ctx(), conflict, sa_config(Cipher::Gcm, false, true))
        ),
        Err(Error::Kernel(libc::EEXIST))
    );
    assert_eq!(owned_links().len(), 1);
    rpc.call(rpc.kernel.remove_sa(ctx(), Family::V4.sa(0x10002), 0))
        .unwrap();
    assert!(owned_links().is_empty());
    assert!(links()
        .iter()
        .any(|l| l.name == "foreign" && l.xfrm_if_id == Some(77)));
    rpc.close();
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn released_interface_is_not_mutated_or_deleted(
    daemon: Fixture,
    #[values(false, true)] remove_sa: bool,
) {
    let rpc = daemon.session();
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        Family::V4.sa(0x10001),
        sa_config(Cipher::Gcm, false, true),
    ))
    .unwrap();
    ip(&["link", "set", "ranet00000029", "group", "0"]);
    ip(&[
        "link",
        "set",
        "ranet00000029",
        "type",
        "xfrm",
        "if_id",
        "66",
    ]);
    ip(&[
        "link",
        "set",
        "ranet00000029",
        "down",
        "mtu",
        "1280",
        "multicast",
        "off",
    ]);
    if remove_sa {
        rpc.call(rpc.kernel.remove_sa(ctx(), Family::V4.sa(0x10001), 0))
            .unwrap();
    } else {
        let mut update = sa_config(Cipher::Gcm, false, true);
        update.update = true;
        assert_eq!(
            rpc.call(rpc.kernel.install_sa(ctx(), Family::V4.sa(0x10001), update)),
            Err(Error::Kernel(libc::EEXIST))
        );
    }
    let link = links()
        .into_iter()
        .find(|l| l.name == "ranet00000029")
        .unwrap();
    assert_eq!((link.group, link.mtu, link.xfrm_if_id), (0, 1280, Some(66)));
    assert!(!link.flags.intersects(LinkFlags::Up | LinkFlags::Multicast));
    rpc.call(rpc.kernel.flush_sas(ctx())).unwrap();
    rpc.close();
    assert!(links().iter().any(|l| l.index == link.index));
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn foreign_replacement_at_reused_index_is_preserved(
    daemon: Fixture,
    #[values(false, true)] remove_sa: bool,
) {
    let rpc = daemon.session();
    let id = || Family::V4.sa(0x10001);
    rpc.call(
        rpc.kernel
            .install_sa(ctx(), id(), sa_config(Cipher::Gcm, false, true)),
    )
    .unwrap();
    let index = owned_links()[0].index;
    let states_before = states();
    // Release ownership before replacement, and reserve the desired native ID
    // so the reconciler cannot recreate its interface during this operation.
    ip(&["link", "set", "ranet00000029", "group", "0"]);
    ip(&[
        "link",
        "set",
        "ranet00000029",
        "type",
        "xfrm",
        "if_id",
        "66",
    ]);
    ip(&["link", "add", "guard41", "type", "xfrm", "if_id", "41"]);
    ip(&["link", "del", "ranet00000029"]);
    ip(&[
        "link",
        "add",
        "ranet00000029",
        "index",
        &index.to_string(),
        "type",
        "xfrm",
        "if_id",
        "66",
    ]);
    ip(&[
        "link",
        "set",
        "ranet00000029",
        "down",
        "mtu",
        "1280",
        "multicast",
        "off",
    ]);
    if remove_sa {
        rpc.call(rpc.kernel.remove_sa(ctx(), id(), 0)).unwrap();
    } else {
        let mut update = sa_config(Cipher::Gcm, false, true);
        update.update = true;
        assert_eq!(
            rpc.call(rpc.kernel.install_sa(ctx(), id(), update)),
            Err(Error::Kernel(libc::EEXIST))
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    let foreign = links()
        .into_iter()
        .find(|l| l.name == "ranet00000029")
        .unwrap();
    assert_eq!(
        (
            foreign.index,
            foreign.group,
            foreign.mtu,
            foreign.xfrm_if_id
        ),
        (index, 0, 1280, Some(66))
    );
    assert!(!foreign
        .flags
        .intersects(LinkFlags::Up | LinkFlags::Multicast));
    assert!(owned_links().is_empty());
    if !remove_sa {
        ip(&["link", "del", "ranet00000029"]);
        ip(&["link", "del", "guard41"]);
        eventually(|| !owned_links().is_empty());
        let repaired = owned_links().pop().unwrap();
        assert_ne!(repaired.index, index);
        assert_eq!((repaired.mtu, repaired.xfrm_if_id), (1400, Some(41)));
        assert!(repaired
            .flags
            .contains(LinkFlags::Up | LinkFlags::Multicast));
        assert_eq!(states(), states_before);
        rpc.call(rpc.kernel.remove_sa(ctx(), id(), 0)).unwrap();
    }
    rpc.close();
    if remove_sa {
        assert!(links().iter().any(|l| l.index == foreign.index));
        assert!(links().iter().any(|l| l.name == "guard41"));
    }
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn final_sa_removal_does_not_resurrect_missing_interfaces(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
) {
    let rpc = daemon.session();
    for attempt in 0..4 {
        let id = || family.sa(0x30000 + attempt);
        rpc.call(
            rpc.kernel
                .install_sa(ctx(), id(), sa_config(Cipher::Gcm, false, true)),
        )
        .unwrap();
        ip(&["link", "del", "ranet00000029"]);
        rpc.call(rpc.kernel.remove_sa(ctx(), id(), 0)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            owned_links().is_empty(),
            "final removal resurrected an interface"
        );
        assert!(states().is_empty());
    }
    rpc.close();
}
