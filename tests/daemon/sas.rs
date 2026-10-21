// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr};

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn installs_sa_options(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
    #[values(Cipher::Gcm, Cipher::CbcSha256, Cipher::CbcSha384, Cipher::ChaCha)] cipher: Cipher,
    #[values(false, true)] inbound: bool,
    #[values(false, true)] esn: bool,
) {
    let rpc = daemon.session();
    let mut config = sa_config(cipher, inbound, esn);
    config.forward_icmp = true;
    config.copy_df = false;
    config.copy_ecn = false;
    config.copy_dscp = 3;
    rpc.call(rpc.kernel.install_sa(ctx(), family.sa(0x10001), config))
        .unwrap();
    let native = states().pop().unwrap();
    let info = native.user_sa_info;
    assert_eq!(info.family, family.af());
    assert_eq!(info.mode, packet::XFRM_MODE_TUNNEL);
    assert_eq!(info.reqid, 42);
    for (flag, expected) in [
        (packet::XFRM_STATE_ESN, esn),
        (packet::XFRM_STATE_ICMP, inbound),
        (packet::XFRM_STATE_NOPMTUDISC, !inbound),
        (packet::XFRM_STATE_NOECN, true),
    ] {
        assert_eq!(info.flags & flag != 0, expected, "flag {flag:#x}");
    }
    assert!(native.nlas.contains(&Attr::IfId(41)));
    assert!(native.nlas.contains(&Attr::MarkVal(123)));
    assert!(native
        .nlas
        .iter()
        .any(|attr| matches!(attr, Attr::EncapsulationTemplate(encap)
        if encap.encap_sport == 13000 && encap.encap_dport == 13000)));
    let (expected_name, integrity) = match cipher {
        Cipher::Gcm => ("rfc4106(gcm(aes))", None),
        Cipher::ChaCha => ("rfc7539esp(chacha20,poly1305)", None),
        Cipher::CbcSha256 => ("cbc(aes)", Some(("hmac(sha256)", 128))),
        Cipher::CbcSha384 => ("cbc(aes)", Some(("hmac(sha384)", 192))),
    };
    assert!(native.nlas.iter().any(|attr| match attr {
        Attr::EncryptionAlgAead(a) =>
            a.alg_name.starts_with(expected_name.as_bytes()) && a.alg_icv_len == 128,
        Attr::EncryptionAlg(a) => a.alg_name.starts_with(expected_name.as_bytes()),
        _ => false,
    }));
    if let Some((name, bits)) = integrity {
        assert!(native
            .nlas
            .iter()
            .any(|a| matches!(a, Attr::AuthenticationAlgTrunc(a)
                if a.alg_trunc_len == bits && a.alg_name.starts_with(name.as_bytes()))));
    }
    let link = owned_links().pop().unwrap();
    assert_eq!(
        (link.name.as_str(), link.mtu, link.xfrm_if_id),
        ("ranet00000029", 1400, Some(41))
    );
    assert_eq!(
        rpc.call(rpc.kernel.query_sa(ctx(), family.sa(0x10001), 0))
            .unwrap(),
        SaUsage::default()
    );
    assert_eq!(
        rpc.call(
            rpc.kernel
                .install_sa(ctx(), family.sa(0x10001), sa_config(cipher, inbound, esn))
        ),
        Err(Error::Kernel(libc::EEXIST))
    );
    rpc.call(rpc.kernel.remove_sa(ctx(), family.sa(0x10001), 0))
        .unwrap();
    assert!(states().is_empty() && owned_links().is_empty());
    rpc.close();
}

#[rstest]
#[case::missing_interface(|id: &mut SaId, _: &mut SaConfig| id.interface_id = 0, libc::EINVAL)]
#[case::reserved_spi(|id: &mut SaId, _: &mut SaConfig| id.spi = 255, libc::EINVAL)]
#[case::other_protocol(|id: &mut SaId, _: &mut SaConfig| id.protocol = libc::IPPROTO_AH as u8, libc::EOPNOTSUPP)]
#[case::mixed_families(|id: &mut SaId, _: &mut SaConfig| id.dst = Family::V6.peer(), libc::EINVAL)]
#[case::low_source_port(|id: &mut SaId, _: &mut SaConfig| id.src.port = 500, libc::EINVAL)]
#[case::low_peer_port(|id: &mut SaId, _: &mut SaConfig| id.dst.port = 450, libc::EINVAL)]
#[case::missing_lifetime(|_: &mut SaId, c: &mut SaConfig| c.lifetime = None, libc::EINVAL)]
#[case::zero_reqid(|_: &mut SaId, c: &mut SaConfig| c.reqid = 0, libc::EINVAL)]
#[case::replay_window(|_: &mut SaId, c: &mut SaConfig| c.replay_window = 131073, libc::EINVAL)]
#[case::copy_dscp(|_: &mut SaId, c: &mut SaConfig| c.copy_dscp = 4, libc::EINVAL)]
#[case::unknown_cipher(|_: &mut SaId, c: &mut SaConfig| c.encryption.id = u16::MAX, libc::EOPNOTSUPP)]
#[case::key_length(|_: &mut SaId, c: &mut SaConfig| c.encryption.key = vec![0; 8193], libc::EINVAL)]
#[case::transport_mode(|_: &mut SaId, c: &mut SaConfig| c.mode = 1, libc::EOPNOTSUPP)]
#[case::compression(|_: &mut SaId, c: &mut SaConfig| c.ipcomp = 1, libc::EOPNOTSUPP)]
#[case::cpi(|_: &mut SaId, c: &mut SaConfig| c.cpi = 1, libc::EOPNOTSUPP)]
#[case::label(|_: &mut SaId, c: &mut SaConfig| c.security_label = Some(vec![]), libc::EOPNOTSUPP)]
#[case::offload(|_: &mut SaId, c: &mut SaConfig| c.hw_offload = 1, libc::EOPNOTSUPP)]
#[case::cpu(|_: &mut SaId, c: &mut SaConfig| c.cpu = 0, libc::EOPNOTSUPP)]
#[case::bound_interface(|_: &mut SaId, c: &mut SaConfig| c.interface = Some("underlay".into()), libc::EOPNOTSUPP)]
#[case::iptfs_tfc(|_: &mut SaId, c: &mut SaConfig| { c.mode = mode::IPTFS; c.tfc = 1; }, libc::EOPNOTSUPP)]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn rejected_install_rolls_back(
    daemon: Fixture,
    #[case] change: fn(&mut SaId, &mut SaConfig),
    #[case] errno: i32,
) {
    let rpc = daemon.session();
    let mut id = Family::V4.sa(0x10001);
    let mut config = sa_config(Cipher::Gcm, false, true);
    change(&mut id, &mut config);
    assert_eq!(
        rpc.call(rpc.kernel.install_sa(ctx(), id, config)),
        Err(Error::Kernel(errno))
    );
    assert!(
        states().is_empty() && owned_links().is_empty(),
        "rejected installs must not leave objects"
    );
    rpc.close();
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn larval_reservation_is_completed_only_once(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
    #[values(false, true)] reservation_lost: bool,
) {
    let rpc = daemon.session();
    let spi = rpc
        .call(rpc.kernel.allocate_spi(
            ctx(),
            family.local(),
            family.peer(),
            libc::IPPROTO_ESP as u8,
            0xc0000000,
            0xcfffffff,
        ))
        .unwrap();
    assert!((0xc0000000..=0xcfffffff).contains(&spi));
    assert!(
        owned_links().is_empty(),
        "larval SAs must not create interfaces"
    );
    if reservation_lost {
        ip(&[
            "xfrm",
            "state",
            "delete",
            "dst",
            &family.peer().address.to_string(),
            "proto",
            "esp",
            "spi",
            &spi.to_string(),
        ]);
    }
    let config = || {
        let mut c = sa_config(Cipher::Gcm, true, true);
        c.update = true;
        c
    };
    rpc.call(rpc.kernel.install_sa(ctx(), family.sa(spi), config()))
        .unwrap();
    assert_eq!(
        rpc.call(rpc.kernel.install_sa(ctx(), family.sa(spi), config())),
        Err(Error::Kernel(libc::EEXIST))
    );
    rpc.call(rpc.kernel.remove_sa(ctx(), family.sa(spi), 0))
        .unwrap();
    rpc.close();
}

#[derive(Debug, Clone, Copy)]
enum Loss {
    Delete,
    Flush,
    Drift,
}
#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn loss_retires_keys_and_withdraws_only_unused_interfaces(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
    #[values(Loss::Delete, Loss::Flush, Loss::Drift)] loss: Loss,
) {
    let rpc = daemon.session();
    for spi in [0x10001, 0x10002] {
        rpc.call(
            rpc.kernel
                .install_sa(ctx(), family.sa(spi), sa_config(Cipher::Gcm, false, true)),
        )
        .unwrap();
    }
    let original_index = owned_links()[0].index;
    ip(&["route", "add", "198.18.0.1/32", "dev", "ranet00000029"]);
    let id = family.sa(0x10001);
    match loss {
        Loss::Delete => {
            ip(&[
                "xfrm",
                "state",
                "delete",
                "dst",
                &id.dst.address.to_string(),
                "proto",
                "esp",
                "spi",
                &id.spi.to_string(),
            ]);
        }
        Loss::Flush => {
            ip(&["xfrm", "state", "flush"]);
        }
        Loss::Drift => {
            let source = id.src.address.to_string();
            let destination = id.dst.address.to_string();
            let spi = id.spi.to_string();
            let key = format!("0x{}", "00".repeat(20));
            let mut args = vec![
                "xfrm",
                "state",
                "update",
                "src",
                &source,
                "dst",
                &destination,
                "proto",
                "esp",
                "spi",
                &spi,
                "mode",
                "tunnel",
                "aead",
                "rfc4106(gcm(aes))",
                &key,
                "128",
                "encap",
                "espinudp",
                "13000",
                "13000",
                "0.0.0.0",
                "if_id",
                "41",
                "output-mark",
                "999",
            ];
            if ip(&["xfrm", "state"]).contains("dir out") {
                args.extend(["dir", "out"]);
            }
            ip(&args);
        }
    }
    let mut expired: Vec<_> = rpc
        .expiries(if matches!(loss, Loss::Flush) { 2 } else { 1 })
        .into_iter()
        .map(|e| {
            assert!(e.hard);
            e.spi
        })
        .collect();
    expired.sort_unstable();
    assert_eq!(
        expired,
        if matches!(loss, Loss::Flush) {
            vec![0x10001, 0x10002]
        } else {
            vec![0x10001]
        }
    );
    if !matches!(loss, Loss::Flush) {
        assert_eq!(owned_links()[0].index, original_index);
        assert_eq!(
            rpc.call(rpc.kernel.query_sa(ctx(), family.sa(0x10002), 0))
                .unwrap(),
            SaUsage::default()
        );
        rpc.call(rpc.kernel.remove_sa(ctx(), family.sa(0x10002), 0))
            .unwrap();
    }
    eventually(|| owned_links().is_empty());
    assert!(ip(&["route", "show", "198.18.0.1/32"]).is_empty());
    let mut update = sa_config(Cipher::Gcm, false, true);
    update.update = true;
    assert_eq!(
        rpc.call(rpc.kernel.install_sa(ctx(), family.sa(0x10001), update)),
        Err(Error::Kernel(libc::ENOENT))
    );
    // Removing a retired SA is an idempotent acknowledgement, not a repair.
    rpc.call(rpc.kernel.remove_sa(ctx(), family.sa(0x10001), 0))
        .unwrap();
    assert!(states().is_empty());
    rpc.close();
}

#[rstest]
#[case::one(1)]
#[case::over_queue_capacity(300)]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn bulk_flush_reports_each_sa_once(daemon: Fixture, #[case] count: u32) {
    let rpc = daemon.session();
    for n in 0..count {
        rpc.call(rpc.kernel.install_sa(
            ctx(),
            Family::V4.sa(0x71000 + n),
            sa_config(Cipher::Gcm, n % 2 != 0, true),
        ))
        .unwrap();
    }
    ip(&["xfrm", "state", "flush"]);
    let mut expired: Vec<_> = rpc
        .expiries(count as usize)
        .into_iter()
        .map(|e| {
            assert!(e.hard);
            e.spi
        })
        .collect();
    expired.sort_unstable();
    assert_eq!(expired, (0..count).map(|n| 0x71000 + n).collect::<Vec<_>>());
    eventually(|| owned_links().is_empty());
    // Cross the periodic audit boundary: retirement must neither replay keys nor notify twice.
    std::thread::sleep(std::time::Duration::from_millis(5200));
    assert!(states().is_empty());
    assert!(rpc.events().iter().all(|e| e.expiry.is_none()));
    rpc.close();
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
fn kernel_lifetime_delivers_soft_then_hard_expiry(
    daemon: Fixture,
    #[values(Family::V4, Family::V6)] family: Family,
) {
    let rpc = daemon.session();
    let mut config = sa_config(Cipher::Gcm, true, true);
    config.lifetime.as_mut().unwrap().time = LifetimeLimit {
        life: 3,
        rekey: 1,
        jitter: 0,
    };
    rpc.call(rpc.kernel.install_sa(ctx(), family.sa(0x10001), config))
        .unwrap();
    let soft = rpc.expiries(1).pop().unwrap();
    assert_eq!((soft.spi, soft.hard), (0x10001, false));
    let hard = rpc.expiries(1).pop().unwrap();
    assert_eq!((hard.spi, hard.hard), (0x10001, true));
    eventually(|| owned_links().is_empty());
    rpc.close();
}
