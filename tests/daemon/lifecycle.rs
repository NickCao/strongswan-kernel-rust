// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use charon_kernel_daemon::{linux::policy::LinuxPolicies, policy::PolicyKernel};
use nix::sys::signal::Signal;
use std::{fs, os::unix::fs::MetadataExt, process::Command};

async fn assert_empty() {
    assert_empty_in_group(17227).await;
}
async fn assert_empty_in_group(group: u32) {
    assert!(states().await.is_empty(), "SAs and larval SPIs remain");
    assert!(
        !links().await.iter().any(|l| l.group == group),
        "owned interfaces remain"
    );
    assert!(
        LinuxPolicies::new()
            .await
            .unwrap()
            .list()
            .await
            .unwrap()
            .is_empty(),
        "global policies remain"
    );
    assert!(
        links().await.iter().any(|l| l.name == "foreign"),
        "unowned interface was deleted"
    );
}
async fn populate(rpc: &Rpc) {
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        Family::V4.sa(0x10001),
        sa_config(Cipher::Gcm, false, true),
    ))
    .await
    .unwrap();
    rpc.call(rpc.kernel.allocate_spi(
        ctx(),
        Family::V4.local(),
        Family::V4.peer(),
        libc::IPPROTO_ESP as u8,
        0xd0000000,
        0xdfffffff,
    ))
    .await
    .unwrap();
    for family in [Family::V4, Family::V6] {
        rpc.call(rpc.kernel.bypass_port(ctx(), family.af(), 13000))
            .await
            .unwrap();
        for direction in [
            PolicyDirection::Inbound,
            PolicyDirection::Outbound,
            PolicyDirection::Forward,
        ] {
            rpc.call(rpc.kernel.install_policy(
                ctx(),
                family.policy(direction),
                policy_config(Family::V4, 0x10001),
            ))
            .await
            .unwrap();
        }
    }
}
fn leftovers() {
    ip(&[
        "xfrm",
        "state",
        "add",
        "src",
        "192.0.2.10",
        "dst",
        "192.0.2.11",
        "proto",
        "esp",
        "spi",
        "0xaaaa",
        "mode",
        "tunnel",
        "aead",
        "rfc4106(gcm(aes))",
        &format!("0x{}", "00".repeat(20)),
        "128",
    ]);
    ip(&[
        "xfrm",
        "policy",
        "add",
        "src",
        "203.0.113.0/24",
        "dst",
        "203.0.114.0/24",
        "dev",
        "lo",
        "dir",
        "out",
        "mark",
        "0x123",
        "mask",
        "0xfff",
        "if_id",
        "77",
        "action",
        "block",
    ]);
    ip(&[
        "link",
        "add",
        "owned-orphan",
        "group",
        "17227",
        "type",
        "dummy",
    ]);
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn session_is_connection_bound_and_clean_close_releases_it(
    daemon: Fixture,
    #[values(false, true)] with_sa: bool,
) {
    let first = daemon.connect().await;
    assert_eq!(
        first.call(first.kernel.flush_sas(ctx())).await,
        Err(Error::InvalidSession)
    );
    drop(first); // Unopened probes do not own the daemon's lifetime.
    let active = daemon.session().await;
    let other = daemon.connect().await;
    assert!(matches!(
        other
            .call(other.kernel.open_session(ctx(), SessionConfig::default()))
            .await,
        Err(Error::SessionBusy)
    ));
    assert_eq!(
        other.call(other.kernel.flush_sas(ctx())).await,
        Err(Error::InvalidSession)
    );
    assert!(matches!(
        other.call(other.kernel.next_events(ctx())).await,
        Err(Error::InvalidSession)
    ));
    if with_sa {
        active
            .call(active.kernel.install_sa(
                ctx(),
                Family::V4.sa(0x10001),
                sa_config(Cipher::Gcm, false, true),
            ))
            .await
            .unwrap();
    } else {
        active
            .call(active.kernel.install_policy(
                ctx(),
                Family::V4.policy(PolicyDirection::Outbound),
                policy_config(Family::V4, 0x10001),
            ))
            .await
            .unwrap();
    }
    assert_eq!(
        active.call(active.kernel.close_session(ctx())).await,
        Err(Error::Kernel(libc::EBUSY))
    );
    active
        .call(active.kernel.flush_policies(ctx()))
        .await
        .unwrap();
    active.call(active.kernel.flush_sas(ctx())).await.unwrap();
    active.close().await;
    drop(active);
    other.open(SessionConfig::default()).await;
    other.close().await;
}

#[rstest]
#[case::term(Some(Signal::SIGTERM))]
#[case::interrupt(Some(Signal::SIGINT))]
#[case::disconnect(None)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn active_shutdown_cleans_the_namespace(
    mut daemon: Fixture,
    #[case] signal: Option<Signal>,
    #[values(false, true)] queued_request: bool,
) {
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    let rpc = daemon.session().await;
    populate(&rpc).await;
    let _idle = daemon.connect().await;
    assert_eq!(
        states().await.len(),
        2,
        "established SA and larval reservation"
    );
    assert_eq!(owned_links().await.len(), 1);
    leftovers();
    if queued_request {
        use futures::SinkExt;
        // All earlier calls have completed. Use the production transport to
        // flush one more typed request on this connection without waiting for
        // its response, then immediately shut down. The high request ID keeps
        // this untracked response distinct from the generated client's calls.
        rpc.run(async {
            let socket = tokio::net::UnixStream::from_std(rpc.socket.try_clone().unwrap()).unwrap();
            let mut outgoing: transport::Framed<
                tarpc::Response<KernelResponse>,
                tarpc::ClientMessage<KernelRequest>,
            > = transport::framed(socket);
            let mut id = Family::V6.policy(PolicyDirection::Outbound);
            id.interface_id = 99;
            outgoing
                .send(tarpc::ClientMessage::Request(tarpc::Request {
                    context: ctx(),
                    id: u64::MAX,
                    message: KernelRequest::InstallPolicy {
                        id,
                        config: policy_config(Family::V4, 0x10001),
                    },
                }))
                .await
                .unwrap();
        })
        .await;
    }
    if let Some(signal) = signal {
        daemon.signal(signal);
    } else {
        drop(rpc);
    }
    assert_eq!(
        daemon.wait().await.code(),
        Some(if signal.is_some() { 0 } else { 1 })
    );
    assert_empty().await;
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn shutdown_without_active_session_also_cleans_leftovers(
    mut daemon: Fixture,
    #[values(false, true)] after_clean_close: bool,
) {
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    if after_clean_close {
        let rpc = daemon.session().await;
        rpc.close().await;
    }
    leftovers();
    daemon.signal(Signal::SIGTERM);
    assert_eq!(daemon.wait().await.code(), Some(0));
    assert_empty().await;
}

#[rstest]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires root and iproute2; creates a network namespace"]
async fn stopped_session_resumes_notifications_and_shuts_down_cleanly(mut daemon: Fixture) {
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    let rpc = daemon.session().await;
    populate(&rpc).await;
    let original = owned_links().await[0].index;
    daemon.signal(Signal::SIGSTOP);
    eventually(async || {
        fs::read_to_string(format!("/proc/{}/status", daemon.process.id()))
            .unwrap()
            .lines()
            .any(|line| line.starts_with("State:\tT"))
    })
    .await;
    daemon.signal(Signal::SIGCONT);
    rpc.call(rpc.kernel.query_sa(ctx(), Family::V4.sa(0x10001), 0))
        .await
        .unwrap();
    // Exercise notifications as well as request/reply after resuming.
    ip(&["link", "set", "ranet00000029", "mtu", "1280"]);
    eventually(async || {
        let links = owned_links().await;
        links.len() == 1 && links[0].index == original && links[0].mtu == 1400
    })
    .await;
    daemon.signal(Signal::SIGTERM);
    assert_eq!(daemon.wait().await.code(), Some(0));
    assert_empty().await;
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn active_session_prunes_unsolicited_native_objects(daemon: Fixture) {
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    let rpc = daemon.session().await;
    leftovers();
    eventually(async || {
        states().await.is_empty()
            && owned_links().await.is_empty()
            && LinuxPolicies::new()
                .await
                .unwrap()
                .list()
                .await
                .unwrap()
                .is_empty()
    })
    .await;
    assert_empty().await;
    rpc.close().await;
}

#[rstest]
#[case::default("ranet", 17227)]
#[case::custom("resume", 17229)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn fresh_session_discovers_leftovers_after_crash(
    namespace: common::netns::Netns,
    #[case] prefix: &str,
    #[case] group: u32,
    #[values("dummy", "bridge")] orphan_kind: &str,
) {
    let _namespace = namespace;
    ip(&["link", "add", "foreign", "type", "xfrm", "if_id", "77"]);
    let group_arg = group.to_string();
    let args = ["--ifname-prefix", prefix, "--interface-group", &group_arg];
    let owned = async || {
        links()
            .await
            .into_iter()
            .filter(|l| l.group == group)
            .collect::<Vec<_>>()
    };
    let name = format!("{prefix}00000029");
    let mut previous = Daemon::start(&args);
    let rpc = previous.session().await;
    populate(&rpc).await;
    let previous_index = owned().await[0].index;
    ip(&[
        "link",
        "set",
        &name,
        "alias",
        "retained-after-crash",
        "txqueuelen",
        "321",
    ]);
    previous.signal(Signal::SIGKILL);
    assert!(!previous.wait().await.success());
    drop(rpc);
    assert!(!states().await.is_empty() && !owned().await.is_empty());
    assert_eq!(owned().await[0].index, previous_index);
    ip(&["link", "set", &name, "type", "xfrm", "if_id", "170"]);
    ip(&[
        "link",
        "set",
        &name,
        "down",
        "mtu",
        "1280",
        "multicast",
        "off",
    ]);
    ip(&[
        "link",
        "add",
        "owned-orphan",
        "group",
        &group_arg,
        "type",
        orphan_kind,
    ]);
    let mut next = Daemon::start(&args);
    let rpc = next.session().await;
    assert_empty_in_group(group).await;
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        Family::V4.sa(0x10002),
        sa_config(Cipher::Gcm, false, true),
    ))
    .await
    .unwrap();
    let recovered = owned().await.pop().unwrap();
    assert_ne!(recovered.index, previous_index);
    assert_eq!(
        (recovered.name.as_str(), recovered.mtu, recovered.xfrm_if_id),
        (name.as_str(), 1400, Some(41))
    );
    assert!(!ip(&["-d", "link", "show", "dev", &name]).contains("retained-after-crash"));
    rpc.call(rpc.kernel.flush_sas(ctx())).await.unwrap();
    rpc.close().await;
    next.signal(Signal::SIGTERM);
    assert_eq!(next.wait().await.code(), Some(0));
    assert_empty_in_group(group).await;
}

#[rstest]
#[case::custom("resume", 17229, 1380)]
#[case::longest_prefix("abcdefg", 17230, 1280)]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn custom_interface_settings_and_group_ownership(
    namespace: common::netns::Netns,
    #[case] prefix: &str,
    #[case] group: u32,
    #[case] mtu: u32,
) {
    let _namespace = namespace;
    let mut daemon = Daemon::start(&[
        "--ifname-prefix",
        prefix,
        "--interface-group",
        &group.to_string(),
        "--mtu",
        &mtu.to_string(),
    ]);
    let rpc = daemon.session().await;
    let name = format!("{prefix}00000029");
    let foreign_name = format!("{prefix}0000002a");
    ip(&[
        "link",
        "add",
        &name,
        "group",
        &group.to_string(),
        "type",
        "dummy",
    ]);
    ip(&[
        "link",
        "add",
        &foreign_name,
        "group",
        &(group + 1).to_string(),
        "type",
        "dummy",
    ]);
    rpc.call(rpc.kernel.install_sa(
        ctx(),
        Family::V4.sa(0x10001),
        sa_config(Cipher::Gcm, false, true),
    ))
    .await
    .unwrap();
    let native = links().await.into_iter().find(|l| l.name == name).unwrap();
    assert_eq!(
        (native.group, native.mtu, native.xfrm_if_id),
        (group, mtu, Some(41))
    );
    let foreign = links()
        .await
        .into_iter()
        .find(|l| l.name == foreign_name)
        .unwrap();
    let mut conflict = Family::V4.sa(0x10002);
    conflict.interface_id = 42;
    assert_eq!(
        rpc.call(
            rpc.kernel
                .install_sa(ctx(), conflict, sa_config(Cipher::Gcm, false, true))
        )
        .await,
        Err(Error::Kernel(libc::EEXIST))
    );
    assert_eq!(
        states().await.len(),
        1,
        "failed interface creation must roll back the SA"
    );
    rpc.call(rpc.kernel.flush_sas(ctx())).await.unwrap();
    rpc.close().await;
    daemon.signal(Signal::SIGTERM);
    assert_eq!(daemon.wait().await.code(), Some(0));
    assert!(!links().await.iter().any(|l| l.group == group));
    assert!(links().await.iter().any(|l| l.name == foreign_name
        && l.index == foreign.index
        && l.group == group + 1
        && l.xfrm_if_id.is_none()));
}

#[rstest]
#[ignore = "requires root and iproute2; creates a network namespace"]
#[tokio::test(flavor = "current_thread")]
async fn socket_permissions_authorize_groups(namespace: common::netns::Netns) {
    let _namespace = namespace;
    let mut daemon = Daemon::start(&["--group", "65534"]);
    let metadata = fs::metadata(&daemon.path).unwrap();
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
        (0, 65534, 0o660)
    );
    // Re-enter this Rust test binary under setpriv, without changing the test
    // runner's process-wide credentials or introducing a helper protocol.
    for (member, gid) in [(true, "65534"), (false, "65533")] {
        let status = Command::new("setpriv")
            .args([
                "--reuid=65533",
                "--regid",
                gid,
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lifecycle::unprivileged_socket_probe",
                "--ignored",
            ])
            .env("KERNEL_TEST_SOCKET", &daemon.path)
            .env("KERNEL_TEST_MEMBER", if member { "yes" } else { "no" })
            .status()
            .unwrap();
        assert!(status.success());
    }
    daemon.signal(Signal::SIGTERM);
    assert_eq!(daemon.wait().await.code(), Some(0));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "subprocess probe used by socket_permissions_authorize_groups"]
async fn unprivileged_socket_probe() {
    let Ok(path) = std::env::var("KERNEL_TEST_SOCKET") else {
        return;
    };
    assert_ne!(nix::unistd::Uid::effective().as_raw(), 0);
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(status.contains(&format!("{field}:\t0000000000000000")));
    }
    if std::env::var("KERNEL_TEST_MEMBER").unwrap() == "yes" {
        let rpc = Rpc::connect(&path.into()).await;
        rpc.open(SessionConfig::default()).await;
        populate(&rpc).await;
        assert_eq!(
            rpc.call(rpc.kernel.query_sa(ctx(), Family::V4.sa(0x10001), 0))
                .await
                .unwrap(),
            SaUsage::default()
        );
        assert_eq!(
            rpc.call(
                rpc.kernel
                    .query_policy(ctx(), Family::V4.policy(PolicyDirection::Outbound))
            )
            .await
            .unwrap(),
            0
        );
        for family in [Family::V4, Family::V6] {
            assert_eq!(
                rpc.call(rpc.kernel.get_interface(ctx(), family.local()))
                    .await
                    .unwrap(),
                "underlay"
            );
            assert_eq!(
                rpc.call(
                    rpc.kernel
                        .get_source_address(ctx(), family.peer(), Some(family.local()))
                )
                .await
                .unwrap(),
                family.local()
            );
        }
        assert!(!rpc
            .call(rpc.kernel.list_addresses(ctx(), AddressTypes::REGULAR))
            .await
            .unwrap()
            .is_empty());
        assert!(!rpc
            .call(rpc.kernel.list_subnets(ctx()))
            .await
            .unwrap()
            .is_empty());
        rpc.events().await;
        rpc.call(rpc.kernel.flush_sas(ctx())).await.unwrap();
        rpc.call(rpc.kernel.flush_policies(ctx())).await.unwrap();
        rpc.close().await;
    } else {
        assert_eq!(
            std::os::unix::net::UnixStream::connect(path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
