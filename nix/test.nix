{
  pkgs,
  module,
  package,
}:
let
  abiPrefix = pkgs.symlinkJoin {
    name = "kernel-rust-abi-prefix";
    paths = [
      package.strongswan
      package
    ];
  };
  # Disposable credentials for raw-public-key authentication coverage.
  testKeys = pkgs.runCommand "kernel-rust-test-keys" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p "$out"
    for peer in 1 2; do
      openssl genpkey -algorithm ED25519 -out "$out/peer-$peer.pem"
      openssl pkey -in "$out/peer-$peer.pem" -pubout -out "$out/peer-$peer.pub.pem"
    done
  '';
  connection = peer: proposal: connectionWithMode peer proposal "tunnel";
  connectionWithMode =
    peer: proposal: mode:
    connectionWithAuth peer proposal mode "psk";
  connectionWithAuth =
    peer: proposal: mode: auth:
    let
      config = pkgs.writeText "swanctl-${toString peer}-${proposal}-${mode}-${auth}.conf" ''
        connections {
          tunnel {
            version = 2
            local_addrs = 192.0.2.${toString peer}
            remote_addrs = 192.0.2.${toString (3 - peer)}
            local_port = 13000
            remote_port = 13000
            proposals = aes128-sha256-x25519
            # The Rust backend must force ESP-in-UDP without a connection override.
            encap = no
            mobike = no
            if_id_in = ${if peer == 1 then "%unique" else "42"}
            if_id_out = ${if peer == 1 then "%unique" else "42"}
            local {
              auth = ${auth}
              ${pkgs.lib.optionalString (
                auth == "pubkey"
              ) "pubkeys = ${testKeys}/peer-${toString peer}.pub.pem"}
              id = peer-${toString peer}
            }
            remote {
              auth = ${auth}
              ${pkgs.lib.optionalString (
                auth == "pubkey"
              ) "pubkeys = ${testKeys}/peer-${toString (3 - peer)}.pub.pem"}
              id = peer-${toString (3 - peer)}
            }
            children {
              net {
                local_ts = 0.0.0.0/0, ::/0
                remote_ts = 0.0.0.0/0, ::/0
                mode = ${mode}
                icmp = yes
                esp_proposals = ${proposal}
                tfc_padding = ${if mode == "iptfs" then "0" else "256"}
                set_mark_out = 123
                rekey_time = 300s
                life_time = 600s
                rand_time = 0s
              }
            }
          }
        }
        secrets {
          ike-test {
            id-1 = peer-1
            id-2 = peer-2
            secret = "only-for-the-nixos-vm-test"
          }
        }
      '';
      # --file makes swanctl search beside that configuration for credentials.
      credentials = pkgs.runCommand "swanctl-${toString peer}-${proposal}-${mode}-pubkey" { } ''
        mkdir -p "$out/private"
        cp ${config} "$out/swanctl.conf"
        ln -s ${testKeys}/peer-${toString peer}.pem "$out/private/test.pem"
      '';
    in
    if auth == "pubkey" then "${credentials}/swanctl.conf" else config;

  node =
    peer:
    { config, lib, ... }:
    let
      native = peer == 2;
      master = if native then "gravity" else "overlay";
    in
    {
      imports = [ module ];
      services.charon-kernel = {
        enable = !native;
        mtu = 1380;
        interfaceNamePrefix = "gn";
        interfaceGroup = 17228;
        masterDevice = master;
      };
      virtualisation = {
        vlans = [ 1 ];
        memorySize = 768;
        cores = 2;
      };
      boot.kernelModules = [
        "xfrm_user"
        "xfrm_interface"
        "esp4"
        "esp6"
        "xfrm_iptfs"
        "vrf"
      ];
      # Tokio/tarpc read the clock frequently. The test harness's emulated ACPI
      # clock is costly under nested KVM; use its paravirtual clock for VICI.
      boot.kernelParams = lib.mkAfter (
        lib.optional pkgs.stdenv.hostPlatform.isx86_64 "clocksource=kvm-clock"
      );
      networking = {
        useDHCP = false;
        interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.0.2.${toString peer}";
            prefixLength = 24;
          }
        ];
        firewall = {
          allowedUDPPorts = [ 13000 ];
          checkReversePath = false;
        };
      };
      environment.systemPackages = [
        pkgs.iproute2
        pkgs.python3
        pkgs.util-linux
      ]
      ++ lib.optional native package.strongswan;
      environment.pathsToLink = lib.mkIf native [ "/lib/ipsec/plugins" ];
      services.strongswan-swanctl.enable = lib.mkIf native true;
      services.strongswan-swanctl.package = lib.mkIf native package.strongswan;
      systemd.services =
        if native then
          {
            strongswan-swanctl.serviceConfig.RuntimeDirectory = "strongswan";
          }
        else
          lib.genAttrs [ "strongswan-swanctl" "charon-kernel" ] (name: {
            postStart =
              "${pkgs.python3}/bin/python3 ${../tests/hardening.py} "
              + (if name == "strongswan-swanctl" then "strongswan" else name)
              + " ${pkgs.keyutils}/bin/keyctl";
          });
      systemd.network = {
        enable = true;
        netdevs = {
          "20-overlay-vrf" = {
            netdevConfig = {
              Name = master;
              Kind = "vrf";
            };
            vrfConfig.Table = 42;
          };
          "20-overlay-addresses".netdevConfig = {
            Name = "overlay0";
            Kind = "dummy";
          };
        }
        // lib.optionalAttrs native {
          # kernel-netlink installs SAs/policies but does not create XFRM links.
          "20-ipsec" = {
            netdevConfig = {
              Name = "stock0000002a";
              Kind = "xfrm";
              MTUBytes = "1400";
            };
            xfrmConfig = {
              InterfaceId = 42;
              Independent = true;
            };
          };
        };
        networks = {
          "20-overlay-vrf" = {
            matchConfig.Name = master;
            networkConfig.LinkLocalAddressing = "no";
          };
          "20-overlay-addresses" = {
            matchConfig.Name = "overlay0";
            address = [
              "10.${toString peer}.0.1/32"
              "fd10:${toString peer}::1/128"
            ];
            networkConfig = {
              VRF = master;
              LinkLocalAddressing = "no";
            };
          };
          # Networkd owns the upstream peer's static link. On the Rust peer it
          # only reapplies addresses/routes when the daemon recreates the link.
          "30-ipsec" = {
            matchConfig.Name = if native then "stock*" else "gn*";
            linkConfig = {
              RequiredForOnline = false;
              ActivationPolicy = if native then "up" else "manual";
            }
            // lib.optionalAttrs native { Multicast = true; };
            networkConfig = {
              KeepMaster = !native;
              ConfigureWithoutCarrier = true;
              LinkLocalAddressing = "no";
              IPv6AcceptRA = false;
            }
            // lib.optionalAttrs native { VRF = master; };
            address = [
              "198.18.${toString peer}.1/32"
              "fd20:${toString peer}::1/128"
            ];
            routes = [
              {
                Destination = "10.${toString (3 - peer)}.0.1/32";
                Table = 42;
                Scope = "link";
              }
              {
                Destination = "fd10:${toString (3 - peer)}::1/128";
                Table = 42;
              }
            ];
          };
        };
      };

      services.strongswan-swanctl.strongswan.extraConfig = ''
        charon {
          port = 0
          port_nat_t = 13000
          install_routes = no
          load_modular = yes
          iptfs {
            drop_time = 500000
            reorder_window = 5
            init_delay = 100000
            max_queue_size = 262144
            packet_size = 512
          }
          plugins {
            include ${config.services.strongswan-swanctl.package}/share/strongswan/templates/config/plugins/*.conf
            kernel-netlink {
              load = ${if native then "yes" else "no"}
            }
            kernel-rust {
              load = ${if native then "no" else "yes"}
            }
          }
        }
      '';
    };
in
{
  name = "strongswan-kernel-rust";
  nodes = {
    left = node 1;
    right = node 2;
  };

  testScript = ''
    import json
    import re
    import time

    machines = [left, right]
    interface_settings = [("gn", 1380, "overlay"), ("stock", 1400, "gravity")]
    interface_groups = [17228, 0]
    capability_fields = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]

    def ctl(machine, arguments):
        return machine.succeed("swanctl " + arguments)

    def links(machine):
        return json.loads(machine.succeed("ip -N -j -d link show type xfrm"))

    def indices(machine):
        return {link["ifname"]: link["ifindex"] for link in links(machine)}

    def spis(machine):
        return set(re.findall(r"spi (0x[0-9a-f]+)", machine.succeed("ip xfrm state")))

    def matched_value(pattern, text):
        match = re.search(pattern, text)
        assert match is not None, text
        return match[1]

    def policy_specs(machine):
        return set(re.split(r"(?=^src )", machine.succeed("ip xfrm policy list nosock"), flags=re.M)[1:])

    def process_status(machine, unit):
        pid = property(machine, unit, "MainPID")
        assert int(pid) > 1
        return dict(
            line.split(":", 1)
            for line in machine.succeed("cat /proc/" + pid + "/status").splitlines()
            if ":" in line
        )

    def property(machine, unit, name):
        return machine.succeed("systemctl show " + unit + " -p " + name + " --value").strip()

    def assert_stopped(machine, unit):
        machine.wait_until_succeeds(
            "systemctl show " + unit + " -p ActiveState --value | grep -Eq '^(inactive|failed)$'"
        )
        assert property(machine, unit, "MainPID") == "0"

    def assert_start_order(machine):
        daemon_ready = int(property(machine, "charon-kernel.service", "ActiveEnterTimestampMonotonic"))
        ike_started = int(property(machine, "strongswan-swanctl.service", "ExecMainStartTimestampMonotonic"))
        assert 0 < daemon_ready < ike_started, (daemon_ready, ike_started)

    def assert_stop_order(machine):
        ike_exited = int(property(machine, "strongswan-swanctl.service", "InactiveEnterTimestampMonotonic"))
        daemon_exited = int(property(machine, "charon-kernel.service", "ExecMainExitTimestampMonotonic"))
        assert 0 < ike_exited < daemon_exited, (ike_exited, daemon_exited)

    def assert_empty(machine):
        assert not spis(machine) and not links(machine)
        assert not machine.succeed("ip xfrm policy list nosock").strip()

    def pair_pids(machine):
        return {
            unit: property(machine, unit, "MainPID")
            for unit in ["strongswan-swanctl.service", "charon-kernel.service"]
        }

    def assert_recovered(machine, previous):
        # No systemctl start/restart here: recovery must be automatic.
        for unit, pid in previous.items():
            machine.wait_until_succeeds(
                "systemctl is-active --quiet " + unit
                + " && test $(systemctl show " + unit + " -p MainPID --value) != " + pid
            )
            machine.wait_for_unit(unit)
        assert_start_order(machine)
        assert "kernel-rust" in ctl(machine, "--stats")
        assert not spis(machine) and not links(machine)
        remaining = policy_specs(machine)
        assert remaining and all(
            "priority 32" in policy and "proto udp" in policy and "if_id" not in policy
            for policy in remaining
        ), remaining
        ike_pid = property(machine, "strongswan-swanctl.service", "MainPID")
        bound_ports = {
            int(line.split()[3].rsplit(":", 1)[1])
            for line in machine.succeed("ss -H -u -l -n -p").splitlines()
            if "pid=" + ike_pid + "," in line
        }
        bypass_ports = {int(matched_value(r"[sd]port (\d+)", policy)) for policy in remaining}
        assert bound_ports and bypass_ports == bound_ports, (bound_ports, remaining)
        assert len(remaining) == 4 * len(bound_ports), remaining

    def ping_overlay(machine, peer):
        other = 3 - peer
        master = interface_settings[peer - 1][2]
        machine.succeed(f"ip vrf exec {master} ping -c 3 -W 2 -I 10.{peer}.0.1 10.{other}.0.1")
        machine.succeed(f"ip vrf exec {master} ping -6 -c 3 -W 2 -I fd10:{peer}::1 fd10:{other}::1")

    def wait_interface(machine, peer, interface):
        prefix, mtu, master = interface_settings[peer - 1]
        for attempt in range(100):
            current = links(machine)
            if (len(current) == 1 and current[0]["ifname"] == interface
                    and current[0]["mtu"] == mtu and current[0].get("master") == master
                    and int(current[0].get("group", 0)) == interface_groups[peer - 1]
                    and {"UP", "MULTICAST"} <= set(current[0]["flags"])):
                return current[0]
            time.sleep(0.1)
        raise AssertionError(f"interface reconciliation did not restore {interface}: {current}")

    def wait_overlay_config(machine, peer, interface):
        other = 3 - peer
        machine.wait_until_succeeds(
            f"ip -o address show dev {interface} | grep -F '198.18.{peer}.1/32'"
        )
        machine.wait_until_succeeds(
            f"ip -o -6 address show dev {interface} | grep -F 'fd20:{peer}::1/128' | grep -v tentative"
        )
        for family, destination in [("-4", f"10.{other}.0.1/32"), ("-6", f"fd10:{other}::1/128")]:
            machine.wait_until_succeeds(
                f"ip {family} route show table 42 exact {destination} | grep -F 'dev {interface}'"
            )

    def sa_use_times(machine):
        listing = ctl(machine, "--list-sas --raw")
        result = {}
        for direction in ["in", "out"]:
            values = re.findall(rf"\buse-{direction}=(\d+)", listing)
            assert len(values) == 1, listing
            result[direction] = int(values[0])
        return result

    start_all()
    with subtest("systemd runtime directories and least privilege"):
        for peer, machine in enumerate(machines, 1):
            machine.wait_for_unit("strongswan-swanctl.service")
            machine.wait_for_unit("systemd-networkd.service")
            machine.wait_until_succeeds(
                f"ip -o -6 address show dev overlay0 | grep -F 'fd10:{peer}::1/128' | grep -v tentative"
            )
            statistics = ctl(machine, "--stats")
            if machine is right:
                assert "kernel-netlink" in statistics and "kernel-rust" not in statistics
                assert property(machine, "charon-kernel.service", "LoadState") == "not-found"
                machine.succeed("test ! -e /run/charon-kernel")
                machine.succeed("test ! -e /run/current-system/sw/lib/ipsec/plugins/libstrongswan-kernel-rust.so")
                ike = process_status(machine, "strongswan-swanctl.service")
                assert int(ike["CapEff"], 16) & (1 << 12), ike
                assert not spis(machine)
                wait_interface(machine, peer, "stock0000002a")
                wait_overlay_config(machine, peer, "stock0000002a")
                continue
            machine.wait_for_unit("charon-kernel.service")
            assert_start_order(machine)
            assert "charon-kernel.service" in property(machine, "strongswan-swanctl.service", "Requires").split()
            assert not property(machine, "strongswan-swanctl.service", "BindsTo").split()
            assert "charon-kernel.service" in property(machine, "strongswan-swanctl.service", "After").split()
            assert "strongswan-swanctl.service" in property(machine, "charon-kernel.service", "PartOf").split()
            assert "strongswan-swanctl.service" in property(machine, "charon-kernel.service", "Wants").split()
            assert property(machine, "charon-kernel.service", "StopWhenUnneeded") == "yes"
            for unit in ["strongswan-swanctl.service", "charon-kernel.service"]:
                assert property(machine, unit, "Restart") == "always"
            machine.succeed("test -S /run/charon-kernel/charon-kernel.sock")
            assert property(machine, "charon-kernel.service", "Type") == "notify"
            backend = process_status(machine, "charon-kernel.service")
            backend_uid = int(backend["Uid"].split()[0])
            assert 61184 <= backend_uid <= 65519
            for field in capability_fields:
                assert int(backend[field], 16) == 1 << 12, backend
            assert backend["NoNewPrivs"].strip() == "1"
            assert set(machine.succeed(
                "systemctl show charon-kernel.service -p RestrictAddressFamilies --value"
            ).split()) == {"AF_UNIX", "AF_NETLINK"}
            socket_stat = machine.succeed(
                "stat -c '%u %G %a' /run/charon-kernel/charon-kernel.sock"
            ).split()
            assert socket_stat == [str(backend_uid), "ipsec", "660"]
            machine.succeed(
                "test -e /run/current-system/sw/lib/ipsec/plugins/libstrongswan-kernel-rust.so"
            )
            machine.fail(
                "setpriv --reuid=65534 --regid=65534 --clear-groups python3 -c "
                + "\"import socket; socket.socket(socket.AF_UNIX).connect("
                + "'/run/charon-kernel/charon-kernel.sock')\""
            )
            ike = process_status(machine, "strongswan-swanctl.service")
            ike_uid = int(ike["Uid"].split()[0])
            assert 61184 <= ike_uid <= 65519 and ike_uid != backend_uid
            for field in capability_fields:
                assert int(ike[field], 16) == 0, ike
            host_ipc = machine.succeed("readlink /proc/1/ns/ipc").strip()
            service_ipc = []
            for unit, runtime in [("charon-kernel.service", "charon-kernel"),
                                  ("strongswan-swanctl.service", "strongswan")]:
                pid = property(machine, unit, "MainPID")
                service_ipc.append(machine.succeed(f"readlink /proc/{pid}/ns/ipc").strip())
                machine.succeed(f"journalctl -u {unit} --no-pager | grep -F 'sandbox probe passed'")
                assert machine.succeed(f"stat -c %a /run/{runtime}").strip() == "750"
            assert host_ipc not in service_ipc and len(set(service_ipc)) == 2
            assert set(property(machine, "strongswan-swanctl.service", "RestrictAddressFamilies").split()) == {
                "AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"
            }
            assert "kernel-rust" in statistics and "kernel-netlink" not in statistics
            assert not links(machine) and not spis(machine)
            controller = machine.succeed(
                "systemd-run --quiet --wait --pipe --collect "
                "--property=DynamicUser=yes --property=SupplementaryGroups=ipsec "
                "--property=CapabilityBoundingSet= --property=AmbientCapabilities= "
                + machine.succeed("command -v swanctl").strip() + " --stats"
            )
            assert "kernel-rust" in controller

    with subtest("C ABI and complete IPv6 endpoints through tarpc"):
        left.succeed("unshare --net python3 ${../tests/plugin.py} ${abiPrefix}")

    with subtest("VICI stays responsive with 200 connections and continuous route updates"):
        left.succeed(
            "PYTHONPATH=${pkgs.strongswan.src}/src/libcharon/plugins/vici/python "
            "timeout 45s python3 ${../tests/vici_churn.py}"
        )
        assert not links(left) and not spis(left)

    proposals = [
        ("AES-GCM", "${connection 1 "aes128gcm128-esn"}", "${connection 2 "aes128gcm128-esn"}", "rfc4106(gcm(aes))"),
        ("AES-CBC/HMAC", "${connection 1 "aes128-sha256-esn"}", "${connection 2 "aes128-sha256-esn"}", "cbc(aes)"),
        ("Ed25519/AES-GCM", "${connectionWithAuth 1 "aes128gcm128-esn" "tunnel" "pubkey"}", "${
          connectionWithAuth 2 "aes128gcm128-esn" "tunnel" "pubkey"
        }", "rfc4106(gcm(aes))"),
    ]
    for proposal_index, (name, left_config, right_config, algorithm) in enumerate(proposals):
        with subtest(name + ": IKE, ESP-in-UDP, wildcard selectors and IPv4/IPv6 traffic"):
            for machine, config_file in zip(machines, [left_config, right_config]):
                ctl(machine, "--load-all --noprompt --file " + config_file)
            # Exercise each implementation as both initiator and responder.
            initiator = machines[proposal_index % len(machines)]
            assert "established" in ctl(initiator, "--initiate --child net")
            original_indices = []
            for peer, machine in enumerate(machines, 1):
                listing = ctl(machine, "--list-sas --raw")
                match = re.search(r"if-id-out=([0-9a-f]+)", listing)
                assert match is not None, listing
                prefix, mtu, master = interface_settings[peer - 1]
                name_out = f"{prefix}{int(match[1], 16):08x}"
                current = links(machine)
                assert len(current) == 1 and current[0]["ifname"] == name_out, current
                assert current[0]["mtu"] == mtu and {"UP", "MULTICAST"} <= set(current[0]["flags"]), current
                assert current[0]["master"] == master, current
                assert int(current[0].get("group", 0)) == interface_groups[peer - 1], current
                original_indices.append(indices(machine))
                wait_overlay_config(machine, peer, name_out)
            for peer, machine in enumerate(machines, 1):
                ping_overlay(machine, peer)
                state = machine.succeed("ip -s xfrm state")
                assert algorithm in state, state
                assert "output-mark 0x7b" in state, state
                assert "encap type espinudp sport 13000 dport 13000" in state, state
                assert "tfcpad 256" in state, state
                state_blocks = re.split(r"(?=^src )", state, flags=re.M)[1:]
                assert all(("icmp" in block) == ("dir in" in block) for block in state_blocks), state
                for policy in policy_specs(machine):
                    if "if_id" in policy:
                        assert ("flag icmp" in policy) == ("dir out" in policy), policy
                assert any(int(value) > 0 for value in re.findall(r"(\d+)\(packets\)", state))

        with subtest(name + ": policy flush recovers without replacing SAs or interfaces"):
            expected_policies = [policy_specs(machine) for machine in machines]
            original_spis = [spis(machine) for machine in machines]
            left.succeed("ip xfrm policy flush")
            for peer, machine in enumerate(machines, 1):
                for attempt in range(100):
                    if policy_specs(machine) == expected_policies[peer - 1]:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("policy reconciliation did not restore the tunnel")
                assert spis(machine) == original_spis[peer - 1]
                assert indices(machine) == original_indices[peer - 1]
                ping_overlay(machine, peer)

        with subtest(name + ": interface settings repair preserves SAs and interface indices"):
            original_spis = [spis(machine) for machine in machines]
            expected_policies = [policy_specs(machine) for machine in machines]
            interface = next(iter(original_indices[0]))
            left.succeed(f"ip link set dev {interface} alias user-managed txqueuelen 123 promisc on")
            left.succeed(f"ip link set dev {interface} nomaster")
            left.succeed(f"ip link set dev {interface} down mtu 1280 multicast off")
            for peer, machine in enumerate(machines, 1):
                interface = next(iter(original_indices[peer - 1]))
                repaired = wait_interface(machine, peer, interface)
                if machine is left:
                    assert repaired["ifalias"] == "user-managed" and repaired["txqlen"] == 123, repaired
                    assert "PROMISC" in repaired["flags"], repaired
                assert indices(machine) == original_indices[peer - 1]
                assert spis(machine) == original_spis[peer - 1]
                assert policy_specs(machine) == expected_policies[peer - 1]
                wait_overlay_config(machine, peer, interface)
                ping_overlay(machine, peer)

        for mutation in ["deleted", "renamed"]:
            with subtest(name + f": {mutation} interfaces recover with networkd addresses and routes"):
                original_spis = [spis(machine) for machine in machines]
                expected_policies = [policy_specs(machine) for machine in machines]
                interface = next(iter(original_indices[0]))
                if mutation == "deleted":
                    left.succeed(f"ip link del dev {interface}")
                else:
                    left.succeed(f"ip link set dev {interface} name renamed")
                for peer, machine in enumerate(machines, 1):
                    interface = next(iter(original_indices[peer - 1]))
                    recreated = wait_interface(machine, peer, interface)
                    if machine is left:
                        assert recreated["ifindex"] != original_indices[peer - 1][interface]
                        if mutation == "renamed":
                            machine.fail("ip link show dev renamed")
                    else:
                        assert indices(machine) == original_indices[peer - 1]
                    assert spis(machine) == original_spis[peer - 1]
                    assert policy_specs(machine) == expected_policies[peer - 1]
                    wait_overlay_config(machine, peer, interface)
                    ping_overlay(machine, peer)
                    original_indices[peer - 1] = indices(machine)

        with subtest(name + ": VICI SA use times age while idle and reset after traffic"):
            # Stop background traffic before XFRM processing during the idle interval.
            tunnels = [(machine, next(iter(current)))
                       for machine, current in zip(machines, original_indices)]
            for machine, interface in tunnels:
                machine.succeed(f"tc qdisc add dev {interface} clsact")
                machine.succeed(f"tc filter add dev {interface} egress matchall action drop")
            recent = [sa_use_times(machine) for machine in machines]
            assert all(0 <= value <= 10 for usage in recent for value in usage.values()), recent
            time.sleep(3)
            for machine, previous in zip(machines, recent):
                idle = sa_use_times(machine)
                assert all(2 <= idle[direction] - previous[direction] <= 10
                           for direction in previous), (previous, idle)
            for machine, interface in tunnels:
                machine.succeed(f"tc qdisc del dev {interface} clsact")
            left.succeed("ip vrf exec overlay ping -c 1 -W 2 -I 10.1.0.1 10.2.0.1")
            for machine in machines:
                usage = sa_use_times(machine)
                assert all(0 <= value <= 2 for value in usage.values()), usage

        with subtest(name + ": rekey keeps interface indices and traffic working"):
            previous_spis = spis(left)
            ctl(left, "--rekey --child net")
            for attempt in range(100):
                if spis(left) - previous_spis:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("rekey did not install new SAs")
            for peer, machine in enumerate(machines, 1):
                ping_overlay(machine, peer)
                assert indices(machine) == original_indices[peer - 1]
                assert all(link["master"] == interface_settings[peer - 1][2]
                           and "MULTICAST" in link["flags"] for link in links(machine))

        for mutation in ["inbound", "outbound", "flush", "drift", "rekey-flush"]:
            with subtest(name + ": SA " + mutation + " recovers through fresh CHILD negotiation"):
                old_spis = [spis(machine) for machine in machines]
                ike_ids = [matched_value(r"\buniqueid=(\d+)", ctl(machine, "--list-sas --raw"))
                           for machine in machines]
                pids = [property(machine, "strongswan-swanctl.service", "MainPID")
                        for machine in machines]
                if mutation == "rekey-flush":
                    # Hold the peer's replies long enough to lose the old SAs
                    # while a real rekey exchange is in flight.
                    right.succeed("tc qdisc add dev eth1 root netem delay 500ms")
                    ctl(left, "--rekey --child net")
                try:
                    if mutation in ["flush", "rekey-flush"]:
                        left.succeed("ip xfrm state flush")
                    else:
                        blocks = re.split(r"(?=^src )", left.succeed("ip xfrm state"), flags=re.M)[1:]
                        direction = "in" if mutation == "inbound" else "out"
                        state = next(block for block in blocks if "dir " + direction in block)
                        destination = matched_value(r"^src \S+ dst (\S+)", state)
                        spi = matched_value(r"\bspi (0x[0-9a-f]+)", state)
                        if mutation != "drift":
                            left.succeed(f"ip xfrm state delete dst {destination} proto esp spi {spi}")
                        else:
                            # UPDSA preserves running crypto state but changes
                            # the output mark. Our backend must retire it.
                            source = matched_value(r"^src (\S+)", state)
                            if algorithm == "rfc4106(gcm(aes))":
                                crypto = "aead 'rfc4106(gcm(aes))' 0x" + "00" * 20 + " 128"
                            else:
                                crypto = ("enc 'cbc(aes)' 0x" + "00" * 16
                                          + " auth-trunc 'hmac(sha256)' 0x" + "00" * 32 + " 128")
                            left.succeed(
                                f"ip xfrm state update src {source} dst {destination} proto esp spi {spi} "
                                f"mode tunnel {crypto} encap espinudp 13000 13000 0.0.0.0 "
                                "output-mark 999 dir out"
                            )
                    for attempt in range(150):
                        current = [spis(machine) for machine in machines]
                        if all(len(now) >= 2 and not now.intersection(old)
                               for now, old in zip(current, old_spis)):
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("lost/drifted SAs did not get replaced")
                    for peer, machine in enumerate(machines, 1):
                        assert property(machine, "strongswan-swanctl.service", "MainPID") == pids[peer - 1]
                        assert matched_value(r"\buniqueid=(\d+)", ctl(machine, "--list-sas --raw")) == ike_ids[peer - 1]
                        interface = next(iter(original_indices[peer - 1]))
                        wait_interface(machine, peer, interface)
                        wait_overlay_config(machine, peer, interface)
                        ping_overlay(machine, peer)
                        if mutation == "flush" and peer == 1:
                            assert indices(machine)[interface] != original_indices[0][interface]
                        original_indices[peer - 1] = indices(machine)
                finally:
                    if mutation == "rekey-flush":
                        right.succeed("tc qdisc del dev eth1 root")

        with subtest(name + ": final-SA cleanup removes only the Rust-managed interface"):
            ctl(left, "--terminate --ike tunnel")
            for peer, machine in enumerate(machines, 1):
                machine.wait_until_succeeds("test -z \"$(ip xfrm state)\"")
                if machine is left:
                    machine.wait_until_succeeds("test \"$(ip -j link show type xfrm)\" = '[]'")
                else:
                    assert indices(machine) == original_indices[peer - 1]
                master = interface_settings[peer - 1][2]
                machine.succeed(f"ip link show dev {master}")
                policies = machine.succeed("ip xfrm policy list nosock")
                if machine is left:
                    assert "if_id" not in policies and "priority 32" in policies, policies
                else:
                    # The native backend's bypasses are socket policies.
                    assert not policies.strip(), policies

    with subtest("IP-TFS interoperates with kernel-netlink, aggregates and fragments"):
        for machine, config_file in zip(machines, [
                "${connectionWithMode 1 "aes128gcm128-esn" "iptfs"}",
                "${connectionWithMode 2 "aes128gcm128-esn" "iptfs"}"]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        ctl(left, "--initiate --child net")
        iptfs_indices = [indices(machine) for machine in machines]
        # iproute2 7.1 prints the native XFRM_MODE_IPTFS value without a name.
        iptfs_mode = r"\bmode (?:iptfs|5)\b"
        for peer, machine in enumerate(machines, 1):
            wait_overlay_config(machine, peer, next(iter(iptfs_indices[peer - 1])))
            state = machine.succeed("ip -s xfrm state")
            assert len(re.findall(iptfs_mode, state)) == 2, state
            assert "tfcpad" not in state, state
            assert all(re.search(iptfs_mode, policy) for policy in policy_specs(machine) if "if_id" in policy)
            ping_overlay(machine, peer)

        def outbound_packets():
            state = left.succeed("ip -s xfrm state")
            block = next(block for block in re.split(r"(?=^src )", state, flags=re.M)[1:]
                         if "dir out" in block)
            return int(matched_value(r"(\d+)\(packets\)", block))

        before = outbound_packets()
        left.succeed("ip vrf exec overlay ping -c 4 -i 0.01 -W 3 -s 32 -I 10.1.0.1 10.2.0.1")
        assert 0 < outbound_packets() - before < 4, "small packets were not aggregated"
        before = outbound_packets()
        left.succeed("ip vrf exec overlay ping -c 1 -W 3 -M do -s 1200 -I 10.1.0.1 10.2.0.1")
        assert outbound_packets() - before > 1, "large inner packet was not fragmented"
        # A periodic audit and policy repair must preserve the mode/settings.
        expected_policies = policy_specs(left)
        previous_spis = spis(left)
        left.succeed("ip xfrm policy flush")
        for attempt in range(100):
            if policy_specs(left) == expected_policies:
                break
            time.sleep(0.1)
        assert policy_specs(left) == expected_policies
        time.sleep(5.3)
        assert spis(left) == previous_spis
        assert indices(left) == iptfs_indices[0]
        ctl(left, "--rekey --child net")
        for attempt in range(100):
            if spis(left) - previous_spis:
                break
            time.sleep(0.1)
        assert spis(left) - previous_spis, "IP-TFS rekey did not install new SAs"
        ping_overlay(left, 1)
        assert indices(left) == iptfs_indices[0]
        ctl(left, "--terminate --ike tunnel")
        for machine in machines:
            machine.wait_until_succeeds("test -z \"$(ip xfrm state)\"")
        assert not links(left)

    with subtest("strongSwan restart restarts the backend after cleaning live SAs"):
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        previous = {
            unit: property(left, unit, "MainPID")
            for unit in ["strongswan-swanctl.service", "charon-kernel.service"]
        }
        left.succeed("systemctl restart strongswan-swanctl.service")
        for unit, pid in previous.items():
            left.wait_for_unit(unit)
            assert property(left, unit, "MainPID") != pid
        assert "kernel-rust" in ctl(left, "--stats")
        assert_start_order(left)
        for machine in machines:
            machine.wait_until_succeeds("test -z \"$(ip xfrm state)\"")
        assert not links(left)
        assert indices(right) == original_indices[1]

    with subtest("restarting the backend also restarts its strongSwan dependent"):
        previous = property(left, "strongswan-swanctl.service", "MainPID")
        left.succeed("systemctl restart charon-kernel.service")
        left.wait_for_unit("strongswan-swanctl.service")
        assert property(left, "strongswan-swanctl.service", "MainPID") != previous
        assert "kernel-rust" in ctl(left, "--stats")
        assert_start_order(left)

    with subtest("stopping the backend stops charon before backend exit"):
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        left.succeed("systemctl stop charon-kernel.service")
        assert_stopped(left, "strongswan-swanctl.service")
        assert_stopped(left, "charon-kernel.service")
        assert_stop_order(left)
        assert_empty(left)
        left.succeed("systemctl start strongswan-swanctl.service")
        assert_start_order(left)

    with subtest("daemon SIGTERM cleans an active tunnel and automatically restarts the pair"):
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        retained = spis(left)
        assert retained and links(left)
        previous = pair_pids(left)
        left.succeed("systemctl kill --signal=TERM --kill-whom=main charon-kernel.service")
        assert_recovered(left, previous)

    with subtest("lost RPC cleans the kernel and automatically restarts both services"):
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        previous = pair_pids(left)
        assert spis(left) and links(left)
        left.succeed("python3 ${../tests/disconnect.py} " + previous["strongswan-swanctl.service"]
                     + " /run/charon-kernel/charon-kernel.sock")
        assert_recovered(left, previous)

    with subtest("strongSwan exiting without a stop job automatically restarts the pair"):
        previous = pair_pids(left)
        left.succeed("systemctl kill --signal=TERM --kill-whom=main strongswan-swanctl.service")
        assert_recovered(left, previous)

    with subtest("charon crash cleans its failed session and automatically restarts the pair"):
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        assert spis(left) and links(left)
        previous = pair_pids(left)
        left.succeed("systemctl kill --signal=KILL --kill-whom=main strongswan-swanctl.service")
        assert_recovered(left, previous)
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        for peer, machine in enumerate(machines, 1):
            wait_overlay_config(machine, peer, links(machine)[0]["ifname"])
            ping_overlay(machine, peer)

    with subtest("stopping strongSwan stops the backend and removes runtime directories"):
        for machine in machines:
            machine.succeed("systemctl stop strongswan-swanctl.service")
            machine.succeed("test ! -e /run/strongswan")
            machine.succeed("test ! -e /run/charon-kernel")
        assert_stopped(left, "charon-kernel.service")
        assert_stop_order(left)
        assert_empty(left)
        assert not spis(right)
        assert indices(right) == original_indices[1]
        assert not right.succeed("ip xfrm policy list nosock").strip()

    with subtest("persistent backend startup failure blocks charon and rate-limits retries"):
        left.succeed("mkdir -p /run/systemd/system/charon-kernel.service.d")
        left.succeed(
            "printf '[Service]\\nExecStartPre=/run/current-system/sw/bin/false\\n' "
            "> /run/systemd/system/charon-kernel.service.d/test-failure.conf"
        )
        left.succeed("systemctl daemon-reload")
        left.fail("systemctl start strongswan-swanctl.service")
        left.wait_until_succeeds(
            "test $(systemctl show charon-kernel.service -p Result --value) = start-limit-hit"
        )
        assert_stopped(left, "strongswan-swanctl.service")
        assert_stopped(left, "charon-kernel.service")
        left.succeed("rm /run/systemd/system/charon-kernel.service.d/test-failure.conf")
        left.succeed("systemctl daemon-reload && systemctl reset-failed")
        left.succeed("systemctl start strongswan-swanctl.service")
        assert "kernel-rust" in ctl(left, "--stats")
        assert_start_order(left)

    with subtest("backend crash automatically replaces charon and retires leftover kernel objects"):
        right.succeed("systemctl start strongswan-swanctl.service")
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        previous = pair_pids(left)
        assert spis(left) and links(left)
        left.succeed("systemctl kill --signal=KILL --kill-whom=main charon-kernel.service")
        assert_recovered(left, previous)
        for machine, config_file in zip(machines, [proposals[0][1], proposals[0][2]]):
            ctl(machine, "--load-all --noprompt --file " + config_file)
        assert "established" in ctl(left, "--initiate --child net")
        for peer, machine in enumerate(machines, 1):
            wait_overlay_config(machine, peer, links(machine)[0]["ifname"])
            ping_overlay(machine, peer)
        left.succeed("systemctl stop strongswan-swanctl.service")
        assert_empty(left)

    with subtest("a fresh strongSwan session retires global policy and SA leftovers"):
        left.succeed(
            "ip xfrm policy add src 203.0.113.0/24 dst 203.0.114.0/24 "
            "dev lo dir out mark 0x123 mask 0xfff if_id 77 action block"
        )
        assert "203.0.113.0/24" in left.succeed("ip xfrm policy list nosock")
        left.succeed(
            "ip xfrm state add src 192.0.2.1 dst 192.0.2.2 proto esp spi 0x77777 "
            "mode tunnel aead 'rfc4106(gcm(aes))' 0x" + "00" * 20 + " 128"
        )
        left.succeed("systemctl reset-failed && systemctl start strongswan-swanctl.service")
        left.wait_for_unit("strongswan-swanctl.service")
        assert "kernel-rust" in ctl(left, "--stats")
        assert not spis(left)
        remaining = policy_specs(left)
        assert all("priority 32" in policy and "proto udp" in policy
                   and "if_id" not in policy for policy in remaining), remaining
        left.succeed("systemctl stop strongswan-swanctl.service")
        assert_empty(left)
  '';
}
