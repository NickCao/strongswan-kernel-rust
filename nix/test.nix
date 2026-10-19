{ pkgs, module }:
let
  connection =
    peer: proposal:
    pkgs.writeText "swanctl-${toString peer}-${proposal}.conf" ''
      connections {
        tunnel {
          version = 2
          local_addrs = 192.0.2.${toString peer}
          remote_addrs = 192.0.2.${toString (3 - peer)}
          local_port = 13000
          remote_port = 13000
          proposals = aes128-sha256-x25519
          encap = yes
          mobike = no
          if_id_in = %unique
          if_id_out = %unique
          local {
            auth = psk
            id = peer-${toString peer}
          }
          remote {
            auth = psk
            id = peer-${toString (3 - peer)}
          }
          children {
            net {
              local_ts = 0.0.0.0/0, ::/0
              remote_ts = 0.0.0.0/0, ::/0
              mode = tunnel
              esp_proposals = ${proposal}
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

  node =
    peer:
    { config, lib, ... }:
    let
      master = if peer == 1 then "gravity" else "overlay";
    in
    {
      imports = [ module ];
      services.charon-kernel = {
        enable = true;
      }
      // lib.optionalAttrs (peer == 2) {
        mtu = 1380;
        interfaceNamePrefix = "gn";
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
        "vrf"
      ];
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
      ];
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
        };
      };

      services.strongswan-swanctl.strongswan.extraConfig = ''
        charon {
          port = 0
          port_nat_t = 13000
          install_routes = no
          load_modular = yes
          plugins {
            include ${config.services.strongswan-swanctl.package}/share/strongswan/templates/config/plugins/*.conf
            kernel-netlink {
              load = no
            }
            kernel-rust {
              load = yes
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
    interface_settings = [("ranet", 1400, "gravity"), ("gn", 1380, "overlay")]
    capability_fields = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]

    def ctl(machine, arguments):
        return machine.succeed("swanctl " + arguments)

    def links(machine):
        return json.loads(machine.succeed("ip -j -d link show type xfrm"))

    def indices(machine):
        return {link["ifname"]: link["ifindex"] for link in links(machine)}

    def spis(machine):
        return set(re.findall(r"spi (0x[0-9a-f]+)", machine.succeed("ip xfrm state")))

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

    def assert_empty(machine):
        assert not spis(machine) and not links(machine)
        assert not machine.succeed("ip xfrm policy list nosock").strip()

    def ping_overlay(machine, peer):
        other = 3 - peer
        master = interface_settings[peer - 1][2]
        machine.succeed(f"ip vrf exec {master} ping -c 3 -W 2 -I 10.{peer}.0.1 10.{other}.0.1")
        machine.succeed(f"ip vrf exec {master} ping -6 -c 3 -W 2 -I fd10:{peer}::1 fd10:{other}::1")

    start_all()
    with subtest("systemd runtime directories and least privilege"):
        for peer, machine in enumerate(machines, 1):
            machine.wait_for_unit("strongswan-swanctl.service")
            machine.wait_for_unit("charon-kernel.service")
            machine.wait_for_unit("systemd-networkd.service")
            machine.wait_until_succeeds(
                f"ip -o -6 address show dev overlay0 | grep -F 'fd10:{peer}::1/128' | grep -v tentative"
            )
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
            statistics = ctl(machine, "--stats")
            assert "kernel-rust" in statistics and "kernel-netlink" not in statistics
            assert not links(machine) and not spis(machine)
            controller = machine.succeed(
                "systemd-run --quiet --wait --pipe --collect "
                "--property=DynamicUser=yes --property=SupplementaryGroups=ipsec "
                "--property=CapabilityBoundingSet= --property=AmbientCapabilities= "
                + machine.succeed("command -v swanctl").strip() + " --stats"
            )
            assert "kernel-rust" in controller

    proposals = [
        ("AES-GCM", "${connection 1 "aes128gcm128-esn"}", "${connection 2 "aes128gcm128-esn"}", "rfc4106(gcm(aes))"),
        ("AES-CBC/HMAC", "${connection 1 "aes128-sha256-esn"}", "${connection 2 "aes128-sha256-esn"}", "cbc(aes)"),
    ]
    for name, left_config, right_config, algorithm in proposals:
        with subtest(name + ": IKE, ESP-in-UDP, wildcard selectors and IPv4/IPv6 traffic"):
            for machine, config_file in zip(machines, [left_config, right_config]):
                ctl(machine, "--load-all --noprompt --file " + config_file)
            assert "established" in ctl(left, "--initiate --child net")
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
                original_indices.append(indices(machine))
                other = 3 - peer
                machine.succeed(f"ip route add vrf {master} 10.{other}.0.1/32 dev {name_out}")
                machine.succeed(f"ip -6 route add vrf {master} fd10:{other}::1/128 dev {name_out}")
            for peer, machine in enumerate(machines, 1):
                ping_overlay(machine, peer)
                state = machine.succeed("ip -s xfrm state")
                assert algorithm in state, state
                assert "output-mark 0x7b" in state, state
                assert "encap type espinudp sport 13000 dport 13000" in state, state
                assert any(int(value) > 0 for value in re.findall(r"(\d+)\(packets\)", state))

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

        with subtest(name + ": removing the final SA removes its interface"):
            ctl(left, "--terminate --ike tunnel")
            for peer, machine in enumerate(machines, 1):
                machine.wait_until_succeeds("test -z \"$(ip xfrm state)\"")
                machine.wait_until_succeeds("test \"$(ip -j link show type xfrm)\" = '[]'")
                master = interface_settings[peer - 1][2]
                machine.succeed(f"ip link show dev {master}")
                policies = machine.succeed("ip xfrm policy list nosock")
                assert "if_id" not in policies and "priority 32" in policies, policies

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
        for machine in machines:
            machine.wait_until_succeeds("test -z \"$(ip xfrm state)\"")
            assert not links(machine)

    with subtest("restarting the backend also restarts its strongSwan dependent"):
        previous = property(left, "strongswan-swanctl.service", "MainPID")
        left.succeed("systemctl restart charon-kernel.service")
        left.wait_for_unit("strongswan-swanctl.service")
        assert property(left, "strongswan-swanctl.service", "MainPID") != previous
        assert "kernel-rust" in ctl(left, "--stats")

    with subtest("strongSwan exiting without a stop job stops the unused backend"):
        right.succeed("systemctl kill --signal=TERM --kill-whom=main strongswan-swanctl.service")
        assert_stopped(right, "strongswan-swanctl.service")
        assert_stopped(right, "charon-kernel.service")
        assert_empty(right)
        right.succeed("test ! -e /run/strongswan && test ! -e /run/charon-kernel")
        right.succeed("systemctl start strongswan-swanctl.service")
        assert "kernel-rust" in ctl(right, "--stats")

    with subtest("stopping strongSwan stops the backend and removes runtime directories"):
        for machine in machines:
            machine.succeed("systemctl stop strongswan-swanctl.service")
            assert_stopped(machine, "charon-kernel.service")
            machine.succeed("test ! -e /run/strongswan")
            machine.succeed("test ! -e /run/charon-kernel")
            assert_empty(machine)

    with subtest("failed backend startup prevents strongSwan startup"):
        left.succeed("mkdir -p /run/systemd/system/charon-kernel.service.d")
        left.succeed(
            "printf '[Service]\\nExecStartPre=/run/current-system/sw/bin/false\\n' "
            "> /run/systemd/system/charon-kernel.service.d/test-failure.conf"
        )
        left.succeed("systemctl daemon-reload")
        left.fail("systemctl start strongswan-swanctl.service")
        assert_stopped(left, "strongswan-swanctl.service")
        assert_stopped(left, "charon-kernel.service")
        left.succeed("rm /run/systemd/system/charon-kernel.service.d/test-failure.conf")
        left.succeed("systemctl daemon-reload && systemctl reset-failed")
        left.succeed("systemctl start strongswan-swanctl.service")
        assert "kernel-rust" in ctl(left, "--stats")

    with subtest("backend process failure stops strongSwan"):
        left.succeed("systemctl kill --signal=KILL --kill-whom=main charon-kernel.service")
        assert_stopped(left, "charon-kernel.service")
        assert_stopped(left, "strongswan-swanctl.service")
        left.succeed("test ! -e /run/strongswan && test ! -e /run/charon-kernel")
  '';
}
