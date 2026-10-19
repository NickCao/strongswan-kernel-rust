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

  node = peer: { lib, ... }: {
    imports = [ module ];
    services.charon-kernel.enable = true;
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
    ];
    networking = {
      useDHCP = false;
      interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = "192.0.2.${toString peer}";
          prefixLength = 24;
        }
      ];
      interfaces.lo = {
        ipv4.addresses = [
          {
            address = "10.${toString peer}.0.1";
            prefixLength = 32;
          }
        ];
        ipv6.addresses = [
          {
            address = "fd10:${toString peer}::1";
            prefixLength = 128;
          }
        ];
      };
      firewall = {
        allowedUDPPorts = [
          13000
          13001
        ];
        checkReversePath = false;
      };
    };
    environment.systemPackages = [
      pkgs.iproute2
      pkgs.python3
      pkgs.util-linux
    ];
    systemd.services.network-addresses-lo.wantedBy = [ "network.target" ];

    services.strongswan-swanctl = {
      enable = true;
      strongswan.extraConfig = ''
        charon {
          port = 13001
          port_nat_t = 13000
          install_routes = no
          load = random nonce x509 pubkey pkcs1 pem openssl kdf kernel-rust! socket-default vici
        }
      '';
    };
    systemd.services.strongswan-swanctl = {
      # Start IKE explicitly after checking the kernel daemon's socket.
      wantedBy = lib.mkForce [ ];
      requires = [ "charon-kernel.service" ];
      after = [ "charon-kernel.service" ];
      serviceConfig = {
        DynamicUser = true;
        SupplementaryGroups = [ "ipsec" ];
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        ExecStartPost = lib.mkForce [ ];
      };
    };
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
        pid = machine.succeed("systemctl show " + unit + " -p MainPID --value").strip()
        assert int(pid) > 1
        return dict(
            line.split(":", 1)
            for line in machine.succeed("cat /proc/" + pid + "/status").splitlines()
            if ":" in line
        )

    def ping_overlay(machine, peer):
        other = 3 - peer
        machine.succeed(f"ping -c 3 -W 2 -I 10.{peer}.0.1 10.{other}.0.1")
        machine.succeed(f"ping -6 -c 3 -W 2 -I fd10:{peer}::1 fd10:{other}::1")

    start_all()
    with subtest("systemd runtime directories and least privilege"):
        for machine in machines:
            machine.wait_for_unit("charon-kernel.service")
            machine.wait_for_unit("network-addresses-lo.service")
            machine.wait_until_succeeds(
                "test -S /run/charon-kernel/charon-kernel.sock"
            )
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
            machine.succeed("systemctl start strongswan-swanctl.service")
            machine.wait_for_unit("strongswan-swanctl.service")
            ike = process_status(machine, "strongswan-swanctl.service")
            ike_uid = int(ike["Uid"].split()[0])
            assert 61184 <= ike_uid <= 65519 and ike_uid != backend_uid
            for field in capability_fields:
                assert int(ike[field], 16) == 0, ike
            statistics = ctl(machine, "--stats")
            assert "kernel-rust" in statistics and "kernel-netlink" not in statistics
            assert not links(machine) and not spis(machine)

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
                name_out = f"ranet{int(match[1], 16):08x}"
                current = links(machine)
                assert len(current) == 1 and current[0]["ifname"] == name_out, current
                assert current[0]["mtu"] == 1400 and "UP" in current[0]["flags"]
                original_indices.append(indices(machine))
                other = 3 - peer
                machine.succeed(f"ip route add 10.{other}.0.1/32 dev {name_out}")
                machine.succeed(f"ip -6 route add fd10:{other}::1/128 dev {name_out}")
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

        with subtest(name + ": removing the final SA removes its interface"):
            ctl(left, "--terminate --ike tunnel")
            for machine in machines:
                machine.wait_until_succeeds("test -z \"$(ip xfrm state)\"")
                machine.wait_until_succeeds("test \"$(ip -j link show type xfrm)\" = '[]'")
                policies = machine.succeed("ip xfrm policy list nosock")
                assert "if_id" not in policies and "priority 32" in policies, policies

    with subtest("clean shutdown and systemd runtime directory cleanup"):
        for machine in machines:
            machine.succeed("systemctl stop strongswan-swanctl.service")
            machine.succeed("test ! -e /run/strongswan")
            machine.wait_until_succeeds("test -z \"$(ip xfrm policy list nosock)\"")
            machine.succeed("systemctl stop charon-kernel.service")
            machine.succeed("test ! -e /run/charon-kernel")
  '';
}
