self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.charon-kernel;
in
{
  options.services.charon-kernel = {
    enable = lib.mkEnableOption "the Rust kernel backend and unprivileged strongSwan IKE service";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The daemon and plugin, built for the matching strongSwan package.";
    };
    group = lib.mkOption {
      type = lib.types.str;
      default = "ipsec";
      description = "Static group authorized to access the kernel daemon and strongSwan VICI sockets.";
    };
    mtu = lib.mkOption {
      type = lib.types.ints.between 1280 65535;
      default = 1400;
      description = "MTU of daemon-owned XFRM interfaces.";
    };
    interfaceNamePrefix = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9_-]{1,7}";
      default = "ranet";
      description = "Interface name prefix, followed by the XFRM interface ID as eight hexadecimal digits.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = { };
    environment.systemPackages = [
      cfg.package
      cfg.package.strongswan
    ];
    environment.pathsToLink = [ "/lib/ipsec/plugins" ];
    services.strongswan-swanctl = {
      enable = true;
      package = lib.mkDefault cfg.package.strongswan;
    };

    systemd.services.strongswan-swanctl = {
      bindsTo = [ "charon-kernel.service" ];
      after = [ "charon-kernel.service" ];
      serviceConfig = {
        DynamicUser = lib.mkDefault true;
        Group = lib.mkDefault cfg.group;
        CapabilityBoundingSet = lib.mkDefault "";
        AmbientCapabilities = lib.mkDefault "";
        RuntimeDirectory = "strongswan";
      };
    };

    systemd.services.charon-kernel = {
      description = "strongSwan Rust kernel backend";
      partOf = [ "strongswan-swanctl.service" ];
      unitConfig.StopWhenUnneeded = true;
      serviceConfig = {
        Type = "notify";
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/charon-kernel-daemon"
          "--group"
          cfg.group
          "--mtu"
          (toString cfg.mtu)
          "--ifname-prefix"
          cfg.interfaceNamePrefix
        ];
        RuntimeDirectory = "charon-kernel";
        RuntimeDirectoryMode = "0755";
        DynamicUser = true;
        User = "charon-kernel";
        Group = cfg.group;
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
      };
    };
  };
}
