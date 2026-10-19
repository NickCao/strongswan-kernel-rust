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
    enable = lib.mkEnableOption "the privileged Rust kernel backend for strongSwan";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The daemon and plugin, built for the matching strongSwan package.";
    };
    group = lib.mkOption {
      type = lib.types.str;
      default = "ipsec";
      description = "Static group authorized to connect to the kernel daemon.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.${cfg.group} = { };
    environment.systemPackages = [
      cfg.package
      cfg.package.strongswan
    ];
    environment.pathsToLink = [ "/lib/ipsec/plugins" ];
    services.strongswan-swanctl.package = lib.mkDefault cfg.package.strongswan;

    systemd.services.strongswan-swanctl = lib.mkIf config.services.strongswan-swanctl.enable {
      serviceConfig.RuntimeDirectory = "strongswan";
    };

    systemd.services.charon-kernel = {
      description = "strongSwan Rust kernel backend";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/charon-kernel-daemon --group ${lib.escapeShellArg cfg.group}";
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
