self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.charon-kernel;
  hardening = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = "disconnected";
    PrivateDevices = true;
    PrivateIPC = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@keyring"
    ];
    SystemCallErrorNumber = "EPERM";
    UMask = "0077";
    LimitCORE = 0;
    RuntimeDirectoryMode = "0750";
  };
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
    interfaceGroup = lib.mkOption {
      type = lib.types.ints.between 1 4294967295;
      default = 17227;
      description = ''
        Numeric Linux link group reserved for this daemon. Every interface in
        this group is owned by the backend, regardless of its interface type.
        The daemon also exclusively owns all global XFRM policies in its network
        namespace, so independent instances need separate network namespaces.
      '';
    };
    masterDevice = lib.mkOption {
      type = lib.types.str;
      default = "gravity";
      description = ''
        Existing master interface, usually a VRF, for daemon-owned XFRM
        interfaces. It must exist before the first SA or trap policy is installed.
        The daemon manages attachment, but does not create or remove the master.
      '';
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
      # BindsTo would turn backend failure into a stop job, suppressing recovery.
      # Requires propagates restarts; After orders shutdown and fresh startup.
      requires = [ "charon-kernel.service" ];
      after = [ "charon-kernel.service" ];
      serviceConfig = hardening // {
        # PartOf propagates automatic charon restarts to the kernel daemon.
        Restart = lib.mkForce "always";
        RestartSec = "2s";
        DynamicUser = lib.mkDefault true;
        Group = lib.mkDefault cfg.group;
        CapabilityBoundingSet = lib.mkDefault "";
        AmbientCapabilities = lib.mkDefault "";
        RuntimeDirectory = "strongswan";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          # glibc address-family discovery during hostname resolution.
          "AF_NETLINK"
        ];
      };
    };

    systemd.services.charon-kernel = {
      description = "strongSwan Rust kernel backend";
      # Pull charon back in after an automatic backend restart, even if it
      # already exited. Requires/After orders the fresh pair in either case.
      wants = [ "strongswan-swanctl.service" ];
      partOf = [ "strongswan-swanctl.service" ];
      unitConfig.StopWhenUnneeded = true;
      serviceConfig = hardening // {
        Type = "notify";
        Restart = "always";
        RestartSec = "2s";
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/charon-kernel-daemon"
          "--group"
          cfg.group
          "--mtu"
          (toString cfg.mtu)
          "--ifname-prefix"
          cfg.interfaceNamePrefix
          "--interface-group"
          (toString cfg.interfaceGroup)
          "--master-device"
          cfg.masterDevice
        ];
        RuntimeDirectory = "charon-kernel";
        DynamicUser = true;
        User = "charon-kernel";
        Group = cfg.group;
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
      };
    };
  };
}
