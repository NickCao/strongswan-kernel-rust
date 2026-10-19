# SPDX-License-Identifier: GPL-2.0-or-later
project('strongswan-kernel-rust', 'c',
        version: '0.1.0', license: 'GPL-2.0-or-later', meson_version: '>=1.1.0',
        default_options: ['c_std=gnu11', 'buildtype=debugoptimized', 'warning_level=2'])

if host_machine.system() != 'linux'
  error('The XFRM backend requires Linux')
endif
if not get_option('plugin') and not get_option('daemon')
  error('Enable at least one of -Dplugin=true or -Ddaemon=true')
endif

if get_option('plugin')
  subdir('plugin')
endif

if get_option('daemon')
  if meson.is_cross_build()
    error('Cross-compile the daemon with Cargo separately and use -Ddaemon=false for the plugin build')
  endif
  cargo = find_program('cargo')
  python = import('python').find_installation('python3')
  daemon_inputs = files(
    'Cargo.toml', 'Cargo.lock', 'build.rs', 'io.ranet.Kernel.varlink',
    'src/backend.rs', 'src/error.rs', 'src/lib.rs', 'src/main.rs', 'src/model.rs',
    'src/netlink.rs', 'src/network.rs', 'src/service.rs', 'src/transport.rs',
    'src/uapi.rs', 'src/xfrm.rs',
  )
  custom_target('charon-kernel-daemon',
    input: daemon_inputs,
    output: 'charon-kernel-daemon',
    command: [python, files('tools/build-daemon.py'), cargo,
              meson.project_source_root() / 'Cargo.toml',
              meson.project_build_root() / 'cargo-target', '@OUTPUT@'],
    build_by_default: true,
    console: true,
    install: true,
    install_dir: get_option('libexecdir') / 'ipsec',
  )
  test('rust-unit', cargo,
       args: ['test', '--locked', '--manifest-path', meson.project_source_root() / 'Cargo.toml',
              '--target-dir', meson.project_build_root() / 'cargo-target'],
       timeout: 180)
endif

summary({'Plugin': get_option('plugin'), 'Daemon': get_option('daemon')})
