# SPDX-License-Identifier: GPL-2.0-or-later
fs = import('fs')
cc = meson.get_compiler('c')
strongswan_source = get_option('strongswan_source')
strongswan_build = get_option('strongswan_build')
if strongswan_source == '' or not fs.is_absolute(strongswan_source)
  error('Set -Dstrongswan_source=/absolute/path/to/matching/strongswan/source')
endif
if strongswan_build == ''
  strongswan_build = strongswan_source
elif not fs.is_absolute(strongswan_build)
  error('strongswan_build must be an absolute path')
endif
foreach header : ['src/libstrongswan/library.h', 'src/libcharon/daemon.h']
  if not fs.is_file(strongswan_source / header)
    error('Missing strongSwan header: ' + strongswan_source / header)
  endif
endforeach
config_header = strongswan_build / 'config.h'
if not fs.is_file(config_header)
  error('Missing ' + config_header + '; use the config.h from the matching strongSwan build')
endif
if not fs.is_absolute(get_option('piddir'))
  error('piddir must be an absolute runtime path')
endif

# Use both trees for configured builds with generated headers. Neither tree is
# changed or built by this project. No copies of strongSwan structs are vendored.
strongswan_includes = []
foreach directory : [strongswan_build / 'src/libstrongswan',
                     strongswan_build / 'src/libcharon',
                     strongswan_source / 'src/libstrongswan',
                     strongswan_source / 'src/libcharon']
  if fs.is_dir(directory)
    strongswan_includes += [include_directories(directory)]
  endif
endforeach
sdk_args = ['-include', config_header]
strongswan_version = cc.get_define('VERSION', args: sdk_args,
                                  include_directories: strongswan_includes).strip('"')
if strongswan_version == ''
  error('The selected config.h does not define strongSwan VERSION')
endif

plugin_config = configuration_data()
plugin_config.set_quoted('IPSEC_PIDDIR', get_option('piddir'))
configure_file(output: 'kernel_rust_build_config.h', configuration: plugin_config)
plugin_args = sdk_args + ['-include', meson.current_build_dir() / 'kernel_rust_build_config.h']
# Match strongSwan's METHOD()/debug-format conventions, including unused callback
# arguments. Keep entry points visible when a distribution hides other symbols.
plugin_args += cc.get_supported_arguments(
  '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-pointer-sign',
  '-Wno-format', '-Wno-format-security', '-Wno-missing-field-initializers',
  '-Wno-type-limits', '-fvisibility=default',
)
plugin_dir = get_option('plugin_dir')
if plugin_dir == ''
  plugin_dir = get_option('libdir') / 'ipsec/plugins'
endif

# Charon/libstrongswan supply the unresolved host symbols at dlopen(). The
# module needs no link-time libcharon, libstrongswan, libtool, or core patches.
shared_module('strongswan-kernel-rust',
  'kernel_rust_plugin.c', 'kernel_rust_ipsec.c', 'kernel_rust_net.c', 'kernel_rust_client.c',
  include_directories: strongswan_includes,
  c_args: plugin_args,
  dependencies: dependency('jansson', version: '>=2.7'),
  override_options: ['b_lundef=false'],
  install: true,
  install_dir: plugin_dir,
)
summary({'strongSwan version': strongswan_version,
         'strongSwan source': strongswan_source,
         'strongSwan config': config_header,
         'Plugin installation': get_option('prefix') / plugin_dir})
