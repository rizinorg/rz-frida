cc = meson.get_compiler('c')
fs = import('fs')
python = import('python').find_installation(required: false)

rz_core_dep = dependency('rz_core')
frida_core_opt = get_option('frida_core')
frida_core_dep = []
frida_core_enabled = false
frida_core_manual = false
frida_core_compile_args = []
frida_core_link_args = []
frida_core_manual_deps = []
frida_core_fetch_failed = false

if not frida_core_opt.disabled()
  frida_host_system = host_machine.system()
  if frida_host_system == 'linux' and cc.compiles('#ifndef __ANDROID__\n#error android\n#endif', name: 'android bionic check')
    # termux like hosts show linux but link against bionic
    frida_host_system = 'android'
  endif
  frida_include_dir = get_option('frida_include_dir')
  frida_library = get_option('frida_library')
  if frida_include_dir == '' or frida_library == ''
    # probe pkg-config first, then fetch devkit when enabled
    frida_core_dep = dependency('frida-core-1.0', required: false)
    if not frida_core_dep.found() and frida_core_opt.enabled()
      # no devkit
      if meson.is_cross_build()
        error('cross builds need -Dfrida_include_dir and -Dfrida_library, the devkit cannot be fetched')
      endif
      if not python.found()
        error('python3 is required to fetch the frida-core devkit, or pass -Dfrida_include_dir and -Dfrida_library')
      endif
      frida_host_musl = false
      if frida_host_system == 'linux' and cc.compiles('#ifndef __MUSL__\n#error musl\n#endif', name: 'musl libc check')
        frida_host_musl = true
      endif
      frida_platform = ''
      if frida_host_system == 'linux'
        if frida_host_musl and host_machine.cpu_family() == 'x86_64'
          frida_platform = 'linux-x86_64-musl'
        elif frida_host_musl and host_machine.cpu_family() == 'aarch64'
          frida_platform = 'linux-arm64-musl'
        elif frida_host_musl and host_machine.cpu_family() == 'arm'
          frida_platform = 'linux-armhf-musl'
        elif host_machine.cpu_family() == 'x86_64' and host_machine.endian() == 'little'
          frida_platform = 'linux-x86_64'
        elif host_machine.cpu_family() == 'x86' and host_machine.endian() == 'little'
          frida_platform = 'linux-x86'
        elif host_machine.cpu_family() == 'aarch64' and host_machine.endian() == 'little'
          frida_platform = 'linux-arm64'
        elif host_machine.cpu_family() == 'arm' and host_machine.endian() == 'little'
          frida_platform = 'linux-armhf'
        elif host_machine.cpu_family() == 'aarch64' and host_machine.endian() == 'big'
          frida_platform = 'linux-arm64be'
        elif host_machine.cpu_family() == 'arm' and host_machine.endian() == 'big'
          frida_platform = 'linux-armbe8'
        elif host_machine.cpu_family() == 'mips' and host_machine.endian() == 'big'
          frida_platform = 'linux-mips'
        elif host_machine.cpu_family() == 'mips' and host_machine.endian() == 'little'
          frida_platform = 'linux-mipsel'
        elif host_machine.cpu_family() == 'mips64' and host_machine.endian() == 'big'
          frida_platform = 'linux-mips64'
        elif host_machine.cpu_family() == 'mips64' and host_machine.endian() == 'little'
          frida_platform = 'linux-mips64el'
        endif
      elif frida_host_system == 'darwin'
        if host_machine.cpu_family() == 'x86_64'
          frida_platform = 'macos-x86_64'
        elif host_machine.cpu_family() == 'aarch64'
          frida_platform = 'macos-arm64'
        endif
      elif frida_host_system == 'windows'
        if host_machine.cpu_family() == 'x86_64'
          frida_platform = 'windows-x86_64'
        elif host_machine.cpu_family() == 'x86'
          frida_platform = 'windows-x86'
        elif host_machine.cpu_family() == 'aarch64'
          frida_platform = 'windows-arm64'
        endif
      elif frida_host_system == 'android'
        if host_machine.cpu_family() == 'aarch64'
          frida_platform = 'android-arm64'
        elif host_machine.cpu_family() == 'arm'
          frida_platform = 'android-arm'
        elif host_machine.cpu_family() == 'x86_64'
          frida_platform = 'android-x86_64'
        elif host_machine.cpu_family() == 'x86'
          frida_platform = 'android-x86'
        endif
      endif
      if frida_platform == ''
        warning('no frida-core devkit exists for this host, building without frida support')
        frida_core_fetch_failed = true
      else
        frida_fetch = files('../../scripts/fetch_frida_devkit.py')
        frida_devkit_dir = run_command(
          python, frida_fetch, get_option('frida_version'), frida_platform,
          check: true,
        ).stdout().strip()
        frida_include_dir = frida_devkit_dir
        if frida_host_system == 'windows'
          frida_library = frida_devkit_dir / 'frida-core.lib'
        else
          frida_library = frida_devkit_dir / 'libfrida-core.a'
        endif
        if not fs.exists(frida_include_dir / 'frida-core.h') or not fs.exists(frida_library)
          error('frida-core devkit was fetched but expected files are missing in ' + frida_devkit_dir)
        endif
      endif
    endif
  endif

  if frida_include_dir != '' and frida_library != ''
    frida_core_manual = true
    if host_machine.system() == 'windows' and cc.get_id() == 'gcc' and frida_library.to_lower().endswith('.lib')
      error('frida-core was found but cannot be linked with this compiler and toolchain')
    endif
    frida_core_compile_args = ['-I' + frida_include_dir]
    frida_core_link_args = [frida_library]
    # devkit gives static frida core that doesnt carry its own system
    # libs, so just naming them here for link to resolve. pkg-config path
    # below declares these itself, so not needed there.
    if frida_host_system == 'linux'
      frida_core_manual_deps += dependency('threads')
      dl_dep = cc.find_library('dl', required: false)
      if dl_dep.found()
        frida_core_manual_deps += dl_dep
      endif
      m_dep = cc.find_library('m', required: false)
      if m_dep.found()
        frida_core_manual_deps += m_dep
      endif
    endif
    if frida_host_system == 'android'
      # needs liblog and libm for the static devkit
      log_dep = cc.find_library('log', required: false)
      if log_dep.found()
        frida_core_manual_deps += log_dep
      endif
      m_dep = cc.find_library('m', required: false)
      if m_dep.found()
        frida_core_manual_deps += m_dep
      endif
    endif
    if frida_host_system == 'windows'
      frida_core_manual_deps += cc.find_library('setupapi', required: false)
    endif
    if frida_host_system == 'darwin'
      frida_core_manual_deps += dependency('appleframeworks', modules: ['Foundation', 'CoreFoundation', 'AppKit'])
      frida_core_manual_deps += cc.find_library('bsm', required: false)
      frida_core_manual_deps += cc.find_library('resolv', required: false)
    endif
    frida_core_dep = declare_dependency(
      compile_args: frida_core_compile_args,
      link_args: frida_core_link_args,
      dependencies: frida_core_manual_deps,
    )
  endif

  if frida_core_dep.found()
    frida_core_link_check = '''
    #include <frida-core.h>
    int main(void) {
      frida_init();
      frida_deinit();
      return 0;
    }
    '''
    if frida_core_manual
      frida_core_enabled = cc.links(
        frida_core_link_check,
        args: frida_core_compile_args + frida_core_link_args,
        dependencies: frida_core_manual_deps,
        name: 'frida-core link check',
      )
    else
      frida_core_enabled = cc.links(
        frida_core_link_check,
        dependencies: frida_core_dep,
        name: 'frida-core link check',
      )
    endif
    if not frida_core_enabled and frida_core_opt.enabled()
      error('frida-core was found but cannot be linked with this compiler and toolchain')
    endif
  elif frida_core_opt.enabled() and not frida_core_fetch_failed
    error('frida-core was requested but not found through pkg-config or manual devkit options')
  endif
endif

rz_frida_c_args = []
rz_frida_deps = [rz_core_dep]
rz_frida_include_args = []

rizin_include_dir = get_option('rizin_include_dir')
if rizin_include_dir != ''
  rz_frida_include_args += ['-I' + rizin_include_dir]
endif
rizin_build_dir = get_option('rizin_build_dir')
if rizin_build_dir != ''
  rz_frida_include_args += ['-I' + rizin_build_dir]
endif
rizin_sdb_include_dir = get_option('rizin_sdb_include_dir')
if rizin_sdb_include_dir != ''
  rz_frida_include_args += ['-I' + rizin_sdb_include_dir]
endif

if frida_core_enabled
  rz_frida_deps += frida_core_dep
  rz_frida_backend_src = 'src/rz_frida_backend.c'
  rz_frida_c_args += ['-DHAVE_FRIDA_CORE']
else
  rz_frida_backend_src = 'src/rz_frida_backend_null.c'
endif

rz_frida_agent_header = files('src/rzfrida_agent.h')
if python.found()
  rz_frida_agent_embed = files('agent/embed_agent.py')
  rz_frida_agent_header = custom_target(
    'rzfrida_agent.h',
    input: 'agent/rzfrida_agent.js',
    output: 'rzfrida_agent.h',
    command: [python, rz_frida_agent_embed, '@OUTPUT@'],
    depend_files: [rz_frida_agent_embed, 'agent/entry.js', 'agent/package.json'],
  )
endif

rz_frida_incs = include_directories('.', 'include', 'src', 'src/cmd_descs')
rz_frida_test_incs = include_directories('.', 'include', 'src', 'src/cmd_descs', 'tests')

rz_frida_src = [
  rz_frida_agent_header,
  rz_frida_backend_src,
  'src/cmd_descs/cmd_descs.c',
  'src/rz_frida_message.c',
  'src/rz_frida_plugin.c',
  'src/rz_frida_protocol.c',
  'src/rz_frida_session.c',
  'src/rz_frida_uri.c',
]

rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
  rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
endif

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

rz_frida_lib = shared_library('rz_frida',
  rz_frida_src,
  c_args: rz_frida_c_args + rz_frida_include_args,
  dependencies: rz_frida_deps,
  include_directories: rz_frida_incs,
  implicit_include_directories: false,
  install: true,
  install_dir: rizin_plugdir,
)

test_uri = executable('test_uri',
  ['tests/test_uri.c', 'src/rz_frida_uri.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('uri parser', test_uri)

test_session = executable('test_session',
  ['tests/test_session.c', 'src/rz_frida_session.c', 'src/rz_frida_uri.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('session lifecycle', test_session)

test_protocol = executable('test_protocol',
  ['tests/test_protocol.c', 'src/rz_frida_protocol.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('protocol helpers', test_protocol)

test_message = executable('test_message',
  ['tests/test_message.c', 'src/rz_frida_message.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('agent message protocol', test_message)

test_backend = executable('test_backend',
  ['tests/test_backend.c', 'src/rz_frida_backend_null.c', 'src/rz_frida_protocol.c', 'src/rz_frida_session.c', 'src/rz_frida_uri.c'],
  c_args: rz_frida_include_args,
  dependencies: rz_core_dep,
  include_directories: rz_frida_test_incs,
)

test('backend unavailable response', test_backend)

test_plugin = executable('test_plugin',
  [
    'tests/test_plugin.c',
    rz_frida_agent_header,
    rz_frida_backend_src,
    'src/cmd_descs/cmd_descs.c',
    'src/rz_frida_message.c',
    'src/rz_frida_plugin.c',
    'src/rz_frida_protocol.c',
    'src/rz_frida_session.c',
    'src/rz_frida_uri.c',
  ],
  c_args: rz_frida_c_args + rz_frida_include_args,
  dependencies: rz_frida_deps,
  include_directories: rz_frida_test_incs,
)

test('plugin command registration', test_plugin)

node_exe = find_program('node', 'nodejs', required: false)
if node_exe.found()
  test('agent script protocol', node_exe,
    args: [
      files('tests/test_agent.js'),
      files('agent/rzfrida_agent.js'),
    ],
  )
endif
