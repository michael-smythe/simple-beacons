#
# Main build file for the Echo Server
#

project('sbs','c',
    meson_version: '>= 0.40',
    version:'0.0.1',
    default_options: [
        'warning_level=3',                  # Highest warning level
        'b_sanitize=address,undefined',     # Address sanitizer
        'b_coverage=true',                  # generate code coverage reports
    ])


# grab the compiler
cc = meson.get_compiler('c')

# define global flags (compiler agnostic at least for gcc/clang)
add_project_arguments(
	cc.get_supported_arguments(
            '-Werror',
            '-Wshadow',
            '-Wmissing-prototypes',
            '-Wcast-align',
            '-Werror=address',
            '-Werror=strict-prototypes',
            '-Werror=write-strings',
            '-Werror=implicit-function-declaration',
            '-Werror=pointer-arith',
            '-Werror=declaration-after-statement',
            '-Werror=return-type',
            '-Werror=uninitialized',
            '-Wimplicit-fallthrough',
            '-Werror=strict-overflow',
            '-Wstrict-overflow=2',
            '-Wno-format-zero-length',
            '-Wformat',
            '-Werror=format-security',
            '-Wno-gnu-zero-variadic-macro-arguments',
            '-fno-common',
        ), language: 'c')

# if we're using clang/LLVM compile extra warnings
if cc.get_id() == 'clang' and not meson.is_cross_build()
    add_global_arguments('-Weverything',language: 'c')
endif

# export include directory and sources for testing
root_include = include_directories('src')

# add main to sources
root_sources = ['src/server.c', 'src/comms.c', 'src/commands.c', 'src/tunnel.c']

openssl = dependency('openssl')

# define our executable sources
server = executable('sbs', sources: root_sources, dependencies : [openssl])