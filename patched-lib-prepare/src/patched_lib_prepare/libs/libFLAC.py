from typing import override

from patched_lib_prepare.util import absolute_patch_path
from patched_lib_prepare.version import VersionSpecificCommands

from patched_lib_prepare.github import GitHubBuilder
from pathlib import Path
from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]

class LibFLACBuilder(GitHubBuilder):
    build_parent_base: Path = Path('build/libFLAC')
    owner: str = 'xiph'
    repo: str = 'flac'
    product: str = 'libflac'

    @property
    @override
    def output_file_fmts(self) -> list[str]:
        return [f'src/libFLAC/.libs/libFLAC.so']

    @property
    @override
    def build_commands(self) -> str:
        library_path = str((Path('toolchains') / self.toolchain / 'output' / 'host' / self.toolchain / 'sysroot' / 'usr' / 'lib').absolute())
        configure_args: str = f"--disable-ogg --disable-xmms-plugin --disable-cpplibs --host={self.toolchain} CFLAGS='-mthumb -fno-stack-protector {self.compile_flags}'"
        # return '''
        # export LD_LIBRARY_PATH="%(library_path)s:$LD_LIBRARY_PATH"
        # cp /usr/share/gettext/config.rpath config.rpath
        # autoreconf -fiv
        # aclocal -I m4
        # { [ -f configure ] || ./autogen.sh %(configure_args)s; }
        # ./configure %(configure_args)s
        # make -j$(nproc)
        # ''' % {'toolchain': self.toolchain, 'configure_args': configure_args, 'library_path': library_path}
        # if 'uclibc' not in self.toolchain and self.version == Version('1.2.1'):
        #     configure_args = configure_args + " LIBICONV=''"

        def patch_configure_iconv(s: str) -> str:
            patch_name = f'libflac-iconv-{self.toolchain}-1.2.1.patch'
            return f'patch -p1 <{absolute_patch_path(patch_name)}\n' + s

        version_specific_commands_list: list[VersionSpecificCommands] = [
            VersionSpecificCommands(
                start = Version("1.2.1"),
                end = Version("1.2.1"),
                customizer = patch_configure_iconv
            ),
        ]
        commands = '''
        [ -f configure ] || ./autogen.sh %(configure_args)s
        ./configure %(configure_args)s
        make -j$(nproc)
        '''
        for vsc in version_specific_commands_list:
            if self.version in vsc:
                commands = vsc.customize_commands(commands)
        return commands % {'toolchain': self.toolchain, 'configure_args': configure_args, 'library_path': library_path}

    @override
    @classmethod
    def get_version_for_tag(cls, tag: str) -> Version:
        return Version(tag)

