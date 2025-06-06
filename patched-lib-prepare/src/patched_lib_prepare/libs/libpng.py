from typing import override

from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]

from patched_lib_prepare.preparer import Builder
from patched_lib_prepare.github import GitHubBuilder
from patched_lib_prepare.libs.zlib import ZLibBuilder
from pathlib import Path

from patched_lib_prepare.util import absolute_patch_path

class LibPNGBuilder(GitHubBuilder):

    build_parent_base: Path = Path('build/libpng')
    owner: str = 'pnggroup'
    repo: str = 'libpng'
    product: str = 'libpng'

    dependency_list: list[tuple[type['Builder'], Version]] = [
        (ZLibBuilder, Version("1.3.1"))
    ]

    
    @property
    @override
    def output_file_fmts(self) -> list[str]:
        # Get major version (first number in version string)
        version_parts = str(self.version).split('.')
        major_version = version_parts[0] + version_parts[1]
        # minor_version = version_parts[2]
        # suffix = major_version + "." + minor_version
        # Format: .libs/libpngMM.so.MM.X.Y where MM is major version
        return [f'.libs/libpng{major_version}.so']

    @classmethod
    @override
    def is_out_of_scope(cls, version: Version, _cve: str, _affected_path: Path) -> bool:
        return version in (Version('1.6.20'),)

    @property
    @override
    def build_commands(self) -> str:
        patches = ''
        if self.version >= Version('1.5.21') and self.version <= Version('1.6.32'):
            patches += f'patch -p1 <{absolute_patch_path("libpng-no-checks.patch")}\n'
            patches += f'patch -p1 <{absolute_patch_path("libpng-no-checks-in.patch")}\n'
        cflags = f'-g -mthumb -fno-stack-protector %(include_flags)s {self.compile_flags}' 
        return f'''
        %(patches)s
    [ -f configure ] || ./autogen.sh
    ./configure --host="%(toolchain)s" LDFLAGS="%(ldflags)s %(include_flags)s" CFLAGS='{cflags}' CPPFLAGS='{cflags}' --enable-shared --disable-static
    make -j$(nproc)
    ''' % {'toolchain': self.toolchain, 'patches': patches, 'ldflags': ' '.join(self.ldflags), 'include_flags': ' '.join(self.include_flags)}



    @override
    @classmethod
    def get_version_for_tag(cls, tag: str) -> Version:
        if not tag[0] == 'v':
            raise NotImplementedError(f'tag does not start with v: {tag}')
        return Version(tag[1:])

