from collections.abc import Generator
import logging
from typing import override

from cve_bin_tool.version_compare import Version

from patched_lib_prepare.libs.libgpg_error import LibGPGErrorBuilder
from patched_lib_prepare.git import GitBuilder
from pathlib import Path

from patched_lib_prepare.preparer import Builder
from patched_lib_prepare.util import absolute_patch_path, get_toolchain_sysroot


l = logging.getLogger('patched-lib-prepare')

class LibGCryptBuilder(GitBuilder):
    build_parent_base: Path = Path('build/libgcrypt')
    _url: str = 'git://git.gnupg.org/libgcrypt.git'
    product: str = 'libgcrypt'

    dependency_list: list[tuple[type[Builder], Version]] = [
        (LibGPGErrorBuilder, Version("1.40"))
    ]

    @property
    @override
    def output_file_fmts(self) -> list[str]: 
        return [f'src/.libs/libgcrypt.so']

    @property
    @override
    def build_commands(self) -> str:
        def add_commits(s: str) -> str:
            if self.patch in self.supported_cves:
                return '\n'.join([f'patch -p1 <{absolute_patch_path(f"{self.product}-{self.version}-{self.patch}.patch")}', s])
            return s
        libgpg_error_prefix = Path(self.dependencies[0].INCLUDE_FLAGS()[0][2:]).parent.absolute()
        # The -fngu89-inline is necessary due to some weird behavior with extern inline functions when it is not supplied.
        dummy_makefile_content = '\\n\\n'.join(map(lambda target: f'{target}:\\n\\t@true', ['all', 'clean', 'check']))
        commands = f'''
            autoreconf -vfi
            CFLAGS="-fgnu89-inline {' '.join(self.include_flags)} {self.compile_flags}" LDFLAGS="{' '.join(self.ldflags)}" ./configure --disable-static --enable-shared --disable-doc --disable-asm --without-doc --host {self.toolchain} --enable-mpi-path=generic --with-gpg-error-prefix={libgpg_error_prefix}
            echo -e "{dummy_makefile_content}" > doc/Makefile
            make -j$(nproc) V=1
        '''
        commands = add_commits(commands)
        return commands

    supported_cves: list[str] = [
        'CVE-2021-33560'
    ]

    @classmethod
    @override
    def is_out_of_scope(cls, _version: Version, cve: str, _affected_path: Path) -> bool:
        return cve not in cls.supported_cves
    #
    # @override
    # @classmethod
    # def get_manual_patch_for_version(cls, cve: str, version: Version) -> str | None:
    #     if cve in cls.supported_cves:
    #         tag = cls.get_tag_for_version(version)
    #         return f'{tag}$patch${cve}'
    #
