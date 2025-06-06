from collections.abc import Generator
import logging
from typing import override

from cve_bin_tool.version_compare import Version

from patched_lib_prepare.git import GitBuilder
from pathlib import Path

from patched_lib_prepare.util import absolute_patch_path


l = logging.getLogger('patched-lib-prepare')

class Bzip2Builder(GitBuilder):
    build_parent_base: Path = Path('build/bzip2')
    _url: str = 'https://gitlab.com/bzip2/bzip2'
    product: str = 'bzip2'
    keywords: list[str] = ['libbz2']

    @property
    @override
    def output_file_fmts(self) -> list[str]: 
        version_str = self.version
        if self.version == '1.0.5':
            version_str = '1.0.4'
        return [f'libbz2.so.{version_str}', 'bzip2', 'bzip2recover']

    @property
    @override
    def build_commands(self) -> str:
        commands = f'''
            patch -p1 <{absolute_patch_path('bzip2-no-static-lib.patch')}
            make CC={self.toolchain}-gcc AR={self.toolchain}-ar RANLIB={self.toolchain}-ranlib CFLAGS={self.compile_flags} -j$(nproc) -f Makefile-libbz2_so
            ln -s {self.output_file_fmts[0]} libbz2.so
            make CC={self.toolchain}-gcc AR={self.toolchain}-ar RANLIB={self.toolchain}-ranlib CFLAGS={self.compile_flags} -j$(nproc) bzip2
            make CC={self.toolchain}-gcc AR={self.toolchain}-ar RANLIB={self.toolchain}-ranlib CFLAGS={self.compile_flags} -j$(nproc) bzip2recover
        '''
        # commands = add_commits(commands)
        return commands

    supported_cves: dict[str, list[str]] = {
        'CVE-2010-0405': [''],
        'CVE-2016-3189': ['bzip2recover'],
        'CVE-2019-12900': [],
    }

    @classmethod
    @override
    def is_out_of_scope(cls, _version: Version, cve: str, affected_path: Path) -> bool:
        if cve not in cls.supported_cves:
            return True
        return affected_path.name.split('.')[0] not in cls.supported_cves[cve]
        

    @classmethod
    @override
    def get_version_for_tag(cls, tag: str) -> Version:
        assert tag.startswith(f'{cls.product}-')
        return Version(tag[len(cls.product)+1:])

    # @override
    # @classmethod
    # def get_manual_patch_for_version(cls, cve: str, version: Version) -> str | None:
    #     if cve in cls.supported_cves:
    #         tag = cls.get_tag_for_version(version)
    #         return f'{tag}$patch${cve}'
    #
