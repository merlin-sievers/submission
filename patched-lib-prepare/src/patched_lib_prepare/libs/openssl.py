from collections.abc import Generator
import logging
from typing import override

from cve_bin_tool.version_compare import Version

from patched_lib_prepare.github import GitHubBuilder
from pathlib import Path

from patched_lib_prepare.util import absolute_patch_path


l = logging.getLogger('patched-lib-prepare')

class OpenSSLBuilder(GitHubBuilder):
    build_parent_base: Path = Path('build/openssl')
    owner: str = 'openssl'
    repo: str = 'openssl'
    product: str = 'openssl'
    keywords: list[str] = ['libcrypto', 'libssl']

    @property
    @override
    def output_file_fmts(self) -> list[str]: 
        return ['libcrypto.so', 'libssl.so']

    @property
    @override
    def build_commands(self) -> str:
        def add_commits(s: str) -> str:
            if self.patch in self.supported_cves:
                return '\n'.join([f'patch -F100 -p1 <{absolute_patch_path(f"openssl-{self.patch}.patch")}', s])
            return s
            # patch -p1 <{absolute_patch_path("openssl-tests.patch")}
        commands = f'''
            ./Configure --cross-compile-prefix={self.toolchain}- shared linux-generic32
            make -j$(nproc) build_libs
        '''
        commands = add_commits(commands)
        return commands

    supported_cves: list[str] = [
        'CVE-2016-2105',
        'CVE-2016-2109',
        # 'CVE-2016-2176'
    ]

    @classmethod
    @override
    def is_out_of_scope(cls, _version: Version, cve: str, _affected_path: Path) -> bool:
        return cve not in cls.supported_cves

    @override
    @classmethod
    def get_manual_patch_for_version(cls, cve: str, version: Version) -> str | None:
        if cve in cls.supported_cves:
            tag = cls.get_tag_for_version(version)
            return f'{tag}$patch${cve}'

    @override
    @classmethod
    def get_tag_for_version(cls, version: str) -> str:
        raise NotImplementedError

    @override
    @classmethod
    def get_version_for_tag(cls, tag: str) -> Version:
        l.info(f'Trying to get version for tag: {tag}')
        return super().get_version_for_tag(tag)

    @classmethod
    @override
    def mangle_version(cls, version: str) -> Generator[str]:
        yield f'OpenSSL_{version.replace('.', '_')}'
        # yield f'OpenSSL-engine-{version[i:].replace('.', '_')}'
        # yield f'openssl-{version[i:]}'
