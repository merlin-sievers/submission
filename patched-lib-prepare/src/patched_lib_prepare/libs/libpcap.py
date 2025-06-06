from typing import override
import logging

from patched_lib_prepare.util import absolute_patch_path
from patched_lib_prepare.version import VersionSpecificCommands

from patched_lib_prepare.github import GitHubBuilder
from pathlib import Path
from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]

l = logging.getLogger('patched-lib-prepare')

# BUILD DEPENDENCIES:
# bison
# flex
# ...?
class LibPCAPBuilder(GitHubBuilder):
    build_parent_base: Path = Path('build/libpcap')
    owner: str = 'the-tcpdump-group'
    repo: str = 'libpcap'
    product: str = 'libpcap'

    @property
    @override
    def output_file_fmts(self) -> list[str]:
        # Format: libpcap.so.X.Y.Z where X.Y.Z is the version
        return [f'libpcap.so.{self.version}']

    @override
    @classmethod
    def get_manual_patch_for_version(cls, cve: str, version: Version) -> str | None:
        if version == Version('1.1.1') and cve == 'CVE-2019-15165':
            l.debug(f'got manual patch for: {cve} {version}')
            tag = cls.get_tag_for_version(version)
            return f'{tag}$patch$CVE-2019-15165'
        l.debug(f'found no manual patch for: {cve} {version}')
        return None

    @property
    @override
    def build_commands(self) -> str:
        def add_commits(s: str) -> str:
            if self.patch == 'CVE-2019-15165':
                return '\n'.join([f'patch -p1 <{absolute_patch_path("libpcap-1.1.1-CVE-2019-15165.patch")}', s])
            return s
        def with_pcap_linux_6(s: str) -> str:
            return "export ac_cv_linux_vers=6\n" + s
        def cmake_build(_: str) -> str:
            return f'''
cmake -S . -B build -DCMAKE_C_COMPILER={self.toolchain}-gcc -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -fno-stack-protector -mthumb {self.compile_flags}" -DCMAKE_SHARED_LINKER_FLAGS="-mthumb" -DBUILD_SHARED_LIBS=ON
cmake --build build -j$(nproc)
cp build/libpcap.so.{self.version} .
            '''
        version_specific_commands_list: list[VersionSpecificCommands] = [
            VersionSpecificCommands(
                start = Version("1.1.1"),
                end = Version("1.1.1"),
                customizer = with_pcap_linux_6
            ),
            VersionSpecificCommands(
                start = Version("1.9.1"),
                end = Version("9999999"),
                customizer = cmake_build
            ),
            VersionSpecificCommands(
                start = Version("1.1.1"),
                end = Version("1.1.1"),
                customizer = add_commits
            ),
        ]
        commands: str = f'''
            ./configure CFLAGS='-mthumb -fno-stack-protector -g -D SIOCGSTAMP=0x8906 {self.compile_flags}' --host '%(toolchain)s' --with-pcap=linux
            make -j$(nproc)
        '''
        for vsc in version_specific_commands_list:
            if self.version in vsc:
                commands = vsc.customize_commands(commands)
        return commands % {'toolchain': self.toolchain}

    @override
    def test_is_prepared(self) -> bool:
        return (self.repo_dir / 'cvetest').exists()

    @override
    def prepare_for_tests_commands(self) -> str:
        return f'''
            cp {absolute_patch_path("cvetest.c")} .
            cp {absolute_patch_path("run-cvetest.sh")} .
            ln -sf {self.output_file_fmts[0]} libpcap.so
            ln -sf {self.output_file_fmts[0]} libpcap.so.{self.version[:1].split('.')[0]}
            ln -sf {self.output_file_fmts[0]} libpcap.so.{'.'.join(self.version.split('.')[:2])}
            patch -p1 <{absolute_patch_path("libpcap-cve-test-makefile.patch")}
            chmod +x run-cvetest.sh
            make cvetest
            '''

