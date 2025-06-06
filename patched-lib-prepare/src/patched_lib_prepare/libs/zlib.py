from functools import cache
from typing import override

from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]

from patched_lib_prepare.util import absolute_patch_path
from patched_lib_prepare.version import VSC, VersionSpecificCommands
from patched_lib_prepare.github import GitHubBuilder
from pathlib import Path

class ZLibBuilder(GitHubBuilder):
    build_parent_base: Path = Path('build/zlib')
    owner: str = 'madler'
    repo: str = 'zlib'
    product: str = 'zlib'
    keywords: list[str] = ['libz']

    version_specific_changes: list[VSC] = [
        VSC(
            Version('1.2.1'),
            Version('1.2.3'),
            {},
            [],
            ['test-zlib-1.2.3.patch'],
            [],
        ),
        VSC(
            Version('1.2.4'),
            Version('99999999'),
            {},
            [],
            ['test-zlib-newer.patch'],
            [],
        )
    ]

    @property
    @override
    def output_file_fmts(self) -> list[str]:
        return [f'libz.so.{self.version}']

    @property
    @override
    def build_commands(self) -> str: 
        def add_ldshared(s: str) -> str:
            lines = s.splitlines()
            for i in range(len(lines)):
                line = lines[i]
                if line.startswith("CC="):
                    lines[i] = 'LDSHARED="%(toolchain)s-gcc -shared" ' + line
            return '\n'.join(lines)
        version_specific_commands_list: list[VersionSpecificCommands] = [
            VersionSpecificCommands(
                start = Version("1.2.12"),
                end = Version("1.2.12"),
                customizer = lambda c: ' '.join(filter(lambda w: 'CC=' not in w, c.split(" ")))
            ),
            VersionSpecificCommands(
                start = Version("1.1.4"),
                end = Version("1.1.4"),
                customizer = add_ldshared
            )
        ]
        commands: str = f'''
CC="%(toolchain)s-gcc" CHOST="%(toolchain)s" CFLAGS='-U_TIME_BITS -mthumb -g -fno-stack-protector -fPIC {self.compile_flags}' ./configure --shared
( make -j$(nproc) ; make -j$(nproc) )
'''
        for vsc in version_specific_commands_list:
            if self.version in vsc:
                commands = vsc.customize_commands(commands)
                break
        return commands % {'toolchain': self.toolchain}

    @override
    @classmethod
    def get_version_for_tag(cls, tag: str) -> Version:
        if not tag[0] == 'v':
            raise NotImplementedError(f'tag does not start with v: {tag}')
        return Version(tag[1:])

    @cache
    def get_my_changes(self) -> VSC:
        my_vsc = VSC(self.version, self.version, config_overwrites={}, patches=[], test_patches=[], make_args=[])
        for vsc in self.version_specific_changes:
            if vsc.is_in_range(self.version):
                my_vsc.config_overwrites.update(vsc.config_overwrites)
                my_vsc.patches.extend(vsc.patches)
                my_vsc.test_patches.extend(vsc.test_patches)
                my_vsc.make_args.extend(vsc.make_args)
        return my_vsc

    @property
    def test_patches(self) -> str:
        my_vsc = self.get_my_changes()
        def patch_cmd(patch: str) -> str:
            return f'patch -p1 <{absolute_patch_path(patch)}'
        return '\n'.join(map(patch_cmd, my_vsc.test_patches))

    @override
    def test_is_prepared(self) -> bool:
        test_bins = ['minigzipsh', 'examplesh'] if self.version > Version('1.2.3') else ['minigzip', 'example']
        return all(map(lambda p: (self.repo_dir / p).exists(), test_bins))

    @override
    def prepare_for_tests_commands(self) -> str:
        return f'''
            make test ; echo compiled
            {self.test_patches}
            '''

