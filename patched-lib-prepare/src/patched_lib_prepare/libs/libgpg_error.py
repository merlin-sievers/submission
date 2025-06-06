from typing import override


from patched_lib_prepare.git import GitBuilder
from pathlib import Path

from patched_lib_prepare.util import get_toolchain_sysroot


class LibGPGErrorBuilder(GitBuilder):
    build_parent_base: Path = Path('build/libgpg-error')
    _url: str = 'git://git.gnupg.org/libgpg-error.git'
    product: str = 'libgpg-error'

    @property
    @override
    def output_file_fmts(self) -> list[str]: 
        return ['src/.libs/libgpg-error.so']

    @property
    @override
    def include_paths(self) -> list[Path]:
        return [self.build_parent / 'src']

    @property
    @override
    def build_commands(self) -> str:
        commands = f'''
            autoreconf -vfi
            ./configure --prefix {get_toolchain_sysroot(self.toolchain)} --disable-nls --disable-languages --disable-doc --host {self.toolchain}
            make -j$(nproc)
            ln -s src bin
        '''
        return commands
