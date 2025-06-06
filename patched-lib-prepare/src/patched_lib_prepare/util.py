from collections.abc import Generator
from functools import cache
import logging
from pathlib import Path
from subprocess import run
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
import lief
from lief import Header
from lief.ELF import PROCESSOR_FLAGS

import random
import string
import os

l = logging.getLogger('patched-lib-prepare')

def random_id(length: int) -> str:
    chars: str = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def _get_possible_lib_dirs(p: Path) -> Generator[Path]:
    yield p.parent / 'lib'
    yield p.parent / 'usr'/ 'lib'
    yield p.parent.parent / 'lib'
    yield p.parent.parent / 'usr' / 'lib'
    yield p.parent.parent.parent / 'lib'
    yield p.parent.parent.parent / 'usr' / 'lib'

def detect_toolchain(path: Path, binary: lief.Binary):
    # TODO search for uclibc and change the toolchain accordingly
    header: Header = binary.header
    def is_uclibc():
        for possible_lib_dir in _get_possible_lib_dirs(path):
            try:
                _ = next(possible_lib_dir.glob('ld-uclibc.so*', case_sensitive=False))
                return True
            except StopIteration:
                pass
        return False

    arch = header.machine_type  # pyright:ignore[reportAttributeAccessIssue,reportUnknownMemberType,reportUnknownVariableType]
    is_64 = header.identity_class == lief.ELF.Header.CLASS.ELF64  # pyright:ignore[reportAttributeAccessIssue,reportUnknownMemberType,reportUnknownVariableType]

    # Map machine type to toolchain prefix
    toolchains = {
        lief.ELF.ARCH.X86_64: "x86_64-linux-gnu",  # pyright:ignore[reportUnhashable]
        lief.ELF.ARCH.I386: "i686-linux-gnu",  # pyright:ignore[reportUnhashable]
        lief.ELF.ARCH.AARCH64: "aarch64-linux-gnu" if not binary.is_targeting_android else "aarch64-linux-android",  # pyright:ignore[reportAttributeAccessIssue,reportUnknownMemberType,reportUnhashable]
        lief.ELF.ARCH.MIPS: "mips-linux-gnu",  # pyright:ignore[reportUnhashable]
        lief.ELF.ARCH.RISCV: "riscv64-linux-gnu" if is_64 else "riscv32-linux-gnu",  # pyright:ignore[reportUnhashable]
        lief.ELF.ARCH.PPC64: "powerpc64-linux-gnu",  # pyright:ignore[reportUnhashable]
        lief.ELF.ARCH.PPC: "powerpc-linux-gnu",  # pyright:ignore[reportUnhashable]
    }

    if arch == lief.ELF.ARCH.ARM:
        if binary.is_targeting_android:  # pyright:ignore[reportAttributeAccessIssue,reportUnknownMemberType]
            return "arm-linux-androideabi"
        uclibc_str = 'uclibc' if is_uclibc() else ''
        if header.has(PROCESSOR_FLAGS.ARM_VFP_FLOAT):  # pyright:ignore[reportAttributeAccessIssue,reportUnknownMemberType]
            return f"arm-buildroot-linux-{uclibc_str}gnueabihf"
        else:
            return f"arm-buildroot-linux-{uclibc_str}gnueabi"

    prefix: str = toolchains.get(arch, '')  # pyright:ignore[reportUnknownArgumentType]
    if prefix:
        return prefix
    else:
        raise NotImplementedError(f"Unknown toolchain for architecture: {arch.name}")  # pyright:ignore[reportUnknownMemberType]


@cache
def assert_toolchain_exists(toolchain: str) -> None:
    try:
        _ = run([f'{toolchain}-gcc', '--version'])
        return
    except FileNotFoundError:
        l.info(f'Could not yet find gcc for toolchain "{toolchain}". Building with buildroot...')

    toolchains_dir = get_toolchains_dir()
    toolchain_dir = toolchains_dir / toolchain

    this_file = Path(__file__).resolve()
    toolchain_config = (this_file.parent / "buildroot-configs" / toolchain).absolute()
    if not toolchain_config.is_file():
        l.error(f"There is no config for toolchain: {toolchain}")
        exit(1)

    toolchains_dir.mkdir(parents=True, exist_ok=True)

    if not toolchain_dir.is_dir():
        _ = run([
            "git", "clone",
            "--branch", "2025.02",
            "--depth", "1",
            "https://github.com/buildroot/buildroot.git",
            str(toolchain_dir)
        ], check=True)

    gcc_path = toolchain_dir / "output" / "host" / "bin" / f"{toolchain}-gcc"
    if not gcc_path.exists() or not os.access(gcc_path, os.X_OK):
        prev_cwd = Path('.').resolve()
        os.chdir(toolchain_dir)
        _ = run(["cp", str(toolchain_config), ".config"], check=True)
        _ = run(["make", f"-j{os.cpu_count()}"], check=True)
        os.chdir(prev_cwd)

    add_buildroot_out_to_PATH(toolchain)

    try:
        _ = run([f'{toolchain}-gcc', '--version'])
    except FileNotFoundError:
        l.error("Can't run toolchain gcc even after it was built. Needs manual intervention.")
        exit(1)

def absolute_patch_path(patch: str) -> str:
    return str((Path(__file__).resolve().parent / 'patches' / patch).absolute())

def get_toolchains_dir() -> Path:
    return Path(os.environ.get('TOOLCHAINS_DIR', './toolchains'))

def add_buildroot_out_to_PATH(toolchain: str) -> None:
    os.environ['PATH'] = str((get_toolchains_dir() / toolchain / 'output/host/bin').absolute()) + ':' + os.environ['PATH']

@cache
def path_has_arch(path: Path, arch: str) -> bool:
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            elf_arch = elf.get_machine_arch()
            elf_class = elf.elfclass
            arch_result = f'{elf_arch}{elf_class}'.lower()
            return arch_result == arch.lower()
    except ELFError:
        l.warning(f"Error parsing file. Is it really an ELF file? {path}")
        return False

def get_toolchain_sysroot(toolchain: str) -> Path:
    td = get_toolchains_dir()
    return (td / toolchain / 'output' / 'host' / toolchain / 'sysroot').resolve().absolute()

def get_firmware_sysroot(firmware: Path) -> Path:
    p = firmware
    while p.name in ('lib', 'usr', 'bin') or p.parent.name in ('lib', 'usr', 'bin'):
        p = p.parent
    return p

