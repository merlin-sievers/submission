from dataclasses import dataclass
from pathlib import Path
from subprocess import run
from typing import override
import logging

from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]

from patched_lib_prepare.git import GitBuilder
from patched_lib_prepare.util import absolute_patch_path, get_firmware_sysroot, get_toolchains_dir, get_toolchain_sysroot
from patched_lib_prepare.version import VSC  

l = logging.getLogger('patched-lib-prepare')

class BusyboxBuilder(GitBuilder):
    build_parent_base: Path = Path('build/busybox')
    product: str = 'busybox'
    _url: str = 'https://github.com/mirror/busybox.git' # unreliable: 'https://git.busybox.net/busybox/'

    version_specific_changes: list[VSC] = [
        VSC(
            start=Version("1.20.0"),
            end=Version("1.20.0"),
            config_overwrites={},
            patches=['busybox-1.20.0.patch'],
            test_patches=[],
            make_args=[]
        ),
        VSC(
            start=Version("1.7.2"),
            end=Version("1.23.0"),
            config_overwrites={
                'FEATURE_INETD_RPC': 'n',
                'MONOTONIC_SYSCALL': 'y',
            },
            patches=[],
            test_patches=[],
            make_args=[]
        ),
        VSC(
            start=Version("1.20.0"),
            end=Version("1.30.1"),
            config_overwrites={
                'RDATE': 'n',
                'DATE': 'n',
            },
            patches=[],
            test_patches=[],
            make_args=[]
        ),
        VSC(
            start=Version("1.29.0"),
            end=Version("1.36.0"),
            config_overwrites={
                'TC': 'n',
            },
            patches=[],
            test_patches=[],
            make_args=[]
        ),
        VSC(
            start=Version("1.14.1"),
            end=Version("1.19.4"),
            config_overwrites={
                'EXTRA_CFLAGS': f'"-mthumb -I../../../{get_toolchains_dir()}/%(toolchain)s/output/host/%(toolchain)s/sysroot/usr/include/ -include sys/resource.h %(compile_flags)s"',
            },
            patches=[],
            test_patches=[],
            make_args=[]
        ),
        VSC(
            start=Version("1.7.2"),
            end=Version("1.14.1"),
            config_overwrites={
                'MOUNT': 'n',
            },
            patches=['busybox-makefile.patch'],
            test_patches=[],
            make_args=[]
        ),
        VSC(
            start=Version("1.7.2"),
            end=Version("1.7.2"),
            config_overwrites={
                'STATIC': 'n',
                'TAR': 'n',
                'TCPSVD': 'n',
                'UDPSVD': 'n',
                'IPTUNNEL': 'n',
                'FEATURE_IP_TUNNEL': 'n',
                'INSMOD': 'n',
                'RMMOD': 'n',
                'LSMOD': 'n',
                'MODPROBE': 'n',
            },
            patches=[],
            test_patches=[],
            make_args=[
                'CROSS_COMPILE=%(toolchain)s-',
                'CFLAGS="-mthumb -include sys/resource.h %(compile_flags)s"',
            ]
        ),
        VSC(
            start=Version("1.19.2"),
            end=Version("1.19.4"),
            config_overwrites={
                'MKFS_EXT2': 'n',
                'FEATURE_MOUNT_NFS': 'n',
            },
            patches=[],
            test_patches=[],
            make_args=[]
        ),
    ]

    @property
    @override
    def output_file_fmts(self) -> list[str]:
        return ['busybox']

    @override
    @classmethod
    def is_executable(cls) -> bool:
         return True

    @property
    @override
    def build_commands(self) -> str:
        return ("""
        %(patches)s
        make defconfig %(make_args)s
        %(config_overwrite)s
        make -j$(nproc) %(make_args)s
        cp busybox_unstripped busybox
""" % { 'config_overwrite': self.config_overwrite_cmds(), 'patches': self.patch_cmds(), 'make_args': self.get_make_args() }) % { 'toolchain': self.toolchain, 'compile_flags': self.compile_flags }


    @override
    @classmethod
    def get_version_for_tag(cls, tag: str) -> Version:
        return Version(tag.replace('_', '.'))

    def get_make_args(self) -> str:
        cmds: list[str] = []
        for vsc in self.version_specific_changes:
            if vsc.is_in_range(self.version):
                for make_arg in vsc.make_args:
                    cmds.append(make_arg)
        return ' '.join(cmds)

    def patch_cmds(self) -> str:
        cmds: list[str] = []
        for vsc in self.version_specific_changes:
            if vsc.is_in_range(self.version):
                for patch in vsc.patches:
                    cmds.append(f'patch -f -p1 <{absolute_patch_path(patch)} || [ $? = 1 ]')
        return '\n'.join(cmds)


    @classmethod
    def busybox_includes_tool(cls, path: Path, tool: str) -> bool:
        def symlink_search() -> bool:
            sysroot = get_firmware_sysroot(path)
            completed = run(['find', '-lname', '*busybox', '-name', tool], check=True, capture_output=True, cwd=sysroot)
            lines = completed.stdout.decode().splitlines()
            return len(lines) > 0
        def string_contains() -> bool:
            return tool.encode() in path.read_bytes()
        return string_contains()


    @classmethod
    @override
    def is_out_of_scope(cls, version: Version, cve: str, affected_path: Path) -> bool:
        return cve != 'CVE-2021-42386' or not cls.busybox_includes_tool(affected_path, 'awk')
        # if self.version < Version('1.7.2'):
        #     return True
        # if cve == 'CVE-2021-42386' and not self.busybox_includes_tool(affected_path, 'awk'):
        #     return True
        # return False

    def config_overwrite_cmds(self) -> str:
        cmds: list[str] = []
        def create_sed_cmd(overwrites: dict[str,str]) -> str:
                    return 'sed -i ' + \
                        ' '.join([
                        f"-e 's;.*\\bCONFIG_{option}\\b.*;CONFIG_{option}={value};'" % {'toolchain': self.toolchain, 'compile_flags': self.compile_flags}
                             for option, value in overwrites.items()
                        ]) + ' .config'
        always_overwrites: dict[str,str] = {
            'DEBUG': 'y',
            'EXTRA_CFLAGS': f'"-mthumb {self.compile_flags}"',
            'STATIC': 'y',
            'CROSS_COMPILER_PREFIX': f'"{self.toolchain}-"',
        }
        cmds.append(create_sed_cmd(always_overwrites))
        for vsc in self.version_specific_changes:
            if vsc.is_in_range(self.version):
                if len(vsc.config_overwrites) != 0:
                    cmds.append(create_sed_cmd(vsc.config_overwrites))
        return '\n'.join(cmds)
