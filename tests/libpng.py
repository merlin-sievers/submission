from pathlib import Path
from typing import override
from patched_lib_prepare.util import assert_toolchain_exists
from helpers import CVEFunctionInfo
from patching.configuration import Config
from tests.unit_test import UnitTest


class LibPNGUnitTest(UnitTest):
    EVALUATE_CMD: str = f"grep -q 'uncaught' test.log"

    def __init__(self, config: Config):
        super().__init__(config)

        self.cves["CVE-2016-10087"] = CVEFunctionInfo("png_free_data", "png_free_data")
 #       self.name["CVE-2017-12652"] = ("png_read_chunk_header", "png_read_chunk_header")

        major = config.version.split(".")
        major_version = major[0] + major[1]
        self.test_binary: str = config.test_dir +'/.libs/libpng' + major_version + '.so'


    @override
    def unit_test_patch(self):
        assert_toolchain_exists(self.config.toolchain)

        command = f"cd {self.config.test_dir}"
        if not self.run_command(command, self.config.test_dir):
            return False
        major = self.config.version.split(".")
        major_version = major[0] + major[1]

        zlib_dir = (Path(self.config.test_dir).parent.parent / 'zlib' / f'{self.config.toolchain}-zlib-1.3.1').resolve().absolute()
        command = f"{self.config.toolchain}-gcc  -I.  -I{zlib_dir}  -fno-stack-protector -L.libs/ -L{zlib_dir} -l:libz.so.1 -l:libpng{major_version}.so -o pngtest pngtest.c "
        if not self.run_command(command, self.config.test_dir):
            return False
        major = self.config.version.split(".")
        major_version = major[0] + major[1]

        if major_version == "14":
            command = f"cp {self.config.output_path} libpng{major_version}.so.14"
        else:
            command = f"cp {self.config.output_path} libpng{major_version}.so.0"
        if not self.run_command(command, self.config.test_dir):
            return False
        command = f"QEMU_LD_PREFIX={self.ldprefix} LD_LIBRARY_PATH=$PWD:{self.config.firmware}:{self.ldprefix / 'lib'} ./pngtest > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            return False

        return True
