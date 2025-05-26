from typing import override

from patched_lib_prepare.util import assert_toolchain_exists, get_toolchain_sysroot
from helpers import CVEFunctionInfo
from patching.configuration import Config
from tests.unit_test import UnitTest


class LibFlacUnitTest(UnitTest):
    EVALUATE_CMD: str = f"! grep '# PASS:  6' test/test-suite.log"

    def __init__(self, config: Config):
        super().__init__(config)

#        self.name["CVE-2017-6888"] = "read_metadata_"
        self.cves["CVE-2020-22219"] = CVEFunctionInfo("FLAC__bitwriter_get_buffer", "FLAC__bitwriter_get_buffer")
        #self.name["CVE-2020-22219"] = "bitwriter_grow_"
        self.test_binary: str = config.test_dir + '/src/libFLAC/.libs/libFLAC.so'


    @override
    def unit_test_patch(self):
        assert_toolchain_exists(self.config.toolchain)

        command = f"cp {self.config.output_path} {self.config.test_binary}"
        if not self.run_command(command, self.config.test_dir):
            return False
        command = f"QEMU_LD_PREFIX={get_toolchain_sysroot(self.config.toolchain)} LD_LIBRARY_PATH=$PWD make check"
        if not self.run_command(command, self.config.test_dir):
            return False
        return True

