from typing import override

from patched_lib_prepare.util import assert_toolchain_exists
from helpers import CVEFunctionInfo
from patching.configuration import Config
from tests.unit_test import UnitTest
from pathlib import Path


class ZlibUnitTest(UnitTest):
    EVALUATE_CMD: str = f"grep -q 'FAILED' test.log"

    def __init__(self, config: Config):
        super().__init__(config)

  #     self.name["CVE-2016-9841"] = "inflate_fast"
        self.cves["CVE-2016-9840"] = CVEFunctionInfo("inflate_table", "inflate_table")
        self.cves["CVE-2016-9842"] = CVEFunctionInfo("inflateMark", "inflateMark")
        # name["CVE-2023-45853"] = "zipOpenNewFileInZip4_64"
        self.cves["CVE-2016-9843"] = CVEFunctionInfo("crc32_z", "crc32")
        # name["CVE-2022-37434"] = "inflate"
        # name["CVE-2018-25032"] = "deflateInit2_"

        self.test_binary: str = config.test_dir + '/libz.so.' + config.version


    @override
    def unit_test_patch(self) -> bool:
        assert_toolchain_exists(self.config.toolchain)

        command = f"QEMU_LD_PREFIX={self.ldprefix} LD_LIBRARY_PATH=$PWD make test > test.log 2>&1"
        tst_cmd_path = Path(self.config.test_dir) / 'matchmend-test-cmd.sh'
        assert not tst_cmd_path.exists()
        _ = tst_cmd_path.write_text(command)
        return self.run_command(command, self.config.test_dir)

