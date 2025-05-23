from typing import override

from patched_lib_prepare.util import assert_toolchain_exists
from helpers import CVEFunctionInfo
from tests.unit_test import UnitTest
import logging

results_error_logger = logging.getLogger('results_error_log')
results_success_logger = logging.getLogger('results_success_log')


class BusyBoxUnitTest(UnitTest):
    EVALUATE_CMD: str = f"grep -q 'FAILED' test.log"

    def __init__(self, config):
        super().__init__(config)

        #self.name["CVE-2014-9645"] = "modprobe_main"
 #       self.name["CVE-2015-9261"] = "huft_build"
        #self.name["CVE-2018-1000500"] = "add_match"
#        self.name["CVE-2021-42378"] = "getvar_i"
  #      self.name["CVE-2021-42379"] ="next_input_file"
   #     self.name["CVE-2021-42381"]= "hash_init"
    #    self.name["CVE-2021-42384"] = "handle_special"
        self.cves["CVE-2021-42386"] = CVEFunctionInfo("nvalloc", "nvalloc")

        self.test_binary: str = config.test_dir + '/busybox'

    @override
    def unit_test_patch(self):
        assert_toolchain_exists(self.config.toolchain)
        #     Build the unit tests
        command = f"CC='{self.config.toolchain}-gcc' ./self.configure --shared"
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"make"
        print(self.config.test_dir)
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"cp {self.config.output_path} libz.so.{self.config.version}"
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"QEMU_LD_PREFIX='{self.ldprefix}' LD_LIBRARY_PATH=:{self.config.firmware} make test > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            return False

        return True

