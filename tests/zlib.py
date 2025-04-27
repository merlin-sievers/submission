from tests.unit_test import UnitTest
import subprocess
import logging

results_error_logger = logging.getLogger('results_error_log')
results_success_logger = logging.getLogger('results_success_log')


class ZlibUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()
        # name["CVE-2016-9841"] = "inflate_fast"
        self.name["CVE-2016-9840"] = "inflate_table"
        self.name["CVE-2016-9842"] = "inflateMark"
        # name["CVE-2023-45853"] = "zipOpenNewFileInZip4_64"
        self.name["CVE-2016-9843"] = "crc32_combine"
        # name["CVE-2022-37434"] = "inflate"
        # name["CVE-2018-25032"] = "deflateInit2_"



    def unit_test_patch(self):
        #     Build the unit tests
        command = f"cd {self.config.test_dir}"
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"chmod +x ./self.configure"
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"CC='arm-linux-gnueabi-gcc' ./self.configure --shared"
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"make"
        print(self.config.test_dir)
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"cp {self.config.output_path} libz.so.{self.config.version}"
        if not self.run_command(command, self.config.test_dir):
            return False

        command = f"QEMU_LD_PREFIX=/usr/arm-linux-gnueabi/ LD_LIBRARY_PATH=:{self.config.firmware} make test > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            return False

        return True

    def evaluate_results(self):
        cwd = self.config.test_dir
        command = f"grep -q 'FAILED' test.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)

        if result.returncode == 0:
            results_error_logger.error("Unit test of %s failed", self.config.output_path)
        elif result.returncode == 1:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)
