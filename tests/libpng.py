from tests.unit_test import UnitTest
import subprocess
import logging

results_error_logger = logging.getLogger('results_error.log')
results_success_logger = logging.getLogger('results_success.log')


class LibPNGUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()

        self.name["CVE-2016-10087"] = "png_set_text_2"
        self.name["CVE-2017-12652"] = "png_read_chunk_header"



    def unit_test_patch(self):
        #     Build the unit tests
        command = f"cd {self.config.test_dir}"
        if not self.run_command(command, self.config.test_dir):
            return False
        
        major = self.config.version.split(".")
        major_version = major[0] + major[1]

        command = f"cp {self.config.output_path} .libs/libpng{major_version}.so"
        if not self.run_command(command, self.config.test_dir):
            return False
        ldpath = self.config.firmware.replace("usr/","")

        command = f"QEMU_LD_PREFIX=/usr/arm-linux-gnueabi/ LD_LIBRARY_PATH=:{self.config.firmware}:{ldpath} make test > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            command = f"make clean"
            self.run_command(command, self.config.test_dir)
            command = f"make"
            self.run_command(command, self.config.test_dir)
            return False
        
        command = f"make clean"
        self.run_command(command, self.config.test_dir)
        command = f"make"
        self.run_command(command, self.config.test_dir)

        return True

    def evaluate_results(self):
        cwd = self.config.test_dir
        command = f"grep -q 'failed' test.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)

        if result.returncode == 0:
            results_error_logger.error("Unit test of %s failed", self.config.output_path)
        elif result.returncode == 1:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)
