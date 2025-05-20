from tests.unit_test import UnitTest
import subprocess
import logging
from pathlib import Path


class ZlibUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()
        self.test_binary = None

  #     self.name["CVE-2016-9841"] = "inflate_fast"
        self.name["CVE-2016-9840"] = ("inflate_table", "inflate_table")
        self.name["CVE-2016-9842"] = ("inflateMark", "inflateMark")
        # name["CVE-2023-45853"] = "zipOpenNewFileInZip4_64"
        self.name["CVE-2016-9843"] = ("crc32_z", "crc32")
        # name["CVE-2022-37434"] = "inflate"
        # name["CVE-2018-25032"] = "deflateInit2_"
        
        self.test_binary = config.test_dir + '/libz.so.' + config.version


    def unit_test_patch(self):
        import os
        os.environ['PATH'] = str(Path(f'/home/jaenich/CVE-bin-tool/patched-lib-prepare/toolchains/{self.config.toolchain}/output/host/bin').absolute()) + ':' + os.environ['PATH']

        ldpath = self.config.firmware.replace("usr/","")
        ldprefix = ldpath.replace("lib","")

        (Path(self.config.test_dir) / "patch-configuration").write_text(f'''
firmware: {self.config.firmware}
test_dir: {self.config.test_dir}
patch_path: {self.config.patch_path}
output_path: {self.config.output_path}
                                                                        ''')
        command = f"QEMU_LD_PREFIX={ldprefix} LD_LIBRARY_PATH=$PWD make test > test.log 2>&1"
        return self.run_command(command, self.config.test_dir)

    def evaluate_results(self):
        
        
        results_error_logger = logging.getLogger('results_error-'+self.config.product+'.log')
        
        results_success_logger = logging.getLogger('results_success-'+self.config.product+'.log')
        cwd = self.config.test_dir
        command = f"grep -q 'FAILED' test.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)
        
        if result.returncode == 0:
            results_error_logger.error("Unit test of %s failed in %s" , self.config.output_path, self.config.firmware)
        elif result.returncode == 1:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)

    
