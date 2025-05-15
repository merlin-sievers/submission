from tests.unit_test import UnitTest
import subprocess
import logging
from pathlib import Path


class LibPNGUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()
        self.test_binary = None

        self.name["CVE-2016-10087"] = ("png_free_data.localalias", "png_free_data")
 #       self.name["CVE-2017-12652"] = ("png_read_chunk_header", "png_read_chunk_header")

        major = config.version.split(".")
        major_version = major[0] + major[1]
        self.test_binary = config.test_dir +'/.libs/libpng' + major_version + '.so'


    def unit_test_patch(self):
        #     Build the unit tests
        import os
        os.environ['PATH'] = str(Path(f'/home/jaenich/CVE-bin-tool/patched-lib-prepare/toolchains/{self.config.toolchain}/output/host/bin').absolute()) + ':' + os.environ['PATH']
        command = f"cd {self.config.test_dir}"
        if not self.run_command(command, self.config.test_dir):
            return False
        major = self.config.version.split(".")
        major_version = major[0] + major[1]

        command = f"arm-buildroot-linux-uclibcgnueabi-gcc  -I.  -I/home/jaenich/CVE-bin-tool/patched-lib-prepare/build/zlib/arm-buildroot-linux-uclibcgnueabi-zlib-1.3.1  -fno-stack-protector -I/home/jaenich/CVE-bin-tool/patched-lib-prepare/build/zlib/arm-buildroot-linux-uclibcgnueabi-zlib-1.3.1 -L.libs/ -L/home/jaenich/CVE-bin-tool/patched-lib-prepare/build/zlib/arm-buildroot-linux-uclibcgnueabi-zlib-1.3.1/ -l:libz.so.1 -l:libpng{major_version}.so -o pngtest pngtest.c "
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
        ldpath = self.config.firmware.replace("usr/","")
        ldprefix = ldpath.replace("lib","")
        command = f"QEMU_LD_PREFIX={ldprefix} LD_LIBRARY_PATH=$PWD:{self.config.firmware}:{ldpath} ./pngtest > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            return False

        return True

    def evaluate_results(self):

        results_error_logger = logging.getLogger('results_error-'+self.config.product+'.log')
        
        results_success_logger = logging.getLogger('results_success-'+self.config.product+'.log')
        cwd = self.config.test_dir
        command = f"grep -q 'uncaught' test.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)

        if result.returncode == 0:
            results_error_logger.error("Unit test of %s failed", self.config.output_path)
        elif result.returncode == 1:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)
