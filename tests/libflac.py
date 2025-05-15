from tests.unit_test import UnitTest
import subprocess
import logging
from pathlib import Path


class LibFlacUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()
        self.test_binary = None

#        self.name["CVE-2017-6888"] = "read_metadata_"
        self.name["CVE-2020-22219"] = ("FLAC__bitwriter_get_buffer","FLAC__bitwriter_get_buffer")
        #self.name["CVE-2020-22219"] = "bitwriter_grow_"
        self.test_binary = config.test_dir + '/src/libFLAC/.libs/libFLAC.so'


    def unit_test_patch(self):
        #     Build the unit tests
        import os
        os.environ['PATH'] = str(Path(f'/home/jaenich/CVE-bin-tool/patched-lib-prepare/toolchains/{self.config.toolchain}/output/host/bin').absolute()) + ':' + os.environ['PATH']

        command = f"cd {self.config.test_dir}"
        if not self.run_command(command, self.config.test_dir):
            return False



        command = f"cp {self.config.output_path} {self.config.test_binary}"
        if not self.run_command(command, self.config.test_dir):
            return False
        ldpath = self.config.firmware.replace("usr/","")
        ldprefix = ldpath.replace("lib","")
        command = f"QEMU_LD_PREFIX=/home/jaenich/CVE-bin-tool/patched-lib-prepare/toolchains/{self.config.toolchain}/output/host/{self.config.toolchain}/sysroot/ LD_LIBRARY_PATH=$PWD make check"
        if not self.run_command(command, self.config.test_dir):
            return False
        return True

    def evaluate_results(self):

        results_success_logger = logging.getLogger('results_success-'+self.config.product+'.log')
        results_error_logger = logging.getLogger('results_error-'+self.config.product+'.log')
        cwd = self.config.test_dir
        command = f"grep '# PASS:  6' test/test-suite.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)

        if result.returncode == 0:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        elif result.returncode == 1:
            results_error_logger.error("Unit test of %s failed", self.config.output_path)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)

if __name__ == '__main__':
    import sys
    from pathlib import Path
    args = sys.argv
    # TODO
    test_dir = str(Path(args[1]).absolute())
    output_path = str(next(Path(test_dir).glob('*_CVE*')).absolute())
    config = {
        'product': 'libflac',
        'output_path': output_path,
        'test_dir': test_dir,
        'test_binary': '',
        'toolchain': '',
        'firmware': '',
    }
    test = LibFlacUnitTest(config)
    test.unit_test_patch()
    test.evaluate_results()
