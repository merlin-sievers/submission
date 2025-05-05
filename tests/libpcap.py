from tests.unit_test import UnitTest
import subprocess
import logging

results_error_logger = logging.getLogger('results_error.log')
results_success_logger = logging.getLogger('results_success.log')


class LibpcapUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()
        self.name["CVE-2024-8006"] = "pcap_findalldevs"
        self.name["CVE-2019-15165"] = "pcap_ng_check_header"
       # self.name["CVE-2019-15161"] = "daemon_msg_findallif_req"


    def unit_test_patch(self):
        #     Build the unit tests
        return  NotImplementedError

    def evaluate_results(self):
        cwd = self.config.test_dir
        command = f"grep -q 'FAILED' test.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)

        if result.returncode == 0:
            results_error_logger.error("Unit test of %s failed in %s" , self.config.output_path, self.config.firmware)
        elif result.returncode == 1:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)
