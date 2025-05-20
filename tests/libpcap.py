from tests.unit_test import UnitTest
import subprocess
import logging



class LibpcapUnitTest(UnitTest):

    def __init__(self, config):
        super().__init__(config)
        self.name = dict()
        self.test_binary =  None
        
 #       self.name["CVE-2011-1935"]= "pcap_activate_linux"
       # self.name["CVE-2024-8006"] = "pcap_findalldevs"
        self.name["CVE-2019-15165"] = ("pcap_ng_check_header","pcap_ng_check_header")
       # self.name["CVE-2019-15161"] = "daemon_msg_findallif_req"

        self.test_binary = config.test_dir +  '/libpcap.so.' + config.version


    def unit_test_patch(self):
        #     Build the unit tests
        command = f"cp {self.config.output_path} {self.test_binary}"
        if not self.run_command(command, self.config.test_dir):
            return False


        ldpath = self.config.firmware.replace("usr/","")
        ldprefix = ldpath.replace("lib","")
        command = f"SYSROOT='{ldprefix}' ./run-cvetest.sh > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            return False
        
        return True

    def evaluate_results(self):
        results_error_logger = logging.getLogger('results_error-'+self.config.product+'.log')
        results_success_logger = logging.getLogger('results_success-'+self.config.product+'.log')
        cwd = self.config.test_dir
        command = f"grep -q 'Section Header Block in pcapng dump file has invalid length' test.log"

        result = subprocess.run(command, shell=True, capture_output=True, cwd=cwd)

        if result.returncode == 1:
            results_error_logger.error("Unit test of %s failed in %s" , self.config.output_path, self.config.firmware)
        elif result.returncode == 0:
            results_success_logger.info("Unit test of %s passed in %s", self.config.output_path, self.config.firmware)
        else:
            results_error_logger.error("Unknown error occurred while evaluating results for %s", self.config.output_path)
