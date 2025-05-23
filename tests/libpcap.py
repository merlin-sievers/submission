from typing import override
from patched_lib_prepare.util import assert_toolchain_exists
from helpers import CVEFunctionInfo
from patching.configuration import Config
from tests.unit_test import UnitTest


class LibpcapUnitTest(UnitTest):
    EVALUATE_CMD: str = f"! grep -q 'Section Header Block in pcap-ng dump file has a length of' test.log"

    def __init__(self, config: Config):
        super().__init__(config)
        
 #       self.name["CVE-2011-1935"]= "pcap_activate_linux"
       # self.name["CVE-2024-8006"] = "pcap_findalldevs"
        self.cves["CVE-2019-15165"] = CVEFunctionInfo("pcap_ng_check_header", "pcap_ng_check_header")
       # self.name["CVE-2019-15161"] = "daemon_msg_findallif_req"

        self.test_binary: str = config.test_dir +  '/libpcap.so.' + config.version


    @override
    def unit_test_patch(self):
        assert_toolchain_exists(self.config.toolchain)

        command = f"cp {self.config.output_path} {self.test_binary}"
        if not self.run_command(command, self.config.test_dir):
            return False


        command = f"SYSROOT='{self.ldprefix}' ./run-cvetest.sh > test.log 2>&1"
        if not self.run_command(command, self.config.test_dir):
            return False
        
        return True
