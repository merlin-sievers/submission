from enum import Enum
import multiprocessing
import os
import signal
import subprocess

import builtins
from types import FrameType

from rich.progress import Progress

from log import patch_log
from patching.configuration import Config
from patching.function import FunctionPatch

from tests.busybox import BusyBoxUnitTest
from tests.libflac import LibFlacUnitTest
from tests.zlib import ZlibUnitTest
from tests.libpng import LibPNGUnitTest
from tests.libpcap import LibpcapUnitTest

from patched_lib_prepare.scan_entry import Result as PrepareResult

class TimeoutException(Exception):
    pass


def timeout_handler(_signum: int, _frame: FrameType | None) -> None:
    raise TimeoutException("Operation timed out")



def patch(config: Config):

    _ = signal.signal(signal.SIGALRM, timeout_handler)
    if config.fn_info.patch_fn:
        try:
            _ = signal.alarm(4200)
            patching = FunctionPatch(config)
            patching.patch_functions()
            # Disable the alarm if patching is successful
            _ = signal.alarm(0)
            patch_log.info(f"Patching completed successfully for binary_path: {config.binary_path} function name: {config.fn_info.patch_fn}")
            return True
        except TimeoutException as te:
            print(f"Operation for config {config.binary_path} timed out", te)
            patch_log.error(f"Timeout occurred for binary_path: {config.binary_path} function name: {config.fn_info.patch_fn}")
            return False
   
        except Exception as e:
            import traceback
            print("Error occurred while patching:", e)
            patch_log.error(f"An error occurred: {traceback.format_exc()} binary_path: {config.binary_path} function name: {config.fn_info.patch_fn}")
            return False
        finally:
            #Ensure the alarm is always disabled after each iteration
            _ = signal.alarm(0)

    else:
        patch_log.error(f"Function name is None for binary_path: {config.binary_path}")
        return False


class JobResult(Enum):
    UNSUPPORTED_PRODUCT = 0
    UNKNOWN_CVE = 1
    PATCH_FAIL = 2
    TEST_FAIL = 3
    EVAL_FAIL = 4
    SUCCESS = 5

def karonte_job(config: Config) -> JobResult:
    supported_libs = {
        "zlib": ZlibUnitTest,
        "libpng": LibPNGUnitTest,
        "flac": LibFlacUnitTest,
        "busybox": BusyBoxUnitTest,
        "libpcap": LibpcapUnitTest,
    }

    if config.product not in supported_libs:
        return JobResult.UNSUPPORTED_PRODUCT

    tester = supported_libs[config.product](config)
    if config.cve not in tester.cves:
        return JobResult.UNKNOWN_CVE

    config.test_binary = tester.test_binary
    cve_fn_info = tester.cves[config.cve]
    config.fn_info = cve_fn_info

    if not patch(config):
        return JobResult.PATCH_FAIL


    if not tester.unit_test_patch():
        return JobResult.TEST_FAIL

    return JobResult.SUCCESS if tester.evaluate_results() else JobResult.EVAL_FAIL

