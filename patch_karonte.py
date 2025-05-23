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


# def get_error_logger(name):
#     # --- Error Logger ---
#     e_logger = logging.getLogger(name)
#     e_logger.setLevel(logging.ERROR)
#     e_handler = logging.FileHandler(name)
#     e_formatter = logging.Formatter('%(asctime)s - ERROR - %(message)s')
#     e_handler.setFormatter(e_formatter)
#     e_logger.addHandler(e_handler)
#     return e_logger
#
# def get_success_logger(name):
#     # --- Success Logger ---
#     logger = logging.getLogger(name)
#     logger.setLevel(logging.INFO)
#     handler = logging.FileHandler(name)
#     formatter = logging.Formatter('%(asctime)s - SUCCESS - %(message)s')
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)
#     return  logger


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

# def unit_test_patch(config):
# #     Build the unit tests
#     command = f"cd {config.test_dir}"
#     if not run_command(command, config.test_dir):
#         return False
#
#     command = f"chmod +x ./configure"
#     if not run_command(command, config.test_dir):
#         return False
#
#     command = f"CC='arm-linux-gnueabi-gcc' ./configure --shared"
#     if not run_command(command, config.test_dir):
#         return False
#
#     command = f"make"
#     print(config.test_dir)
#     if not run_command(command, config.test_dir):
#         return False
#
#     command = f"cp {config.output_path} libz.so.{config.version}"
#     if not run_command(command, config.test_dir):
#         return False
#
#     command = f"QEMU_LD_PREFIX=/usr/arm-linux-gnueabi/ LD_LIBRARY_PATH=:{config.firmware} make test > test.log 2>&1"
#     if not run_command(command, config.test_dir):
#         return False
#
#     return True
#


# def run_command(command, cwd):
#
#     try:
#         result = subprocess.run(command, shell=True, check=True, capture_output=True, cwd=cwd)
#     except subprocess.CalledProcessError as e:
#         command_error_logger.error(f'Command "{command}" failed with error: {e.stderr.decode()}',e)
#         return False
#
#     if result.returncode != 0:
#         command_error_logger.error(f'Failed to run "{command}" in "{cwd}"')
#         return False
#     return True

# def evaluate_results(config, cwd):
#     command = f"grep -q 'FAILED' test.log"
#
#     result = subprocess.run(command, shell=True,  capture_output=True, cwd=cwd)
#
#     if result.returncode == 0:
#         results_error_logger.error("Unit test of %s failed", config.output_path)
#     elif result.returncode ==1:
#         results_success_logger.info("Unit test of %s passed in %s", config.output_path, config.firmware)
#     else:
#         results_error_logger.error("Unknown error occurred while evaluating results for %s", config.output_path)

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



if __name__ == "__main__":

    import sys
    start = Config()
    library = sys.argv[1]
    results = start.readJsonConfigFile("/home/jaenich/CVE-bin-tool/patched-lib-prepare/results-"+library+".json")
    # results_error_logger = get_error_logger("results_error-"+library+".log")
    # results_success_logger = get_success_logger("results_success-"+library+".log")
    # command_error_logger = get_error_logger("command_error-"+library+".log")
    # success_logger = get_success_logger("success-"+library+".log")
    # error_logger = get_error_logger("error-"+library+".log")
    # match_logger = get_success_logger("match-"+library+".log")

    # Save reference to the real print
    def mute_print(*_args, **_kwargs):  # pyright:ignore[reportUnknownParameterType,reportMissingParameterType]
        pass
    builtins.print = mute_print

    with Progress() as progress:
        task = progress.add_task("[cyan]Patching...", total=len(results))
        with multiprocessing.Pool() as pool:
            for _ in pool.imap_unordered(karonte_job, results):
                progress.update(task, advance=1)



    # with multiprocessing.Pool() as pool:
    #     pool.map(karonte_job, results)





