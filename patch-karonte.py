import multiprocessing
import os
import signal
import subprocess

import builtins

from rich.progress import Progress

from patching.configuration import Config
from patching.function import FunctionPatch

import logging


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("Operation timed out")


def get_error_logger(name):
    # --- Error Logger ---
    e_logger = logging.getLogger(name)
    e_logger.setLevel(logging.ERROR)
    e_handler = logging.FileHandler(name)
    e_formatter = logging.Formatter('%(asctime)s - ERROR - %(message)s')
    e_handler.setFormatter(e_formatter)
    e_logger.addHandler(e_handler)
    return e_logger

def get_success_logger(name):
    # --- Success Logger ---
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(name)
    formatter = logging.Formatter('%(asctime)s - SUCCESS - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return  logger


def patch(config):


    signal.signal(signal.SIGALRM, timeout_handler)
    if config.functionName is not None:
        try:
            patching = FunctionPatch(config)
            patching.patch_functions()
            # Disable the alarm if patching is successful
            success_logger.info("Patching completed successfully for binary_path: %s functionName: %s",
                                config.binary_path, config.functionName)
            signal.alarm(0)
            return True
        except TimeoutException as te:
            print(f"Operation for config {config.binary_path} timed out", te)
            error_logger.error("Timeout occurred for binary_path: %s functionName: %s", config.binary_path,
                               config.functionName)
            return False
        except Exception as e:
            print("Error occurred while patching:", e)
            error_logger.error("An error occurred: %s binary_path: %s functionName: %s", e, config.binary_path,
                               config.functionName)
            return False
        finally:
            # Ensure the alarm is always disabled after each iteration
            signal.alarm(0)

    else:
        error_logger.error("Function name is None for binary_path: %s", config.binary_path)
        return False
def unit_test_patch(config):
#     Build the unit tests
    command = f"cd {config.test_dir}"
    if not run_command(command, config.test_dir):
        return False

    command = f"chmod +x ./configure"
    if not run_command(command, config.test_dir):
        return False

    command = f"CC='arm-linux-gnueabi-gcc' ./configure --shared"
    if not run_command(command, config.test_dir):
        return False

    command = f"make"
    print(config.test_dir)
    if not run_command(command, config.test_dir):
        return False

    command = f"cp {config.output_path} libz.so.{config.version}"
    if not run_command(command, config.test_dir):
        return False

    command = f"QEMU_LD_PREFIX=/usr/arm-linux-gnueabi/ LD_LIBRARY_PATH=:{config.firmware} make test > test.log 2>&1"
    if not run_command(command, config.test_dir):
        return False

    return True



def run_command(command, cwd):

    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        command_error_logger.error(f'Command "{command}" failed with error: {e.stderr.decode()}')
        return False

    if result.returncode != 0:
        command_error_logger.error(f'Failed to run "{command}" in "{cwd}"')
        return False
    return True

def evaluate_results(config, cwd):
    command = f"grep -q 'FAILED' test.log"

    result = subprocess.run(command, shell=True,  capture_output=True, cwd=cwd)

    if result.returncode == 0:
        results_error_logger.error("Unit test of %s failed", config.output_path)
    elif result.returncode ==1:
        results_successor_logger.info("Unit test of %s passed", config.output_path)
    else:
        results_error_logger.error("Unknown error occurred while evaluating results for %s", config.output_path)


def karonte_job(result):
    name = dict()
    # name["CVE-2016-9841"] = "inflate_fast"
    name["CVE-2016-9840"] = "inflate_table"
    # name["CVE-2016-9842"] = "inflateMark"
    # name["CVE-2023-45853"] = "zipOpenNewFileInZip4_64"
    # name["CVE-2016-9843"] = "crc32_combine"
    # name["CVE-2022-37434"] = "inflate"
    config = Config()
    config.binary_path = result["affected_path"]
    config.patch_path = result["patched_path"]
    config.output_path = result["test_dir"] + "/" + result["product"] + "_" + result["cve"] + ".so"
    if result["cve"] in name:
        config.functionName = name[result["cve"]]
    else:
        return
    config.test_dir = result["test_dir"] + "/" + result["product"] + "-" + result["affected_version"]
    config.product = result["product"]
    config.version = result["affected_version"]
    config.firmware = os.path.dirname(config.binary_path)

    if not patch(config):
        return

    if not unit_test_patch(config):
        return

    evaluate_results(config, config.test_dir)



if __name__ == "__main__":

    start = Config()
    results = start.readJsonConfig("/home/jaenich/CVE-bin-tool/patched-lib-prepare/results-no-stack.json")
    results_error_logger = get_error_logger("results_error.log")
    results_successor_logger = get_success_logger("results_success.log")
    command_error_logger = get_error_logger("command_error.log")
    success_logger = get_success_logger("success.log")
    error_logger = get_error_logger("error.log")



    # Save reference to the real print
    _real_print = builtins.print


    def mute_print(*args, **kwargs):
        # no-op: do nothing
        pass


    builtins.print = mute_print

    with Progress() as progress:
        task = progress.add_task("[cyan]Patching...", total=len(results))
        with multiprocessing.Pool(processes=1) as pool:
            for _ in pool.imap_unordered(karonte_job, results):
                progress.update(task, advance=1)



    # with multiprocessing.Pool() as pool:
    #     pool.map(karonte_job, results)





