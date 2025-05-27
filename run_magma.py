import signal
import multiprocessing

import pyvex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import angr
import lief
import re
import os
import pickle

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

from patching.configuration import Config
from patching.function import FunctionPatch

import logging

# Configure logging

# Setup logging to a file
logging.basicConfig(filename='patching_errors.txt', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s', force=True)


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("Operation timed out")


# Set up the signal handler for the alarm
signal.signal(signal.SIGALRM, timeout_handler)

def run_patching(config_path):
    i = 23
    while i <= 23:
        config = Config(config_path, str(i))

        # Set the alarm for 20 minutes (1200 seconds)
        signal.alarm(4400)

        try:
            patching = FunctionPatch(config)
            patching.patch_functions()
            # Disable the alarm if patching is successful
            signal.alarm(0)
        except TimeoutException as te:
            print(f"Operation for config {config} timed out")
            logging.error("Timeout occurred for binary_path: %s function name: %s", config.binary_path, config.fn_info.patch_fn)
            pass
        except Exception as e:
            print("Error occurred while patching:", e)
            logging.error("An error occurred: %s binary_path: %s function name: %s", e, config.binary_path,
                          config.fn_info.patch_fn)
            pass
        finally:
            # Ensure the alarm is always disabled after each iteration
            signal.alarm(0)

        i += 1

    print("Patching completed successfully")

if __name__ == "__main__":
    config_path = ["unit-test-O2.properties", "unit-test-O1.properties",  "unit-test-O3.properties"]

    with multiprocessing.Pool() as pool:
        pool.map(run_patching, config_path)
