import signal

import pyvex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import angr
import lief
import re
# the detour backend can be used as well:
import os
import pickle

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

from patching.configuration import Config
from patching.patching import Patching

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

i = 35
while i <= 54:
    config = Config("magma-config.properties", str(i))

    # Set the alarm for 20 minutes (1200 seconds)
    signal.alarm(4400)

    try:
        patching = Patching(config)
        patching.patch(config.binary_path)
        # Disable the alarm if patching is successful
        signal.alarm(0)
    except TimeoutException as te:
        print(f"Operation for config {config} timed out")
        logging.error("Timeout occurred for binary_path: %s functionName: %s", config.binary_path, config.functionName)
        pass
    except Exception as e:
        print("Error occurred while patching:", e)
        logging.error("An error occurred: %s binary_path: %s functionName: %s", e, config.binary_path,
                      config.functionName)
        pass
    finally:
        # Ensure the alarm is always disabled after each iteration
        signal.alarm(0)

    i += 1

print("Patching completed successfully")

