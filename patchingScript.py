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
logging.basicConfig(filename='error.log', level=logging.ERROR)



i=2;
while i <=2:
    config = Config("magma-config.properties", str(i))
    # try:
    patching = Patching(config)
    patching.patch(config.binary_path)
    # except Exception as e:
    #     print("Error occurred while patching:", e)
    #     logging.error("An error occurred: %s %s %s", e, config.binary_path, config.functionName)
    #
        # Handle the error gracefully or continue to the next task
        # pass
    i+=1


print("Patching completed successfully")