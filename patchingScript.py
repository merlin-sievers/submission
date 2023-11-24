import pyvex
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import angr
import lief
import re
# the detour backend can be used as well:


from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

from patching.configuration import Config
from patching.patching import Patching

config = Config()

patching = Patching(config)
patching.patch(config.binary_path)



# project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)
# backend = DetourBackend("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0")
# patches = []
# addr = 0x4049f5
# block = project.factory.block(addr)
# block_next = project.factory.block(addr+block.size)
# new_memory_address = project.loader.main_object.segments[0].vaddr + project.loader.main_object.segments[0].memsize
#
# cfg = project.analyses.CFGFast()
#
# target_function = project.loader.find_symbol("png_check_keyword")
# block_next.vex.pp()
#
# for instruction in block.capstone.insns:
#     print("Hallo")
#
# expr = block.vex.statements[1]
#
# instruction_string = block.disassembly.insns[0].mnemonic + " " + block.disassembly.insns[0].op_str
# difference = 100
# modified_string = re.sub(r'#0x[0-9A-Fa-f]+', "#" + str(hex(difference)), instruction_string)
# print(modified_string)

# print(new_memory_address)
# patches.append(RawFilePatch(addr, b"\x00\x00\xff\xff"*4))
# backend.apply_patches(patches)
# patches =[]
# target_address = str(hex(addr))
# patches.append(InlinePatch(0x4049f4, "b " + target_address))
# backend.apply_patches(patches)
#
#
# print(backend.elf._get_section_header(1))
# section_header = backend.elf._get_section_header(1)
# backend.elf._make_section(section_header)
#
# print("hallo")
# backend.save("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0_detoured")

