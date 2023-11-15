from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import angr

# the detour backend can be used as well:


from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section


project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)
backend = DetourBackend("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0")
patches = []
addr = len(backend.ocontent)

patches.append(RawFilePatch(addr, b"\x00\x00\xff\xff"*4))
backend.apply_patches(patches)
patches =[]
target_address = str(hex(addr))
patches.append(InlinePatch(0x4049f4, "b " + target_address))
backend.apply_patches(patches)


print(backend.elf._get_section_header(1))
section_header = backend.elf._get_section_header(1)
backend.elf._make_section(section_header)

print("hallo")
backend.save("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0_detoured")