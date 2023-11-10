from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *
import angr

# the detour backend can be used as well:





backend = DetourBackend("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0")
patches = []
patches.append(RawMemPatch(0x4049f5, b"\x00\x00\xff\xff"))
backend.apply_patches(patches)
backend.save("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0_detoured")