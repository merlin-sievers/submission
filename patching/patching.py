import angr

from patcherex.patches import *
from patching.matcher import Matcher
from patching.matcher import RefMatcher
from patcherex.backends.detourbackend import DetourBackend

class Patching:
    def __init__(self, patching_config):
        self.patching_config = patching_config
        self.backend = none

    def patch(self, binary_fname, patch_list, output_fname):
        """
        :param binary_fname: path to the binary to be patched
        :param patch_list: list of patches to be applied
        :param output_fname: path to the patched binary
        :return:
        """
        # TODO: Add path to the binary as an argument for the configuration
        self.patching_config.start()

        # Find entry point of vulnerable function
        project_vuln = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)
        cfg_vuln = project_vuln.analyses.CFGFast()
        entryPoint_vuln = project_vuln.loader.find_symbol(self.patching_config.functionName).rebased_addr
        end_vuln = entryPoint_vuln + project_vuln.loader.find_symbol(self.patching_config.functionName).size


        project_patch = angr.Project("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0", auto_load_libs=False)
        cfg_patch = project_patch.analyses.CFGFast()
        entryPoint_patch = project_patch.loader.find_symbol(self.patching_config.functionName).rebased_addr
        end_patch = entryPoint_patch + project_patch.loader.find_symbol(self.patching_config.functionName).size

        # TODO: Translate to python WARNING: Before beginning with patch check if lr has been pushed to the stack
        # if (!(vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains(
        #         "push") & & vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains("lr"))) {
        # printf("\n\t WARNING LR NOT PUSHED TO STACK");
        # }


        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        perfectMatches = Matcher(cfg_vuln, cfg_patch)

        # Getting all References from both the vulnerable Program and the patch Program
        matchedRefs = RefMatcher()
        refs = matchedRefs.get_refs(True)
        # Match all References
        matchedRefs.matchReferencesFromPerfectMatchedBlocks(perfectMatches, refs)


        # Preparation for writing the Patch in the vulnerable Version

        vulnerableBlocks = perfectMatches.getNotMatchedBlocks(project_vuln, entryPoint_vuln, end_vuln)
        patchBlocks = perfectMatches.getNotMatchedBlocks(project_patch, entryPoint_patch, end_patch)

        start_address_of_patch = min(vulnerableBlocks)

        codeBlockStart = project_vuln.factory.block(start_address_of_patch)
        codeBlockEnd = project_vuln.factory.block(max(vulnerableBlocks))

        patch_start_address_of_patch = min(patchBlocks)

        patchCodeBlockStart = project_patch.factory.block(patch_start_address_of_patch)
        patchCodeBlockEnd = project_patch.factory.block(max(patchBlocks))


        # Start of the actual patching:

        # Create a new memory section to write the patch into
        # CURRENTLY: We just write the patch at the end of the elf file.
        # TODO: Integrate pacherex properly
        self.backend = DetourBackend("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0")
        patches = []

        new_memory_address = len(self.backend.ocontent)
        uninitialized_data = b"\x00\x00\x00\x00"*100
        patches.append(RawFilePatch(new_memory_address, uninitialized_data))
        self.backend.apply_patches(patches)

        patches = []

        # Jump to new Memory
        self.jump_to_new_memory(new_memory_address, start_address_of_patch)

        Address pCBStart = patchCodeBlockStart.getFirstStartAddress();

        cfg_patch.get_any_node(patch_start_address_of_patch)

        while (pCBStart.compareTo(patchCodeBlockEnde.getFirstStartAddress().next()) == -1):
            # TODO: Check what happens to the project after patching
            # Assumption CodeUnitIterator stable even if listing gets modified


            CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlockStart, true)

             # Going through every CodeUnit from the BasicBlock
            for(codeUnitIteratorneu = listingneu.getCodeUnits(patchCodeBlockStart, true); CodeUnitIteratorneu.hasNext(); ){

                codunneu = codeUnitIteratorneu.next()
                #  Rewriting of  patch codeUnit to the vulnerable Version, if it is not part of a perfectly matched Block

                codun = codeUnitIterator.next()
                if (next == null):
                    next = patchMemory.freeAddress
                codunaddr = next


            	# Implement the following to use Angr References
                Reference[] datref = getAngrReference(codunneu)

                # Handling of possible References
                if(datref.length >0):
                    handleReferences(datref, refs, codun, codunneu, ldrAddress)
                else:
                    rewritingBytesofCodeUnitToNewAddress(codunneu, codunaddr)
                    next = codunaddr.add(codunneu.getLength())

                codeBlockStart = basicBlockModelOld.getCodeBlockAt(codeBlockStart.getMaxAddress().next(), monitor)

                patchCodeBlockStart = basicBlockModelNew.getCodeBlockAt(patchCodeBlockStart.getMaxAddress().next(), monitor)

                if (patchCodeBlockStart == null):
                    pCBStart = patchCodeBlockEnde.getMaxAddress()
                else:
                    pCBStart = patchCodeBlockStart.getFirstStartAddress()

                # Set the End for the last ShiftZone
                shiftsAscending.get(shiftsAscending.size()-1).end = next
                shiftsDescending.get(shiftsDescending.size()-1).end = next

                # Fix all References broken by shifts
                fixShiftsInReferences()

                # // Jump back to the original function since the patch is now integrated

                if (!(next.subtract(codeBlockEnde.getMaxAddress().next()) % 4 == 0)):
                    byte[] test = new byte[2]
                    test[0] = (byte) 0x00
                    test[1] = (byte) 0xbf

                asmVuln.patchProgram(test, next)
                Disassembler disasm = Disassembler.getDisassembler(vulnerableProgram, monitor, null)

                # Disassemble correctly in ArmThumbMode
                clearListing(next, next.add(2))
                ArmDisassembleCommand arws = new ArmDisassembleCommand(next, new AddressSet(next), true)
                arws.applyTo(vulnerableProgram)
                disasm.disassemble(next, new AddressSet(next))

                next = next.add(2)

                clearListing(next, next.add(4))
                asmVuln.assemble(next, "bl 0x" + codeBlockEnde.getMaxAddress().next())



    def jump_to_new_memory(self, base_address, target_address):
        patches = []
        target_address = str(hex(target_address))
        patches.append(InlinePatch(base_address, "b " + target_address))
        self.backend.apply_patches(patches)