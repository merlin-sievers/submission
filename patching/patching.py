import re

import angr
from angr.sim_variable import SimRegisterVariable

from patcherex.patches import *

import variable_backward_slicing
from patching.analysis.backward_slice import VariableBackwardSlicing
from patching.matcher import Matcher
from patching.matcher import RefMatcher
from patcherex.backends.detourbackend import DetourBackend

from patching.section_extender import SectionExtender


class Patching:
    def __init__(self, patching_config):

        self.patching_config = patching_config
        self.backend = None
        self.writing_address = None
        # TODO: Add path to the binary as an argument for the configuration
        self.project_vuln = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)
        self.cfg_vuln = self.project_vuln.analyses.CFGFast()
        self.entry_point_vuln = self.project_vuln.loader.find_symbol(self.patching_config.functionName).rebased_addr
        self.end_vuln = self.entry_point_vuln + self.project_vuln.loader.find_symbol(self.patching_config.functionName).size

        self.project_patch = angr.Project("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0", auto_load_libs=False)
        self.cfg_patch = self.project_patch.analyses.CFGFast()
        self.entry_point_patch = self.project_patch.loader.find_symbol(self.patching_config.functionName).rebased_addr
        self.end_patch = self.entry_point_patch + self.project_patch.loader.find_symbol(self.patching_config.functionName).size

        self.cfge_patch_specific = self.project_patch.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, starts=[self.entry_point_patch])
        self.ddg_patch_specific = self.project_patch.analyses.DDG(cfg=self.cfge_patch_specific, start=self.entry_point_patch)
        self.cdg_patch_specific = self.project_patch.analyses.CDG(cfg=self.cfge_patch_specific, start=self.entry_point_patch)

    def patch(self, binary_fname, patch_list, output_fname):
        """
        :param binary_fname: path to the binary to be patched
        :param patch_list: list of patches to be applied
        :param output_fname: path to the patched binary
        :return:
        """

        # TODO: Translate to python WARNING: Before beginning with patch check if lr has been pushed to the stack
        # if (!(vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains(
        #         "push") & & vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains("lr"))) {
        # printf("\n\t WARNING LR NOT PUSHED TO STACK");
        # }

        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        perfect_matches = Matcher(self.cfg_vuln, self.cfg_patch)

        # Getting all References from both the vulnerable Program and the patch Program
        matched_refs = RefMatcher()
        refs = matched_refs.get_refs(True)

        # Match all References
        matched_refs.match_references_from_perfect_matched_blocks(perfect_matches, refs)

        # Preparation for writing the Patch in the vulnerable Version

        vulnerable_blocks = perfect_matches.get_not_matched_blocks(self.project_vuln, self.entry_point_vuln, self.end_vuln)
        patch_blocks = perfect_matches.get_not_matched_blocks(self.project_patch, self.entry_point_patch, self.end_patch)

        start_address_of_patch = min(vulnerable_blocks)

        code_block_start = self.project_vuln.factory.block(start_address_of_patch)
        code_block_end = self.project_vuln.factory.block(max(vulnerable_blocks))

        patch_start_address_of_patch = min(patch_blocks)

        patchCodeBlockStart = self.project_patch.factory.block(patch_start_address_of_patch)
        patch_code_block_end = self.project_patch.factory.block(max(patch_blocks))

        # Start of the actual patching:

        # Create a new memory section to write the patch into
        # CURRENTLY: We try to use lief to extend the last section of the LOAD segment

        file_to_be_patched = SectionExtender(binary_fname, 1024)

        self.backend = DetourBackend(file_to_be_patched)
        new_memory_address = self.project_vuln.loader.main_object.segments[0].vaddr + self.project_vuln.loader.main_object.segments[0].memsize

        # Jump to new Memory
        self.jump_to_new_memory(new_memory_address, start_address_of_patch)

        self.cfg_patch.get_any_node(patch_start_address_of_patch)

        patch_block_start_address = patch_start_address_of_patch
        vuln_block_start_address = start_address_of_patch

        self.writing_address = new_memory_address

        while patch_block_start_address < patch_code_block_end.addr:
            block_patch = self.project_patch.factory.block(patch_block_start_address)

            # Going through every CodeUnit from the BasicBlock
            for instruction_patch in block_patch.capstone.insns:

                # Implement the following to use Angr References

                reference = self.get_references_from_instruction(instruction_patch, refs)

                # Handling of possible References
                if reference is not None:
                    self.handle_references(reference, refs, instruction_vuln, instruction_patch)
                else:
                    self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch)
                    self.writing_address = self.writing_address + instruction_patch.size

                patch_block_start_address = patch_block_start_address + block_patch.size

    #
    #    # Set the End for the last ShiftZone
    #    shiftsAscending.get(shiftsAscending.size()-1).end = next
    #    shiftsDescending.get(shiftsDescending.size()-1).end = next
    #
    #    # Fix all References broken by shifts
    #    fixShiftsInReferences()
    #
    # # Jump back to the original function since the patch is now integrated
    #
    #     if (!(next.subtract(codeBlockEnde.getMaxAddress().next()) % 4 == 0)):
    #                 byte[] test = new byte[2]
    #                 test[0] = (byte) 0x00
    #                 test[1] = (byte) 0xbf
    #
    #             asmVuln.patchProgram(test, next)
    #             Disassembler disasm = Disassembler.getDisassembler(vulnerableProgram, monitor, null)
    #
    #
    #             next = next.add(2)
    #
    #             clearListing(next, next.add(4))
    #             asmVuln.assemble(next, "bl 0x" + codeBlockEnde.getMaxAddress().next())


    def jump_to_new_memory(self, base_address, target_address):
        """
        Write a branch to target_address instruction at base_address
        :param base_address: Address of the instruction to be patched
        :param target_address: Address of the target instruction
        """

        target_address = str(hex(target_address))
        patches = [InlinePatch(base_address, "b " + target_address)]
        self.backend.apply_patches(patches)


    def get_references_from_instruction(self, instruction, refs):
        """
        Check if there is a Reference in refs that is from the given instruction
        :param instruction:
        :param refs:
        :return: Reference or None
        """
        for ref in refs:
            if ref.fromAddr == instruction.address:
                return ref
            else:
                return None

    def handle_references(self, reference, refs, matched_refs, instruction_patch):
        """
        See if Reference is a matched Address, then use the matched Reference instead

        :param reference:
        :param refs:
        :param instruction_vuln:
        :param instruction_patch:
        :return:
        """

        # First check if from Address of Reference is perfectly matched
        if reference.fromAddr in matched_refs.matchNewAddress:
            self.handle_matched_from_reference(reference, matched_refs, instruction_patch)

        # Check if the To Address of the Reference is perfectly matched
        elif reference.toAddr in matched_refs.matchToNewAddress:
            self.handle_matched_to_reference(refs, reference, instruction_patch)

        # If the Reference is not perfectly matched
        else:
            self.add_new_reference()


    def rewriting_bytes_of_code_unit_to_new_address(self, instruction, address):
        """
        Taking the bytes of an instruction and writing them to the given address
        :param instruction:
        :param address:
        """
        patches = [RawMemPatch(address, instruction.bytes)]
        self.backend.apply_patches(patches)

    def handle_read_reference(self, reference, instruction_patch):

        # Tracking Register for later backward slicing and static analysis --> TODO Adapt to python and angr needs
        # instruction = instruction_vuln
        #
        # Register register = new Register();
        # register.getRegister(instruction);

        # TODO: Difference now assumes there are no more shifts than 32 bytes (pc + 28). That is a random guess.

        difference = reference.toAddr - reference.fromAddr
        difference = difference + 28
        # TODO: Check if necessary: Some alignment stuff
        # if (!(codunaddr.add(difference).getOffset() % 4 == 0)) {
        # difference = difference + 2;
        # }

        # Replacing the reference with the new target address
        new_instruction_string = self.replace_jump_target_address(instruction_patch, difference)

        patches = [InlinePatch(self.writing_address, new_instruction_string)]
        self.backend.apply_patches(patches)

        # Tracking the address that will be read from
        # register.setLdrDataAddr(self.writing_address.add(difference + 4 );
        #
        # newDefRegisters.put(register.getName(), register);

        self.writing_address = self.writing_address + instruction_patch.size


    def handle_offset_reference(self, instruction_patch, old_reference):

        # Get Variable defined in instruction and the CodeLocation of the instruction
        instr_view = self.ddg_patch_specific.view[instruction_patch.addr]
        definitions: list = instr_view.definitions
        variable = None
        location = None
        for definition in definitions:
        #     Now only take the register variable
            if isinstance(definition._variable.variable, SimRegisterVariable):
                variable = definition._variable.variable
                location = definition._variable.location



        # TODO: Needs to be implemented here again... :(
        smtSolver = SMTSolver()
        # Calculate Address where the value of the PARAM reference need to be written

        jump_target = old_reference.toAddr

        # Tracking Registers --> TODO: Need to implement this
        # Set < String > intersection = new HashSet <> (newDefRegisters.keySet());
        # intersection.retainAll(statAna.getUsedRegisters().keySet());
        # List < Register > inputs = new ArrayList < Register > ();
        # int i = 0;
        # for (Iterator < String > it = intersection.iterator(); it.hasNext();) {
        #     inputs.add(newDefRegisters.get(it.next()));
        #     i++;
        #     }

        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                                           ddg=self.ddg_patch_specific,
                                                                           cdg=self.cdg_patch_specific,
                                                                           project=self.project_patch,
                                                                           variable=variable, targets=location)

        smtResult = smtSolver.run(backward_slice.chosen_statements_addrs, jumpTarget, codunaddr, true, inputs);

        # Calculate bytes of value that needs to be loaded in the previously modified address

        data[p] = (byte) (smtResult.get(0).getValue() >> p * 8)

        setBytes(smtResult.get(0).getLdrDataAddr(), data);

        newDefRegisters.remove(smtResult.get(0).getName());

        replacingADDwithSUB(codunneu);

        self.writing_address = codunaddr.add(codunneu.getLength() * 2);

        self.remember_shifted_bytes(instruction_patch, 2)


def handle_control_flow_jump_reference(self):
        // Check if Reference jumps outside of the patch
        if (referenceOutsideOfPatch(refs.matchNewAddress.get(datref[0].getFromAddress()).getOldRef().getToAddress(), 0)) {

        // Check if Reference stays inside of the function -- That means it originally might have been a "b target" thumb instruction that needs to be changed
        if (patchProgram.getListing().getFunctionContaining(datref[0].getFromAddress()).getBody().contains(datref[0].getToAddress())) {

        reassemblingReferenceAtDifferentAddressThumb(codunneu, refs.matchNewAddress.get(datref[0].getFromAddress()).getOldRef().getToAddress());
        next = codunaddr.add(codunneu.getLength() * 2);
        rememberShiftedBytes(codunneu, 4);

        // Reference outside of function and outside of patch
        } else {

        reassemblingReferenceAtDifferentAddress(codunneu, codunaddr, refs.matchNewAddress.get(datref[0].getFromAddress()).getOldRef().getToAddress());
        printf("\n\t CB outside function");
        next = codunaddr.add(codunneu.getLength());
        }
        // Reference inside of patch
        } else {
        rewritingBytesofCodeUnitToNewAddress(codunneu, codunaddr);
        next = codunaddr.add(codunneu.getLength());
        }
        }
        pass

    def handle_matched_to_reference(self, refs, reference, instruction_patch):
        pass

    def add_new_reference(self):
        #
        # if (referenceOutsideOfPatch(datref[0].getToAddress(), 1)) {
        #
        # rewritingAndAddingReferenceToTheOldProgram(datref[0], refs, codunneu, ldrAddress);
        #
        # next = codunaddr.add(vulnerableProgram.getListing().getCodeUnitAt(codunaddr).getLength());
        # printf("\n \t next  %s", next);
        # } else {
        # printf("\n \t notMatchedRewritten  %s", codunneu.getLength());
        # rewritingBytesofCodeUnitToNewAddress(codunneu, codunaddr);
        # next = codunaddr.add(codunneu.getLength());
        # }
        # }
        # }
        #
        # }

    def handle_matched_from_reference(self, reference, matched_refs, instruction_patch):
        ref_type = reference.refType
        # Get the old Reference
        old_reference = matched_refs.matchNewAddress[reference.fromAddr]

        # Depending on the type of the reference there are now different ways to proceed:
        # First READ reference
        if ref_type == "read":
            self.handle_read_reference(old_reference, instruction_patch)

        # Then OFFSET reference
        elif ref_type == "offset":
            self.handle_offset_reference()

        # Then CONTROL_FLOW_JUMP reference
        elif ref_type == "control_flow_jump":
            self.handle_control_flow_jump_reference()

    def replace_jump_target_address(self, instruction_patch, difference):
        instruction_string =  instruction_patch.mnemonic + " " + instruction_patch.op_str

        modified_string = re.sub(r'#0x[0-9A-Fa-f]+', "#" + str(hex(difference)), instruction_string)
        return modified_string