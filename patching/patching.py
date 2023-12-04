import re

import angr
from angr.sim_variable import SimRegisterVariable

from patcherex.patches import *

import variable_backward_slicing
from patching.analysis.backward_slice import VariableBackwardSlicing
from patching.analysis.constraint_solver import ConstraintSolver
from patching.matcher import Matcher
from patching.matcher import RefMatcher
from patcherex.backends.detourbackend import DetourBackend

from patching.reference import TrackingRegister
from patching.section_extender import SectionExtender
from patching.shifts import Shift


class Patching:
    def __init__(self, patching_config):

        self.new_memory_data_address = None
        self.new_memory_writing_address = None
        self.patch_code_block_end = None
        self.patch_code_block_start = None
        self.code_block_start = None
        self.code_block_end = None

        self.patching_config = patching_config
        self.backend = None
        self.writing_address = None
        # TODO: Add path to the binary as an argument for the configuration
        self.project_vuln = angr.Project("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0", auto_load_libs= False)
        self.cfg_vuln = self.project_vuln.analyses.CFGFast()
        self.entry_point_vuln = self.project_vuln.loader.find_symbol(self.patching_config.functionName).rebased_addr
        self.end_vuln = self.entry_point_vuln + self.project_vuln.loader.find_symbol(self.patching_config.functionName).size

        self.project_patch = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs = False)
        self.cfg_patch = self.project_patch.analyses.CFGFast()
        self.entry_point_patch = self.project_patch.loader.find_symbol(self.patching_config.functionName).rebased_addr
        self.end_patch = self.entry_point_patch + self.project_patch.loader.find_symbol(self.patching_config.functionName).size

        self.cfge_patch_specific = self.project_patch.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, starts=[self.entry_point_patch])
        self.ddg_patch_specific = self.project_patch.analyses.DDG(cfg=self.cfge_patch_specific, start=self.entry_point_patch)
        self.cdg_patch_specific = self.project_patch.analyses.CDG(cfg=self.cfge_patch_specific, start=self.entry_point_patch)


        self.new_def_registers = []
        self.used_registers = []

        self.shifts_ascending = []
        self.shifts_descending = []

    def patch(self, binary_fname):
        """
        :param binary_fname: path to the binary to be patched
        :return:
        """

        # TODO: Translate to python WARNING: Before beginning with patch check if lr has been pushed to the stack
        # if (!(vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains(
        #         "push") & & vulnerableProgram.getListing().getCodeUnitAt(entryPoint_vuln).toString().contains("lr"))) {
        # printf("\n\t WARNING LR NOT PUSHED TO STACK");
        # }

        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        perfect_matches = Matcher(self.cfg_vuln, self.cfg_patch, self.project_vuln, self.project_patch)

        # Getting all References from both the vulnerable Program and the patch Program
        matched_refs = RefMatcher()
        refs_vuln = matched_refs.get_refs(self.project_vuln)
        refs_patch = matched_refs.get_refs(self.project_patch)

        # Match all References
        matched_refs.match_references_from_perfect_matched_blocks(perfect_matches, refs_vuln, refs_patch, self.project_vuln, self.project_patch)
        s = matched_refs.match_from_new_address
        # Preparation for writing the Patch in the vulnerable Version

        vulnerable_blocks = perfect_matches.get_not_matched_blocks(self.cfg_vuln, self.entry_point_vuln, self.end_vuln, perfect_matches.match_old_address)
        patch_blocks = perfect_matches.get_not_matched_blocks(self.cfg_patch, self.entry_point_patch, self.end_patch, perfect_matches.match_new_address)

        start_address_of_patch = min(vulnerable_blocks)

        self.code_block_start = self.project_vuln.factory.block(start_address_of_patch)
        self.code_block_end = self.project_vuln.factory.block(max(vulnerable_blocks))

        patch_start_address_of_patch = min(patch_blocks)

        self.patch_code_block_start = self.project_patch.factory.block(patch_start_address_of_patch)
        self.patch_code_block_end = self.project_patch.factory.block(max(patch_blocks))

        # Start of the actual patching:

        # Create a new memory section to write the patch into
        # CURRENTLY: We try to use lief to extend the last section of the LOAD segment

        file_to_be_patched = SectionExtender(binary_fname, 1024).extend_last_section_of_segment()

        self.backend = DetourBackend(file_to_be_patched)
        new_memory_address = self.project_vuln.loader.main_object.segments[0].vaddr + self.project_vuln.loader.main_object.segments[0].memsize

        # Estimate size of patch to find space for newly added references and data
        self.new_memory_writing_address = new_memory_address + 2 * (self.patch_code_block_end.addr - self.patch_code_block_start.addr)

        # Jump to new Memory
        print(start_address_of_patch)
        self.jump_to_new_memory(start_address_of_patch-1, new_memory_address)

        self.cfg_patch.get_any_node(patch_start_address_of_patch)

        patch_block_start_address = patch_start_address_of_patch
        vuln_block_start_address = start_address_of_patch

        self.writing_address = new_memory_address

        while patch_block_start_address < self.patch_code_block_end.addr:
            block_patch = self.project_patch.factory.block(patch_block_start_address)

            # Going through every CodeUnit from the BasicBlock
            for instruction_patch in block_patch.capstone.insns:

                # Implement the following to use Angr References

                reference = self.get_references_from_instruction(instruction_patch, refs_patch, block_patch.thumb)

                # Handling of possible References
                if reference is not None:
                    self.handle_references(reference, matched_refs, instruction_patch)
                else:
                    self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
                    self.writing_address = self.writing_address + instruction_patch.size

                patch_block_start_address = patch_block_start_address + block_patch.size

        #    Set the End for the last ShiftZone
        if self.shifts_ascending:
            self.shifts_ascending[-1].end = self.writing_address
            self.shifts_descending[-1].end = self.writing_address

        # Fix all References broken by shifts
        # self.fix_shifts_in_references()
        self.backend.save("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0_detoured")

        # Jump back to the original function since the patch is now integrated


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
        patches = [InlinePatch(base_address, "bl " + target_address)]
        self.backend.apply_patches(patches)


    def get_references_from_instruction(self, instruction, refs, thumb):
        """
        Check if there is a Reference in refs that is from the given instruction
        :param instruction:
        :param refs:
        :return: Reference or None
        """
        for ref in refs:
            if thumb:
                if ref.fromAddr == instruction.address - 1:
                    return ref
                else:
                    pass
            else:
                if ref.fromAddr == instruction.address:
                    return ref
                else:
                    pass


    def handle_references(self, reference, matched_refs, instruction_patch):
        """
        See if Reference is a matched Address, then use the matched Reference instead

        :param reference:
        :param matched_refs:
        :param instruction_patch:
        :return:
        """

        # First check if from Address of Reference is perfectly matched
        if reference.fromAddr in matched_refs.match_from_new_address:
            self.handle_matched_reference(reference, matched_refs.match_from_new_address[reference.fromAddr], instruction_patch)

        # Check if the To Address of the Reference is perfectly matched
        elif reference.toAddr in matched_refs.match_to_new_address:
            self.handle_matched_reference(reference, matched_refs.match_to_new_address[reference.toAddr], instruction_patch)

        # If the Reference is not perfectly matched
        else:
            self.add_new_reference(instruction_patch, reference)


    def rewriting_bytes_of_code_unit_to_new_address(self, instruction, address):
        """
        Taking the bytes of an instruction and writing them to the given address
        :param instruction:
        :param address:
        """
        print(bytes(instruction.insn.bytes))
        patches = [RawMemPatch(address, bytes(instruction.insn.bytes))]
        self.backend.apply_patches(patches)

    def handle_read_reference(self, instruction_patch, reference):

        # Tracking Register for later backward slicing and static analysis

        register_pattern = re.compile(r'r\d+')

        # Find all matches in the instruction string
        matches = register_pattern.findall(instruction_patch.op_str)

        # Extract the first match (assuming there is at least one match)
        register_name = matches[0]


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
        register = TrackingRegister(register_name, self.writing_address + difference + 4)

        self.new_def_registers.append(register)


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


        solver = ConstraintSolver(self.project_patch)
        # Calculate Address where the value of the PARAM reference need to be written

        jump_target = old_reference.toAddr


        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                                           ddg=self.ddg_patch_specific,
                                                                           cdg=self.cdg_patch_specific,
                                                                           project=self.project_patch,
                                                                           variable=variable, targets=location)


        # Tracking Registers used in the backward slice
        for address in backward_slice.chosen_statements_addrs:
            register_pattern = re.compile(r'r\d+')
            # Find all matches in the instruction string
            matches = register_pattern.findall(self.project_patch.factory.block(address).capstone.insns[0].op_str)
            # Extract the first match (assuming there is at least one match)
            register_name = matches[0]
            register = TrackingRegister(register_name, address)
            self.used_registers.append(register)



        results = solver.solve(backward_slice.chosen_statements, jump_target)


        for res in self.new_def_registers:
            if res in self.used_registers:
                for result , _  in results:
                    if res.register_name == result:
                        reg = res
                        self.new_def_registers.remove(res)


        # Calculate bytes of value that needs to be loaded in the previously modified address

        for (register, value) in results:
            if register == reg.register_name:
                data = value.to_bytes(4, byteorder='little')

        patches = [RawMemPatch(reg.ldr_data_address, data)]

        self.backend.apply(patches)

        self.replacing_add_with_sub(instruction_patch)

        self.writing_address = self.writing_address + len(instruction_patch) * 2

        self.remember_shifted_bytes(2)

    def replacing_add_with_sub(self, instruction_patch):
        pass


    def handle_control_flow_jump_reference(self, instruction_patch, old_reference):
        # Check if Reference jumps outside of the patch
        if self._reference_outside_of_patch(self.code_block_start, self.code_block_end, old_reference):
    
        # Check if Reference stays inside of the function -- That means it originally might have been a "b target" thumb instruction that needs to be changed
            if self.entry_point_vuln < old_reference.toAddr < self.end_vuln:

                self.reassemble_reference_at_different_address_thumb(instruction_patch, old_reference)
                self.writing_address = self.writing_address + (instruction_patch.size * 2)
                self.remember_shifted_bytes(4)

        # Reference outside of function and outside of patch
            else:
                self.reassemble_reference_at_different_address(instruction_patch, old_reference)
                self.writing_address = self.writing_address + instruction_patch.size

        # Reference inside of patch
        else:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size


    def add_new_reference(self, instruction_patch, reference):

        if self._reference_outside_of_patch(self.patch_code_block_start, self.patch_code_block_end, reference):
            self.rewriting_and_adding_reference_to_the_old_program(reference, instruction_patch)
            self.writing_address = self.writing_address + 4
        else:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size

    def handle_matched_reference(self, reference, old_reference, instruction_patch):
        ref_type = reference.refType

        # Depending on the type of the reference there are now different ways to proceed:
        # First READ reference
        if ref_type == "read":
            self.handle_read_reference(instruction_patch, old_reference)

        # Then OFFSET reference
        elif ref_type == "offset":
            self.handle_offset_reference(instruction_patch, old_reference)

        # Then CONTROL_FLOW_JUMP reference
        elif ref_type == "control_flow_jump":
            self.handle_control_flow_jump_reference(instruction_patch, old_reference)

    def remember_shifted_bytes(self, number_shifted_bytes):

        outside_shift_ascending = Shift()

        outside_shift_descending = Shift()
        outside_shift_ascending.start = self.writing_address

        if number_shifted_bytes == 4:
            patches = [RawMemPatch(self.writing_address, b"\x00\xbf")]
            self.backend.apply_patches(patches)
            self.writing_address = self.writing_address + 2

        outside_shift_descending.start = self.writing_address
        outside_shift_ascending.shiftedBytesNum = number_shifted_bytes
        outside_shift_descending.shiftedBytesNum = number_shifted_bytes

        if len(self.shifts_ascending) > 0:
            self.shifts_ascending[len(self.shifts_ascending)-1].end = outside_shift_ascending.start
            self.shifts_descending[len(self.shifts_descending)-1].end = self.writing_address

        self.shifts_ascending.append(outside_shift_ascending)
        self.shifts_descending.append(outside_shift_descending)

    def reassemble_reference_at_different_address_thumb(self, instruction_patch, old_reference):

        new_string = self.replace_jump_target_address(instruction_patch, old_reference.toAddr)

        new_string = new_string.replace("b ", "bl ")

        if "cbz" in new_string:
            real_target_address = old_reference.toAddr

            target_address = self.writing_address + 130
            new_string = self.replace_jump_target_address(instruction_patch, target_address)

            patches = [InlinePatch(target_address, "bl 0x" + real_target_address)]

            # TODO: Is this really necessary or some ghidra hack? rewritingBytesofCodeUnitToNewAddress(codunneu, codunaddr);

            patches.append(InlinePatch(self.writing_address, new_string))
            self.backend.apply_patches(patches)
            return

        result = self.writing_address - old_reference.toAddr % 4
        if result == 0:
            self.remember_shifted_bytes(2)

            patches = [RawMemPatch(self.writing_address, b"\x00\xbf")]
            self.backend.apply_patches(patches)
            self.writing_address = self.writing_address + 2


        patches = [InlinePatch(self.writing_address, new_string)]
        self.backend.apply_patches(patches)

    def reassemble_reference_at_different_address(self, instruction_patch, old_reference, writing_address):

        new_string = self.replace_jump_target_address(instruction_patch, old_reference.toAddr)

        patches = [InlinePatch(writing_address, new_string)]
        self.backend.apply_patches(patches)

    def rewriting_and_adding_reference_to_the_old_program(self, reference, instruction_patch):

        # Distinguish two cases 1. Read(e.g.ldr..) 2. Param(e.g.add...)

        if reference.refType == "read":
            self.add_read_reference(instruction_patch)
        elif reference.refType == "param":
            self.add_offset_reference(reference, instruction_patch)

    def add_read_reference(self, instruction_patch):

        # Tracking register

        register_pattern = re.compile(r'r\d+')

        # Find all matches in the instruction string
        matches = register_pattern.findall(instruction_patch.op_str)

        # Extract the first match (assuming there is at least one match)
        register_name = matches[0]

        # Jump to new memory
        patches = [InlinePatch(self.writing_address, "bl 0x" + str(self.new_memory_writing_address))]
        self.backend.apply_patches(patches)

        if instruction_patch.size == 2:
            self.remember_shifted_bytes(2)

        # At the new memory address put the instruction with the load Reference
        target_address = self.new_memory_writing_address + 12

        self.reassemble_reference_at_different_address(instruction_patch, target_address, self.new_memory_writing_address)
        self.new_memory_writing_address = self.new_memory_writing_address + instruction_patch.size

        # Save this load data address in the corresponding register
        register = TrackingRegister(register_name, target_address)
        
        # Add the register to the list of registers that need to be tracked
        self.new_def_registers.append(register)

        # Write the jump back to the original code
        patches = [InlinePatch(self.new_memory_writing_address, "bx lr")]

        self.backend.apply_patches(patches)
        self.new_memory_writing_address = target_address + 8

    def add_offset_reference(self, reference, instruction_patch):

        # Run analysis to get the value that needs to be loaded in the previously modified address
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

        solver = ConstraintSolver(self.project_patch)

        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                 ddg=self.ddg_patch_specific,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)

        # Tracking Registers used in the backward slice
        for address in backward_slice.chosen_statements_addrs:
            register_pattern = re.compile(r'r\d+')
            # Find all matches in the instruction string
            matches = register_pattern.findall(self.project_patch.factory.block(address).capstone.insns[0].op_str)
            # Extract the first match (assuming there is at least one match)
            register_name = matches[0]
            register = TrackingRegister(register_name, address)
            self.used_registers.append(register)

        # Check what we want here. We could extend the .data .rodata section maybe?? Or just put it at a very far way address in the already extended section
        self.new_memory_data_address = self.new_memory_writing_address + 80

        results = solver.solve(backward_slice.chosen_statements, self.new_memory_data_address)

        for res in self.new_def_registers:
            if res in self.used_registers:
                for result, _ in results:
                    if res.register_name == result:
                        reg = res
                        self.new_def_registers.remove(res)

        # Calculate bytes of value that needs to be loaded in the previously modified address

        for (register, value) in results:
            if register == reg.register_name:
                data = value.to_bytes(4, byteorder='little')

        patches = [RawMemPatch(reg.ldr_data_address, data)]

        self.backend.apply(patches)

        data = self.load_data_from_memory(reference.toAddr)

        # Write the data to the new memory address

        patches = [RawMemPatch(self.new_memory_writing_address, data)]
        self.backend.apply(patches)

        self.new_memory_data_address = self.new_memory_data_address + len(data)

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)

    def load_data_from_memory(self, address):

        data = b""
        while True:
            byte_data = self.project_patch.loader.memory.load(address, 1)
            if byte_data == b'\x00':
                break
            data += byte_data
            address += 1
            return data

    def fix_shifts_in_references(self, patch_start_address_of_patch):
        pass
    #     patch_end = self.shifts_ascending[len(self.shifts_ascending)-1].end
    #
    #     self.project_patch.factory.block(patch_start_address_of_patch)
    #     codunHelp = vulnerableProgram.getListing().getCodeUnitAt(patchStart)
    #     for  vulnerableProgram.getListing().getCodeUnits(patchStart, true):
    #
    #
    #
    #     refsToBeFixed = codunHelp.getReferencesFrom();
    #
    #     if refsToBeFixed.length > 0:
    #         Address jumpTarget =  refsToBeFixed[0].getToAddress()
    #         if isInShiftListZone(jumpTarget, "asc") != 0:
    #             startAddr =refsToBeFixed[0].getFromAddress();
    #             refT = startAddr;
    #             while (!jumpTarget.equals(refT)) {
    #                 refT = jumpTarget
    #                 if (refsToBeFixed[0].getFromAddress().compareTo(refsToBeFixed[0].getToAddress()) == -1):
    #                     jumpTarget = addingShiftToAddress(startAddr, jumpTarget)
    #                 else:
    #                     jumpTarget = subtractingShiftFromAddress(startAddr, jumpTarget)
    #
    #     startAddr = refT;
    #     asm = Assemblers.getAssembler(vulnerableProgram)
    #
    # newString = replaceJumpAddr(codunHelp, jumpTarget)
    #
    # asm.assemble(refsToBeFixed[0].getFromAddress(), newString)


    # Static methods
    @staticmethod
    def _reference_outside_of_patch(block_start, block_end, old_reference):
        if block_start.addr < old_reference.toAddr < block_end.addr + block_end.size:
            return False
        else:
            return True

    @staticmethod
    def replace_jump_target_address(instruction_patch, difference):
        instruction_string = instruction_patch.mnemonic + " " + instruction_patch.op_str

        modified_string = re.sub(r'#0x[0-9A-Fa-f]+', "#" + str(hex(difference)), instruction_string)
        return modified_string



