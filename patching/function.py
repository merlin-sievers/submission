import copy
import re
import pickle
import os
import angr
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable

from patcherex.patches import *
from patching.patching import Patching
from patching.analysis.backward_slice import VariableBackwardSlicing
from patching.analysis.constraint_solver import ConstraintSolver
from patching.matcher import Matcher
from patching.matcher import RefMatcher
from patcherex.backends.detourbackend import DetourBackend

from patching.reference import TrackingRegister, Reference
from patching.section_extender import SectionExtender
from patching.shifts import Shift

import time
import logging


class FunctionPatch(Patching):




    def __init__(self, patching_config):
        super().__init__(patching_config)
        self.worklist = True


    def patch_functions(self):
        logging.getLogger('angr').setLevel(logging.CRITICAL)

        initial = FunctionPatch(patching_config=self.patching_config)
        initial.start()

        initial.initial_patch()

        initial.patch()
        patched_functions = []

        function_list = list(initial.new_added_function)
        for function in function_list:
            if function in patched_functions:
                continue
            print("Function", initial.new_added_function[function])
            initial.additional_function(function)
            patched_functions.append(function)
            set1 = set(function_list)
            function_list.extend(x for x in initial.new_added_function if x not in set1)
            initial.patch()
                # Add only unique elements




    def start(self):

        self.limit = 1
        # TODO: Hack to extend segment and match afterwards
        vuln = SectionExtender(self.patching_config.binary_path, 1048576).add_section()

        # TODO: Add path to the binary as an argument for the configuration
        self.project_vuln = angr.Project(vuln, auto_load_libs=False)

        print("\n\t Starting to analyze the vulnerable Program CFGFast...")
        self.cfg_vuln = self.project_vuln.analyses.CFGFast()

        if self.project_vuln.loader.find_symbol(self.patching_config.functionName) is None:
            print(self.patching_config.functionName + " not found in binary")
            return
        self.entry_point_vuln = self.project_vuln.loader.find_symbol(self.patching_config.functionName).rebased_addr
        # TODO: Find a better option to get the end
        self.end_vuln = self.entry_point_vuln + self.project_vuln.loader.find_symbol(
            self.patching_config.functionName).size
        print("\n\t Starting to analyze the vulnerable Program CFGEmul...")

        option = angr.sim_options.refs
        # option = angr.sim_options.resilience
        # option = angr.sim_options.modes["fastpath"]
        # option.add(angr.sim_options.FAST_MEMORY)
        # option.add(angr.sim_options.FAST_REGISTERS)

        # TODO: Check if the context_sensitivity_level is correct
        self.cfge_vuln_specific = self.project_vuln.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                                         state_add_options=option,
                                                                         starts=[self.entry_point_vuln], call_depth=2)

        self.project_patch = angr.Project(self.patching_config.patch_path, auto_load_libs=False)
        # self.project_patch = angr.Project("/Users/sebastian/PycharmProjects/angrProject/Testsuite/ReferenceTest/patch_test_4", auto_load_libs= False)

        # self.patching_config.functionName ="TIFFWriteDirectorySec.part.0"

        print("\n\t Starting to analyze the patch Program CFGFast...")
        self.cfg_patch = self.project_patch.analyses.CFGFast()
        self.entry_point_patch = self.project_patch.loader.find_symbol(self.patching_config.functionName).rebased_addr
        self.end_patch = self.entry_point_patch + self.project_patch.loader.find_symbol(
            self.patching_config.functionName).size

        print("\n\t Starting to analyze the patch Program CFGEmul...")
        self.cfge_patch_specific = self.project_patch.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                                           state_add_options=option,
                                                                           starts=[self.entry_point_patch], call_depth=2)

        print("\n\t Starting to analyze the patch Program DDG...")
        self.ddg_patch_specific = self.project_patch.analyses.DDG(cfg=self.cfge_patch_specific,
                                                                  start=self.entry_point_patch, call_depth=2)
        # self.cdg_patch_specific = self.project_patch.analyses.CDG(cfg=self.cfge_patch_specific, start=self.entry_point_patch)

    def initial_patch(self):
        print("\n\t Starting Patching Process...")
        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        perfect_matches = Matcher(self.cfge_vuln_specific, self.cfge_patch_specific, self.project_vuln,
                                  self.project_patch)

        print("\n\t Getting References...")
        # Getting all References from both the vulnerable Program and the patch Program
        self.matched_refs = RefMatcher(bindiff_results=perfect_matches.bindiff_results)
        refs_vuln = self.matched_refs.get_refs(self.project_vuln, self.cfge_vuln_specific, self.entry_point_vuln,
                                          self.cfg_vuln)
        self.refs_patch = self.matched_refs.get_refs(self.project_patch, self.cfge_patch_specific, self.entry_point_patch,
                                                self.cfg_patch)

        print("\n\t Starting to match References...")
        # Match all References
        self.matched_refs.match_references_from_perfect_matched_blocks(perfect_matches, refs_vuln, self.refs_patch,
                                                                  self.project_vuln, self.project_patch,
                                                                  self.entry_point_patch, self.end_patch)

        # Preparation for writing the Patch in the vulnerable Version

        vulnerable_blocks = perfect_matches.get_not_matched_blocks(self.cfge_vuln_specific, self.entry_point_vuln,
                                                                   self.end_vuln, perfect_matches.match_old_address)
        patch_blocks = perfect_matches.get_not_matched_blocks(self.cfge_patch_specific, self.entry_point_patch,
                                                              self.end_patch, perfect_matches.match_new_address)

        print(patch_blocks)

        if vulnerable_blocks == []:
            print("No vulnerable Blocks found")
            return
        # TODO: Check if whole function should be patched or not
        # self.start_address_of_patch = min(vulnerable_blocks)
        self.start_address_of_patch = self.entry_point_vuln

        self.code_block_start = self.project_vuln.factory.block(self.start_address_of_patch)
        self.code_block_end = self.project_vuln.factory.block(max(vulnerable_blocks))
        # self.code_block_end = self.project_vuln.factory.block(self.end_vuln)
        self.jump_back_address = min(
            [match for match in perfect_matches.match_old_address if match > self.code_block_end.addr], default=None)

        # TODO: Check if whole function should be patched or not
        # patch_start_address_of_patch = min(patch_blocks)
        self.patch_start_address_of_patch = self.entry_point_patch

        self.patch_code_block_start = self.project_patch.factory.block(self.patch_start_address_of_patch)
        self.patch_code_block_end = self.project_patch.factory.block(max(patch_blocks))
        # self.patch_code_block_end = self.project_patch.factory.block(self.end_patch)

        with open("block.txt", 'a') as error_file:
            error_message = f"BinaryName: {self.patching_config.binary_path} functionName: {self.patching_config.functionName} Function Size:{self.project_patch.loader.find_symbol(self.patching_config.functionName).size}  Patch Size: {self.patch_code_block_end.addr + self.patch_code_block_end.size - self.patch_code_block_start.addr}"
            error_file.write(error_message + '\n')



        # Calculate the elapsed time




        # Start of the actual patching:

        # Create a new memory section to write the patch into
        # CURRENTLY: We try to use lief to extend the last section of the LOAD segment

        print("\n\t Starting to extend Section...")
        # TODO: Adaption for extending Segment:
        # file_to_be_patched = SectionExtender(binary_fname, 16384).extend_last_section_of_segment()

        # TODO: Adaption for adding Segment:
        # file_to_be_patched = SectionExtender(binary_fname, 65536).add_section()

        # TODO: Adaption for monolithic firmware
        # file_to_be_patched = SectionExtender(binary_fname, 4096).extend_monolithic_firmware()

        # file_to_be_patched = SectionExtender(binary_fname, 1024).add_section()

        self.backend = DetourBackend(self.patching_config.binary_path + "_modified")
        # TODO: Adaption for extending Segment:
        # new_memory_address = self.project_vuln.loader.main_object.segments[0].vaddr + self.project_vuln.loader.main_object.segments[0].memsize

        # TODO: Adaption for adding Segment:
        # for seg in self.project_vuln.loader.main_object.segments:

        new_memory_address = self.backend.project.loader.main_object.segments[2].vaddr
        print("New Memory Address", new_memory_address)
        # TODO: Adaption for monolithic firmware
        # max_offset = 0
        # for segment in self.project_vuln.loader.main_object.segments:
        #     if segment.offset > max_offset:
        #         max_offset = segment.offset
        #         max_segment = segment
        # new_memory_address = max_segment.vaddr + max_segment.memsize

        # Estimate size of patch to find space for newly added references and data
        self.new_memory_writing_address = new_memory_address + 2 * (
                    self.patch_code_block_end.addr - self.patch_code_block_start.addr)

        start_time = time.time()

        # Jump to new Memory
        print("\n\t " + str(self.start_address_of_patch),
              self.patch_code_block_end.addr - self.patch_code_block_start.addr)
        if self.code_block_start.thumb:
            self.start_address_of_patch = self.start_address_of_patch - 1
            patch = self.patch_start_address_of_patch - 1
            if (new_memory_address % 4) == (patch % 4):
                new_memory_address = new_memory_address + 2

        self.jump_to_new_memory(self.start_address_of_patch, new_memory_address, self.patch_start_address_of_patch)
        # TODO: Check and update for thumb and not thumb
        new_memory_address = new_memory_address + 2

        self.writing_address = new_memory_address



    def additional_function(self, function_addr):

            function = self.project_patch.kb.functions.function(addr=function_addr)
            largest_block = max(function.blocks, key=lambda block: block.addr + block.size)
            function_end = largest_block.addr + largest_block.size
            self.end_patch = function_end
            print("function end", function_end)
            self.entry_point_patch = function_addr
            self.patch_code_block_end = max(function.blocks, key=lambda block: block.addr)
            self.cfge_patch_specific = self.project_patch.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                                            state_add_options=angr.sim_options.refs,
                                                                            starts=[function_addr], call_depth=2)
            self.refs_patch = self.matched_refs.get_refs(self.project_patch, self.cfge_patch_specific, function_addr, self.cfg_patch)
            self.matched_refs.match_references_from_perfect_matched_blocks(None, None ,self.refs_patch, self.project_vuln, self.project_patch, function_addr,function_end)
            self.patch_start_address_of_patch = function_addr
            self.patches = []
            print(self.entry_point_patch)
            self.ddg_patch_specific = self.project_patch.analyses.DDG(cfg=self.cfge_patch_specific,
                                                                      start=self.entry_point_patch, call_depth=2)

            self.new_def_registers = []
            self.used_registers = dict()

            self.shifts_ascending = []
            self.shifts_descending = []
            self.shift_references = []
            self.indirection_address = None
            self.new_memory_data_address = None
            self.patch_code_block_start = min(function.blocks, key=lambda block: block.addr)
            self.backend = None
            self.writing_address = self.new_added_function[function_addr]


            self.jump_tables = []

            self.limit = 1

    def patch(self):
        """
        :param binary_fname: path to the binary to be patched
        :return:
        """
        if self.backend is None:
            print("BACKEND NONE!!!")
            self.backend = DetourBackend(self.patching_config.output_path)
        patch_block_start_address = self.patch_start_address_of_patch
        end_address = 1
        matched_refs = self.matched_refs
        self.indirection_address = self.start_address_of_patch + 8
        new_memory_address = self.writing_address
        while patch_block_start_address <= self.patch_code_block_end.addr:
            nodes = self.cfge_patch_specific.get_all_nodes(patch_block_start_address)
            node = max(nodes, key=lambda node: node.size, default=None)

            if node is None:
                size = None
            else:
                size = node.block.size
            block_patch = self.project_patch.factory.block(patch_block_start_address, size)
            self.is_thumb = block_patch.thumb
            # Going through every CodeUnit from the BasicBlock
            for instruction_patch in block_patch.capstone.insns:


                # TODO: Adapt to work for non-thumb as well
                end_address = self.check_for_data(instruction_patch, end_address)
                if end_address != instruction_patch.address:
                    print("Check For data", end_address, instruction_patch.address)
                    continue

                # Check if there is a reference from outside of the patch into the patch. If so, handle it
                self.get_references_to_instruction(instruction_patch, matched_refs)

                # Implement the following to use Angr References
                print("\n\t instruction patch: " + str(instruction_patch))
                reference = self.get_references_from_instruction(instruction_patch, self.refs_patch, block_patch.thumb)

                # Handling of possible References
                if reference is not None:
                    print("reference", reference.refType)
                    self.handle_references(reference, matched_refs, instruction_patch)
                else:
                    self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
                    self.writing_address = self.writing_address + instruction_patch.size

                # if self.writing_address >= self.new_memory_writing_address:
                #     print("data mixed with code")
                # el
                if len(self.new_def_registers) >= self.limit:
                    minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                    i = self.limit
                    while i < len(self.new_def_registers):
                        if self.new_def_registers[i].ldr_data_address <= minimal_address:
                            minimal_address = self.new_def_registers[i].ldr_data_address
                        i = i + 1
                    if self.writing_address >= minimal_address - 4:
                        print("data mixed with code ldr 1a")
                        maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                        shift = minimal_address - self.writing_address
                        self.writing_address = maximum_address + 4
                        print("Shift", shift, "writing adress", self.writing_address)
                        self.remember_shifted_bytes(shift)
                        self.limit = len(self.new_def_registers) + 1
                        continue

            # Handle data mixed between code:
            # if self.writing_address >= self.new_memory_writing_address:
            #     print("data mixed with code")
            # el
            if len(self.new_def_registers) >= self.limit:
                minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                i = self.limit
                while i < len(self.new_def_registers):
                    if self.new_def_registers[i].ldr_data_address <= minimal_address:
                        minimal_address = self.new_def_registers[i].ldr_data_address
                    i = i + 1
                if self.writing_address >= minimal_address - 4:
                    print("data mixed with code ldr 1b")
                    print(patch_block_start_address, block_patch.size)
                    maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                    shift = minimal_address - self.writing_address
                    self.writing_address = maximum_address + 4
                    print("Shift", shift, "writing adress", self.writing_address)
                    self.remember_shifted_bytes(shift)
                    self.limit = len(self.new_def_registers) + 1
                    if block_patch.size == 0:
                        print(block_patch)
                        break

            patch_block_start_address = patch_block_start_address + block_patch.size
            data_shifter = True
            shift_address = self.writing_address
            while patch_block_start_address - 1 in self.cfg_patch.memory_data:
                if patch_block_start_address > self.patch_code_block_end.addr:
                    break
                if self.cfg_patch.memory_data[patch_block_start_address - 1].size is None:
                    break
                print("Data Address", patch_block_start_address, self.patch_code_block_end.addr, self.cfg_patch.memory_data[patch_block_start_address - 1])


                self.handle_jump_table(patch_block_start_address)
                if data_shifter:
                    byte_data = self.project_patch.loader.memory.load(patch_block_start_address - 1,
                                                                      self.cfg_patch.memory_data[
                                                                          patch_block_start_address - 1].size)
                    patches = RawMemPatch(self.writing_address, byte_data)
                    self.patches.append(patches)
                    self.writing_address = self.writing_address + self.cfg_patch.memory_data[
                        patch_block_start_address - 1].size
                if self.cfg_patch.memory_data[patch_block_start_address - 1].size < 1:
                    break

                patch_block_start_address = patch_block_start_address + self.cfg_patch.memory_data[
                    patch_block_start_address - 1].size
                # if self.writing_address >= self.new_memory_writing_address:
                #     print("data mixed with code")
                # el
                if len(self.new_def_registers) >= self.limit:
                    minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                    i = self.limit
                    while i < len(self.new_def_registers):
                        if self.new_def_registers[i].ldr_data_address <= minimal_address:
                            minimal_address = self.new_def_registers[i].ldr_data_address
                        i = i + 1
                    if self.writing_address >= minimal_address - 4:
                        print("data mixed with code ldr 2c")
                        print(patch_block_start_address, block_patch.size)
                        maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                        shift = minimal_address - shift_address
                        # shift = maximum_address + 4 - minimal_address
                        # self.writing_address = self.writing_address - 2
                        self.remember_shifted_bytes(shift)
                        self.writing_address = maximum_address + 4
                        print("Shift", shift, "writing adress", self.writing_address)
                        self.limit = len(self.new_def_registers) + 1
                        data_shifter = False
                        if block_patch.size == 0:
                            print(block_patch)
                            break

        # Jump back to the original function.
        if self.jump_back_address is not None:
            target_address_str = str(hex(self.jump_back_address))
            patches = InlinePatch(self.writing_address, "bl " + target_address_str,
                                  is_thumb=self.code_block_start.thumb)
            self.patches.append(patches)

        #    Set the End for the last ShiftZone
        if self.shifts_ascending:
            self.shifts_ascending[-1].end = self.writing_address
            self.shifts_descending[-1].end = self.writing_address

        # Fix all References broken by shifts

        self.backend.apply_patches(self.patches)

        # self.backend.save("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0_detoured")
        self.backend.save("/Users/sebastian/PycharmProjects/angrProject/Testsuite/vuln_test_detoured")

        # Reopen the patched binary to fix the shifts
        shift_backend = angr.Project("/Users/sebastian/PycharmProjects/angrProject/Testsuite/vuln_test_detoured",
                                     auto_load_libs=False)

        # Jump back to the original function since the patch is now integrated
        if self.shifts_ascending:
            self.fix_shifts_in_references(new_memory_address, shift_backend)

        self.backend.save(self.patching_config.output_path)
        self.backend = None

    def jump_to_new_memory(self, base_address, target_address, patch_start_address_of_patch):
        """
        Write a branch to target_address instruction at base_address
        :param base_address: Address of the instruction to be patched
        :param target_address: Address of the target instruction
        # """
        patches = InlinePatch(base_address, "mov ip, lr", is_thumb=self.code_block_start.thumb)
        self.patches.append(patches)
        base_address = base_address + 2

        target_address_str = str(hex(target_address))

        patches = InlinePatch(base_address, "bl " + target_address_str, is_thumb=self.code_block_start.thumb)
        self.patches.append(patches)
        print("Jump to new Memory", base_address, target_address_str)
        patches = InlinePatch(target_address, "mov lr, ip", is_thumb=self.code_block_start.thumb)
        self.patches.append(patches)

        # self.backend.apply_patches(patches)

    def get_references_from_instruction(self, instruction, refs, thumb):
        """
        Check if there is a Reference in refs that is from the given instruction
        :param instruction:
        :param refs:
        :return: Reference or None
        """
        references = []
        if instruction.mnemonic == 'pop' or instruction.mnemonic == 'pop.w':
            return None
        for ref in refs:
            # if thumb:
            #     if ref.fromAddr == instruction.address - 1:
            #         references.append(ref)
            #         if ref.refType == "read":
            #             return ref
            #     else:
            #         pass
            # else:
            if ref == instruction.address:
                references = (refs[ref])
                for r in refs[ref]:
                    if r.refType == "read":
                        return r
                else:
                    pass
        if len(references) >= 1:
            reference = max(references, key=lambda ref: ref.toAddr)
            if reference.toAddr <= self.project_patch.loader.min_addr:
                return None
            else:
                return reference

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
            old_reference = max(matched_refs.match_from_new_address[reference.fromAddr], key=lambda ref: ref.toAddr)
            self.handle_matched_reference(reference, old_reference, instruction_patch, matched_refs)
        # Check if the To Address of the Reference is perfectly matched
        elif reference.toAddr in matched_refs.match_to_new_address:
            old_reference = max(matched_refs.match_to_new_address[reference.toAddr], key=lambda ref: ref.toAddr)
            self.handle_matched_reference(reference, old_reference, instruction_patch, matched_refs)

        # If the Reference is not perfectly matched
        else:
            # TODO: ADAPT current workaround...
            if instruction_patch.mnemonic == "mov":
                self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
                self.writing_address = self.writing_address + instruction_patch.size
            else:
                self.add_new_reference(instruction_patch, reference, matched_refs)

    def rewriting_bytes_of_code_unit_to_new_address(self, instruction, address):
        """
        Taking the bytes of an instruction and writing them to the given address
        :param instruction:
        :param address:
        """
        # print(bytes(instruction.insn.bytes))
        patches = RawMemPatch(address, bytes(instruction.insn.bytes))
        self.patches.append(patches)
        # self.backend.apply_patches(patches)

    def handle_read_reference(self, instruction_patch, reference):

        # Tracking Register for later backward slicing and static analysis

        register_pattern = re.compile(r'\b(r\d+|sb|sl|ip|fp|sp|lr|s[0-9]+|d[0-9]+)\b')
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

        patches = InlinePatch(self.writing_address, new_instruction_string, is_thumb=self.is_thumb)
        self.patches.append(patches)
        # self.backend.apply_patches(patches)

        # Tracking the address that will be read from
        register = TrackingRegister(register_name, self.writing_address + difference + 4, reference.toAddr)

        self.new_def_registers.append(register)

        self.writing_address = self.writing_address + instruction_patch.size

    def handle_offset_reference(self, instruction_patch, reference, old_reference):
        # Get Variable defined in instruction and the CodeLocation of the instruction
        instr_view = self.ddg_patch_specific.view[instruction_patch.address]
        definitions: list = instr_view.definitions
        variable = None
        location = None
        register = self.get_register_from_instruction(instruction_patch, self.project_patch.arch)
        for definition in definitions:
            #     Now only take the register variable
            if isinstance(definition._variable.variable, SimRegisterVariable):
                if (definition._variable.variable.reg == register):
                    variable = definition._variable
                    location = [definition._variable.location]

        if variable is None:
            maximum = 0
            for definition in definitions:
                if len(definition.dependents) > 0:
                    if isinstance(definition._variable.variable, SimTemporaryVariable):
                        if maximum < definition._variable.location.stmt_idx:
                            maximum = definition._variable.location.stmt_idx
                            variable = definition._variable

        if variable is None:
            self.handle_reference_without_ddg(instruction_patch, reference)
            return

        solver = ConstraintSolver(self.project_patch, instruction_patch.address - 1, self.new_def_registers)
        # Calculate Address where the value of the PARAM reference need to be written

        jump_target = old_reference.toAddr

        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                 ddg=self.ddg_patch_specific,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)

        if jump_target < self.writing_address:
            subtraction = True
            subtraction_address = reference.fromAddr
        results = solver.solve(backward_slice.chosen_statements, jump_target, self.writing_address, variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return

        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            # Write the data to the ldr_data_address
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)
            # self.backend.apply_patches(patches)

        # Write the new instruction to the new memory

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def replacing_add_with_sub(self, instruction_patch):
        pass

    def handle_control_flow_jump_reference(self, instruction_patch, reference, old_reference):
        # Check if Reference jumps outside of the patch
        if self._reference_outside_of_patch(self.code_block_start, self.code_block_end, old_reference):

            # Check if Reference stays inside of the function -- That means it originally might have been a "b target" thumb instruction that needs to be changed
            if self.entry_point_vuln < old_reference.toAddr < self.end_vuln:
                if self.is_thumb:
                    self.reassemble_reference_at_different_address_thumb(instruction_patch, old_reference)

                else:
                    self.reassemble_reference_at_different_address(instruction_patch, old_reference.toAddr,
                                                                   self.writing_address)

            # Reference outside of function and outside of patch
            else:
                changed = self.reassemble_reference_at_different_address(instruction_patch, old_reference.toAddr,
                                                                         self.writing_address)
                # self.writing_address = self.writing_address + instruction_patch.size
                if instruction_patch.size == 2 and changed:
                    self.remember_shifted_bytes(4)
                    print("Shift", 4, "writing adress", self.writing_address)
                    self.writing_address = self.writing_address + (instruction_patch.size * 2)
                    patches = RawMemPatch(self.writing_address, b"\x00\xbf")
                    self.patches.append(patches)
                    # self.backend.apply_patches(patches)
                    self.writing_address = self.writing_address + 2
                else:
                    self.writing_address = self.writing_address + instruction_patch.size

            shift_reference = Reference(self.writing_address, old_reference.toAddr, "control_flow_jump")
            self.shift_references.append(shift_reference)

        # Reference inside of patch
        else:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            shift_reference = Reference(self.writing_address,
                                        self.writing_address + reference.toAddr - reference.fromAddr,
                                        "control_flow_jump")
            self.shift_references.append(shift_reference)
            self.writing_address = self.writing_address + instruction_patch.size

    def add_new_reference(self, instruction_patch, reference, matched_refs):

        if self._reference_outside_of_patch(self.patch_code_block_start, self.patch_code_block_end,
                                            reference) or reference.refType == "read":
            self.rewriting_and_adding_reference_to_the_old_program(reference, instruction_patch, matched_refs)
        else:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            shift_reference = Reference(self.writing_address,
                                        self.writing_address + reference.toAddr - reference.fromAddr,
                                        reference.refType)
            self.shift_references.append(shift_reference)
            self.writing_address = self.writing_address + instruction_patch.size

    def handle_matched_reference(self, reference, old_reference, instruction_patch, matched_refs):
        ref_type = reference.refType
        print("reference matched")
        # Depending on the type of the reference there are now different ways to proceed:
        # First READ reference
        if ref_type == "read":
            self.add_read_reference(instruction_patch, reference, matched_refs)
            # self.handle_read_reference(instruction_patch, old_reference)

        # Then OFFSET reference
        elif ref_type == "offset":
            if old_reference.toAddr < self.writing_address:
                # self.add_offset_reference(reference, instruction_patch)
                self.handle_offset_reference(instruction_patch, reference, old_reference)
            else:
                self.handle_offset_reference(instruction_patch, reference, old_reference)

        # Then CONTROL_FLOW_JUMP reference
        elif ref_type == "control_flow_jump":
            self.handle_control_flow_jump_reference(instruction_patch, reference, old_reference)

        else:
            print("Okay then it should be here", instruction_patch, reference.refType)
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size


    def remember_shifted_bytes(self, number_shifted_bytes):
        print("Shift remembered", number_shifted_bytes, self.writing_address)
        outside_shift_ascending = Shift()

        outside_shift_descending = Shift()
        outside_shift_ascending.start = self.writing_address

        outside_shift_descending.start = self.writing_address + number_shifted_bytes + 2
        outside_shift_ascending.shifted_bytes = number_shifted_bytes
        outside_shift_descending.shifted_bytes = number_shifted_bytes

        if len(self.shifts_ascending) > 0:
            self.shifts_ascending[len(self.shifts_ascending) - 1].end = outside_shift_ascending.start
            self.shifts_descending[len(self.shifts_descending) - 1].end = outside_shift_descending.start

        self.shifts_ascending.append(outside_shift_ascending)
        self.shifts_descending.append(outside_shift_descending)

    def reassemble_reference_at_different_address_thumb(self, instruction_patch, old_reference):

        new_string = self.replace_jump_target_address(instruction_patch, old_reference.toAddr - 1)

        new_string = new_string.replace("b ", "bl ")

        if instruction_patch.mnemonic not in {"bl", "blx", "b", "bx", "cbz", "cbnz", "b.w", "bls.w"}:

            if instruction_patch.size == 2:
                offset = 4
            else:
                offset = 4
            target_address = old_reference.toAddr - 1 - self.writing_address - offset
            new_string = instruction_patch.mnemonic
            if target_address > 0:
                if ".w" not in new_string:
                    new_string += ".w"
                new_string = instruction_patch.mnemonic + ".w $+" + str(hex(target_address))
            else:
                if ".w" not in new_string:
                    new_string += ".w"
                new_string += " $" + str(hex(target_address))

            if abs(target_address) >= 0x10000:
                real_target_address = old_reference.toAddr

                target_address = self.new_memory_writing_address
                new_string = self.replace_jump_target_address(instruction_patch, target_address)

                patches = InlinePatch(target_address, "bl 0x" + str(real_target_address))

                self.patches.append(patches)
                self.patches.append(InlinePatch(self.writing_address, new_string))
                self.new_memory_writing_address = self.new_memory_writing_address + 4
                # self.backend.apply_patches(patches)
                self.writing_address = self.writing_address + instruction_patch.size
                return
            base = self.writing_address - self.project_patch.loader.min_addr
            if base >= 850000:
                base = 0
            code = self.backend.compile_asm(new_string, base=base, is_thumb=True)

            patches = RawMemPatch(self.writing_address, code)

        else:
            patches = InlinePatch(self.writing_address, new_string)

        #
        # result = (self.writing_address - old_reference.toAddr) % 4
        # if result == 0:
        #     self.remember_shifted_bytes(2)
        #
        #     patches = RawMemPatch(self.writing_address, b"\x00\xbf")
        #     self.patches.append(patches)
        #     # self.backend.apply_patches(patches)
        #     self.writing_address = self.writing_address + 2

        self.patches.append(patches)
        if instruction_patch.size == 2:
            self.remember_shifted_bytes(4)
            print("Shift", 4, "writing adress", self.writing_address)
            self.writing_address = self.writing_address + (instruction_patch.size * 2)
            patches = RawMemPatch(self.writing_address, b"\x00\xbf")
            self.patches.append(patches)
            # self.backend.apply_patches(patches)
            self.writing_address = self.writing_address + 2
        else:
            self.writing_address = self.writing_address + instruction_patch.size

        # self.backend.apply_patches(patches)

    def reassemble_reference_at_different_address(self, instruction_patch, target_address, writing_address):
        if target_address % 2 != 0:
            target_address = target_address - 1

        if 'pc' in instruction_patch.op_str:
            target_address = target_address - writing_address
            new_string = self.replace_jump_target_address(instruction_patch, target_address)
        else:
            new_string = self.replace_jump_target_address(instruction_patch, target_address)

        patches = InlinePatch(writing_address, new_string, is_thumb=self.is_thumb)
        self.patches.append(patches)
        # Return if the instruction has changed or not to know if we need to add a nop
        instruction_string = instruction_patch.mnemonic + " " + instruction_patch.op_str
        if new_string == instruction_string:
            return False
        else:
            return True

        # self.backend.apply_patches(patches)

    def rewriting_and_adding_reference_to_the_old_program(self, reference, instruction_patch, matched_refs):

        # Distinguish two cases 1. Read(e.g.ldr..) 2. Param(e.g.add...)

        if reference.refType == "read":
            self.add_read_reference(instruction_patch, reference, matched_refs)
        elif reference.refType == "offset":
            self.add_offset_reference(reference, instruction_patch)
        elif reference.refType == "control_flow_jump":
            self.add_control_flow_jump_reference(instruction_patch, reference, matched_refs)
        else:
            print("It should be here", reference.refType, instruction_patch)
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            # shift_reference = Reference(self.writing_address, self.writing_address + reference.toAddr - reference.fromAddr, "control_flow_jump")
            # self.shift_references.append(shift_reference)
            self.writing_address = self.writing_address + instruction_patch.size

    def add_read_reference(self, instruction_patch, reference, matched_refs):

        # # Tracking register
        # offset = self.get_offset_reference_from_instruction(instruction_patch)
        #
        # if offset is not None:
        #     reference = offset

        register_pattern = re.compile(r'\b(r\d+|sb|sl|ip|fp|sp|lr|s[0-9]+|d[0-9]+)\b')

        # Find all matches in the instruction string
        matches = register_pattern.findall(instruction_patch.op_str)

        # Handle cases like ldr r1, [r0, #4] or ldr r1, [r0, r2]
        if len(matches) > 1:
            new_target = None
            if reference.toAddr in matched_refs.match_to_new_address:
                new_target = matched_refs.match_to_new_address[reference.toAddr][0]
            elif reference.fromAddr in matched_refs.match_from_new_address:
                new_target = matched_refs.match_from_new_address[reference.fromAddr][0]

            self.handle_read_offset(instruction_patch, reference, matches, new_target)
            return

        # Extract the first match (assuming there is at least one match)

        register_name = matches[0]

        if self.is_thumb:
            thumb = 1
        else:
            thumb = 0
        # Replacing the reference with the new target address Difference includes 2 bytes for the pc, so if we add difference to the pc the new target address is 2 bytes away.
        difference = reference.toAddr - reference.fromAddr
        difference = difference + 26 - thumb
        if difference % 4 != 0:
            difference = difference + 2
        new_instruction_string = self.replace_jump_target_address(instruction_patch, difference)

        patches = InlinePatch(self.writing_address, new_instruction_string, is_thumb=self.is_thumb)
        self.patches.append(patches)

        pc = 2
        alignment = (self.writing_address + difference + pc) % 4
        data_address = self.writing_address + difference + pc + alignment

        # shift_reference = Reference(self.writing_address, data_address, "read")
        # self.shift_references.append(shift_reference)

        # Check if there is an offset reference as well from this instruction
        # offset_reference = self.get_offset_reference_from_instruction(instruction_patch)
        # # Check if the offset reference is perfectly matched
        # if offset_reference is not None:
        #     # If it is perfectly match we can just take the value of the offset address and write it at the address of the reference.toAddr
        #     if offset_reference.toAddr in matched_refs.match_to_new_address:
        #         new_target = matched_refs.match_to_new_address[offset_reference.toAddr][0]
        #         data = new_target.toAddr.to_bytes(4, byteorder='little')
        #         patches = RawMemPatch(data_address, data)
        #         # self.backend.apply_patches(patches)
        #         self.patches.append(patches)
        #     # Else we need to add the actual data to the new memory as well...
        #     else:
        #         # Get the data we need to add to the vulnerable program
        #         if offset_reference.toAddr <= self.project_patch.loader.min_addr:
        #             data = offset_reference.toAddr.to_bytes(4, byteorder='little')
        #             patches = RawMemPatch(data_address, data)
        #             self.patches.append(patches)
        #             # self.backend.apply_patches(patches)
        #         else:
        #             data = self.load_data_from_memory(offset_reference.toAddr)
        #             patches = RawMemPatch(self.new_memory_writing_address, data)
        #         # Write the address of the data as a data to be read
        #             self.patches.append(patches)
        #             # self.backend.apply_patches(patches)
        #             data_to_be_read = self.new_memory_writing_address.to_bytes(4, byteorder='little')
        #
        #             patches = RawMemPatch(data_address, data_to_be_read)
        #             self.patches.append(patches)
        #             # self.backend.apply_patches(patches)
        #             self.new_memory_writing_address = self.new_memory_writing_address + len(data) + 4

        self.writing_address = self.writing_address + instruction_patch.size

        # Save this load data address in the corresponding register
        register = TrackingRegister(register_name, data_address, reference.toAddr)

        # Add the register to the list of registers that need to be tracked
        self.new_def_registers.append(register)

    def add_offset_reference(self, reference, instruction_patch):

        # Run analysis to get the value that needs to be loaded in the previously modified address
        # Get Variable defined in instruction and the CodeLocation of the instruction
        instr_view = self.ddg_patch_specific.view[instruction_patch.address]
        definitions: list = instr_view.definitions
        variable = None
        location = None
        register = self.get_register_from_instruction(instruction_patch, self.project_patch.arch)
        for definition in definitions:
            #     Now only take the register variable
            if isinstance(definition._variable.variable, SimRegisterVariable):
                if (definition._variable.variable.reg == register):
                    variable = definition._variable
                    location = [definition._variable.location]

        if variable is None:
            maximum = 0
            for definition in definitions:
                if len(definition.dependents) > 0:
                    if isinstance(definition._variable.variable, SimTemporaryVariable):
                        if maximum < definition._variable.location.stmt_idx:
                            maximum = definition._variable.location.stmt_idx
                            variable = definition._variable
        if variable is None:
            self.handle_reference_without_ddg(instruction_patch, reference)
            return

        # TODO JUST A HACK TO MAKE IT GO THROUGH
        # if variable is None:
        #     self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        #     self.writing_address = self.writing_address + instruction_patch.size
        #     return

        solver = ConstraintSolver(self.project_patch, instruction_patch.address - 1, self.new_def_registers)

        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                 ddg=self.ddg_patch_specific,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)

        # Check what we want here. We could extend the .data .rodata section maybe?? Or just put it at a very far way address in the already extended section
        if self.new_memory_data_address is None:
            self.new_memory_data_address = self.new_memory_writing_address + 100

        results = solver.solve(backward_slice.chosen_statements, self.new_memory_writing_address, self.writing_address,
                               variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return

        # TODO: What if there is a register in results that is not in the new_def_registers list?  Then there is no information of where to put the data
        # Get all affected registers, i.e. intersection of new_def_registers and results
        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            # Write the data to the ldr_data_address
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)
            # self.backend.apply_patches(patches)
        data = self.load_data_from_memory(reference.toAddr)

        # Write the data to the new memory address

        patches = RawMemPatch(self.new_memory_writing_address, data)
        self.patches.append(patches)
        # self.backend.apply_patches(patches)
        alignment = (self.new_memory_writing_address + len(data) + 4) % 4
        self.new_memory_writing_address = self.new_memory_writing_address + len(data) + 4 + alignment

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def load_data_from_memory(self, address):

        data = b""
        while True:
            byte_data = self.project_patch.loader.memory.load(address, 2)
            if byte_data == b'\x00\x00':
                break
            data += byte_data
            address += 2
        return data

    def get_affected_registers(self, results):
        affected_registers = []

        for res in self.new_def_registers:
            for result, value in results:
                # offset = re.search(r'\d+', str(result)).group()
                pattern = re.compile(r"^(?!r|t)")

                # Extract strings that match the pattern

                offset = str(result)
                if pattern.match(offset):
                    pattern = re.compile(r"^(?!x)")
                    if pattern.match(offset):
                        offset = int(offset, 16)
                    else:
                        offset = int(offset)
                    if res.old_ldr_data_address == offset:

                        value = int(str(value))
                        if self.is_thumb:
                            value = value
                        data = value.to_bytes(4, byteorder='little')
                        affected_registers.append((res, data))
                        self.used_registers[result] = value
                        # self.new_def_registers.remove(res)
                # offset = int(offset)
                # reg_offset = self.project_patch.arch.get_register_offset(res.register_name)
                # if reg_offset == offset:
                #     value = int(str(value))
                #     data = value.to_bytes(4, byteorder='little')
                #     affected_registers.append((res, data))
        #         #     self.new_def_registers.remove(res)
        # for (reg, data) in affected_registers:
        #     indices = [i for i, t in enumerate(affected_registers) if t[0].register_name == reg.register_name]
        #     if len(indices) >= 2:
        #         # Find the index of the tuple with the lowest value in the second position
        #         min_index = min(indices, key=lambda i: affected_registers[i][1])
        #         # Remove the tuple with the lowest value in the second position
        #         del affected_registers[min_index]

        return affected_registers

    def get_offset_reference_from_instruction(self, instruction_patch):
        for ref in self.refs_patch:
            # if self.is_thumb:
            #     if ref == instruction_patch.address - 1:
            #         for r in self.refs_patch[ref]:
            #             if r.refType == "offset":
            #                 return r
            #             else:
            #                 pass
            # elif
            if ref == instruction_patch.address:
                for r in self.refs_patch[ref]:
                    if r.refType == "offset":
                        return r
                    else:
                        pass

    def fix_shifts_in_references(self, patch_start_address_of_patch, shift_backend):

        # TODO: Double Check if "asc" and "desc" are corrrectly used

        patch_end = self.shifts_ascending[-1].end

        self.patches = []
        xrefs = self.shift_references
        for ref in xrefs:
            jump_target = ref.toAddr
            if ref.toAddr < ref.fromAddr:
                condition = self.isInShiftListZone(ref.fromAddr, "desc")
                if ref.toAddr < patch_start_address_of_patch:
                    condition = -1
            else:
                condition = self.isInShiftListZone(jump_target, "asc")
                if ref.toAddr > patch_end:
                    condition = -1

            if ref.refType == "jump_table":
                print("jump table RefType")
            if condition != -1:
                print("Ref.fromAddr", ref.fromAddr, "Ref.toAddr", ref.toAddr, ref.refType)
                instruction = shift_backend.factory.block(ref.fromAddr + 1).disassembly.insns[0]
                start_addr = ref.fromAddr
                refT = start_addr
                while refT != jump_target:
                    refT = jump_target
                    if ref.fromAddr < ref.toAddr:
                        jump_target = self.adding_shift_to_address(start_addr, jump_target)
                    else:
                        jump_target = self.subtracting_shift_from_address(start_addr, jump_target)

                    start_addr = refT
                if jump_target != ref.toAddr:
                    # handle Jump Table:
                    if ref.refType == "jump_table":
                        start = min(self.jump_tables, key=lambda x: abs(x - ref.fromAddr))
                        difference = jump_target - start
                        difference = int(0.5 * difference)
                        bytes = difference.to_bytes(2, byteorder='little')
                        print("jump bytes", bytes)
                        patch = RawMemPatch(ref.fromAddr, bytes)
                        self.patches.append(patch)


                    elif 'pc' in instruction.op_str:
                        target_address = jump_target - ref.fromAddr - 4
                        new_string = self.replace_jump_target_address(instruction, target_address)
                        patch = InlinePatch(ref.fromAddr, new_string, is_thumb=self.is_thumb)
                    elif instruction.mnemonic not in {"bl", "blx", "b", "bx", "cbz", "cbnz", "b.w"}:
                        # TODO: Decrease the size of the instruction address so that the keystone assembler works... (maybe)
                        if instruction.size == 2:
                            offset = 0
                            base = 0
                        else:
                            offset = 4
                            base = ref.fromAddr - self.project_patch.loader.min_addr
                        target_address = jump_target - ref.fromAddr - offset
                        if target_address > 0:
                            new_string = instruction.mnemonic + " $+" + str(hex(target_address))
                        else:
                            new_string = instruction.mnemonic + " $" + str(hex(target_address))
                        print("new_string", new_string)
                        code = self.backend.compile_asm(new_string, base=base, is_thumb=self.is_thumb)
                        patch = RawMemPatch(ref.fromAddr, code)
                    else:
                        new_string = self.replace_jump_target_address(instruction, jump_target)
                        patch = InlinePatch(ref.fromAddr, new_string, is_thumb=self.is_thumb)

                    self.patches.append(patch)

        self.backend.apply_patches(self.patches)
        # patch_start_address_of_patch = patch_start_address_of_patch + instruction.size

    #
    #     startAddr = refT;
    #     asm = Assemblers.getAssembler(vulnerableProgram)
    #
    # newString = replaceJumpAddr(codunHelp, jumpTarget)
    #
    # asm.assemble(refsToBeFixed[0].getFromAddress(), newString)

    def isInShiftListZone(self, ref, order):

        #       print("\n\t IsInShiftList " + "%s %s", shifts.get(shifts.size() - 1).start, shifts.get(shifts.size() - 1).end);
        if order == "asc":
            for i in range(len(self.shifts_ascending)):
                # printf("\n\t Shifted at %s", shifts.get(i).start)
                # printf("\n\t Shifted at %s", shifts.get(i).end)
                if self.shifts_ascending[i].isInsideShiftZone(ref):
                    # print("\n\t Counter", i)
                    return i
            if self.shifts_ascending[-1].end <= ref:
                return len(self.shifts_ascending)
            return -1
        else:
            for i in range(len(self.shifts_descending) - 1, -1, -1):
                # printf("\n\t Shifted at %s", shifts.get(i).start);
                # printf("\n\t Shifted at %s", shifts.get(i).end);
                if self.shifts_descending[i].isInsideShiftZone(ref):
                    # print("\n\t Counter desc", i)
                    return i
            # TODO: Check if this is correct <=
            if self.shifts_descending[-1].end <= ref:
                return len(self.shifts_descending)

            return -1

    def subtracting_shift_from_address(self, ref_start, ref_end):
        start = self.isInShiftListZone(ref_start, "desc")
        shift_bytes = 0
        jump_target = ref_end
        if start >= len(self.shifts_descending):
            start = len(self.shifts_descending) - 1
        for i in range(start, -1, -1):
            shift_bytes = shift_bytes + self.shifts_descending[i].smallerThanShiftZone(ref_end)
            if self.shifts_descending[i].isInsideShiftZone(ref_end):
                jump_target = ref_end - shift_bytes
                return jump_target

        jump_target = ref_end - shift_bytes
        return jump_target

    def adding_shift_to_address(self, ref_start, ref_end):
        start = self.isInShiftListZone(ref_start, "asc")
        shift_bytes = 0
        jump_target = ref_end
        if start >= len(self.shifts_ascending):
            start = len(self.shifts_ascending) - 1
        for i in range(start + 1, len(self.shifts_ascending), 1):
            shift_bytes = shift_bytes + self.shifts_ascending[i].biggerThanShiftZone(ref_end)
            if self.shifts_ascending[i].isInsideShiftZone(ref_end):
                jump_target = ref_end + shift_bytes
                return jump_target
        return jump_target

    # Handle read case where something is read from two registers or a register plus a value
    def handle_read_offset(self, instruction_patch, reference, matches, new_target):
        instr_view = self.ddg_patch_specific.view[instruction_patch.address]
        definitions: list = instr_view.definitions
        variable = None
        location = None

        register = self.get_register_from_instruction(instruction_patch, self.project_patch.arch)

        for definition in definitions:
            #     Now only take the register variable
            if isinstance(definition._variable.variable, SimRegisterVariable):
                if (definition._variable.variable.reg == register):
                    variable = definition._variable
                    location = [definition._variable.location]

        if variable is None:
            maximum = 0
            for definition in definitions:
                if len(definition.dependents) > 0:
                    if isinstance(definition._variable.variable, SimTemporaryVariable):
                        if maximum < definition._variable.location.stmt_idx:
                            maximum = definition._variable.location.stmt_idx
                            variable = definition._variable

        # TODO: CHECK LOGIC
        if variable is None:
            self.handle_reference_without_ddg(instruction_patch, reference)
            return

        if self.is_thumb:
            thumb = 1
        else:
            thumb = 0
        solver = ConstraintSolver(self.project_patch, instruction_patch.address - thumb, self.new_def_registers)
        # Calculate Address where the value of the PARAM reference need to be written

        if new_target is None:
            new_target = self.new_memory_writing_address
            if reference.toAddr <= self.project_patch.loader.min_addr:
                self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
                self.writing_address = self.writing_address + instruction_patch.size
                return
            else:
                data = self.load_data_from_memory(reference.toAddr)
                # Write the data to the new memory address
                patches = RawMemPatch(self.new_memory_writing_address, data)
                self.patches.append(patches)
        else:
            new_target = new_target.toAddr

        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                 ddg=self.ddg_patch_specific,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location, offset=True)

        results = solver.solve(backward_slice.chosen_statements, new_target, self.writing_address,
                               variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return

        # TODO: What if there is a register in results that is not in the new_def_registers list?  Then there is no information of where to put the data
        # Get all affected registers, i.e. intersection of new_def_registers and results
        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            # Write the data to the ldr_data_address
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)
            # self.backend.apply_patches(patches)

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def handle_reference_without_ddg(self, instruction_patch, reference):
        print("Reference without DDG")
        nodes = self.cfg_patch.get_all_nodes(instruction_patch.address, anyaddr=True)
        largest_node = max(nodes, key=lambda node: node.size)
        block = largest_node.block
        # TODO: Check if the max_step value should be more flexible
        cfge_help = self.project_patch.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                            state_add_options=angr.sim_options.refs,
                                                            starts=[block.addr], call_depth=1)
        ddge_help = self.project_patch.analyses.DDG(cfg=cfge_help, start=block.addr)

        instr_view = ddge_help.view[instruction_patch.address]
        definitions: list = instr_view.definitions
        variable = None
        location = None
        register = self.get_register_from_instruction(instruction_patch, self.project_patch.arch)
        for definition in definitions:
            #     Now only take the register variable
            if isinstance(definition._variable.variable, SimRegisterVariable):
                if (definition._variable.variable.reg == register):
                    variable = definition._variable
                    location = [definition._variable.location]

        if variable is None:
            maximum = 0
            for definition in definitions:
                if len(definition.dependents) > 0:
                    if isinstance(definition._variable.variable, SimTemporaryVariable):
                        if maximum < definition._variable.location.stmt_idx:
                            maximum = definition._variable.location.stmt_idx
                            variable = definition._variable
        if variable is None:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size
            return

        solver = ConstraintSolver(self.project_patch, instruction_patch.address - 1, self.new_def_registers)

        backward_slice = VariableBackwardSlicing(cfg=cfge_help,
                                                 ddg=ddge_help,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)

        # Check what we want here. We could extend the .data .rodata section maybe?? Or just put it at a very far way address in the already extended section
        if self.new_memory_data_address is None:
            self.new_memory_data_address = self.new_memory_writing_address + 100

        results = solver.solve(backward_slice.chosen_statements, self.new_memory_writing_address, self.writing_address,
                               variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return

        # TODO: What if there is a register in results that is not in the new_def_registers list?  Then there is no information of where to put the data
        # Get all affected registers, i.e. intersection of new_def_registers and results
        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            # Write the data to the ldr_data_address
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)
            # self.backend.apply_patches(patches)
        data = self.load_data_from_memory(reference.toAddr)

        # Write the data to the new memory address

        patches = RawMemPatch(self.new_memory_writing_address, data)
        self.patches.append(patches)
        # self.backend.apply_patches(patches)
        alignment = (self.new_memory_writing_address + len(data) + 4) % 4
        self.new_memory_writing_address = self.new_memory_writing_address + len(data) + 4 + alignment

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def get_references_to_instruction(self, instruction_patch, matched_refs):
        # Getting the references that point to the instruction
        print("Getting references to instruction")
        references = []

        if instruction_patch.address == self.entry_point_patch:
            return

        for addr in matched_refs.match_to_new_address:
            if addr == instruction_patch.address:
                references = matched_refs.match_to_new_address[addr]
                break

        for ref in references:
            # Checking if they are from outside of the patch , if so we need to reassemble them
            if ref.refType == "read":
                continue

            if ref.fromAddr < self.code_block_start.addr or ref.fromAddr > self.code_block_end.addr:
                print("Reference into patch")
                print(self.writing_address)

                # Checking if Instruction would change size, if so solve this via indirection, i.e. jumping into the space after the jump into new memory

                offset = 0
                base = ref.fromAddr - 1 - self.project_patch.loader.min_addr
                target_address = self.writing_address - ref.fromAddr - 1 - offset
                instruction = self.project_vuln.factory.block(ref.fromAddr).disassembly.insns[0]
                print("Ref into patch", ref.fromAddr, ref.toAddr, ref.refType, instruction)
                if instruction.mnemonic in {"ldr", "ldr.w", "ldrb", "ldrb.w", "ldrh", "ldrh.w"}:
                    continue
                if instruction.size == 2:

                    new_string = self.replace_jump_target_address(instruction, self.indirection_address)
                    patch = InlinePatch(ref.fromAddr - 1, new_string, is_thumb=self.code_block_start.thumb)
                    self.patches.append(patch)

                    target_address = self.writing_address - self.indirection_address

                    new_string = "b.w $+" + str(hex(target_address))

                    code = self.backend.compile_asm(new_string, base=0, is_thumb=self.is_thumb)
                    patch = RawMemPatch(self.indirection_address, code)
                    self.patches.append(patch)

                    base = self.indirection_address - self.project_patch.loader.min_addr

                    shift_reference = Reference(self.indirection_address, self.writing_address, "control_flow_jump")
                    self.shift_references.append(shift_reference)

                    self.indirection_address = self.indirection_address + 4
                else:
                    if instruction.mnemonic not in {"bl", "blx", "b", "bx", "cbz", "cbnz"}:
                        offset = 2
                        base = ref.fromAddr - 1 - self.project_patch.loader.min_addr
                        target_address = self.writing_address - ref.fromAddr - 1 - offset
                        if target_address > 0:
                            new_string = instruction.mnemonic + " $+" + str(hex(target_address))
                        else:
                            new_string = instruction.mnemonic + " $" + str(hex(target_address))
                        print("New String", new_string)
                        code = self.backend.compile_asm(new_string, base=base, is_thumb=self.is_thumb)
                        patch = RawMemPatch(ref.fromAddr - 1, code)
                    else:
                        new_string = self.replace_jump_target_address(instruction, self.writing_address)
                        patch = InlinePatch(ref.fromAddr - 1, new_string, is_thumb=self.is_thumb)
                    # new_string = self.replace_jump_target_address(instruction, self.writing_address)
                    # patch = InlinePatch(ref.fromAddr-1, new_string, is_thumb=self.code_block_start.thumb)

                    # if target_address > 0:
                    #     new_string = instruction.mnemonic + " $+" + str(hex(target_address))
                    # else:
                    #     new_string = instruction.mnemonic + " $" + str(hex(target_address))
                    # code = self.backend.compile_asm(new_string, base=base, is_thumb=self.is_thumb)
                    # patch = RawMemPatch(ref.fromAddr-1, code)
                    self.patches.append(patch)
                    shift_reference = Reference(ref.fromAddr - 1, self.writing_address, "control_flow_jump")
                    self.shift_references.append(shift_reference)

    # Add the control flow jump reference to new memory and also add the small function that is jumped to to new memory
    def add_control_flow_jump_reference(self, instruction_patch, reference, matched_refs):
        # The new function that needs to be added to the new memory is a reference.toAddr
        function = self.project_patch.kb.functions.function(addr=reference.toAddr)
        if function is None:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size
        else:
            if function.addr in self.new_added_function:
                new_string = self.replace_jump_target_address(instruction_patch, self.new_added_function[function.addr])
                patches = InlinePatch(self.writing_address, new_string, is_thumb=self.is_thumb)
                self.patches.append(patches)
                self.writing_address = self.writing_address + instruction_patch.size
                return
            # So I need to change the control_flow reference into a reference jumping to new memory.
            new_string = self.replace_jump_target_address(instruction_patch, self.new_memory_writing_address)
            patches = InlinePatch(self.writing_address, new_string, is_thumb=self.is_thumb)
            self.patches.append(patches)
            self.writing_address = self.writing_address + instruction_patch.size
            self.new_added_function[function.addr] = self.new_memory_writing_address
            self.new_memory_writing_address = self.new_memory_writing_address + 2 * (function.size)


    def check_for_data(self, instruction_patch, end_address):

        if instruction_patch.address < end_address:
            print("Hallo")
            return end_address


        if instruction_patch.address - 1 in self.cfg_patch.memory_data:
            if self.cfg_patch.memory_data[instruction_patch.address - 1].sort == "code reference":
                end_address = instruction_patch.address
                return end_address
            if self.cfg_patch.memory_data[instruction_patch.address - 1].size is None:
                return end_address
            data_shifter = True
            shift_address = self.writing_address
            address = instruction_patch.address
            while address - 1 in self.cfg_patch.memory_data:
                if address > self.patch_code_block_end.addr:
                    break

                byte_data = self.project_patch.loader.memory.load(address - 1,
                                                                  self.cfg_patch.memory_data[
                                                                      address - 1].size)
                self.handle_jump_table(address)
                end_address = address + 4
                if data_shifter:
                    print("Hallo1")
                    patches = RawMemPatch(self.writing_address, byte_data)
                    self.patches.append(patches)
                    self.writing_address = self.writing_address + self.cfg_patch.memory_data[
                        address - 1].size
                if self.cfg_patch.memory_data[address - 1].size < 1:
                    break

                address = address + self.cfg_patch.memory_data[
                    address - 1].size
                # if self.writing_address >= self.new_memory_writing_address:
                #     print("data mixed with code")
                # el
                if len(self.new_def_registers) >= self.limit:
                    minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                    i = self.limit
                    while i < len(self.new_def_registers):
                        if self.new_def_registers[i].ldr_data_address <= minimal_address:
                            minimal_address = self.new_def_registers[i].ldr_data_address
                        i = i + 1
                    if self.writing_address >= minimal_address - 4:
                        print("data mixed with code ldr 2c")
                        maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                        shift = minimal_address - shift_address
                        # shift = maximum_address + 4 - minimal_address
                        # self.writing_address = self.writing_address - 2
                        self.remember_shifted_bytes(shift)
                        self.writing_address = maximum_address + 4
                        print("Shift", shift, "writing adress", self.writing_address)
                        self.limit = len(self.new_def_registers) + 1
                        data_shifter = False



            # pririting_address = self.writing_address + self.cfg_patch.memory_data[instruction_patch.address - 1].size
            # self.remember_shifted_bytes(instruction_patch.size)
            # print("Shift", instruction_patch.size, "writing adress", self.writing_address)
            # if len(self.new_def_registers) >= self.limit:
            #     minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
            #     i = self.limit
            #     while i < len(self.new_def_registers):
            #         if self.new_def_registers[i].ldr_data_address <= minimal_address:
            #             minimal_address = self.new_def_registers[i].ldr_data_address
            #         i = i + 1
            #     if self.writing_address >= minimal_address - 4:
            #         print("data mixed with code ldr 1c")
            #         maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
            #         shift = minimal_address - self.writing_address
            #         self.writing_address = maximum_address + 4
            #         print("Shift", shift, "writing adress", self.writing_address)
            #         self.remember_shifted_bytes(shift)
            #         self.limit = len(self.new_def_registers) + 1
            return end_address
        elif instruction_patch.address < end_address:
            # print("Instruction address", instruction_patch.address, "End address", end_address, "CHEck fir data 2")
            # shift_address = self.writing_address
            # self.writing_address = self.writing_address + instruction_patch.size
            # # # self.remember_shifted_bytes(instruction_patch.size)
            # if len(self.new_def_registers) >= self.limit:
            #     minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
            #     i = self.limit
            #     while i < len(self.new_def_registers):
            #         if self.new_def_registers[i].ldr_data_address <= minimal_address:
            #             minimal_address = self.new_def_registers[i].ldr_data_address
            #         i = i + 1
            #     if self.writing_address >= minimal_address - 4:
            #         print("data mixed with code ldr 1d")
            #         maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
            #         shift = minimal_address - shift_address
            #         self.writing_address = maximum_address + 4
            #         print("Shift", shift, "writing adress", self.writing_address)
            #         self.remember_shifted_bytes(shift)
            #         self.limit = len(self.new_def_registers) + 1
            print("Hallo2")
            return end_address
        else:
            end_address = instruction_patch.address
            return end_address

    def handle_jump_table(self, patch_block_start_address):
        start = patch_block_start_address - 4
        if start in self.cfg_patch.indirect_jumps:
            if self.cfg_patch.indirect_jumps[start].jumptable:
                # print("Jump Table", self.cfg_patch.indirect_jumps[start].jumptable_addr)
                jump_table = self.cfg_patch.indirect_jumps[start]
                fromAddress = self.writing_address
                self.jump_tables.append(self.writing_address)
                for jump in jump_table.jumptable_entries:
                    target = jump - jump_table.jumptable_addr + self.writing_address - 1
                    shift_reference = Reference(fromAddress, target, "jump_table")
                    print("Jump Table", fromAddress, target)
                    fromAddress = fromAddress + jump_table.jumptable_entry_size
                    self.shift_references.append(shift_reference)

    # Static methods
    @staticmethod
    def _reference_outside_of_patch(block_start, block_end, old_reference):
        if block_start.addr <= old_reference.toAddr <= block_end.addr + block_end.size:
            return False
        else:
            return True

    @staticmethod
    def replace_jump_target_address(instruction_patch, difference):
        instruction_string = instruction_patch.mnemonic + " " + instruction_patch.op_str

        modified_string = re.sub(r'#0x[0-9A-Fa-f]+', "#" + str(hex(difference)), instruction_string)

        return modified_string

    @staticmethod
    def get_register_from_instruction(instruction, arch):
        register_pattern = re.compile(r'\b(r\d+|sb|sl|ip|fp|sp|lr|s[0-9]+|d[0-9]+)\b')
        # Find all matches in the instruction string
        matches = register_pattern.findall(instruction.op_str)
        # Extract the first match (assuming there is at least one match)
        register_name = matches[0]
        reg = arch.get_register_offset(register_name)
        return reg



