import copy
import re
import pickle
import os
import angr
from angr.analyses.ddg import DDG
from angr.analyses.cfg.cfg_emulated import CFGEmulated
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable, SimMemoryVariable

from cle import Symbol
from patcherex.patches import *
from log import patch_log
from patching.configuration import Config
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

    def __init__(self, patching_config: Config):
        super().__init__(patching_config)
        self.worklist = True
        self.thumb = 0

    def try_harder_to_find_symbol(self, project: angr.Project, symbolname: str, search_original: bool = True) -> Symbol | None:
        def symbol_mangler(original: str):
            yield f'__real_{original}'
            yield f'{original}.localalias'
            yield f'{original}.alias'
            yield f'{original}.part.0'
            if search_original:
                yield original

        for candidate in symbol_mangler(symbolname):
            symbol = project.loader.find_symbol(candidate)  # pyright:ignore[reportUnknownMemberType]
            if symbol:
                return symbol
            symbol = project.loader.main_object.get_symbol(candidate)
            if symbol:
                return symbol
        return None

    def find_symbol(self, project: angr.Project, symbolname: str):
        return project.loader.find_symbol(symbolname)  # pyright:ignore[reportUnknownMemberType]

    def patch_functions(self):
        logging.getLogger('angr').setLevel(logging.CRITICAL)

        initial = FunctionPatch(patching_config=self.patching_config)
        initial.start()

        initial.initial_patch()

        initial.patch()
        patched_functions: list[int] = []

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



    def start(self):
        self.limit: int = 1
        vuln = SectionExtender(self.patching_config.binary_path, 0x80000).add_section()
        if vuln is None:
            vuln = SectionExtender(self.patching_config.binary_path, 524288).add_section_with_program_header()

        self.project_vuln: angr.Project = angr.Project(vuln, auto_load_libs=False)
        self.cfg_vuln: CFGFast = self.project_vuln.analyses.CFGFast()
        print("\n\t Starting to analyze the vulnerable Program CFGFast...")

        vuln_symbol = self.try_harder_to_find_symbol(self.project_vuln, self.patching_config.fn_info.vuln_fn, search_original=self.patching_config.fn_info.search_for_original)
        if vuln_symbol is None:
            patch_log.info(f'could not find vuln fn {self.patching_config.fn_info.vuln_fn}')
            project_help = angr.Project(self.patching_config.test_binary, auto_load_libs=False)
            cfg = project_help.analyses.CFGFast()
            help_symbol = self.try_harder_to_find_symbol(project_help, self.patching_config.fn_info.vuln_fn)
            assert help_symbol
            entry_point: int = help_symbol.rebased_addr  # pyright:ignore[reportUnknownMemberType]
            bindiff_results = project_help.analyses.BinDiff(self.project_vuln, cfg_b=self.cfg_vuln, cfg_a=cfg, entry_point=entry_point)
            match = [e for (s, e) in bindiff_results.function_matches if s == entry_point]

            if len(match) > 0:
                self.entry_point_vuln = match[0]
                self.end_vuln = self.project_vuln.kb.functions[self.entry_point_vuln].size + self.entry_point_vuln
                patch_log.warning(f'There are {len(match)} matches! Taking the first one...')
                patch_log.info("Matched function %s in %s", hex(self.entry_point_vuln), self.patching_config.binary_path)
            else:
                print(self.patching_config.fn_info.vuln_fn + " not found in binary")
                raise Exception("Function not found in binary", self.patching_config.fn_info.vuln_fn)
        else:
            patch_log.info(f'Found vuln fn {self.patching_config.fn_info.vuln_fn}')
            self.entry_point_vuln: int = vuln_symbol.rebased_addr
            self.end_vuln: int = self.project_vuln.kb.functions[self.entry_point_vuln].size + self.entry_point_vuln

        print("\n\t Starting to analyze the vulnerable Program CFGEmul...")

        option = angr.sim_options.refs

        self.cfge_vuln_specific: CFGEmulated = self.project_vuln.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                                         state_add_options=option,
                                                                         starts=[self.entry_point_vuln], call_depth=2)

        self.project_patch: angr.Project = angr.Project(self.patching_config.patch_path, auto_load_libs=False)

        print("\n\t Starting to analyze the patch Program CFGFast...")
        self.cfg_patch: CFGFast = self.project_patch.analyses.CFGFast()
        patch_symbol = self.try_harder_to_find_symbol(self.project_patch, self.patching_config.fn_info.patch_fn)
        assert patch_symbol
        self.entry_point_patch: int = patch_symbol.rebased_addr
        self.end_patch: int = self.project_patch.kb.functions[self.entry_point_patch].size + self.entry_point_patch
        print("\n\t Starting to analyze the patch Program CFGEmul...")
        self.cfge_patch_specific: CFGEmulated = self.project_patch.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                                           state_add_options=option,
                                                                           starts=[self.entry_point_patch], call_depth=2)

        print("\n\t Starting to analyze the patch Program DDG...")
        self.ddg_patch_specific: DDG = self.project_patch.analyses.DDG(cfg=self.cfge_patch_specific,
                                                                  start=self.entry_point_patch)

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

        self.start_address_of_patch = self.entry_point_vuln

        self.code_block_start = self.project_vuln.factory.block(self.start_address_of_patch)
        #self.code_block_end = self.project_vuln.factory.block(max(vulnerable_blocks))
        self.code_block_end = self.project_vuln.factory.block(self.end_vuln)
        self.jump_back_address = min(
            [match for match in perfect_matches.match_old_address if match > self.code_block_end.addr], default=None)



        self.patch_start_address_of_patch = self.entry_point_patch

        self.patch_code_block_start = self.project_patch.factory.block(self.patch_start_address_of_patch)

        self.patch_code_block_end = self.project_patch.factory.block(max(patch_blocks))

        self.is_thumb = self.patch_code_block_start.thumb

        if self.is_thumb:
            self.thumb = 1

        self.backend = DetourBackend(self.patching_config.binary_path + "_modified")
        

        if ".patch" in self.backend.project.loader.main_object.sections_map:
            patch_section = self.backend.project.loader.main_object.sections_map['.patch']
            new_memory_address = patch_section.vaddr
        else:
            new_memory_address = self.backend.project.loader.main_object.segments[2].vaddr
        print("New Memory Address", new_memory_address)


        self.new_memory_writing_address = new_memory_address + 2 * (
                    self.patch_code_block_end.addr - self.patch_code_block_start.addr)

        # Jump to new Memory
        print("\n\t " + str(self.start_address_of_patch),
              self.patch_code_block_end.addr - self.patch_code_block_start.addr)
        if self.code_block_start.thumb:
            self.start_address_of_patch = self.start_address_of_patch - 1
        if self.patch_code_block_start.thumb:
            patch = self.patch_start_address_of_patch - 1
            if (new_memory_address % 4) == (patch % 4):
                new_memory_address = new_memory_address + 2

        self.jump_to_new_memory(self.start_address_of_patch, new_memory_address)
        if self.is_thumb:
            new_memory_address = new_memory_address + 2
        else:
            new_memory_address = new_memory_address + 4
        self.writing_address = new_memory_address

    def additional_function(self, function_addr: int):

            function = self.project_patch.kb.functions.function(addr=function_addr)
            largest_block = max(function.blocks, key=lambda block: block.addr + block.size)
            function_end = largest_block.addr + largest_block.size
            self.end_patch = function_end

            self.entry_point_patch: int = function_addr
            self.patch_code_block_end = max(function.blocks, key=lambda block: block.addr)
            self.cfge_patch_specific = self.project_patch.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,
                                                                            state_add_options=angr.sim_options.refs,
                                                                            starts=[function_addr], call_depth=2)
            self.refs_patch = self.matched_refs.get_refs(self.project_patch, self.cfge_patch_specific, function_addr, self.cfg_patch)
            self.matched_refs.match_references_from_perfect_matched_blocks(None, None ,self.refs_patch, self.project_vuln, self.project_patch, function_addr,function_end)
            self.patch_start_address_of_patch = function_addr
            self.patches = []

            self.ddg_patch_specific = self.project_patch.analyses.DDG(cfg=self.cfge_patch_specific,
                                                                      start=self.entry_point_patch, call_depth=2)
            
            if self.ddg_patch_specific.graph.size() <=1:
                return
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

            for instruction_patch in block_patch.capstone.insns:
                end_address = self.check_for_data(instruction_patch, end_address)
                if end_address != instruction_patch.address:
                    continue

                self.get_references_to_instruction(instruction_patch, matched_refs)

                reference = self.get_references_from_instruction(instruction_patch, self.refs_patch, block_patch.thumb)

                # Handling of possible References
                if reference is not None:
                    self.handle_references(reference, matched_refs, instruction_patch)
                else:
                    self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
                    self.writing_address = self.writing_address + instruction_patch.size

                if len(self.new_def_registers) >= self.limit:
                    minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                    i = self.limit
                    while i < len(self.new_def_registers):
                        if self.new_def_registers[i].ldr_data_address <= minimal_address:
                            minimal_address = self.new_def_registers[i].ldr_data_address
                        i = i + 1
                    if self.writing_address >= minimal_address - 4:
                        maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                        shift = maximum_address + 4 - self.writing_address
                        self.writing_address = maximum_address + 4
                        self.remember_shifted_bytes(shift)
                        self.limit = len(self.new_def_registers) + 1
                        continue

            if len(self.new_def_registers) >= self.limit:
                minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                i = self.limit
                while i < len(self.new_def_registers):
                    if self.new_def_registers[i].ldr_data_address <= minimal_address:
                        minimal_address = self.new_def_registers[i].ldr_data_address
                    i = i + 1
                if self.writing_address >= minimal_address - 4:
                    maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                    shift = minimal_address - self.writing_address
                    self.writing_address = maximum_address + 4
                    self.remember_shifted_bytes(shift)
                    self.limit = len(self.new_def_registers) + 1
                    if block_patch.size == 0:
                        print(block_patch)
                        break

            patch_block_start_address = patch_block_start_address + block_patch.size
            data_shifter = True
            shift_address = self.writing_address
            while patch_block_start_address - self.thumb in self.cfg_patch.memory_data:
                if patch_block_start_address > self.patch_code_block_end.addr:
                    break
                if self.cfg_patch.memory_data[patch_block_start_address - self.thumb].size is None:
                    break

                self.handle_jump_table(patch_block_start_address)
                if data_shifter:
                    byte_data = self.project_patch.loader.memory.load(patch_block_start_address - self.thumb,
                                                                      self.cfg_patch.memory_data[
                                                                          patch_block_start_address - self.thumb].size)
                    patches = RawMemPatch(self.writing_address, byte_data)
                    self.patches.append(patches)
                    self.writing_address = self.writing_address + self.cfg_patch.memory_data[
                        patch_block_start_address - self.thumb].size
                if self.cfg_patch.memory_data[patch_block_start_address - self.thumb].size < 1:
                    break

                patch_block_start_address = patch_block_start_address + self.cfg_patch.memory_data[
                    patch_block_start_address - self.thumb].size

                if len(self.new_def_registers) >= self.limit:
                    minimal_address = self.new_def_registers[self.limit - self.thumb].ldr_data_address
                    i = self.limit
                    while i < len(self.new_def_registers):
                        if self.new_def_registers[i].ldr_data_address <= minimal_address:
                            minimal_address = self.new_def_registers[i].ldr_data_address
                        i = i + 1
                    if self.writing_address >= minimal_address - 4:
                        print(patch_block_start_address, block_patch.size)
                        maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                        shift = minimal_address - shift_address
                        self.remember_shifted_bytes(shift)
                        self.writing_address = maximum_address + 4
                        self.limit = len(self.new_def_registers) + 1
                        data_shifter = False
                        if block_patch.size == 0:
                            print(block_patch)
                            break

        if self.jump_back_address is not None:
            target_address_str = str(hex(self.jump_back_address))
            patches = InlinePatch(self.writing_address, "bl " + target_address_str,
                                  is_thumb=self.code_block_start.thumb)
            self.patches.append(patches)

        #   Set the End for the last ShiftZone
        if self.shifts_ascending:
            self.shifts_ascending[-1].end = self.writing_address
            self.shifts_descending[-1].end = self.writing_address

        print("Hallo")
        self.add_possible_magic_values()

        self.backend.apply_patches(self.patches)

        self.backend.save(self.patching_config.binary_path + "_vuln_test_detoured")

        # Reopen the patched binary to fix the shifts
        shift_backend = angr.Project(self.patching_config.binary_path + "_vuln_test_detoured",
                                     auto_load_libs=False)

        if self.shifts_ascending:
            self.fix_shifts_in_references(new_memory_address, shift_backend)

        self.backend.save(self.patching_config.output_path)
        self.backend = None

    def jump_to_new_memory(self, base_address, target_address):
        """
        Write a branch to target_address instruction at base_address
        :param base_address: Address of the instruction to be patched
        :param target_address: Address of the target instruction
        # """
        patches = InlinePatch(base_address, "mov ip, lr", is_thumb=self.code_block_start.thumb)
        self.patches.append(patches)
        if self.code_block_start.thumb:
            base_address = base_address + 2
        else:
            base_address = base_address + 4

        target_address_str = str(hex(target_address + 1))
        if not self.code_block_start.thumb and self.is_thumb:
            patches = InlinePatch(base_address, "blx " + target_address_str, is_thumb=self.code_block_start.thumb)
        else:
            patches = InlinePatch(base_address, "bl " + target_address_str, is_thumb=self.code_block_start.thumb)

        self.patches.append(patches)
        patches = InlinePatch(target_address, "mov lr, ip", is_thumb=self.patch_code_block_start.thumb)
        self.patches.append(patches)

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
        patches = RawMemPatch(address, bytes(instruction.insn.bytes))
        self.patches.append(patches)

    def handle_read_reference(self, instruction_patch, reference):

        # Tracking Register for later backward slicing and static analysis
        register_pattern = re.compile(r'\b(r\d+|sb|sl|ip|fp|sp|lr|s[0-9]+|d[0-9]+)\b')
        matches = register_pattern.findall(instruction_patch.op_str)
        # Extract the first match (assuming there is at least one match)
        register_name = matches[0]

        difference = reference.toAddr - reference.fromAddr
        difference = difference + 28
        # Replacing the reference with the new target address
        new_instruction_string = self.replace_jump_target_address(instruction_patch, difference)

        patches = InlinePatch(self.writing_address, new_instruction_string, is_thumb=self.is_thumb)
        self.patches.append(patches)

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
            # Now only take the register variable
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

        solver = ConstraintSolver(self.project_patch, instruction_patch.address - self.thumb, self.new_def_registers)
        # Calculate Address where the value of the PARAM reference need to be written

        jump_target = old_reference.toAddr
        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                 ddg=self.ddg_patch_specific,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)


        results = solver.solve(backward_slice.chosen_statements, jump_target, self.writing_address, variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return

        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)

        # Write the new instruction to the new memory
        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def replacing_add_with_sub(self, instruction_patch):
        pass

    def handle_control_flow_jump_reference(self, instruction_patch, reference, old_reference):
        # Check if Reference jumps outside of the patch
        if self._reference_outside_of_patch(self.code_block_start, self.code_block_end, old_reference):
            # Check if Reference stays inside of the function
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
                if instruction_patch.size == 2 and changed:
                    self.remember_shifted_bytes(4)
                    self.writing_address = self.writing_address + (instruction_patch.size * 2)
                    patches = RawMemPatch(self.writing_address, b"\x00\xbf")
                    self.patches.append(patches)
                    self.writing_address = self.writing_address + 2
                else:
                    self.writing_address = self.writing_address + instruction_patch.size

            shift_reference = Reference(self.writing_address, old_reference.toAddr, "control_flow_jump")
            self.shift_references.append(shift_reference)
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
        if ref_type == "read":
            self.add_read_reference(instruction_patch, reference, matched_refs)
        elif ref_type == "offset":
            if old_reference.toAddr < self.writing_address:
                self.handle_offset_reference(instruction_patch, reference, old_reference)
            else:
                self.handle_offset_reference(instruction_patch, reference, old_reference)
        elif ref_type == "control_flow_jump":
            self.handle_control_flow_jump_reference(instruction_patch, reference, old_reference)
        else:
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size


    def remember_shifted_bytes(self, number_shifted_bytes):
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
                self.writing_address = self.writing_address + instruction_patch.size
                return
            base = self.writing_address - self.project_patch.loader.min_addr
            if base >= 850000:
                base = 0
            code = self.backend.compile_asm(new_string, base=base, is_thumb=True)
            patches = RawMemPatch(self.writing_address, code)
        else:
            patches = InlinePatch(self.writing_address, new_string)

        self.patches.append(patches)
        if instruction_patch.size == 2:
            self.remember_shifted_bytes(4)
            self.writing_address = self.writing_address + (instruction_patch.size * 2)
            patches = RawMemPatch(self.writing_address, b"\x00\xbf")
            self.patches.append(patches)
            self.writing_address = self.writing_address + 2
        else:
            self.writing_address = self.writing_address + instruction_patch.size

    def reassemble_reference_at_different_address(self, instruction_patch, target_address, writing_address):
        if target_address % 2 != 0:
            target_address = target_address - 1

        if 'pc' in instruction_patch.op_str:
            target_address = target_address - writing_address
            new_string = self.replace_jump_target_address(instruction_patch, target_address)
        else:
            new_string = self.replace_jump_target_address(instruction_patch, target_address)

        if not self.code_block_start.thumb and self.is_thumb:
            new_string = new_string.replace("b ", "bx ")
            new_string = new_string.replace("bl ", "blx ")

        patches = InlinePatch(writing_address, new_string, is_thumb=self.is_thumb)
        self.patches.append(patches)
        instruction_string = instruction_patch.mnemonic + " " + instruction_patch.op_str
        if new_string == instruction_string:
            return False
        else:
            return True

    def rewriting_and_adding_reference_to_the_old_program(self, reference, instruction_patch, matched_refs):
        if reference.refType == "read":
            self.add_read_reference(instruction_patch, reference, matched_refs)
        elif reference.refType == "offset":
            self.add_offset_reference(reference, instruction_patch)
        elif reference.refType == "control_flow_jump":
            self.add_control_flow_jump_reference(instruction_patch, reference, matched_refs)
        else:
            print("It should be here", reference.refType, instruction_patch)
            self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
            self.writing_address = self.writing_address + instruction_patch.size

    def add_read_reference(self, instruction_patch, reference, matched_refs):
        register_pattern = re.compile(r'\b(r\d+|sb|sl|ip|fp|sp|lr|s[0-9]+|d[0-9]+)\b')
        matches = register_pattern.findall(instruction_patch.op_str)
        if len(matches) > 1:
            new_target = None
            if reference.toAddr in matched_refs.match_to_new_address:
                new_target = matched_refs.match_to_new_address[reference.toAddr][0]
            elif reference.fromAddr in matched_refs.match_from_new_address:
                new_target = matched_refs.match_from_new_address[reference.fromAddr][0]
            self.handle_read_offset(instruction_patch, reference, matches, new_target)
            return
        register_name = matches[0]
        if self.is_thumb:
            thumb = 1
        else:
            thumb = 0
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
            #  Now only take the register variable
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
                    elif isinstance(definition._variable.variable, SimMemoryVariable):
                        if maximum < definition._variable.location.stmt_idx:
                            maximum = definition._variable.location.stmt_idx
                            variable = definition._variable

        if variable is None:
            self.handle_reference_without_ddg(instruction_patch, reference)
            return

        solver = ConstraintSolver(self.project_patch, instruction_patch.address - self.thumb, self.new_def_registers)

        backward_slice = VariableBackwardSlicing(cfg=self.cfge_patch_specific,
                                                 ddg=self.ddg_patch_specific,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)

        if self.new_memory_data_address is None:
            self.new_memory_data_address = self.new_memory_writing_address + 100

        results = solver.solve(backward_slice.chosen_statements, self.new_memory_writing_address, self.writing_address,
                               variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return

        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            # Write the data to the ldr_data_address
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)

        data = self.load_data_from_memory(reference.toAddr)
        patches = RawMemPatch(self.new_memory_writing_address, data)
        self.patches.append(patches)
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
        return affected_registers

    def get_offset_reference_from_instruction(self, instruction_patch):
        for ref in self.refs_patch:
            if ref == instruction_patch.address:
                for r in self.refs_patch[ref]:
                    if r.refType == "offset":
                        return r
                    else:
                        pass

    def fix_shifts_in_references(self, patch_start_address_of_patch, shift_backend):

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

            if condition != -1:
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
                    if ref.refType == "jump_table":
                        start = min(self.jump_tables, key=lambda x: abs(x - ref.fromAddr))
                        difference = jump_target - start
                        difference = int(0.5 * difference)
                        bytes = difference.to_bytes(2, byteorder='little')
                        patch = RawMemPatch(ref.fromAddr, bytes)
                        self.patches.append(patch)


                    elif 'pc' in instruction.op_str:
                        target_address = jump_target - ref.fromAddr - 4
                        new_string = self.replace_jump_target_address(instruction, target_address)
                        patch = InlinePatch(ref.fromAddr, new_string, is_thumb=self.is_thumb)
                    elif instruction.mnemonic not in {"bl", "blx", "b", "bx", "cbz", "cbnz", "b.w"}:
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
                        print("Debug", new_string)
                        code = self.backend.compile_asm(new_string, base=base, is_thumb=self.is_thumb)
                        patch = RawMemPatch(ref.fromAddr, code)
                    else:
                        new_string = self.replace_jump_target_address(instruction, jump_target)
                        patch = InlinePatch(ref.fromAddr, new_string, is_thumb=self.is_thumb)

                    self.patches.append(patch)

        self.backend.apply_patches(self.patches)


    def isInShiftListZone(self, ref, order):
        if order == "asc":
            for i in range(len(self.shifts_ascending)):
                if self.shifts_ascending[i].isInsideShiftZone(ref):
                    return i
            if self.shifts_ascending[-1].end <= ref:
                return len(self.shifts_ascending)
            return -1
        else:
            for i in range(len(self.shifts_descending) - 1, -1, -1):
                if self.shifts_descending[i].isInsideShiftZone(ref):
                    return i
            if self.shifts_descending[-1].end <= ref:
                return len(self.shifts_descending)
            return -1

    def subtracting_shift_from_address(self, ref_start, ref_end):
        start = self.isInShiftListZone(ref_start, "desc")
        shift_bytes = 0
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
            #   Now only take the register variable
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

        if self.is_thumb:
            thumb = 1
        else:
            thumb = 0
        solver = ConstraintSolver(self.project_patch, instruction_patch.address - thumb, self.new_def_registers)
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

        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def handle_reference_without_ddg(self, instruction_patch, reference):
        nodes = self.cfg_patch.get_all_nodes(instruction_patch.address, anyaddr=True)
        largest_node = max(nodes, key=lambda node: node.size)
        block = largest_node.block
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
            # Now only take the register variable
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

        solver = ConstraintSolver(self.project_patch, instruction_patch.address - self.thumb, self.new_def_registers)

        backward_slice = VariableBackwardSlicing(cfg=cfge_help,
                                                 ddg=ddge_help,
                                                 cdg=self.cdg_patch_specific,
                                                 project=self.project_patch,
                                                 variable=variable, targets=location)
        if self.new_memory_data_address is None:
            self.new_memory_data_address = self.new_memory_writing_address + 100
        results = solver.solve(backward_slice.chosen_statements, self.new_memory_writing_address, self.writing_address,
                               variable.variable, self.used_registers, self.cfge_patch_specific)

        if results is None:
            return
        affected_registers = self.get_affected_registers(results)

        for (register, data) in affected_registers:
            patches = RawMemPatch(register.ldr_data_address, data)
            self.patches.append(patches)
        data = self.load_data_from_memory(reference.toAddr)
        patches = RawMemPatch(self.new_memory_writing_address, data)
        self.patches.append(patches)
        alignment = (self.new_memory_writing_address + len(data) + 4) % 4
        self.new_memory_writing_address = self.new_memory_writing_address + len(data) + 4 + alignment

        self.rewriting_bytes_of_code_unit_to_new_address(instruction_patch, self.writing_address)
        self.writing_address = self.writing_address + instruction_patch.size

    def get_references_to_instruction(self, instruction_patch, matched_refs):
        # Getting the references that point to the instruction
        references = []

        if instruction_patch.address == self.entry_point_patch:
            return

        for addr in matched_refs.match_to_new_address:
            if addr == instruction_patch.address:
                references = matched_refs.match_to_new_address[addr]
                break

        for ref in references:
            if ref.refType == "read":
                continue

            if ref.fromAddr < self.code_block_start.addr or ref.fromAddr > self.code_block_end.addr:
                # Checking if Instruction would change size, if so solve this via indirection, i.e. jumping into the space after the jump into new memory
                instruction = self.project_vuln.factory.block(ref.fromAddr).disassembly.insns[0]

                if instruction.mnemonic in {"ldr", "ldr.w", "ldrb", "ldrb.w", "ldrh", "ldrh.w"}:
                    continue
                if instruction.size == 2:
                    new_string = self.replace_jump_target_address(instruction, self.indirection_address)
                    patch = InlinePatch(ref.fromAddr - self.thumb, new_string, is_thumb=self.code_block_start.thumb)
                    self.patches.append(patch)
                    target_address = self.writing_address - self.indirection_address
                    new_string = "b.w $+" + str(hex(target_address))

                    code = self.backend.compile_asm(new_string, base=0, is_thumb=self.is_thumb)
                    patch = RawMemPatch(self.indirection_address, code)
                    self.patches.append(patch)

                    shift_reference = Reference(self.indirection_address, self.writing_address, "control_flow_jump")
                    self.shift_references.append(shift_reference)

                    self.indirection_address = self.indirection_address + 4
                else:
                    if instruction.mnemonic not in {"bl", "blx", "b", "bx", "cbz", "cbnz"}:
                        offset = 2
                        base = ref.fromAddr - self.thumb - self.project_patch.loader.min_addr
                        target_address = self.writing_address - ref.fromAddr - self.thumb - offset
                        if target_address > 0:
                            new_string = instruction.mnemonic + " $+" + str(hex(target_address))
                        else:
                            new_string = instruction.mnemonic + " $" + str(hex(target_address))

                        code = self.backend.compile_asm(new_string, base=base, is_thumb=self.is_thumb)
                        patch = RawMemPatch(ref.fromAddr - self.thumb, code)
                    else:
                        new_string = self.replace_jump_target_address(instruction, self.writing_address)
                        patch = InlinePatch(ref.fromAddr - self.thumb, new_string, is_thumb=self.is_thumb)

                    self.patches.append(patch)
                    shift_reference = Reference(ref.fromAddr - self.thumb, self.writing_address, "control_flow_jump")
                    self.shift_references.append(shift_reference)


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
            new_string = self.replace_jump_target_address(instruction_patch, self.new_memory_writing_address)
            patches = InlinePatch(self.writing_address, new_string, is_thumb=self.is_thumb)
            self.patches.append(patches)
            self.writing_address = self.writing_address + instruction_patch.size
            self.new_added_function[function.addr] = self.new_memory_writing_address
            self.new_memory_writing_address = self.new_memory_writing_address + 2 * (function.size)


    def check_for_data(self, instruction_patch, end_address):

        if instruction_patch.address < end_address:
            return end_address

        if instruction_patch.address - self.thumb in self.cfg_patch.memory_data:
            if self.cfg_patch.memory_data[instruction_patch.address - self.thumb].sort == "code reference":
                end_address = instruction_patch.address
                return end_address
            if self.cfg_patch.memory_data[instruction_patch.address - self.thumb].size is None:
                return end_address
            data_shifter = True
            shift_address = self.writing_address
            address = instruction_patch.address
            while address - self.thumb in self.cfg_patch.memory_data:
                if address > self.patch_code_block_end.addr:
                    break

                byte_data = self.project_patch.loader.memory.load(address - self.thumb,
                                                                  self.cfg_patch.memory_data[
                                                                      address - self.thumb].size)
                self.handle_jump_table(address)
                end_address = address + 4
                if data_shifter:
                    patches = RawMemPatch(self.writing_address, byte_data)
                    self.patches.append(patches)
                    self.writing_address = self.writing_address + self.cfg_patch.memory_data[
                        address - self.thumb].size
                if self.cfg_patch.memory_data[address - self.thumb].size < 1:
                    break

                address = address + self.cfg_patch.memory_data[
                    address - self.thumb].size


                if len(self.new_def_registers) >= self.limit:
                    minimal_address = self.new_def_registers[self.limit - 1].ldr_data_address
                    i = self.limit
                    while i < len(self.new_def_registers):
                        if self.new_def_registers[i].ldr_data_address <= minimal_address:
                            minimal_address = self.new_def_registers[i].ldr_data_address
                        i = i + 1
                    if self.writing_address >= minimal_address - 4:
                        maximum_address = max([register.ldr_data_address for register in self.new_def_registers])
                        shift = minimal_address - shift_address
                        self.remember_shifted_bytes(shift)
                        self.writing_address = maximum_address + 4

                        self.limit = len(self.new_def_registers) + 1
                        data_shifter = False
            return end_address
        elif instruction_patch.address < end_address:
            return end_address
        else:
            end_address = instruction_patch.address
            return end_address

    def handle_jump_table(self, patch_block_start_address):
        start = patch_block_start_address - 4
        if start in self.cfg_patch.indirect_jumps:
            if self.cfg_patch.indirect_jumps[start].jumptable:
                jump_table = self.cfg_patch.indirect_jumps[start]
                fromAddress = self.writing_address
                self.jump_tables.append(self.writing_address)
                for jump in jump_table.jumptable_entries:
                    target = jump - jump_table.jumptable_addr + self.writing_address - self.thumb
                    shift_reference = Reference(fromAddress, target, "jump_table")
                    fromAddress = fromAddress + jump_table.jumptable_entry_size
                    self.shift_references.append(shift_reference)


    def add_possible_magic_values(self):
        for reg in self.new_def_registers:
            found = False
            for k in self.used_registers.keys():
                if reg.old_ldr_data_address == int(str(k),16):
                    found = True
                    if self.used_registers[k] == 0:
                        byte_data = self.project_patch.loader.memory.load(reg.old_ldr_data_address, 4)
                        patches = RawMemPatch(reg.ldr_data_address, byte_data)
                        self.patches.append(patches)
                        break
            if not found:
                byte_data = self.project_patch.loader.memory.load(reg.old_ldr_data_address, 4)
                patches = RawMemPatch(reg.ldr_data_address, byte_data)
                self.patches.append(patches)

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
        matches = register_pattern.findall(instruction.op_str)
        register_name = matches[0]
        reg = arch.get_register_offset(register_name)
        return reg
