import re
import pickle
import os
import angr
from angr.sim_variable import SimRegisterVariable, SimTemporaryVariable

from patcherex.patches import *

from patching.analysis.backward_slice import VariableBackwardSlicing
from patching.analysis.constraint_solver import ConstraintSolver
from patching.configuration import Config
from patching.matcher import Matcher
from patching.matcher import RefMatcher
from patcherex.backends.detourbackend import DetourBackend

from patching.reference import TrackingRegister, Reference
from patching.section_extender import SectionExtender
from patching.shifts import Shift

import time


class Patching:
    def __init__(self, patching_config: Config):
        # Start the timer
        self.cfge_patch_specific = None
        self.entry_point_patch = None
        self.end_patch = None
        self.cfg_patch = None
        self.project_patch = None
        self.cfge_vuln_specific = None
        self.limit = None
        self.end_vuln = None
        self.entry_point_vuln = None
        self.ddg_patch_specific = None
        self.cfg_vuln = None
        self.project_vuln = None
        self.patch_start_address_of_patch = None
        self.matched_refs = None
        self.jump_back_address = None
        self.indirection_address = None
        self.new_memory_data_address = None
        self.new_memory_writing_address = None
        self.patch_code_block_end = None
        self.patch_code_block_start = None
        self.code_block_start = None
        self.code_block_end = None
        self.is_thumb = False
        self.start_address_of_patch = None
        self.patching_config: Config = patching_config
        self.backend = None
        self.writing_address = None
        self.new_added_function: dict[int, int] = dict()

        self.jump_tables = []

        self.cdg_patch_specific = None

        self.refs_patch = None
        self.patches = []

        self.new_def_registers = []
        self.used_registers = dict()

        self.shifts_ascending = []
        self.shifts_descending = []
        self.shift_references = []




