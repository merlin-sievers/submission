import angr, monkeyhex, archinfo
import re
import lief
from lief import ELF
import logging
import claripy
import networkx
from patcherex.backends.detourbackend import DetourBackend
from angr import AngrBackwardSlicingError, Analysis
from angr.analyses import BackwardSlice, CFGEmulated
from angr.code_location import CodeLocation
from angr.sim_variable import SimRegisterVariable
from z3 import z3
from angrutils import plot_cfg
from patcherex.patches import InlinePatch, AddLabelPatch
from patching.analysis.constraint_solver import ConstraintSolver
from patching.configuration import Config
from patching.patching import Patching
from patching.section_extender import SectionExtender
from variable_backward_slicing import VariableBackwardSlicing
import logging
# config = lief.ELF.ParserConfig()
#
# # config.parse_dyn_symbols = True
# # config.parse_symbol_versions = True
# # config.parse_symtab_symbols = True
# # config.parse_relocations = True
# config.DYNSYM_COUNT.SECTION  = True
# config.DYNSYM_COUNT.AUTO = True
# config.DYNSYM_COUNT.RELOCATIONS = True
# Configure logging
# binary = lief.ELF.parse("Testsuite/MAGMA/openssl/vuln/libcrypto.so.3", config)
# s = lief._lief.ELF

i  = 4
while i <=4:
    config = Config("magma-config.properties", str(i))

        # Set the alarm for 20 minutes (1200 seconds)
    patching = Patching(config)
    patching.patch(config.binary_path)
    i = i + 1

# # Setup logging to a file
# logging.basicConfig(filename="/tmp/p_errors.txt", level=logging.ERROR,
#                     format='%(asctime)s - %(levelname)s - %(message)s', force=True)

# Uncommented to enable logging
# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr.analyses').setLevel('DEBUG')

register_pattern = re.compile(r'(?=(r\d+|sb|sl|ip|fp|sp|lr))')
        # Find all matches in the instruction string
matches = register_pattern.findall("ldr r1,r1")
        # Extract the first match (assuming there is at least one match)
register_name = matches[0]



# loading the patch binary to perform backward slicing
project = angr.Project("Testsuite/libpng10.so.0.65.0", auto_load_libs=False)

# project = angr.Project("Testsuite/vuln_test_detoured", auto_load_libs= False)

# Getting the target function
target_function = project.loader.find_symbol("png_check_keyword")

# file_to_be_patched = SectionExtender("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0", 4096).extend_last_section_of_segment()

backend = DetourBackend("Testsuite/libpng10.so.0.65.0")
# patches = []
# patch = InlinePatch(4495446, "mov ip, lr", is_thumb=True)
# patches.append(patch)
# base_address = 4495446 + 2
# target_address = 0x1000
# target_address_str = str(hex(target_address))
# patch = InlinePatch(base_address, "bl " + target_address_str, is_thumb=True)
# patches.append(patch)
#
# patch   = InlinePatch(target_address, "mov lr, ip", is_thumb=True)
# patches.append(patch)
#
# backend.apply_patches(patches)
#
# backend.save("Testsuite/MAGMA/libxml/vuln/libxml_test")

# patches.append(patch)
#
# try:
#     target_function = project.loader.find_symbol("png_check_keywords").rebased_addr
# except Exception as e:
#     logging.error("Error occurred while compiling the assembly code: %s", e)
#
# # patch = InlinePatch(0x40f9f0, "b _png_check_keyword", is_thumb=True)
# # # patch = InlinePatch(0x415a36, "beq #0x166", is_thumb=True)
# # patches.append(patch)
# backend.apply_patches(patches)

backend.save("Testsuite/Modified/libpng10.so.0.65.0_TEST")
# test_project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0_TEST", auto_load_libs=False)
cfg = project.analyses.CFGFast()
# Building the CFGEmulated for the target function in order to be able to build the DDG
cfg = project.analyses.CFGEmulated(keep_state=True,  state_add_options=angr.sim_options.refs, context_sensitivity_level=2, starts=[target_function.rebased_addr])


target_block = project.factory.block(0x404b27)

print(target_block.disassembly)
# Getting the target block to be able to manually verify the backward slicing
# target_block = project.factory.block(addr=0x4049f5)
target_block.vex.pp()
print(target_block.arch)

target_block = project.factory.block(target_function.rebased_addr)
#
string = target_block.disassembly.insns[0].mnemonic + " " + target_block.disassembly.insns[0].op_str
address = target_block.disassembly.insns[0].address-1
code = backend.compile_asm(string, base=target_block.disassembly.insns[0].address-1, is_thumb=True)



# refs = project.analyses.XRefs(func=target_function.rebased_addr)
# print(refs.kb.xrefs.xrefs_by_ins_addr)

cfg.normalize()
# vfg = project.analyses.VSA_DDG(start_addr=target_function.rebased_addr)
# print(vfg.graph.size())
# for node in vfg.graph.nodes:
#     print("VSA", node, type(node))
#
# plot_cfg(cfg_fast, fname="test_vuln", asminst=True, remove_imports=True, remove_path_terminator=True)

# print(cfg.graph.size())



# Getting the DDG
ddg = project.analyses.DDG(cfg, start=target_function.rebased_addr)
#
# plot_ddg_data(ddg.data_sub_graph(), fname="png_check_keyword_ddg", asminst=False)

# for node in ddg.data_graph.nodes:
#     if node.location.ins_addr == 0x4049fb:
#         print("found", node.variable, node.location)

block = project.factory.block(addr=0x404b27)
print("block disassembly", block.disassembly)
block.vex.pp()
instruction = block.disassembly.insns[2]
# reg = instruction.operands[0].reg
# instruction1 = block.disassembly.insns[2]
# reg1 = instruction1.operands[0].reg

register_pattern = re.compile(r'(r\d+|sb|sl)')
# Find all matches in the instruction string
matches = register_pattern.findall(instruction.op_str)
  # Extract the first match (assuming there is at least one match)
register_name = matches[0]
program_var = project.arch
reg = program_var.get_register_offset(register_name)

# CodeLocations are part of the DDG
cl1 = CodeLocation(0x404b27, ins_addr=0x404b2b, stmt_idx=40)
instr_view = ddg.view[0x404b2b]
# Getting variables and their dependencies form the ddg nodes
definitions: list = instr_view.definitions
var = None
for definition in definitions:
    pv = definition._variable
    print(type(definition))
    print(definition._variable, definition.depends_on)
#  Now only take the register variables
    if isinstance(definition._variable.variable, SimRegisterVariable):
        if (definition._variable.variable.reg == reg):
            pv1 = pv
            var = definition._variable.variable
            loc = [definition._variable.location]
            print(var)
            print(loc)
#
# block = cfg.get_any_node(cl1.block_addr)







# TODO: THIS IS HOW YOU GET THE CONNECTION BETWEEN A PROGRAMVARIABLE AND THE OFFSET OF A VEX REGISTER
for ins in block.disassembly.insns:
    offset = ins.operands[0].reg
    if pv1.variable.reg == offset:
        print("found", pv1)

program_var = project.arch
offste = program_var.get_register_offset("sl")
reg = program_var.get_register_by_name("sl")
# Take all definitions of a variable that appear in the DDG
# found: list = ddg.find_definitions(var, simplified_graph=False)
# node = cfg.get_any_node(0x4049f5)
# print("cl1", cl1.block_addr, cl1.ins_addr, cl1.stmt_idx)
# if cl1 in ddg.graph.nodes:
#     print("YES!!!")
# for n in ddg.graph.nodes:
#     print(n.block_addr, n.ins_addr, n.stmt_idx)
#
# loc = [cl1]
# for founds in found:
#     loc.append(founds.location)
# Get the CDG of the target function
cdg = project.analyses.CDG(cfg, start=target_function.rebased_addr)

# Getting the backward slice
# target_node = cfg.get_any_node(target_function.rebased_addr)
# second_node = cfg.get_any_node(0x4049f5)



# acfg = bs.annotated_cfg()

# bs = project.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=loc)


# print(bs.__sizeof__())
# print(bs.dbg_repr())
# print(bs.chosen_statements)
# Get the predecessors of the node that contains the definition of the variable
# for node in cdg.graph.nodes:
    # print(type(node))
#     if node.ins_addr == block.addr and node.stmt_idx == 18:
#         print("Target", node)
#         for pred in ddg.graph.predecessors(node):
#             print(pred)
#             for founds in found:
#                 if pred.ins_addr == founds.location.ins_addr and pred.stmt_idx == founds.location.stmt_idx:
#                     print("finally", founds.location)
#


# Build a sub data graph having as nodes only variables that depend on the variable of interest or the variable depends on them
# (Still unclear at time of writing)
# ddg_sub = ddg.data_sub_graph(pv, simplified=False)
# for node1 in ddg_sub.nodes:
#     print(node1)

sources = ddg.find_sources(pv1, simplified_graph=False)
#
#
# print("input", var)
bs = VariableBackwardSlicing(cfg, cdg=cdg, ddg=ddg, variable=pv1.variable, project=project, targets=loc)
#
# for ins in bs.chosen_statements_addrs:
#     print(hex(ins))
# print(bs.dbg_repr())
#
# nodes = bs._cfg.get_all_nodes(addr=0x4049f5)
#
# plot_cfg(bs._cfg, fname="png_check_keyword_bs", asminst=True, remove_imports=True, remove_path_terminator=True)
#
# print("hello")

for stat, ids in bs.chosen_statements.items():
    print("STATEMENT ", stat)
    # project.factory.block(stat).vex.pp()
    # for id in ids:
    #     print(id)

constraints = ConstraintSolver(project,instruction.address - 1)
results = constraints.solve(bs.chosen_statements, 0x413694, 0x404b2a, pv1.variable)
solver = constraints.solver

while solver.check() != z3.sat:
    solver.pop()

model = solver.model()
s= model.sexpr()
t = model.decls()
f = solver.assertions()
print(solver)





print(solver)
for result , _  in results:
    testst = str(result)
    number = re.search(r'\d+', testst).group()

print(results)