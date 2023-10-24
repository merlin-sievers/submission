import angr, monkeyhex, archinfo
import logging
import claripy
from angr.code_location import CodeLocation
from angr.sim_variable import SimRegisterVariable

# Uncommented to enable logging
# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr.analyses').setLevel('DEBUG')


# loading the patch binary to perform backward slicing
project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)

# Getting the target function
target_function = project.loader.find_symbol("png_check_keyword")

# Getting the target block to be able to manually verify the backward slicing
target_block = project.factory.block(addr=0x4049f5)
target_block.vex.pp()

# Building the CFGEMulated for the targetfunction in order to be able to build the DDG
cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs,
                                   context_sensitivity_level=2, starts=[target_function.rebased_addr])


# Getting the DDG
ddg = project.analyses.DDG(cfg, start=target_function.rebased_addr)

# CodeLocations are part of the DDG
cl1 = CodeLocation(0x4049fb, ins_addr=0x4049f5, stmt_idx=18)
instr_view = ddg.view[0x4049fb]

# Getting variables and their dependencies form the ddg nodes
definitions: list = instr_view.definitions
var = None
for definition in definitions:
    pv = definition._variable
    print(definition._variable, definition.depends_on, definition.dependents)
    # Now only take the register variables
    if isinstance(definition._variable.variable, SimRegisterVariable):
        var = definition._variable.variable
        print(var)
        print(var.loc_repr(arch=project.arch))

block = project.factory.block(addr=0x4049fb)
print("target addres", target_block.addr)

# Take all definitions of a variable that appear in the DDG
# found: list = ddg.find_definitions(var, simplified_graph=False)

# Get the CDG of the target function
cdg = project.analyses.CDG(cfg, start=target_function.rebased_addr)

# Getting the backward slice
target_node = cfg.get_any_node(target_function.rebased_addr)
second_node = cfg.get_any_node(0x4049f5)
bs = project.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1), (second_node,19) ])
print(bs.__sizeof__())
print(bs.dbg_repr())

# Get the predecessors of the node that contains the definition of the variable
# for node in ddg.graph.nodes:
#     if node.ins_addr == block.addr and node.stmt_idx == 18:
#         print("Target", node)
#         for pred in ddg.graph.predecessors(node):
#             print(pred)
#             for founds in found:
#                 if pred.ins_addr == founds.location.ins_addr and pred.stmt_idx == founds.location.stmt_idx:
#                     print("finally", founds.location)
#


# Build a sub data graoh having as nodes only variables that depend on the variable of interest or the variable depends on them
# (Still unclear at time of writing)
# ddg_sub = ddg.data_sub_graph(pv, simplified=False)
# for node1 in ddg_sub.nodes:
#     print(node1)


