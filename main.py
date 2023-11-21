from collections import defaultdict
from angrutils import *
import angr, monkeyhex, archinfo
import logging
import claripy
import networkx
from angr import AngrBackwardSlicingError, Analysis
from angr.analyses import BackwardSlice
from angr.code_location import CodeLocation
from angr.sim_variable import SimRegisterVariable

from patching.analysis.constraint_solver import ConstraintSolver
from variable_backward_slicing import VariableBackwardSlicing

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


# Building the CFGEmulated for the target function in order to be able to build the DDG
cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=0, starts=[target_function.rebased_addr])
# cfg = project.analyses.CFGFast(start=target_function.rebased_addr, end=target_function.rebased_addr+460)


# refs = project.analyses.XRefs(func=target_function.rebased_addr)
# print(refs.kb.xrefs.xrefs_by_ins_addr)

# cfg.normalize()
# vfg = project.analyses.VSA_DDG(start_addr=target_function.rebased_addr)
# print(vfg.graph.size())
# for node in vfg.graph.nodes:
#     print(node, type(node))
#
# plot_cfg(cfg, fname="png_check_keyword_fast", asminst=True, remove_imports=True, remove_path_terminator=True)

print(cfg.graph.size())



# Getting the DDG
ddg = project.analyses.DDG(cfg, start=target_function.rebased_addr)
#
# plot_ddg_data(ddg.data_sub_graph(), fname="png_check_keyword_ddg", asminst=False)

for node in ddg.data_graph.nodes:
    if node.location.ins_addr == 0x4049fb:
        print("found", node.variable, node.location)

# CodeLocations are part of the DDG
cl1 = CodeLocation(0x4049f5, ins_addr=0x4049fb, stmt_idx=19)
instr_view = ddg.view[0x4049fb]
# Getting variables and their dependencies form the ddg nodes
definitions: list = instr_view.definitions
var = None
for definition in definitions:
    pv = definition._variable
    print(type(definition))
    print(definition._variable, definition.depends_on)
#     Now only take the register variables
    if isinstance(definition._variable.variable, SimRegisterVariable):
        var = definition._variable.variable
        print(var)
        print(var.loc_repr(arch=project.arch))

block = project.factory.block(addr=0x4049fb)
print("target address", target_block.addr)



# Take all definitions of a variable that appear in the DDG
# found: list = ddg.find_definitions(var, simplified_graph=False)
# node = cfg.get_any_node(0x4049f5)
# print("cl1", cl1.block_addr, cl1.ins_addr, cl1.stmt_idx)
# if cl1 in ddg.graph.nodes:
#     print("YES!!!")
# for n in ddg.graph.nodes:
#     print(n.block_addr, n.ins_addr, n.stmt_idx)
#
loc = [cl1]
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


#
#
# print("input", var)
bs = VariableBackwardSlicing(cfg, cdg=cdg, ddg=ddg, variable=var, project=project, targets=loc)
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
    for id in ids:
        print(id)

constraints = ConstraintSolver(project)
constraints.solve(bs.chosen_statements, target_block.addr)