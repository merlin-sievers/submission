import angr, monkeyhex, archinfo
import logging
import claripy
from angr.code_location import CodeLocation
from angr.sim_variable import SimRegisterVariable

from angrutils import plot_cfg

# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr.analyses').setLevel('DEBUG')

project1 = angr.Project("/Users/sebastian/Public/Arm_65/libpng10.so.0.65.0", auto_load_libs=False)
# project = angr.Project("/Users/sebastian/Tools/Project/fauxware", engine=angr.engines.UberEnginePcode, auto_load_libs=False)
project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", auto_load_libs=False)
# project = angr.Project("/Users/sebastian/Public/libcurl-7.24/libcurl.so.7.24.0", engine=angr.engines.UberEnginePcode, auto_load_libs=False)


target_function = project.loader.find_symbol("png_check_keyword")

# e_state = project.factory.blank_state(addr=target_function.rebased_addr)

# target_block = project.factory.block(addr=0x4049f5)
# target_block.disassembly
# target_block = project.factory.block(addr=target_function.rebased_addr)

# target_block.vex.pp()
# print(target_function.rebased_addr)
# state = project.factory.blank_state()
# simgr = project.factory.simulation_manager(state)
# simgr.use_technique(angr.exploration_techniques.DFS())

# find_addr = 0x004049f1
# simgr.explore(find=find_addr)
#
# found = simgr.found[0] # A state that reached the find condition from explore
# print(found.solver.all_variables)

cfge = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=2, starts=[target_function.rebased_addr])
# cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=1, starts=[project.entry])

cfg = project1.analyses.CFGFast()
# plot_cfg(cfg, fname="CFGFast", asminst=True, remove_imports=True, remove_path_terminator=False)

print(cfg.graph.size())

print(project.kb.xrefs.xrefs_by_ins_addr)

# cfg.functions.callgraph.
# function = cfg.kb.functions.function(name="png_check_keyword")

# Getting the DDG
ddg = project.analyses.DDG(cfge, start=target_function.rebased_addr)

# CodeLocations are part of the DDG
# cl1 = CodeLocation(0x4049fb, ins_addr=0x4049f5, stmt_idx=18)
# instr_view = ddg.view[0x4049fb]

# Getting variables and their dependencies form the ddg nodes
# definitions: list = instr_view.definitions
# var = None
# for definition in definitions:
#     pv = definition._variable
#     print(definition._variable, definition.depends_on, definition.dependents)
#     # Now only take the register variables
#     if  isinstance(definition._variable.variable, SimRegisterVariable):
#         var = definition._variable.variable
#         print(var)
#         print(var.loc_repr(arch=project.arch))
#
# block = project.factory.block(addr=0x4049fb)
# print("target addres", target_block.addr)

# Take all definitions of a variable that appear in the DDG
# found: list = ddg.find_definitions(var,simplified_graph=False)

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
# # (Still unclear at time of writing)
# ddg_sub = ddg.data_sub_graph(pv,simplified=False)
# for node1 in ddg_sub.nodes:
#     print(node1)






# print(cfg.graph.size())
# print(cfg.model.get_all_nodes(target_function.rebased_addr))

# print(ddg.graph.size())