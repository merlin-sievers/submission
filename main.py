from collections import defaultdict

import angr, monkeyhex, archinfo
import logging
import claripy
import networkx
from angr import AngrBackwardSlicingError
from angr.analyses import BackwardSlice
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
found: list = ddg.find_definitions(var, simplified_graph=False)
loc = []
for founds in found:
    loc.append(founds.location)
# Get the CDG of the target function
cdg = project.analyses.CDG(cfg, start=target_function.rebased_addr)

# Getting the backward slice
target_node = cfg.get_any_node(target_function.rebased_addr)
second_node = cfg.get_any_node(0x4049f5)
bs = project.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=loc)
print(bs.__sizeof__())
print(bs.dbg_repr(max_display=10))
# print(bs.chosen_statements)
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


# Build a sub data graph having as nodes only variables that depend on the variable of interest or the variable depends on them
# (Still unclear at time of writing)
# ddg_sub = ddg.data_sub_graph(pv, simplified=False)
# for node1 in ddg_sub.nodes:
#     print(node1)


# Class for backward slicing from variable use to its definition:
class VariableBackwardSlicing(BackwardSlice):
    """
    Backward slicing from variable use to its definition.
    """

    def __init__(
        self,
        cfg,
        cdg,
        ddg,
        variable,
        targets=None,
        cfg_node=None,
        stmt_id=None,
        control_flow_slice=False,
        same_function=False,
        no_construct=False,
    ):
        """
        Create a backward slice from a specific statement based on provided control flow graph (CFG), control
        dependence graph (CDG), and data dependence graph (DDG).

        The data dependence graph can be either CFG-based, or Value-set analysis based. A CFG-based DDG is much faster
        to generate, but it only reflects those states while generating the CFG, and it is neither sound nor accurate.
        The VSA based DDG (called VSA_DDG) is based on static analysis, which gives you a much better result.

        :param cfg:                 The control flow graph.
        :param cdg:                 The control dependence graph.
        :param ddg:                 The data dependence graph.
        :param variable:            The variable to slice on.
        :param targets:             A list of "target" that specify targets of the backward slices. Each target can be a
                                    tuple in form of (cfg_node, stmt_idx), or a CodeLocation instance.
        :param cfg_node:            Deprecated. The target CFGNode to reach. It should exist in the CFG.
        :param stmt_id:             Deprecated. The target statement to reach.
        :param control_flow_slice:  True/False, indicates whether we should slice only based on CFG. Sometimes when
                                    acquiring DDG is difficult or impossible, you can just create a slice on your CFG.
                                    Well, if you don't even have a CFG, then...
        :param no_construct:        Only used for testing and debugging to easily create a BackwardSlice object.
        """
        self._variable = variable
        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self._same_function = same_function

        # All targets
        self._targets = []

        if cfg_node is not None or stmt_id is not None:


            self._targets = [(cfg_node, stmt_id)]

        if targets is not None:
            for t in targets:
                if isinstance(t, CodeLocation):
                    node = self._cfg.model.get_any_node(t.block_addr)
                    self._targets.append((node, t.stmt_idx))
                elif type(t) is tuple:
                    self._targets.append(t)
                else:
                    raise AngrBackwardSlicingError("Unsupported type of target %s" % t)

        # Save a list of taints to begin with at the beginning of each SimRun
        self.initial_taints_per_run = None
        self.runs_in_slice = None
        self.cfg_nodes_in_slice = None
        # IDs of all chosen statement for each SimRun
        self.chosen_statements = defaultdict(set)
        # IDs for all chosen exit statements as well as their corresponding targets
        self.chosen_exits = defaultdict(list)

        if not no_construct:
            self._construct(self._targets, control_flow_slice=control_flow_slice)

        def _construct_default(self, targets):
            """
            TODO: Update description to reflect the new implementation of backward slicing with a variable.
            Create a backward slice from a specific statement in a specific block. This is done by traverse the CFG
            backwards, and mark all tainted statements based on dependence graphs (CDG and DDG) provided initially. The
            traversal terminated when we reach the entry point, or when there is no unresolved dependencies.

            :param targets: A list of tuples like (cfg_node, stmt_idx), where cfg_node is a CFGNode instance where the
                            backward slice starts, and it must be included in CFG and CDG. stmt_idx is the ID of the target
                            statement where the backward slice starts.
            """


            self.taint_graph = networkx.DiGraph()

            taints = set()
            accessed_taints = set()

            # Fill in the taint set

            for cfg_node, stmt_idx in targets:
                if cfg_node not in self._cfg.graph:
                    raise AngrBackwardSlicingError("Target CFGNode %s is not in the CFG." % cfg_node)

                if stmt_idx == -1:
                    new_taints = self._handle_control_dependence(cfg_node)
                    taints |= new_taints

                else:
                    cl = CodeLocation(cfg_node.addr, stmt_idx)
                    taints.add(cl)

            while taints:
                # Pop a tainted code location
                tainted_cl = taints.pop()


                # Mark it as picked
                if tainted_cl.block_addr is not None and tainted_cl.stmt_idx is not None:
                    # Skip SimProcedures
                    self._pick_statement(tainted_cl.block_addr, tainted_cl.stmt_idx)

                # Mark it as accessed
                accessed_taints.add(tainted_cl)

                # Pick all its data dependencies from data dependency graph
                if self._ddg is not None and tainted_cl in self._ddg:
                    if isinstance(self._ddg, networkx.DiGraph):
                        predecessors = list(self._ddg.predecessors(tainted_cl))
                    else:
                        # angr.analyses.DDG
                        predecessors = list(self._ddg.get_predecessors(tainted_cl))


                    for p in predecessors:
                        if p not in accessed_taints:
                            taints.add(p)

                        self.taint_graph.add_edge(p, tainted_cl)

                # Handle the control dependence
                for n in self._cfg.model.get_all_nodes(tainted_cl.block_addr):
                    new_taints = self._handle_control_dependence(n)

                    for taint in new_taints:
                        if taint not in accessed_taints:
                            taints.add(taint)

                        self.taint_graph.add_edge(taint, tainted_cl)

            # In the end, map the taint graph onto CFG
            self._map_to_cfg()