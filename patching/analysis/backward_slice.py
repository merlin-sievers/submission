# Class for backward slicing from variable use to its definition:
from collections import defaultdict

import networkx
from angr import AngrBackwardSlicingError
from angr.analyses import BackwardSlice
from angr.analyses.ddg import ProgramVariable
from angr.code_location import CodeLocation
from angr.sim_variable import SimTemporaryVariable, SimRegisterVariable


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
        project,
        targets=None,
        cfg_node=None,
        stmt_id=None,
        control_flow_slice=False,
        same_function=False,
        no_construct=False,
        offset=False,
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
        :param project:             The project instance.
        :param targets:             A list of "target" that specify targets of the backward slices. Each target can be a
                                    tuple in form of (cfg_node, stmt_idx), or a CodeLocation instance.
        :param cfg_node:            Deprecated. The target CFGNode to reach. It should exist in the CFG.
        :param stmt_id:             Deprecated. The target statement to reach.
        :param control_flow_slice:  True/False, indicates whether we should slice only based on CFG. Sometimes when
                                    acquiring DDG is difficult or impossible, you can just create a slice on your CFG.
                                    Well, if you don't even have a CFG, then...
        :param no_construct:        Only used for testing and debugging to easily create a BackwardSlice object.
        """
        self.project = project
        self._variable = variable
        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self._same_function = same_function

        # All targets
        self._targets = targets

        if cfg_node is not None or stmt_id is not None:
            self._targets = [(cfg_node, stmt_id)]

        # Save a list of taints to begin with at the beginning of each SimRun
        self.initial_taints_per_run = None
        self.runs_in_slice = None
        self.cfg_nodes_in_slice = None
        # IDs of all chosen statement for each SimRun
        self.chosen_statements = defaultdict(set)
        # IDs for all chosen exit statements as well as their corresponding targets
        self.chosen_exits = defaultdict(list)
        # Address of all chosen statements for each SimRun
        self.chosen_statements_addrs = set()
        self.offset = offset

        if not no_construct:
            self._construct_default(self._targets, variable)


    def _construct_default(self, targets, var):
        """
        Create a backward slice from a specific statement in a specific block. This is done by traverse the CFG
        backwards, and mark all tainted statements based on dependence graphs (CDG and DDG) provided initially. The
        traversal terminated when we reach the entry point, or when there is no unresolved dependencies.

        :param targets: A list of tuples like (cfg_node, stmt_idx), where cfg_node is a CFGNode instance where the
                        backward slice starts, and it must be included in CFG and CDG. stmt_idx is the ID of the target
                        statement where the backward slice starts.
        :param var:     The variable to slice on.
        """
        if isinstance(var, ProgramVariable):
            self._alternativ_worklist(var)
        else:
            self._worklist(targets, var)

    def _constraint_function(self, cl, variables):
        """
            Get the final definition of a variable in a specific statement.
            :param variables = set(var):    The variables to query.
            :param cfg_node:    The CFGNode instance where the statement is located.
            :param stmt_idx:    The statement ID.
            :return:            A list of CodeLocation instances.
        """
        vars_to_remove = set()
        vars_to_add = set()
        for vars in variables:
            if self._ddg is not None and cl in self._ddg:
                definitions = self._ddg.find_definitions(vars, cl, simplified_graph=False)
                for definition in definitions:
                    print(definition)

                    if vars == definition.variable:
                        vars_to_remove.add(vars)
                        self._pick_statement(cl.block_addr, cl.stmt_idx, cl.ins_addr)
                        self.chosen_statements_addrs.add(cl.ins_addr)
                        ddg_definitions = self._ddg.view[cl.ins_addr].definitions
                        view = self._ddg.find_sources(definition, simplified_graph=False)
                        print(view)
                        for dep_def in ddg_definitions:
                            if dep_def._variable.variable == vars:
                                for var_dep in dep_def.depends_on:
                                    vars_to_add.add(var_dep._variable.variable)

        for vars in vars_to_remove:
            variables.remove(vars)

        for vars in vars_to_add:
            variables.add(vars)

        return variables


    def _alternativ_worklist(self, var_def):
        sources = []
        defs = [var_def]
        traversed = set()
        self.chosen_statements_addrs.add(var_def.location.ins_addr)
        self._pick_statement(var_def.location.block_addr, var_def.location.stmt_idx, var_def.location.ins_addr)

        while defs:
            definition = defs.pop()
            in_edges = self._ddg.data_graph.in_edges(definition, data=True)
            if self.offset:
                for src, _, data in in_edges:
                    if isinstance(src.variable, SimTemporaryVariable):
                        if src not in traversed:
                            defs.append(src)
                            traversed.add(src)
                            self.chosen_statements_addrs.add(src.location.ins_addr)
                            self._pick_statement(src.location.block_addr, src.location.stmt_idx, src.location.ins_addr)
                    elif isinstance(src.variable, SimRegisterVariable):
                        if src.variable not in traversed:
                            defs.append(src)
                            traversed.add(src.variable)
                            if src.variable not in sources:
                                sources.append(src.variable)
                            self.chosen_statements_addrs.add(src.location.ins_addr)
                            self._pick_statement(src.location.block_addr, src.location.stmt_idx, src.location.ins_addr)
                    else:
                        if src not in sources:
                            sources.append(src)
                            self.chosen_statements_addrs.add(src.location.ins_addr)
                            self._pick_statement(src.location.block_addr, src.location.stmt_idx, src.location.ins_addr)
            else:
                for src, _, data in in_edges:
                    if "type" in data and data["type"] == "kill":
                        continue
                    if isinstance(src.variable, SimTemporaryVariable):
                        if src.variable not in traversed:
                            defs.append(src)
                            traversed.add(src.variable)
                            self.chosen_statements_addrs.add(src.location.ins_addr)
                            self._pick_statement(src.location.block_addr, src.location.stmt_idx,
                                                     src.location.ins_addr)
                    else:
                        if src.variable not in sources:
                            sources.append(src.variable)
                            self.chosen_statements_addrs.add(src.location.ins_addr)
                            self._pick_statement(src.location.block_addr, src.location.stmt_idx,
                                                     src.location.ins_addr)



    def _worklist(self, starts, var):
        """
        :param self:
        :param targets:
        :param var:
        :return:
        """
        print("there you go")
        worklist = set()
        for start in starts:
            worklist.add(start)
        self.taint_graph = networkx.DiGraph()

        # Initialize variables (abstract State)
        variables = set()
        variables.add(var)

        accessed_taints = set()

        while worklist:
            node = worklist.pop()
            accessed_taints.add(node)
            variables = self._constraint_function(node, variables)
            if variables:
                # Add all predecessors to the worklist
                if self._ddg is not None and node in self._ddg:
                    if isinstance(self._ddg, networkx.DiGraph):
                        predecessors = list(self._ddg.predecessors(node))
                    else:
                        predecessors = list(self._ddg.get_predecessors(node))

                    for p in predecessors:
                        worklist.add(p)
                        self.taint_graph.add_edge(p, node)

        self._map_to_cfg()
        print(self.chosen_statements)