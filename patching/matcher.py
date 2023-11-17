import angr

from patching.reference import Reference
from patching.configuration import Config


class Matcher:
    def __init__(self, project_vuln, project_patch):
        self.matchOldAddress = dict()
        self.matchNewAddress = dict()

        # Get SQLResults
        config = Config()
        results = config.openBindiffResults()

        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        for node in project_vuln.cfg.graph.nodes:
            for row in results:
                address1, address2, count = row
                if node.addr == address1:
                    node_old = project_patch.cfg.get_any_node(address2)
                    if node_old.bock.instructions == node.block.instructions:
                        i = 0
                        # Going through each individual instruction to check if the mnemonics are the same
                        while i < node.block.instructions:
                            if node.block.disassembly.insns[i].mnemonic == node_old.block.disassembly.insns[i].mnemonic:
                                i = i+1
                            else:
                                i = node.block.instructions + 1
                        if i == node.block.instructions:
                            self.matchOldAddress[node.addr] = address2
                            self.matchNewAddress[address2] = node.addr

    def get_not_matched_blocks(self, project, entryPoint, end):
        notMatchedBlocks = []
        nodes = list(filter(lambda node: entryPoint <= node.addr <= end, project.cfg.graph.nodes))
        for block in nodes:
            if block.addr in self.matchOldAddress:
                pass
            else:
                notMatchedBlocks.append(block.addr)
        return notMatchedBlocks




class RefMatcher:

    # TODO: Write constructor in a way that it takes the project of the vulnerable and the patched version and gets all the references
    def __init__(self):
        self.matchToOldAddress = dict()
        self.matchToNewAddress = dict()
        self.matchFromOldAddress = dict()
        self.matchFromNewAddress = dict()


    def match_references_from_perfect_matched_blocks(self, perfectMatches, refs):
        # TODO: Match References if they are in a perfectly matched BasicBlock in the Function and outside of the Function
        for match in perfectMatches:
            for ref in refs:
                if ref.fromAddr == match.oldAddress:
                    self.matchFromOldAddress[ref.fromAddr] = ref
                    self.matchFromNewAddress[match.newAddress] = ref
                if ref.toAddr == match.oldAddress:
                    self.matchToOldAddress[ref.toAddr] = ref
                    self.matchToNewAddress[match.newAddress] = ref

    def get_refs(self, function):
        project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", load_options={'main_opts': {'base_addr': 65536}, 'auto_load_libs': False})
        target_function = project.loader.find_symbol("png_check_keyword")
        cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs,
                                           context_sensitivity_level=0, starts=[target_function.rebased_addr])

        xrefs = set()
        # cfgfast = project.analyses.CFGFast()
        for node in cfg.graph.nodes:

            if node.input_state is not None:
                if node.input_state.history.jump_source is not None:
                    fromAddr = node.input_state.history.jump_source-1
                    toAddr = node.input_state.history.jump_target.concrete_value-1
                    ref = Reference(fromAddr, toAddr, "control_flow_jump")
                    xrefs.add(ref)


        refs = project.analyses.XRefs(func=target_function.rebased_addr)

        for refAddr in refs.kb.xrefs.xrefs_by_ins_addr:
            for r in refs.kb.xrefs.xrefs_by_ins_addr[refAddr]:
                fromAddr = r.ins_addr-1
                toAddr = r.dst
                refType = r.type_string
                ref = Reference(fromAddr, toAddr, refType)
                xrefs.add(ref)

        return xrefs

