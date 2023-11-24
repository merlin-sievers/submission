import angr

from patching.reference import Reference
from patching.configuration import Config


class Matcher:
    def __init__(self, cfg_vuln, cfg_patch):
        self.match_old_address = dict()
        self.match_new_address = dict()

        # Get SQLResults
        config = Config()
        results = config.openBindiffResults()

        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        for node in cfg_vuln.graph.nodes:
            for row in results:
                address1, address2, count = row
                if node.addr == address1:
                    node_old = cfg_patch.get_any_node(address2)
                    if node_old.block.instructions == node.block.instructions:
                        i = 0
                        # Going through each individual instruction to check if the mnemonics are the same
                        while i < node.block.instructions:
                            if node.block.disassembly.insns[i].mnemonic == node_old.block.disassembly.insns[i].mnemonic:
                                i = i+1
                            else:
                                i = node.block.instructions + 1
                        if i == node.block.instructions:
                            self.match_old_address[node.addr] = address2
                            self.match_new_address[address2] = node.addr

    def get_not_matched_blocks(self, cfg, entryPoint, end):
        notMatchedBlocks = []
        nodes = list(filter(lambda node: entryPoint <= node.addr <= end, cfg.graph.nodes))
        for block in nodes:
            if block.addr in self.match_old_address:
                pass
            else:
                notMatchedBlocks.append(block.addr)
        return notMatchedBlocks




class RefMatcher:

    # TODO: Write constructor in a way that it takes the project of the vulnerable and the patched version and gets all the references
    def __init__(self):
        self.match_to_old_address = dict()
        self.match_to_new_address = dict()
        self.match_from_old_address = dict()
        self.match_from_new_address = dict()


    def match_references_from_perfect_matched_blocks(self, perfect_matches, refs_vuln, refs_patch, project_vuln, project_patch):
        # TODO: Match References if they are in a perfectly matched BasicBlock in the Function and outside of the Function
        for ref_vuln in refs_vuln:
            for addr in perfect_matches.match_old_address:
                block_vuln = project_vuln.factory.block(addr)
                if ref_vuln.fromAddr in block_vuln.instruction_addrs:
                    i = block_vuln.instruction_addrs.index(block_vuln.addr)
                    for ref_patch in refs_patch:
                        block_patch = project_patch.factory.block(perfect_matches.match_new_address[addr])
                        if ref_patch.fromAddr == block_patch.instruction_addrs[i]:
                            self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
                            self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
                            self.match_to_old_address[ref_vuln.toAddr] = ref_patch
                            self.match_to_new_address[ref_patch.toAddr] = ref_vuln
                if ref_vuln.toAddr in block_vuln.instruction_addrs:
                    i = block_vuln.instruction_addrs.index(block_vuln.addr)
                    for ref_patch in refs_patch:
                        block_patch = project_patch.factory.block(perfect_matches.match_new_address[addr])
                        if ref_patch.toAddr == block_patch.instruction_addrs[i]:
                            if ref_patch.toAddr in self.match_to_new_address:
                                pass
                            else:
                                self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
                                self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
                                self.match_to_old_address[ref_vuln.toAddr] = ref_patch
                                self.match_to_new_address[ref_patch.toAddr] = ref_vuln



    def get_refs(self, project):

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

