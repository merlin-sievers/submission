import angr

from patching.reference import Reference
from patching.configuration import Config


class Matcher:
    def __init__(self, cfg_vuln, cfg_patch, project_vuln, project_patch):
        self.match_old_address = dict()
        self.match_new_address = dict()

        # Get SQLResults
        # config = Config()
        # results = config.openBindiffResults()

        # Get angr BinDiff results
        bindiff_results = project_vuln.analyses.BinDiff(project_patch)


        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        for tuple in bindiff_results.identical_blocks:
            self.match_old_address[tuple[0].addr] = tuple[1].addr
            self.match_new_address[tuple[1].addr] = tuple[0].addr



        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        # for node in cfg_vuln.graph.nodes:
        #     for row in results:
        #         address1, address2, count = row
        #         if node.thumb:
        #             address1 = address1 + 1
        #             address2 = address2 + 1
        #         if node.addr == address1 + 4128768:
        #             node_patch = cfg_patch.get_any_node(address2 + 4128768)
        #             if node_patch.block.instructions == node.block.instructions:
        #                 i = 0
        #                 # Going through each individual instruction to check if the mnemonics are the same
        #                 while i < node.block.instructions:
        #                     if len(node.block.disassembly.insns) == node.block.instructions:
        #                         if node.block.disassembly.insns[i].mnemonic == node_patch.block.disassembly.insns[i].mnemonic:
        #                             i = i+1
        #                         else:
        #                             i = node.block.instructions + 1
        #                     else:
        #                         i = node.block.instructions + 1
        #                 if i == node.block.instructions:
        #                     self.match_old_address[node.addr] = address2 + 4128768
        #                     self.match_new_address[address2 + 4128768] = node.addr

    def get_not_matched_blocks(self, cfg, entryPoint, end, match_address):
        notMatchedBlocks = []
        nodes = list(filter(lambda node: entryPoint <= node.addr <= end, cfg.graph.nodes))
        for block in nodes:
            if block.addr in match_address:
                pass
            else:
                notMatchedBlocks.append(block.addr)
        return notMatchedBlocks


class RefMatcher:

    # TODO: Write constructor in a way that it takes the project of the vulnerable and the patched version and gets all the references
    def __init__(self):
        self.bindiff_results = None
        self.match_to_old_address = dict()
        self.match_to_new_address = dict()
        self.match_from_old_address = dict()
        self.match_from_new_address = dict()

    def match_references_from_perfect_matched_blocks(self, perfect_matches, refs_vuln, refs_patch, project_vuln, project_patch):
        # TODO: Match References if they are in a perfectly matched BasicBlock in the Function and outside of the Function
        self.bindiff_results = project_vuln.analyses.BinDiff(project_patch)
        for ref_vuln in refs_vuln:
            for addr in perfect_matches.match_old_address:
                if addr - 100 <= ref_vuln.fromAddr <= addr + 100:
                    block_vuln = project_vuln.factory.block(addr)
                    if ref_vuln.fromAddr + 1 in block_vuln.instruction_addrs:
                        i = block_vuln.instruction_addrs.index(block_vuln.addr)
                        for ref_patch in refs_patch:
                            block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
                            # if 4244950 <= ref_patch.fromAddr == 4244975:
                            #     print("hellp")
                            if ref_patch.fromAddr + 1 == block_patch.instruction_addrs[i]:
                                self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
                                self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
                                self.match_to_old_address[ref_vuln.toAddr] = ref_patch
                                self.match_to_new_address[ref_patch.toAddr] = ref_vuln
                    if ref_vuln.toAddr + 1 in block_vuln.instruction_addrs:
                        i = block_vuln.instruction_addrs.index(block_vuln.addr)
                        for ref_patch in refs_patch:
                            block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
                            if ref_patch.toAddr + 1 == block_patch.instruction_addrs[i]:
                                if ref_patch.toAddr in self.match_to_new_address:
                                    pass
                                else:
                                    self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
                                    self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
                                    self.match_to_old_address[ref_vuln.toAddr] = ref_patch
                                    self.match_to_new_address[ref_patch.toAddr] = ref_vuln
            for function_addr, _  in self.bindiff_results.function_matches:
                if ref_vuln.toAddr + 1 == function_addr:
                    for ref_patch in refs_patch:
                        if (ref_vuln.toAddr + 1, ref_patch.toAddr + 1) in self.bindiff_results.function_matches:
                            self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
                            self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
                            self.match_to_old_address[ref_vuln.toAddr] = ref_patch
                            self.match_to_new_address[ref_patch.toAddr] = ref_vuln

    def get_refs(self, project):
        # TODO make independent from function name
        target_function = project.loader.find_symbol("_start")
        cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs,
                                           context_sensitivity_level=0, starts=[target_function.rebased_addr])

        xrefs = set()
        # cfgfast = project.analyses.CFGFast()
        for node in cfg.graph.nodes:

            if node.final_states is not None:

                for final in node.final_states:
                    if final.history.jump_source is not None:
                        if final.history.jump_target.concrete:
                            fromAddr = final.history.jump_source - 1
                            toAddr = final.history.jump_target.concrete_value - 1
                            ref = Reference(fromAddr, toAddr, "control_flow_jump")
                            xrefs.add(ref)


        refs = project.analyses.XRefs(func=target_function.rebased_addr)
        if refs is None:
            return xrefs

        for refAddr in refs.kb.xrefs.xrefs_by_ins_addr:
            for r in refs.kb.xrefs.xrefs_by_ins_addr[refAddr]:
                fromAddr = r.ins_addr-1
                toAddr = r.dst
                refType = r.type_string
                ref = Reference(fromAddr, toAddr, refType)
                xrefs.add(ref)

        return xrefs

