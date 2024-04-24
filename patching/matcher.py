import angr

from patching.reference import Reference
from patching.configuration import Config


class Matcher:
    def __init__(self, cfg_vuln, cfg_patch, project_vuln, project_patch):
        self.match_old_address = dict()
        self.match_new_address = dict()

        # Get angr BinDiff results
        self.bindiff_results = project_vuln.analyses.BinDiff(project_patch, cfg_a=cfg_vuln, cfg_b=cfg_patch)


        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        for tuple in self.bindiff_results.identical_blocks:
            self.match_old_address[tuple[0].addr] = tuple[1].addr
            self.match_new_address[tuple[1].addr] = tuple[0].addr

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
    def __init__(self, bindiff_results):
        self.bindiff_results = bindiff_results
        self.match_to_old_address = dict()
        self.match_to_new_address = dict()
        self.match_from_old_address = dict()
        self.match_from_new_address = dict()

        self.address_to_vuln_refs = dict()
        self.address_to_refs = dict()

    def match_references_from_perfect_matched_blocks(self, perfect_matches, refs_vuln, refs_patch, project_vuln, project_patch):
        # TODO: Match References if they are in a perfectly matched BasicBlock in the Function and outside of the Function
        # self.bindiff_results = project_vuln.analyses.BinDiff(project_patch)


        for ref_vuln in refs_vuln:
            relevant_addrs = [addr for addr in perfect_matches.match_old_address if 0 <= (ref_vuln - addr ) <= 80]
            for addr in relevant_addrs:
                block_vuln = project_vuln.factory.block(addr)
                if ref_vuln in block_vuln.instruction_addrs:
                    i = block_vuln.instruction_addrs.index(ref_vuln)
                    block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
                    if block_patch.instruction_addrs[i] in refs_patch:
                        self.match_from_old_address[ref_vuln] = refs_patch[block_patch.instruction_addrs[i]]
                        self.match_from_new_address[refs_patch[block_patch.instruction_addrs[i]][0].fromAddr] = refs_vuln[ref_vuln]
                        self.match_to_old_address[refs_vuln[ref_vuln][0].toAddr] = refs_patch[block_patch.instruction_addrs[i]]
                        self.match_to_new_address[refs_patch[block_patch.instruction_addrs[i]][0].toAddr] = refs_vuln[ref_vuln]
                if refs_vuln[ref_vuln][0].toAddr in block_vuln.instruction_addrs:
                    i = block_vuln.instruction_addrs.index(refs_vuln[ref_vuln][0].toAddr)
                    block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
                    if block_patch.instruction_addrs[i] in refs_patch:
                        self.match_to_old_address[refs_vuln[ref_vuln][0].toAddr] = refs_patch[block_patch.instruction_addrs[i]]
                        self.match_to_new_address[refs_patch[block_patch.instruction_addrs[i]][0].toAddr] = refs_vuln[ref_vuln]

            for function_addr, function_addr_patch  in self.bindiff_results.function_matches:
                for ref in refs_vuln[ref_vuln]:
                    if ref.toAddr == function_addr:
                        new_ref = Reference(ref.fromAddr, function_addr_patch, ref.refType)
                        self.match_to_old_address[ref.toAddr] = [new_ref]
                        self.match_to_new_address[function_addr_patch] = [ref]

                for ref_patch in refs_patch:
                    for r in refs_patch[ref_patch]:
                        if r.toAddr == function_addr_patch:
                            new_ref = Reference(r.fromAddr, function_addr, r.refType)
                            self.match_to_old_address[function_addr] = [r]
                            self.match_to_new_address[r.toAddr] = [new_ref]



        # for ref_vuln in refs_vuln:
        #     if ref_vuln.refType != "read":
        #         for addr in perfect_matches.match_old_address:
        #             if addr - 100 <= ref_vuln.fromAddr <= addr + 100:
        #                 block_vuln = project_vuln.factory.block(addr)
        #
        #                 if ref_vuln.fromAddr in block_vuln.instruction_addrs:
        #                     i = block_vuln.instruction_addrs.index(ref_vuln.fromAddr)
        #                     for ref_patch in refs_patch:
        #                         if ref_patch.refType != "read":
        #                             block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
        #                             if ref_patch.fromAddr == block_patch.instruction_addrs[i]:
        #                                 self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
        #                                 self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
        #                                 self.match_to_old_address[ref_vuln.toAddr] = ref_patch
        #                                 self.match_to_new_address[ref_patch.toAddr] = ref_vuln
        #                 if ref_vuln.toAddr in block_vuln.instruction_addrs:
        #                     i = block_vuln.instruction_addrs.index(ref_vuln.toAddr)
        #                     for ref_patch in refs_patch:
        #                         if ref_patch.refType != "read":
        #                             block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
        #                             if ref_patch.toAddr == block_patch.instruction_addrs[i]:
        #                                 if ref_patch.toAddr in self.match_to_new_address:
        #                                     pass
        #                                 else:
        #                                     self.match_from_old_address[ref_vuln.fromAddr] = ref_patch
        #                                     self.match_from_new_address[ref_patch.fromAddr] = ref_vuln
        #                                     self.match_to_old_address[ref_vuln.toAddr] = ref_patch
        #                                     self.match_to_new_address[ref_patch.toAddr] = ref_vuln

    def get_refs(self, project, cfg, address):
        # TODO make independent from function name --> DONE

        # target_function = project.loader.find_symbol(function_name)

        # address = target_function.rebased_addr

        # cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs,
        #                                    context_sensitivity_level=0, starts=[address])
        self.address_to_refs = dict()
        xrefs = set()
        # cfgfast = project.analyses.CFGFast()
        for node in cfg.graph.nodes:

            if node.final_states is not None:

                for final in node.final_states:
                    if final.history.jump_source is not None:
                        if final.history.jump_target.concrete:
                            fromAddr = final.history.jump_source
                            toAddr = final.history.jump_target.concrete_value
                            if abs(fromAddr - toAddr) > 4:
                                ref = Reference(fromAddr, toAddr, "control_flow_jump")
                                xrefs.add(ref)
                                if fromAddr not in self.address_to_refs:
                                    self.address_to_refs[fromAddr] = [ref]
                                else:
                                    self.address_to_refs[fromAddr].append(ref)

        refs = project.analyses.XRefs(func=address)

        if refs is None:
            return self.address_to_refs

        for refAddr in refs.kb.xrefs.xrefs_by_ins_addr:
            for r in refs.kb.xrefs.xrefs_by_ins_addr[refAddr]:
                fromAddr = r.ins_addr
                toAddr = r.dst
                refType = r.type_string
                ref = Reference(fromAddr, toAddr, refType)
                xrefs.add(ref)
                if toAddr == 5242880:
                    pass
                else:
                    if fromAddr not in self.address_to_refs:
                        self.address_to_refs[fromAddr] = [ref]
                    else:
                        self.address_to_refs[fromAddr].append(ref)

        return self.address_to_refs



