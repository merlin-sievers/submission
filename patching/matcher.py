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
        print(nodes)
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

    def match_references_from_perfect_matched_blocks(self, perfect_matches, refs_vuln, refs_patch, project_vuln, project_patch, entryPoint, end):
        # TODO: Match References if they are in a perfectly matched BasicBlock in the Function and outside of the Function
        # self.bindiff_results = project_vuln.analyses.BinDiff(project_patch)

        # get got address
        for sec in project_patch.loader.main_object.sections:
            if sec.name == ".got":
                got_addr = sec.min_addr


        for ref_patch in [ref for ref in refs_patch if entryPoint <= ref <= end]:
            relevant_addrs = [addr for addr in perfect_matches.match_new_address if 0 <= (ref_patch - addr) <= 80]
            for addr in relevant_addrs:
                block_patch = project_patch.factory.block(addr)
                if ref_patch in block_patch.instruction_addrs:
                    i = block_patch.instruction_addrs.index(ref_patch)
                    block_vuln = project_vuln.factory.block(perfect_matches.match_new_address[addr])
                    if block_vuln.instruction_addrs[i] in refs_vuln:
                        self.match_from_new_address[ref_patch] = refs_vuln[block_vuln.instruction_addrs[i]]
                        self.match_from_old_address[refs_vuln[block_vuln.instruction_addrs[i]][0].fromAddr] = refs_patch[ref_patch]
                        self.match_to_new_address[refs_patch[ref_patch][0].toAddr] = refs_vuln[block_vuln.instruction_addrs[i]]
                        self.match_to_old_address[refs_vuln[block_vuln.instruction_addrs[i]][0].toAddr] = refs_patch[ref_patch]
            for ref in refs_patch[ref_patch]:
                matching = [(t[0],t[1]) for t in self.bindiff_results.function_matches if ref.toAddr == t[1]]
                #
                if matching:
                    new_ref = Reference(ref.fromAddr, matching[0][0], ref.refType)
                    self.match_to_old_address[matching[0][0]] = [ref]
                    self.match_to_new_address[ref.toAddr] = [new_ref]
                elif ref.toAddr >= got_addr:
                    relocations_patch = [reloc for reloc in project_patch.loader.main_object.relocs if reloc.rebased_addr == ref.toAddr]
                    if relocations_patch:
                        relocations_vuln = [reloc for reloc in project_vuln.loader.main_object.relocs if reloc.symbol.name == relocations_patch[0].symbol.name]
                        if relocations_vuln:
                            new_ref = Reference(ref.fromAddr, relocations_vuln[0].rebased_addr, ref.refType)
                            self.match_to_old_address[relocations_vuln[0].rebased_addr] = [ref]
                            self.match_to_new_address[ref.toAddr] = [new_ref]
                elif ref.toAddr in project_patch.loader.main_object.reverse_plt:
                    name = project_patch.loader.main_object.reverse_plt[ref.toAddr]
                    if name in project_vuln.loader.main_object.plt:
                        new_ref = Reference(ref.fromAddr, project_vuln.loader.main_object.plt[name], ref.refType)
                        self.match_to_old_address[project_vuln.loader.main_object.plt[name]] = [ref]
                        self.match_to_new_address[ref.toAddr] = [new_ref]




        # for ref_vuln in refs_vuln:
        #         relevant_addrs = [addr for addr in perfect_matches.match_old_address if 0 <= (ref_vuln - addr ) <= 80]
        #         for addr in relevant_addrs:
        #             block_vuln = project_vuln.factory.block(addr)
        #             if ref_vuln in block_vuln.instruction_addrs:
        #                 i = block_vuln.instruction_addrs.index(ref_vuln)
        #                 block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
        #                 if block_patch.instruction_addrs[i] in refs_patch:
        #                     self.match_from_old_address[ref_vuln] = refs_patch[block_patch.instruction_addrs[i]]
        #                     self.match_from_new_address[refs_patch[block_patch.instruction_addrs[i]][0].fromAddr] = refs_vuln[ref_vuln]
        #                     self.match_to_old_address[refs_vuln[ref_vuln][0].toAddr] = refs_patch[block_patch.instruction_addrs[i]]
        #                     self.match_to_new_address[refs_patch[block_patch.instruction_addrs[i]][0].toAddr] = refs_vuln[ref_vuln]
        #             if refs_vuln[ref_vuln][0].toAddr in block_vuln.instruction_addrs:
        #                 i = block_vuln.instruction_addrs.index(refs_vuln[ref_vuln][0].toAddr)
        #                 block_patch = project_patch.factory.block(perfect_matches.match_old_address[addr])
        #                 if block_patch.instruction_addrs[i] in refs_patch:
        #                     self.match_to_old_address[refs_vuln[ref_vuln][0].toAddr] = refs_patch[block_patch.instruction_addrs[i]]
        #                     self.match_to_new_address[refs_patch[block_patch.instruction_addrs[i]][0].toAddr] = refs_vuln[ref_vuln]
        #
        #         for function_addr, function_addr_patch  in self.bindiff_results.function_matches:
        #             for ref in refs_vuln[ref_vuln]:
        #                 if ref.toAddr == function_addr:
        #                     new_ref = Reference(ref.fromAddr, function_addr_patch, ref.refType)
        #                     self.match_to_old_address[ref.toAddr] = [new_ref]
        #                     self.match_to_new_address[function_addr_patch] = [ref]
        #
        #             for ref_patch in refs_patch:
        #                 for r in refs_patch[ref_patch]:
        #                     if r.toAddr == function_addr_patch:
        #                         new_ref = Reference(r.fromAddr, function_addr, r.refType)
        #                         self.match_to_old_address[function_addr] = [r]
        #                         self.match_to_new_address[r.toAddr] = [new_ref]
        #


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



