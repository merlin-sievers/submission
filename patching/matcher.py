import angr

from patching.reference import Reference
from patching.configuration import Config

from pathlib import Path
import logging

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

def is_thunk(instrs):
    if len(instrs) != 3:
        return False
    i1, i2, i3 = instrs[0:3]
    return (
        i1.mnemonic == "add" and i1.op_str.startswith("ip, pc") and
        i2.mnemonic == "add" and "ip, ip" in i2.op_str and
        i3.mnemonic == "ldr" and i3.op_str.startswith("pc, [ip") and "!" in i3.op_str
    )

def find_thunks(proj):

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True

    thunks = []

    # Find all executable memory regions
    exec_segments = [
        seg for seg in proj.loader.main_object.segments
    ]


    # For each section, scan for the thunk pattern
    for seg in exec_segments:
        code = proj.loader.memory.load(seg.vaddr, seg.memsize)
        instrs = list(md.disasm(code, seg.vaddr))

        start = seg.vaddr
        end = start + seg.memsize

        addr = start
        while addr < end - 12:
            code = proj.loader.memory.load(addr, 12)
            instrs = list(md.disasm(code, addr))
            if is_thunk(instrs):
                thunks.append(addr)
                addr += 12
            else:
                addr += 2

    names = list(proj.loader.main_object.jmprel.keys())
    if len(names) != len(thunks):
        return {}
    name_to_thunk = {name: addr for name, addr in zip(names, thunks)}
    return name_to_thunk


class Matcher:
    def __init__(self, cfg_vuln, cfg_patch, project_vuln, project_patch):
        self.match_old_address = dict()
        self.match_new_address = dict()

        # Get angr BinDiff results
        self.bindiff_results = project_vuln.analyses.BinDiff(project_patch, cfg_a=cfg_vuln, cfg_b=cfg_patch)


        # Get all perfect Matches of BasicBlocks from the BinDiffResults
        for tuple in self.bindiff_results.identical_blocks:

            # Make a sanity check here...
            if tuple[0].size != tuple[1].size:
                continue



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

        name_to_thunk_vuln = find_thunks(project_vuln)

        # get got address
        for sec in project_patch.loader.main_object.sections:
            if sec.name == ".got":
                got_addr = sec.min_addr

        help = [ref for ref in refs_patch if entryPoint <= ref <= end]
        print(len(help))
        for ref_patch in [ref for ref in refs_patch if entryPoint <= ref <= end]:

            if perfect_matches is not None:
                try:
                    bb_addr = max(filter(lambda x: x <= ref_patch, perfect_matches.match_new_address.keys()))
                except ValueError:
                    bb_addr = None
                if bb_addr:
                    block_patch = project_patch.factory.block(bb_addr)
                    if ref_patch in block_patch.instruction_addrs:
                        i = block_patch.instruction_addrs.index(ref_patch)
                        block_vuln = project_vuln.factory.block(perfect_matches.match_new_address[bb_addr])
                        if block_vuln.instruction_addrs[i] in refs_vuln:
                            self.match_from_new_address.setdefault(ref_patch, []).extend(refs_vuln[block_vuln.instruction_addrs[i]])
                            self.match_from_old_address.setdefault(refs_vuln[block_vuln.instruction_addrs[i]][0].fromAddr, []).extend(refs_patch[ref_patch])

                            for r in refs_patch[ref_patch]:
                                for v in refs_vuln[block_vuln.instruction_addrs[i]]:
                                    if r.refType == v.refType:
    # If there already is a control_flow_jump reference to another address overwrite this one. We trust the basic block matching more than the function matching
                                        if r.refType == "control_flow_jump":
                                            self.match_to_new_address[r.toAddr] = [v]
                                            self.match_to_old_address[v.toAddr] = [r]
                                        else:
                                            self.match_to_new_address.setdefault(r.toAddr, []).append(v)
                                            self.match_to_old_address.setdefault(v.toAddr, []).append(r)



            for ref in refs_patch[ref_patch]:
                matching = [(t[0],t[1]) for t in self.bindiff_results.function_matches if ref.toAddr == t[1]]
                #


                if matching:
                    new_ref = Reference(ref.fromAddr, matching[0][0], ref.refType)
# If there already is a control_flow_jump reference to another address use that one. We trust the basic block matching more than the function matching
                    if ref.refType == "control_flow_jump":
                        if ref.toAddr in self.match_to_new_address:
                            pass
                        else:
                            self.match_to_new_address.setdefault(ref.toAddr, []).append(new_ref)
                            self.match_to_old_address.setdefault(matching[0][0], []).append(ref)

                if ref.toAddr == got_addr:
                    got_addr_vuln = None
                    for sec in project_vuln.loader.main_object.sections:
                        if sec.name == ".got":
                            got_addr_vuln = sec.min_addr
                    if got_addr_vuln is not None:
                        new_ref = Reference(ref.fromAddr, got_addr_vuln, ref.refType)
                        self.match_to_new_address.setdefault(ref.toAddr, []).append(new_ref)
                        self.match_to_old_address.setdefault(got_addr_vuln, []).append(ref)

                if ref.toAddr > got_addr:

                    relocations_patch = [reloc for reloc in project_patch.loader.main_object.relocs if reloc.rebased_addr == ref.toAddr]
                    if relocations_patch:
                        relocations_vuln = [reloc for reloc in project_vuln.loader.main_object.relocs if reloc.symbol.name == relocations_patch[0].symbol.name]
                        if relocations_vuln:
                            new_ref = Reference(ref.fromAddr, relocations_vuln[0].rebased_addr, ref.refType)
                            self.match_to_new_address.setdefault(ref.toAddr, []).append(new_ref)
                            self.match_to_old_address.setdefault(relocations_vuln[0].rebased_addr, []).append(ref)
                if ref.toAddr in project_patch.loader.main_object.reverse_plt:
                    name = project_patch.loader.main_object.reverse_plt[ref.toAddr]
                    if name in project_vuln.loader.main_object.plt:
                        new_ref = Reference(ref.fromAddr, project_vuln.loader.main_object.plt[name], ref.refType)
                        self.match_to_new_address.setdefault(ref.toAddr, []).append(new_ref)
                        self.match_to_old_address.setdefault(project_vuln.loader.main_object.plt[name], []).append(ref)
                elif ref.toAddr+3 in project_patch.loader.main_object.reverse_plt:
                    name = project_patch.loader.main_object.reverse_plt[ref.toAddr + 3]
                    if name in project_vuln.loader.main_object.plt:
                        new_ref = Reference(ref.fromAddr, project_vuln.loader.main_object.plt[name], ref.refType)
                        if ref.refType == "control_flow_jump":
                            self.match_to_new_address[ref.toAddr] = [new_ref]
                            self.match_to_old_address[project_vuln.loader.main_object.plt[name]] = [new_ref]
                        else:
                            self.match_to_new_address.setdefault(ref.toAddr, []).append(new_ref)
                            self.match_to_old_address.setdefault(project_vuln.loader.main_object.plt[name], []).append(ref)
                    else:
                        try:
                            thunk = name_to_thunk_vuln[name]
                            new_ref = Reference(ref.fromAddr, thunk, ref.refType)
                            self.match_to_new_address[ref.toAddr] = [new_ref]
                            self.match_to_old_address[thunk] = [ref]
                        except KeyError:
                            pass

                symbol = project_patch.loader.find_symbol(ref.toAddr)
                if symbol is not None:
                    if symbol.type.value != 1:
                        match_symbol = project_vuln.loader.find_symbol(symbol.name)
                        if match_symbol is not None:
                            new_ref = Reference(ref.fromAddr, match_symbol.rebased_addr, ref.refType)
                            if ref.refType == "control_flow_jump":
                                self.match_to_new_address[ref.toAddr] = [new_ref]
                                self.match_to_old_address[match_symbol.rebased_addr] = [ref]
                            else:
                                self.match_to_new_address.setdefault(ref.toAddr, []).append(new_ref)
                                self.match_to_old_address.setdefault(match_symbol.rebased_addr, []).append(ref)

        print(sum(len(lst) for lst in self.match_to_old_address.values()), sum(len(lst) for lst in self.match_to_new_address.values()), len(self.match_to_old_address), len(self.match_to_new_address), len(self.match_from_old_address), len(self.match_from_new_address))



    def get_refs(self, project, cfg, address, cfg_fast):

        self.address_to_refs = dict()
        xrefs = set()
        # cfgfast = project.analyses.CFGFast()



        for fast_node in cfg_fast.graph.nodes:
            if fast_node.block is not None:
                if fast_node.addr >= address:
                    for succ in fast_node.successors:
                        fromAddr = fast_node.block.instruction_addrs[-1]
                        if abs(fast_node.block.instruction_addrs[-1] - succ.addr) > 4:
                            ref = Reference(fromAddr, succ.addr, "control_flow_jump")
                            xrefs.add(ref)
                            if fast_node.block.instruction_addrs[-1] not in self.address_to_refs:
                                self.address_to_refs[fromAddr] = [ref]
                            else:
                                self.address_to_refs[fromAddr].append(ref)


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

        print("Refs", len(refs.kb.xrefs.xrefs_by_ins_addr), address)

        if refs is None:
            return self.address_to_refs

        ANGR_UNDEFINED_ADDR = 0x500000
        for refAddr in refs.kb.xrefs.xrefs_by_ins_addr:
            for r in refs.kb.xrefs.xrefs_by_ins_addr[refAddr]:
                fromAddr = r.ins_addr
                toAddr = r.dst
                refType = r.type_string
                ref = Reference(fromAddr, toAddr, refType)
                xrefs.add(ref)
                if toAddr == ANGR_UNDEFINED_ADDR or toAddr == 0 or toAddr >= project.loader.main_object.max_addr:
                    pass
                else:
                    if fromAddr not in self.address_to_refs:
                        self.address_to_refs[fromAddr] = [ref]
                    else:
                        self.address_to_refs[fromAddr].append(ref)

        return self.address_to_refs



