import angr
import json
from patching.reference import Reference


class RefMatcher:

    def __init__(self):
        self.matchToOldAddress = dict()
        self.matchToNewAddress = dict()
        self.matchFromOldAddress = dict()
        self.matchFromNewAddress = dict()


    def matchReferencesFromPerfectMatchedBlocks(self, perfectMatches, refs):
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

