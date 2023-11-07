import angr
import json

def get_xrefs():
    project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0", load_options={'main_opts': {'base_addr': 65536}, 'auto_load_libs': False})
    target_function = project.loader.find_symbol("png_check_keyword")
    cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs,
                                       context_sensitivity_level=0, starts=[target_function.rebased_addr])

    xrefs = []
    # cfgfast = project.analyses.CFGFast()
    for node in cfg.graph.nodes:

        if node.input_state is not None:
            if node.input_state.history.jump_source is not None:



                xrefs.append({
                    "fromAddress": hex(node.input_state.history.jump_source-1),
                    "toAddress": hex(node.input_state.history.jump_target.concrete_value-1),
                    "refType": "control_flow_jump"
                })


    for edge in cfg.graph.edges:
        print(edge[0], edge[1])

    print(project.kb.xrefs.xrefs_by_ins_addr)
    refs = project.analyses.XRefs(func=target_function.rebased_addr)
    print(refs.kb.xrefs.xrefs_by_ins_addr)
    for refAddr in refs.kb.xrefs.xrefs_by_ins_addr:
        for r in refs.kb.xrefs.xrefs_by_ins_addr[refAddr]:
            xrefs.append({
                "fromAddress": hex(r.ins_addr-1),
                "toAddress": hex(r.dst),
                "refType": r.type_string  # Define reference type here
            })

    return xrefs

def save_to_json(data):
    with open("xrefs_data.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

def main():
    xrefs_data = get_xrefs()
    save_to_json(xrefs_data)

if __name__ == "__main__":
    main()
