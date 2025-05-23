# # import angr, monkeyhex, archinfo
# # import re
# # import lief
# import signal
# # from lief import ELF
# # import logging
# # import claripy
# # import networkx
# # import time
# # from patcherex.backends.detourbackend import DetourBackend
# # from angr import AngrBackwardSlicingError, Analysis
# # from angr.analyses import BackwardSlice, CFGEmulated
# # from angr.code_location import CodeLocation
# # from angr.sim_variable import SimRegisterVariable
# # from z3 import z3
# # from angrutils import plot_cfg
# # from patcherex.patches import InlinePatch, AddLabelPatch
# #
# # from patcherexMM.patcherex.backends import ReassemblerBackend
# # from patcherexMM.patcherex.patches import AddSegmentHeaderPatch, AddCodePatch
# # from patching.analysis.constraint_solver import ConstraintSolver
# from patching.configuration import Config
# from patching.function import FunctionPatch
# # from patching.patching import Patching
# # from patching.section_extender import SectionExtender
# # from variable_backward_slicing import VariableBackwardSlicing
# import logging
#
#
import logging

import angr

from patching.configuration import Config
from patching.function import FunctionPatch

#
# # config = lief.ELF.ParserConfig()
# #
# # # config.parse_dyn_symbols = True
# # # config.parse_symbol_versions = True
# # # config.parse_symtab_symbols = True
# # # config.parse_relocations = True
# # config.DYNSYM_COUNT.SECTION  = True
# # config.DYNSYM_COUNT.AUTO = True
# # config.DYNSYM_COUNT.RELOCATIONS = True
# # Configure logging
# # binary = lief.ELF.parse("Testsuite/MAGMA/openssl/vuln/libcrypto.so.3", config)
# # s = lief._lief.ELF
# #
#
# class TimeoutException(Exception):
#     pass
#
#
# def timeout_handler(signum, frame):
#     raise TimeoutException("Operation timed out")
# # import multiprocessing
#
# # --- Error Logger ---
# error_logger = logging.getLogger("error_logger")
# error_logger.setLevel(logging.ERROR)
# error_handler = logging.FileHandler("errors.log")
# error_formatter = logging.Formatter('%(asctime)s - ERROR - %(message)s')
# error_handler.setFormatter(error_formatter)
# error_logger.addHandler(error_handler)
#
# # --- Success Logger ---
# success_logger = logging.getLogger("success_logger")
# success_logger.setLevel(logging.INFO)
# success_handler = logging.FileHandler("success.log")
# success_formatter = logging.Formatter('%(asctime)s - SUCCESS - %(message)s')
# success_handler.setFormatter(success_formatter)
# success_logger.addHandler(success_handler)
#
# # signal.signal(signal.SIGALRM, timeout_handler)
# #
# config = Config()
# results = config.readJsonConfigFile("/Users/sebastian/PycharmProjects/cve-bin-tool/NetgearR6200_Test/results.json")
# name = dict()
# name["CVE-2016-9841"] = "inflate_table"
# for r in results:
#     config.binary_path = r["affected_path"]
#     config.patch_path = r["patched_path"]
#     config.output_path = r["test_dir"] + "/" + r["product"] + "_" + r["cve"] + ".so"
#     config.functionName = name[r["cve"]]
#     if config.functionName:
#         try:
#             patching = FunctionPatch(config)
#             patching.patch_functions()
# #             # Disable the alarm if patching is successful
#             success_logger.info(logging.INFO, "Patching completed successfully for binary_path: %s functionName: %s", config.binary_path, config.functionName)
#             signal.alarm(0)
#         except TimeoutException as te:
#             print(f"Operation for config {config} timed out")
#             error_logger.error("Timeout occurred for binary_path: %s functionName: %s", config.binary_path, config.functionName)
#             pass
#         except Exception as e:
#             print("Error occurred while patching:", e)
#             error_logger.error("An error occurred: %s binary_path: %s functionName: %s", e, config.binary_path,
#                           config.functionName)
#             pass
#         finally:
#             # Ensure the alarm is always disabled after each iteration
#             signal.alarm(0)
#
#
#
#
#
#
#     # config.functionName = "png_check_keywor
#
#
# # def run_patching(config_path):
# #     """ Function to execute patching with a given config """
# #     i = 1
# #     while i <=3:
# #         config = Config(config_path, str(i))
# #         print(config.binary_path)
# #         patching = Patching(config)
# #         patching.patch(config.binary_path)
# #         i = i + 1
# #
# # if __name__ == "__main__":
# #     num_processes = 3  # Adjust based on available CPU cores or required configs
# #     indices = range(num_processes)  # Create different configurations (e.g., 0, 1, 2, 3)
# #     config_path = ["unit-test-O1.properties", "unit-test-O2.properties", "unit-test-O3.properties"]
# #
# #
# #     with multiprocessing.Pool(processes=num_processes) as pool:
# #         pool.map(run_patching, config_path)  # Runs patching in parallel for each config
# #
#
# i = 2
# while i <= 2:
#     config = Config()
#     config.readMagmaConfig("firmware-test.properties", str(i))
# # #
# # #         # Set the alarm for 20 minutes (1200 seconds)
#     patching = FunctionPatch(config)
#     patching.patch_functions()
#     i = i + 1
# angr.Project("/Users/sebastian/Tools/firmware-collection/libz.so.1_modified", auto_load_libs=False)

config = Config()
config.binary_path = "/home/jaenich/CVE-bin-tool/karonte/NETGEAR/analyzed/R8000-V1.0.4.4_1.1.42/fw/_R8000-V1.0.4.4_1.1.42.chk.extracted/squashfs-root/lib/libz.so"
#config.binary_path = "/home/jaenich/CVE-bin-tool/karonte/NETGEAR/analyzed/R9000/firmware/squashfs-root/bin/busybox"
# config.output_path = "/home/jaenich/CVE-bin-tool/karonte/NETGEAR/analyzed/R6200v2-V1.0.3.12_10.1.11/fw/_R6200v2-V1.0.3.12_10.1.11.chk.extracted/squashfs-root/lib/libz.so.1_patched"
config.output_path = "/home/jaenich/CVE-bin-tool/libz.so_patched"
config.functionName = "inflate"
config.test_dir = "/home/jaenich/CVE-bin-tool/patched-lib-prepare/build/zlib/arm-linux-gnueabi-zlib-1.2.7-unique-BWhPorpX/zlib-1.2.7/libz.so.1.2.7"
config.patch_path = "/home/jaenich/CVE-bin-tool/patched-lib-prepare/build/zlib/arm-linux-gnueabi-zlib-1.2.9/zlib-1.2.9/libz.so.1.2.9"

p = angr.Project(config.binary_path, auto_load_libs=False)
cfg = p.analyses.CFGFast()

patch = angr.Project(config.test_dir, auto_load_libs=False)
cfg_patch = patch.analyses.CFGFast()

bindiff_results = p.analyses.BinDiff(patch, cfg_a=cfg, cfg_b=cfg_patch)


entry_point_patch = patch.loader.find_symbol(config.functionName).rebased_addr
print("ENTRY", entry_point_patch)

if entry_point_patch in bindiff_results.function_matches:
    print("nice")

for r in bindiff_results.function_matches:
    print(r)
    
#patching = FunctionPatch(config)
#patching.patch_functions()
# # # Setup logging to a filw
# # logging.basicConfig(filename="/tmp/p_errors.txt", level=logging.ERROR,
# #                     format='%(asctime)s - %(levelname)s - %(message)s', force=True)
#
# # Uncommented to enable logging
# # logging.getLogger('angr').setLevel('DEBUG')
# # logging.getLogger('angr.analyses').setLevel('DEBUG')
# #
# # register_pattern = re.compile(r'(?=(r\d+|sb|sl|ip|fp|sp|lr))')
# #         # Find all matches in the instruction string
# # matches = register_pattern.findall("ldr r1,r1")
# #         # Extract the first match (assuming there is at least one match)
# # register_name = matches[0]
# #
# #
# #
# # # loading the patch binary to perform backward slicing
# # project = angr.Project("Testsuite/MAGMA/libxml/fixed/libxml2.so.2.9.12", auto_load_libs=False)
# #s
# # # project = angr.Project("Testsuite/vuln_test_detoured", auto_load_libs= False)
# #
# # # Getting the target function
# # project1 = angr.Project("Testsuite/MAGMA/separate/PNG001/vuln_O3/libpng16.so.16.38.0", auto_load_libs=False)
# # file_to_be_patched = SectionExtender("Testsuite/MAGMA/separate/PNG001/vuln_O3/libpng16.so.16.38.0", 65536).add_section()
# # #
# # for i in range(3):
# #     block = project.factory.block(4364573)
# #     v = block.vex
# #     print("length",i, len(v.statements), block.addr)
#
# # cfg = project.analyses.CFGFast()
# # ddg = project.analyses.DDG(cfg=cfge, start=target_function.rebased_addr, call_depth =1 )
# #
# # target_function = project.loader.find_symbol("htmlParseName")
#
# # cfge= project.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,  state_add_options=angr.sim_options.refs, call_depth=2, starts=[target_function.rebased_addr])
#
#
#
#
# # refs = project.analyses.XRefs(func=target_function.rebased_addr)
# # print("Ref", len(refs.kb.xrefs.xrefs_by_ins_addr))
# # #
#
# # target_function = project.loader.find_symbol("htmlParseNameComplex")
# #
# # cfge= project.analyses.CFGEmulated(keep_state=True, context_sensitivity_level=0,  state_add_options=angr.sim_options.refs, call_depth=2, starts=[target_function.rebased_addr])
# # func = project.kb.functions[target_function.rebased_addr]
# #
# # ddg = project.analyses.DDG(cfg=cfge, start=target_function.rebased_addr, call_depth =2)
# #
# # view = ddg.view[target_function.rebased_addr]
#
# # refs2 = project.analyses.XRefs(func=target_function.rebased_addr)
# # print("Ref", len(refs2.kb.xrefs.xrefs_by_ins_addr), refs2.kb.xrefs.xrefs_by_ins_addr[4507083])
# # nodes= cfge.model.get_all_nodes(4364617)
# #
# #
# # node = cfge.model.get_any_node(4364617, anyaddr=True)
# # print("node", node.addr, node.irsb)
# # nodes = cfge.model.get_all_nodes(4364617, anyaddr=True)
# # for n in nodes:
# #     print("node", n.irsb)
# #
# # vex_block = ddg.project.factory.block(
# #                 node.addr, size=node.size, opt_level=ddg._cfg._iropt_level,
# #             ).vex
# # statements =vex_block.statements
# # print( "length",  cfge._iropt_level)
# # print(statements[3])/
#
# # 4364573, backup_state=None, byte_string=None, collect_data_refs=False, cross_insn_opt=False, extra_stop_points=None, initial_regs=None, insn_bytes=None
#                                 # , insn_text=None, load_from_ro_regions=False, max_size=400, num_inst=None, opt_level=1, size=50, strict_block_end=False, thumb=True)
#
# # for i in range(3):
# #     block = project.factory.block(4364573)
# #     v = block.vex
#     #
#     # vex = block._vex_engine.lift_vex(
#     #     arch = project.arch,
#     #     clemory=None,
#     #     state=None,
#     #     insn_bytes=block.bytes,
#     #     addr=block.addr,
#     #     thumb=True,
#     #     extra_stop_points=None,
#     #     opt_level=1,
#     #     num_inst=None,
#     #     traceflags=0,
#     #     strict_block_end=None,
#     #     collect_data_refs=True,
#     #     load_from_ro_regions=False,
#     #     cross_insn_opt=True,
#     # )
#     #
#
#     # print("length",i, len(vex.statements), block.addr)
# # print(statements[3])
# # backend = DetourBackend("Testsuite/MAGMA/separate/PNG001/vuln_O3/libpng16.so.16.38.0")
# #
# # # backend = ReassemblerBackend("Testsuite/MAGMA/separate/PNG001/vuln_O3/libpng16.so.16.38.0")
# #
# # patch = AddCodePatch("mov r0, #0x0", is_thumb=True)
# #
# # backend.apply_patches([patch])
#
#
# # backend.set_added_segment_headers()
# # backend.added_code_file_start = len(backend.ncontent)
# # backend.name_map["ADDED_CODE_START"] = (len(backend.ncontent) % 0x1000) + backend.added_code_segment
# # backend.ncontent += (b"\x00" * 0x100)
# # backend.added_code = b"\x00" * 0x100
# # backend.set_added_segment_headers()
# # backend.save("patcherex.elf")
#
# # file_to_be_patched = SectionExtender("/Users/sebastian/Public/Arm_65/libpng16.so.16.38.0_patched", 4096).add_new_segment()
# # project = angr.Project(file_to_be_patched, auto_load_libs=False)
# # #
# print("success")
# #
# #
# #
# #
# # #
# # backend = DetourBackend("Testsuite/libpng10.so.0.65.0")
# # patches = []
# # # patch = AddCodePatch("push {r12}", is_thumb=True)
#
# # code = backend.compile_asm("beq.w 0xd132", base=0x25fae, is_thumb=True)
# # print(code)
#
# # patch = InlinePatch(4231176, "mov ip, pc", is_thumb=True)
# # patches.append(patch)
# # patch = InlinePatch(4231178, "str ip, [sp, #-0x4]!", is_thumb=True)
# # patches.append(patch)
# # # base_address = 4495446 + 2
# # # target_address = 0x1000
# # # target_address_str = str(hex(target_address))
# # # patch = InlinePatch(base_address, "bl " + target_address_str, is_thumb=True)
# # patches.append(patch)
# # #
# # # patch   = InlinePatch(target_address, "mov lr, ip", is_thumb=True)
# # # patches.append(patch)
# # #
# # backend.apply_patches(patches)
# # #
# # backend.save("Testsuite/libpng_test_IP")
#
# # patches.append(patch)
# #
# # try:
# #     target_function = project.loader.find_symbol("png_check_keywords").rebased_addr
# # except Exception as e:
# #     logging.error("Error occurred while compiling the assembly code: %s", e)
# #
# # # patch = InlinePatch(0x40f9f0, "b _png_check_keyword", is_thumb=True)
# # # # patch = InlinePatch(0x415a36, "beq #0x166", is_thumb=True)
# # # patches.append(patch)
# # # backend.apply_patches(patches)
# #
# # backend.save("Testsuite/Modified/libpng10.so.0.65.0_TEST")
# # # test_project = angr.Project("/Users/sebastian/Public/Arm_66/libpng10.so.0.66.0_TEST", auto_load_libs=False)
# # cfg = project.analyses.CFGFast()
# # # Building the CFGEmulated for the target function in order to be able to build the DDG
# # cfg = project.analyses.CFGEmulated(keep_state=True,  state_add_options=angr.sim_options.refs, context_sensitivity_level=2, starts=[target_function.rebased_addr])
# #
# #
# # target_block = project.factory.block(0x404b27)
# #
# # print(target_block.disassembly)
# # # Getting the target block to be able to manually verify the backward slicing
# # # target_block = project.factory.block(addr=0x4049f5)
# # target_block.vex.pp()
# # print(target_block.arch)
# #
# # target_block = project.factory.block(target_function.rebased_addr)
# # #
# # string = target_block.disassembly.insns[0].mnemonic + " " + target_block.disassembly.insns[0].op_str
# # address = target_block.disassembly.insns[0].address-1
# # code = backend.compile_asm(string, base=target_block.disassembly.insns[0].address-1, is_thumb=True)
#
#
# # print("stop")
# # refs = project.analyses.XRefs(func=target_function.rebased_addr)
# # print(refs.kb.xrefs.xrefs_by_ins_addr)
# #
# # cfg.normalize()
# # # vfg = project.analyses.VSA_DDG(start_addr=target_function.rebased_addr)
# # # print(vfg.graph.size())
# # # for node in vfg.graph.nodes:
# # #     print("VSA", node, type(node))
# # #
# # # plot_cfg(cfg_fast, fname="test_vuln", asminst=True, remove_imports=True, remove_path_terminator=True)
# #
# # # print(cfg.graph.size())
# #
# #
# #
# # # Getting the DDG
# # ddg = project.analyses.DDG(cfg, start=target_function.rebased_addr)
# # #
# # # plot_ddg_data(ddg.data_sub_graph(), fname="png_check_keyword_ddg", asminst=False)
# #
# # # for node in ddg.data_graph.nodes:
# # #     if node.location.ins_addr == 0x4049fb:
# # #         print("found", node.variable, node.location)
# #
# # block = project.factory.block(addr=0x404b27)
# # print("block disassembly", block.disassembly)
# # block.vex.pp()
# # instruction = block.disassembly.insns[2]
# # # reg = instruction.operands[0].reg
# # # instruction1 = block.disassembly.insns[2]
# # # reg1 = instruction1.operands[0].reg
# #
# # register_pattern = re.compile(r'(r\d+|sb|sl)')
# # # Find all matches in the instruction string
# # matches = register_pattern.findall(instruction.op_str)
# #   # Extract the first match (assuming there is at least one match)
# # register_name = matches[0]
# # program_var = project.arch
# # reg = program_var.get_register_offset(register_name)
# #
# # # CodeLocations are part of the DDG
# # cl1 = CodeLocation(0x404b27, ins_addr=0x404b2b, stmt_idx=40)
# # instr_view = ddg.view[0x404b2b]
# # # Getting variables and their dependencies form the ddg nodes
# # definitions: list = instr_view.definitions
# # var = None
# # for definition in definitions:
# #     pv = definition._variable
# #     print(type(definition))
# #     print(definition._variable, definition.depends_on)
# # #  Now only take the register variables
# #     if isinstance(definition._variable.variable, SimRegisterVariable):
# #         if (definition._variable.variable.reg == reg):
# #             pv1 = pv
# #             var = definition._variable.variable
# #             loc = [definition._variable.location]
# #             print(var)
# #             print(loc)
# # #
# # # block = cfg.get_any_node(cl1.block_addr)
# #
# #
# #
# #
# #
# #
# #
# # # TODO: THIS IS HOW YOU GET THE CONNECTION BETWEEN A PROGRAMVARIABLE AND THE OFFSET OF A VEX REGISTER
# # for ins in block.disassembly.insns:
# #     offset = ins.operands[0].reg
# #     if pv1.variable.reg == offset:
# #         print("found", pv1)
# #
# # program_var = project.arch
# # offste = program_var.get_register_offset("sl")
# # reg = program_var.get_register_by_name("sl")
# # # Take all definitions of a variable that appear in the DDG
# # # found: list = ddg.find_definitions(var, simplified_graph=False)
# # # node = cfg.get_any_node(0x4049f5)
# # # print("cl1", cl1.block_addr, cl1.ins_addr, cl1.stmt_idx)
# # # if cl1 in ddg.graph.nodes:
# # #     print("YES!!!")
# # # for n in ddg.graph.nodes:
# # #     print(n.block_addr, n.ins_addr, n.stmt_idx)
# # #
# # # loc = [cl1]
# # # for founds in found:
# # #     loc.append(founds.location)
# # # Get the CDG of the target function
# # cdg = project.analyses.CDG(cfg, start=target_function.rebased_addr)
# #
# # # Getting the backward slice
# # # target_node = cfg.get_any_node(target_function.rebased_addr)
# # # second_node = cfg.get_any_node(0x4049f5)
# #
# #
# #
# # # acfg = bs.annotated_cfg()
# #
# # # bs = project.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=loc)
# #
# #
# # # print(bs.__sizeof__())
# # # print(bs.dbg_repr())
# # # print(bs.chosen_statements)
# # # Get the predecessors of the node that contains the definition of the variable
# # # for node in cdg.graph.nodes:
# #     # print(type(node))
# # #     if node.ins_addr == block.addr and node.stmt_idx == 18:
# # #         print("Target", node)
# # #         for pred in ddg.graph.predecessors(node):
# # #             print(pred)
# # #             for founds in found:
# # #                 if pred.ins_addr == founds.location.ins_addr and pred.stmt_idx == founds.location.stmt_idx:
# # #                     print("finally", founds.location)
# # #
# #
# #
# # # Build a sub data graph having as nodes only variables that depend on the variable of interest or the variable depends on them
# # # (Still unclear at time of writing)
# # # ddg_sub = ddg.data_sub_graph(pv, simplified=False)
# # # for node1 in ddg_sub.nodes:
# # #     print(node1)
# #
# # sources = ddg.find_sources(pv1, simplified_graph=False)
# # #
# # #
# # # print("input", var)
# # bs = VariableBackwardSlicing(cfg, cdg=cdg, ddg=ddg, variable=pv1.variable, project=project, targets=loc)
# # #
# # # for ins in bs.chosen_statements_addrs:
# # #     print(hex(ins))
# # # print(bs.dbg_repr())
# # #
# # # nodes = bs._cfg.get_all_nodes(addr=0x4049f5)
# # #
# # # plot_cfg(bs._cfg, fname="png_check_keyword_bs", asminst=True, remove_imports=True, remove_path_terminator=True)
# # #
# # # print("hello")
# #
# # for stat, ids in bs.chosen_statements.items():
# #     print("STATEMENT ", stat)
# #     # project.factory.block(stat).vex.pp()
# #     # for id in ids:
# #     #     print(id)
# #
# # constraints = ConstraintSolver(project,instruction.address - 1)
# # results = constraints.solve(bs.chosen_statements, 0x413694, 0x404b2a, pv1.variable)
# # solver = constraints.solver
# #
# # while solver.check() != z3.sat:
# #     solver.pop()
# #
# # model = solver.model()
# # s= model.sexpr()
# # t = model.decls()
# # f = solver.assertions()
# # print(solver)
# #
# #
# #
# #
# #
# # print(solver)
# # for result , _  in results:
# #     testst = str(result)
# #     number = re.search(r'\d+', testst).group()
# #
# # print(results)
