import angr
import argparse
import logging

from inspect_breakpoints_record import callback_after_mem_read, callback_exit, callback_after_mem_write, callback_after_reg_write

from record_plugin import setup_recorder, RecordPlugin

from arch_specific.arm_thumb_regs import STATE_SNAPSHOT_REG_LIST
l = logging.getLogger("DATAFLOW_DUMP")

import sys
import linecache

def trace_func(frame, event, arg):
    if event == "line":
        lineno = frame.f_lineno
        filename = frame.f_globals["__file__"]
        if not filename.endswith(".py"):
            return
        code = linecache.getline(filename, lineno).strip()
        print(f"Executing line {lineno}: {code}")
    return trace_func

# 设置跟踪函数
# sys.settrace(trace_func)

def read_stack_base(binary):
    with open(binary, 'rb') as f:
        sp_initial_bytes = f.read(4)
        sp_initial_value = int.from_bytes(sp_initial_bytes, byteorder='little')
    return sp_initial_value

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='dataflow_dump',
                    description='dump the dataflow information for later synthesis')
    parser.add_argument('-s', '--statefile')
    parser.add_argument('-b', '--binfile')
    # parser.add_argument('-o', '--output')
    args = parser.parse_args()
    project, initial_state = setup_recorder(args.statefile)
    # import ipdb; ipdb.set_trace()

    # setup breakpoint handlers
    def print_constraints(state):
        print("print_constraints", hex(state.addr), state.solver.constraints)

    initial_state.inspect.b('reg_write', when=angr.BP_AFTER, action=callback_after_reg_write)
    initial_state.inspect.b('mem_write', when=angr.BP_AFTER, action=callback_after_mem_write)
    initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=callback_after_mem_read)
    initial_state.inspect.b('exit', when=angr.BP_BEFORE, action=callback_exit)
    # initial_state.inspect.b('instruction', when=angr.BP_BEFORE, action=print_constraints)
    def concretize_hook(state):
        print("concretize_hook", "state.inspect.address_concretization_expr", state.inspect.address_concretization_expr)
        print("concretize_hook", "state.inspect.address_concretization_strategy", state.inspect.address_concretization_strategy)
        print("concretize_hook", "state.inspect.address_concretization_action", state.inspect.address_concretization_action)

    # initial_state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=concretize_hook)

    initial_state.register_plugin('record', RecordPlugin(stackframes=None, 
                                                         written_memories={}, 
                                                         named_mem_read=[], 
                                                         r0_write_instrs=[], 
                                                         stack_base=initial_state.solver.eval(initial_state.regs.sp), 
                                                         func_stack_base=read_stack_base(args.binfile)
                                                        ))

    # initial_state.options.add(angr.options.TRACK_MEMORY_ACTIONS)
    # 推迟对于constraint的求解, 避免在遇到branch时angr漏过某些分支
    # initial_state.options.add(angr.options.LAZY_SOLVES)

    simulation = project.factory.simgr(initial_state, resilience=False)
    
    # TODO: handle strex instruction 在model_arch_specific函数中

    # TODO: 添加合适的simulation technique以及timeout, 主要是为了防止陷入过度分析
    # simulation.use_technique(angr.exploration_techniques.DFS())
    l.warning("Starting simulation now...")

    simulation.run()

    # while simulation.active:
    #     print(simulation.active)
    #     # simulation.step(num_inst=1)  # 每次执行一条指令
    #     # print("XXXXXXXXXXXXXXXXXXXXXXXXXXX", simulation.active[0].history.actions)
    #     # for action in simulation.active[0].history.actions:
    #     #     print(action)
    #     simulation.step()  # 每次执行一条指令
    #     print_current_address(simulation)
    
    # for reg in STATE_SNAPSHOT_REG_LIST:
    #     try:
    #         reg_obj = getattr(initial_state.regs, reg)
    #         print(reg_obj, initial_state.solver.symbolic(reg_obj))
    #     except:
    #         continue
    
    # def print_all_bvs(state):
    #     bvs_set = set()
        
    #     # 遍历所有的约束并提取其中的符号变量
    #     for constraint in state.solver.constraints:
    #         bvs_set.update(constraint.variables)
        
    #     print("Current BVS variables:")
    #     for bvs in bvs_set:
    #         print(bvs)
    
    # print_all_bvs(initial_state)

    

    # import ipdb; ipdb.set_trace()
    # while len(simulation.active) > 0:
    #     # 打印当前活跃状态的地址
    #     for state in simulation.active:
    #         print(f"State at address: 0x{state.addr:x}")
        
    #     # 让每个活跃状态执行一步
    #     simulation.step(num_inst=1)

    # 检查是否有更多活跃状态
    if len(simulation.active) == 0:
        print("No more active states.")
    else:
        print(f"{len(simulation.active)} active states remaining.")