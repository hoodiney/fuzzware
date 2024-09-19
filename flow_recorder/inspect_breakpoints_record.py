import angr, claripy
import logging

l = logging.getLogger("INSPECT_BP_REC")
l.setLevel(logging.INFO)

'''
设想一个场景

已知一系列memory read/write, 

GOAL: 记录一系列memory write/return value, 并知道每个byte是怎么计算出来的

允许出现BVV的情况:
1. 通过local variable计算得到的


mem_read: 现在的处理是在after event触发callback函数, 将read得到的
TODO: mem_write: 暂且不管, 通过后续edge case调整
reg_read: 通过设置所有的初始register值为BVS来taint, 暂时不设置breakpoint
reg_write: 只追踪并dump向r0写入的值

edge case:
1. 当输入中存在一个值, 规定了函数逻辑中某个循环应该执行多少次, 仅仅从side effect的角度并不能知道
全部的逻辑, 某次执行可能向10个连续地址写入值, 某次可能向100个连续地址写入值.
2. 当写入的值是stack上计算出来的BVV, sythesized function能否区分这种情况 
3. 当fuzzware的input无法覆盖原函数中的某个branch, 通过angr能否得到该部分的逻辑
4. 重点在于当记录return value和memory access时要同时记录写入的条件(e.g. 比如当第2个input parameter
是5时才进行某个memory write)
5. 函数逻辑的进行需要interrupt来向某个memory写入内容.
'''
def callback_after_mem_read(state):
    l.info("callback_after_mem_read called")
    # 首先得到访问的地址和长度
    read_addr = state.solver.eval(state.inspect.mem_read_address)
    read_len = state.solver.eval(state.inspect.mem_read_length)

    state.record.on_after_mem_read(state, read_addr, read_len)

def callback_after_mem_write(state):
    l.info("callback_after_mem_write called")
    # 首先得到访问的地址和长度
    if state.inspect.mem_write_length is None:
        raise Exception("callback_after_mem_write, run into state.inspect.mem_write_length being None!")
    write_addr = state.solver.eval(state.inspect.mem_write_address)
    write_len = state.solver.eval(state.inspect.mem_write_length)
    
    state.record.on_after_mem_write(state, write_addr, write_len, state.inspect.mem_write_expr)

def callback_after_reg_write(state):
    l.info("callback_after_reg_write called")
    reg_offset = state.solver.eval(state.inspect.reg_write_offset)
    r0_offset = state.arch.registers['r0'][0]  # 获取 r0 寄存器的偏移量
    if reg_offset == r0_offset:
        # TODO: 暂时不考虑state.inspect.reg_write_length is None的情况, 因为现在不需要load
        # if state.inspect.reg_write_length is None:
        #     raise Exception("callback_after_reg_write, run into state.inspect.reg_write_length being None!")
        print("reg_write_condition", state.inspect.reg_write_condition)
        state.record.on_after_reg_write(state)

def contains_bvs(var):
    # 检查是否包含符号变量
    return any(isinstance(arg, claripy.ast.bv.BV) for arg in var.children_asts())

'''
当branch condition发生时会触发三次exit event (当angr可以通过constraint推断)
1. 离开当前block, Ijk_NoDecode, 不会添加新的约束
2. 进入满足条件的block, Ijk_Boring, 会添加新的约束
3. 进入不满足条件的block, Ijk_Boring, 不会添加新的约束
'''
def callback_exit(state):
    l.info(f"{state} AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcallback_exit called, at addr {state.addr:#x}")
    jumpkind = state.inspect.exit_jumpkind
    print("jumpkind", jumpkind, "exit_guard", state.inspect.exit_guard, "addr", hex(state.addr))
    print(state.solver.constraints)
    if jumpkind == 'Ijk_Boring' and state.inspect.exit_guard is not None and contains_bvs(state.inspect.exit_guard):
        state.record.on_exit_non_ret(state)
    elif jumpkind == 'Ijk_Ret':
        print(f"Function returned at address: {state.addr:#x}")
        state.record.on_func_return()
        # exit(0)   