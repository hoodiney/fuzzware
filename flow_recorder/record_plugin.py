from io import BytesIO
import angr
import claripy
import copy
import logging
import re
from arch_specific import arm_thumb_quirks
from arch_specific.arm_thumb_regs import STATE_SNAPSHOT_REG_LIST, leave_reg_untainted, translate_reg_name_to_vex_internal_name, REG_NAME_PC, REG_NAME_SP 

l = logging.getLogger("RECORD_PLUGIN")
l.setLevel(logging.INFO)

reg_regex = re.compile(r"^[^=]{2,4}=0x([0-9a-f]+)$")

class RecordStackFrame:
    def __init__(self, base_sp=None, tracked_addrs=None):
        # We use a None base_sp as the catchall base_sp for the first frame as we do not know the real stack start
        self.base_sp = base_sp
        self.tracked_addrs = {} if tracked_addrs is None else tracked_addrs

    def holds_local_var(self, addr):
        return addr in self.tracked_addrs

    def add_local_var_addr(self, addr, size):
        self.tracked_addrs[addr] = size

    def remove_local_var_addr(self, addr):
        return self.tracked_addrs.pop(addr)

    def possibly_in_frame(self, addr):
        return self.base_sp is None or self.base_sp >= addr

    def copy(self):
        return RecordStackFrame(self.base_sp, copy.deepcopy(self.tracked_addrs))

'''
This function is for setting up the data-flow recorder using angr.
The recording feature is implemented via angr's bp handlers
'''
def setup_recorder(statefile):
    with open(statefile, "r") as state_file:
        regs = {}

        for name in STATE_SNAPSHOT_REG_LIST:
            line = state_file.readline()
            l.debug("Looking at line: '{}'".format(line.rstrip()))
            val = int(reg_regex.match(line).group(1), 16)
            # l.info("Restoring reg val: 0x{:x}".format(val))
            # DUO: input: name, output: vex_name for registers
            name = translate_reg_name_to_vex_internal_name(name)
            # 在regs中xpsr叫'cc_dep1'
            regs[name] = val

        line = ""
        while line == "":
            line = state_file.readline()
        # DUO: convert the memory data in the state file into angr recognizable io bytes
        sio = BytesIO(line.encode()+state_file.read().encode())

    project = angr.Project(sio, arch="ARMCortexM", main_opts={'backend': 'hex', 'entry_point': regs[REG_NAME_PC]|1})
    
    # We need the following option in order for CBZ to not screw us over
    # DUO: "default_strict_block_end" makes the symbex engine stops at every BB, 提高execution的determinism
    project.factory.default_engine.default_strict_block_end = True
    initial_state = project.factory.blank_state(addr=regs[REG_NAME_PC]|1)

    # DUO: restore condition flags and stuff
    # NOTE: 我们不用处理cc_op和itstate, 因为是函数初始状态
    # arm_thumb_quirks.add_special_initstate_reg_vals(initial_state, regs)

    # DUO: 在这里不需要将stack换成BVS，但需要将registers(pc除外)替换为BVS以便追踪
    for name, val in regs.items():
        if name == REG_NAME_PC:
            continue
        # 对剩下的register保留constraint
        else:
            init_val = claripy.BVV(val, 32)
            # DUO: 对于register的value，只taint初始值，因为后面register的读写都只是参与运算
            ast = claripy.BVS(f"{name}_func_entry_val", 32)
            constraint = ast == init_val
            # TODO: 非常神奇, 添加约束之后在面对分支判定时会默认选择一个初始值 
            initial_state.add_constraints(constraint)
            if leave_reg_untainted(name):
                ast = claripy.BVV(val, 32)

        setattr(initial_state.regs, name, ast)
        l.info(f"register {name} has initial value {val:#x}, represented as {ast}")

    return project, initial_state

# NOTE: Now we don't care about cases where another function is called
# TODO: 获取stack上的input parameter并命名BVS
'''
该plugin用于获取后续synthesizer所需的信息: 
1. 向哪些memory写入了什么
2. return value是什么

在写入的值中, 需要溯源的有:
1. input parameter
2. 从非stack memory读取的值

TODO: 现在只关心input parameter的溯源

TODO: 尝试是否能够保留memory access的地址和长度是从哪里计算得到的. 
构建一个场景, 在该场景下从某个memory读取了一个值, 并将其作为下一个memory访问的地址. 

NOTE: 目前我能想到的溯源的方式就是利用BVS的命名, 当有memory access时, 将读取到的内容记录为一个BVS, 
但目前来看行不通, 可能需要非angr的机制来记录. 

NOTE: 考虑到cortex-m是单线程执行, 可以记录memory read/write lits来作为side information

TODO: 尝试利用angr的address_concretization event 
state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=on_address_concretization)

溯源的原因:
如果不溯源的话, 在最终的写入/返回的值中只会看到一个BVV的值, 而不知道该值是从何处读取的, 不利于函数的泛化.
当在synthesized的函数中构建待写入的值时, 最好能够重新从memory/register中获取, 而不是直接写入一个值.
'''
class RecordPlugin(angr.SimStatePlugin):
    # 用于check当前访问的memory地址是否是stack上的
    stackframes: list
    # 还需要记录写入了哪些non-stack memory, 需要细化到bytes
    written_memories: dict
    # 记录已经命名的memory read防止重名
    named_mem_read: list
    # 记录修改r0的指令有哪些, 判断是否有返回值
    r0_write_instrs: list
    # stack从什么地址开始的
    stack_base: int
    # 进入函数时stack的值, 此时应该还没有分配栈空间
    func_stack_base: int
    # 存放对于外部memory读写的trace
    mem_op_traces: list
    # 存放当前的控制constraint
    control_constraints: list

    def __init__(self, stackframes=None, written_memories={}, named_mem_read=[], r0_write_instrs=[], stack_base=None, func_stack_base=None, mem_op_traces=[]):
        super(RecordPlugin, self).__init__()
    
        if stackframes is None:
            # Create initial stackframe
            self.stackframes = [RecordStackFrame()]
        else:
            self.stackframes = stackframes

        self.written_memories = written_memories
        self.named_mem_read = named_mem_read
        self.r0_write_instrs = r0_write_instrs
        # 下面两个值用来判定memory access是否在访问stack上的参数
        self.stack_base = stack_base
        self.func_stack_base = func_stack_base
        self.mem_op_traces = mem_op_traces
        l.info(f"stack_base: {stack_base:#x}, func_stack_base: {func_stack_base:#x}")

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        l.warning("RecordPlugin is copied")
        return RecordPlugin(stackframes=None, 
                            written_memories=copy.deepcopy(self.written_memories), 
                            named_mem_read=copy.deepcopy(self.named_mem_read), 
                            r0_write_instrs=copy.deepcopy(self.r0_write_instrs), 
                            stack_base=self.stack_base, func_stack_base=self.func_stack_base,
                            mem_op_traces=self.mem_op_traces)


    # DUO: 跟踪mem_write event, 传入参数
    # DUO: 需要记录该行为，只保留最终写入的value
    '''
    state: the angr state
    memory_addr: state.inspect.mem_write_address
    written_value: state.inspect.mem_write_expr
    written_length: state.inspect.mem_write_length

    假定传入的memory_addr已经被eval过了
    NOTE: 暂时假定angr不会回收没有引用的BVS, 这涉及到当某个byte的BVS被覆盖, 但其参与了其他BVS的constraint的情况,
    如果该BVS会被gc, 则需要我们自行记录. 
    NOTE: 不需要考虑读写地址跨过两个BVS的情况(e.g. bvs_0在0x40000000 (4 bytes), bvs_1在0x40000004 (4 bytes), 
    某次从0x40000002读取4个bytes到bvs_2中, 前后两个bytes会自动分别按照bvs_0和bvs_1的constraints eval)
    '''
    def on_before_mem_write(self, state, memory_addr, written_value, written_length):
        pass            

    # DUO: 跟踪mem_read event, 此时已在inspect bp中判定是访问non-stack memory
    # 输入的read_addr以及read_len都是已经经过state.solver.eval的值
    '''
    NOTE: 只需要负责将读取得到的值赋给新的BVS变量即可, angr会处理各个bytes对应的constraint的继承问题.
    对于memory read, 需要为每次读取起一个BVS的名字, 以便后续溯源. 具体做法是,首先检查是否是BVS, 如果是则不用管.
    '''
    def on_after_mem_read(self, state, read_addr, read_len):
        l.info("on_after_mem_read triggered")
        # 检查是否在访问当前stack
        if read_addr <= self.func_stack_base and read_addr >= state.solver.eval(state.regs.sp):
            return
        else:
            bvs_name = f"read_{read_addr:#x}_{read_len}"
            # 首先检查当前是否有同名的
            i = 0
            while bvs_name + f"_{i}" in self.named_mem_read:
                i += 1
            bvs_name = bvs_name + f"_{i}"
            new_bvs = claripy.BVS(bvs_name, read_len * 8)

            state.solver.add(new_bvs == state.inspect.mem_read_expr)
            state.inspect.mem_read_expr = new_bvs
            self.named_mem_read.append(bvs_name)

    # 输入的write_addr以及write_len都是已经经过state.solver.eval的值
    # TODO: 如果write_addr无法得到一个确切的值该怎么办
    def on_after_mem_write(self, state, write_addr, write_len, write_value):
        l.info("on_after_mem_write triggered")
        # 直接按slice存储byte, 其会保存被slice的BVS的constraint

        # 检查是否在访问当前stack
        if write_addr <= self.func_stack_base and write_addr >= state.solver.eval(state.regs.sp):
            return
        else:
            self.mem_op_traces.append(f"{write_addr}, {write_len}, {write_value}, {state.solver.constraints[16:]}")
            print(f"XXXXXXXXXXXXXXXXXXXXXXXXXxx new trace added {self.mem_op_traces}", state.solver.constraints)
            for offset in range(write_len):
                # 记录哪些地址被write了, 后续直接load值看constraint即可.
                self.written_memories[write_addr + offset] = True

    def on_after_reg_write(self, state):
        l.info("on_after_reg_write triggered")
        # 利用指令的地址判断当前是什么指令在修改r0
        # block = state.block(state.addr)
        # disassembly = block.capstone.insns
        # for insn in disassembly:
        print(f"R0 changed, Instruction at {state.addr:#x}")
        self.r0_write_instrs.append((hex(state.addr), state.regs.r0))
    
    def on_exit_non_ret(self, state):
        pass

    def on_func_return(self):
        l.warning(f"on_func_return, returning address {hex(self.state.addr)}")
        print(self.r0_write_instrs)
        for c in self.state.solver.constraints:
            print(c)