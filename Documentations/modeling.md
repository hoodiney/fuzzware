# 1. Fuzzware modeling
Fuzzware utilizes MMIO modeling to either model the peripheral behaviors (Constant Model and Set Model), or improve fuzzing efficiency (Passthrough Model and Bitextract Model). The MMIO behaviors that could not be classified into these four models is considered as Identity Model. In this documentation, we will detail how the MMIO modeling mechanism is implemented in Fuzzware.

# 2. Implementation
## 2.1 MMIO access states
Before every new MMIO access, Fuzzware will take a snapshot state of the current execution state. A state may look like the content below. The state records the register values and the memory content when the MMIO access happens. Angr will load this state and start symbolic execution from it. 

```
r0=0x40003970
r1=0x0
r2=0x7d000140
r3=0x115140
r4=0x1869e
r5=0x400
r6=0x40002b38
r7=0x1
r8=0x0
r9=0x0
r10=0x115be4
r11=0x0
r12=0x0
lr=0x106bb1
pc=0x106bc8
sp=0x4000ff68
cpsr=0x1f3
:020000040010EA
:100000000E0000EA150000EA140000EA130000EAFE
:10001000120000EA110000EA100000EA0F0000EAF6
:1000200000000000000000000000000000000000D0
```

In a fuzzing campaign, a state file (under the folder `fuzzware-project/mmio_states`) may have the name `main001_fuzzer1_mmio_access_state_pc_001000bc_addr_60006050_id:000061,src:000000,op:havoc,rep:16`, where `pc_001000bc_addr_60006050` marks the MMIO access context (at pc 0x1000bc and access address 0x60006050) and `id:000061,src:000000,op:havoc,rep:16` marks the name of input that triggers this MMIO access. 

## 2.2 MMIO analysis
Overall, Fuzzware's modeling implementation follows the rules specified in `modeling/fuzzware_modeling/analyze_mmio.py`.

```
1. Run until no active anymore
- Finished stepping:
    - all variables dead
        - no path constraint -> found
        - path constraint -> vars_dead_but_path_constrained
    - return from function -> returns val ? returning_val : found
- Unfinished stepping:
    - limits:
        - too deep calls
        - too many loop iterations
        - too many steps
        - too many concurrent states
        - too many (tracked) variables dead
        - too much time spent (timeout)
    - analysis scope escapes:
        - write to non-local memory -> globals['dead_write_to_env']

2. Check different stashes upon hitting limits
    - Ignored
        - loops: assume that there is no functionality 'hiding' in later loop iterations
            - in edge cases this could happen such as: for(i=0;i<1000;++i){if(i = 750) do_stuff;}
        - too_many_out_of_scope: assume that last variable will similarly be killed and replaced by new one
    - Fall back to pre-fork state for too complex processing
        - deep_calls: stopped due to path explosion
        - active: still active when limit was reached
        - deferred: still active in DFS
    - If regular case, collect states for modelling
        - returning_val: function returned value
        - found: all vars dead and nothing to step
        - vars_dead_but_path_constrained: also vars dead
```

In this part, we mainly introduce some of the implementation details that are related to Angr usage. We will skip the parts that are straightforward or well-documented. 
### modeling/fuzzware_modeling/analyze_mmio.py
**setup_analysis()**
```
initial_state.inspect.b('reg_write', when=angr.BP_BEFORE, action=inspect_bp_trace_liveness_reg)
```
This is for registering an Angr breakpoint, it means that whenever a `reg_write` event occurs, the callback function `inspect_bp_trace_liveness_reg` will be triggered before the event takes effect (i.e., `BP_BEFORE`).

```
initial_state.options.add(angr.options.TRACK_MEMORY_ACTIONS)
```
This option will make Angr record its memory actions (read and writes) for later inspection. 

```
initial_state.register_plugin('liveness', LivenessPlugin(base_snapshot))
```
The `liveness` plugin is for helping Angr to track the liveness of the variables. We will go into more details in file `modeling/fuzzware_modeling/liveness_plugin.py`

### modeling/fuzzware_modeling/arch_specific/arm_thumb_quirks.py
**model_arch_specific()**
This function takes the first instruction of the initial state and checks if it is a `strex` instruction.

### modeling/fuzzware_modeling/base_state_snapshot.py
**from_state_file()**
This function loads the content of the state file to prepare for Angr's analysis. 
```
# apply registers to state
initial_sp = None
for name, val in regs.items():
    if name == REG_NAME_PC:
        base_snapshot.initial_pc = val
        val |= 1
        continue

    if leave_reg_untainted(name):
        ast = claripy.BVV(val, 32)
    else:
        # For initial registers, we taint them by applying an AST with a fixed value via constraints
        ast, ast_unconstrained = claripy.BVS(f"initstate_{name}", 32), claripy.BVS("{name}_unconstrained", 32)
        bitvecval = claripy.BVV(val, 32)
        constraint = ast == bitvecval

        initial_state.add_constraints(constraint)
        base_snapshot.regvars_by_name['{}'.format(name)] = ast
        base_snapshot.init_reg_bitvecs.append(ast)
        base_snapshot.init_reg_bitvecvals.append(bitvecval)
        base_snapshot.init_reg_bitvecs_unconstrained.append(ast_unconstrained)
        base_snapshot.init_reg_constraints.append(constraint)

        if name == REG_NAME_SP:
            initial_sp = val

    setattr(initial_state.regs, name, ast)
```
`leave_reg_untainted` specifies the Angr registers that we will skip for the taint analysis. In this case the registers are `itstate` and `cc_op`. The rest registers are tainted for further analysis.

## 2.3 Model application
The logic of the models are implemented as callback handlers in `emulator/harness/fuzzware_harness/native/native_hooks.c`. In **hook_mmio_access**, the **get_fuzz** function takes a fuzzing chunk and utilizes the generated model to translate it into the fake peripheral access value. The `ignored_addresses` marks the addresses related to Passthrough Models. Accesses to such addresses will be ignored. `mmio_callbacks` records the different model handlers. If there is no model for the current access, the fuzzing chunk is directly consumed (i.e. Identity Model).
```
void hook_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data)
{
    uint32_t pc = 0;
    latest_mmio_fuzz_access_index = fuzz_cursor;

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    // TODO: optimize this lookup
    for (int i = 0; i < num_ignored_addresses; ++i)
    {
        if(addr == ignored_addresses[i] && (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES || ignored_address_pcs[i] == pc)) {
            #ifdef DEBUG
            printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr, pc); fflush(stdout);
            #endif
            goto out;
        }
    }

    for (int i = 0; i < num_mmio_callbacks; ++i)
    {
        if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
                (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES || mmio_callbacks[i]->pc == pc))
        {
            if(mmio_callbacks[i]->user_data != NULL) {
                user_data = mmio_callbacks[i]->user_data;
            }

            mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
            goto out;
        }
    }

    #ifdef DEBUG
    printf("Serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x, rem bytes: %ld\n", size, addr, pc, fuzz_size-fuzz_cursor); fflush(stdout);
    #endif

    uint64_t val = 0;
    if(get_fuzz(uc, (uint8_t *)&val, size)) {
        return;
    }
    #ifdef DEBUG
    printf(", value: 0x%lx\n", val); fflush(stdout);
    #endif
    uc_mem_write(uc, addr, (uint8_t *)&val, size);


    out:

    latest_mmio_fuzz_access_size = fuzz_cursor - latest_mmio_fuzz_access_index;
    return;
}
```

For example, the bitextract model handler will take a fuzzing chunk and apply the left shift on it to get the fuzz input for the corresponding MMIO access.

```
void bitextract_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data)
{
    struct bitextract_mmio_model_config *config = (struct bitextract_mmio_model_config *) user_data;
    uint64_t result_val = 0;
    uint64_t fuzzer_val = 0;

    // TODO: this currently assumes little endianness on both sides to be correct
    if(get_fuzz(uc, (uint8_t *)(&fuzzer_val), config->byte_size)) {
        return;
    }

    result_val = fuzzer_val << config->left_shift;
    uc_mem_write(uc, addr, &result_val, size);

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] from %d byte input: %lx\n", pc, addr, result_val, config->byte_size, fuzzer_val); fflush(stdout);
    #endif
}
```
