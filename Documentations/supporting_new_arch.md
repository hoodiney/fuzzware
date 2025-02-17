# 1. Notes for supporting new architectures
In this section we will talk about how we partly supported the Cortex-A architecture. The user can use this documentation as a guidance if they want to support other architectures. 
## 1.1 Basic ISA support
To set up the correct ISA, several spots need to be modified.
### emulator/harness/fuzzware_harness/harness.py
#### configure_unicorn()
```
arch = config.get("arch", "cortex-m") 
if arch == "cortex-m":
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
elif arch == "armv4t":
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM926)
elif arch == "cortex-a7":
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
```
The unicorn instance needs to be configured with the correct mode.

```
if not ('entry_point' in config and 'initial_sp' in config):
    # If we don't have explicit configs, try recovering from IVT
    if entry_image_base is None:
        logger.error("Binary entry point missing! Make sure 'entry_point is in your configuration")
        sys.exit(1)
    if arch == "cortex-m":
        config['initial_sp'] = bytes2int(uc.mem_read(entry_image_base, 4))
        config['entry_point'] = bytes2int(uc.mem_read(entry_image_base + 4, 4))
    elif arch == "armv4t":
        config['initial_sp'] = 0
        config['entry_point'] = entry_image_base
```
The initial stack pointer and binary entry point need to be specified correctly. For example, in Cortex-M, the two values are at the begining of the binary.

```
if args.dump_state_filename is not None:
    if arch == "armv4t":
            snapshot_extend.init_state_snapshotting(uc, args.dump_state_filename, args.dump_mmio_states, mmio_ranges, args.dumped_mmio_contexts, args.dumped_mmio_name_prefix)
    elif arch == "cortex-m":
        snapshot.init_state_snapshotting(uc, args.dump_state_filename, args.dump_mmio_states, mmio_ranges, args.dumped_mmio_contexts, args.dumped_mmio_name_prefix)
    else:
        print("Architecture is not currently supported for state snapshotting")
        exit(0)
    if args.dump_mmio_states:
        if args.bb_trace_file is None:
            args.bb_trace_file = "/dev/null"
```
The `snapshot` needs to be specified for each different architecture. The recorded snapshots are loaded into Angr and used for MMIO modeling.

### emulator/harness/fuzzware_harness/native/native_hooks.c
#### run_single()
```
int status;
uint64_t pc = 0;
int sig = -1;

uc_reg_read(uc, UC_ARM_REG_PC, &pc);

uint32_t cpsr_val; 
uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr_val);

if (cpsr_val & 0x20) {
    status = uc_emu_start(uc, pc | 1, 0, 0, 0);
}
else {
    status = uc_emu_start(uc, pc, 0, 0, 0);
}
...
```
We add the check for CPSR register value to determine if the current execution needs to be performed with the thumb bit set. 

#### emulate()
```
...
#if defined(ARMV4T)
if(uc_emu_start(uc, pc, 0, 0, 0)) {
    puts("[ERROR] Could not execute the first some steps");
    exit(-1);
}
#else
if(uc_emu_start(uc, pc | 1, 0, 0, 0)) {
    puts("[ERROR] Could not execute the first some steps");
    exit(-1);
}
#endif
...
#if defined(ARMV4T)
uc_err child_emu_status = uc_emu_start(uc, pc, 0, 0, 0);
#else 
uc_err child_emu_status = uc_emu_start(uc, pc | 1, 0, 0, 0);
#endif
...
```
Ensure the correct execution without thumb bit for Cortex-A. Here we use a macro `ARMV4T` to decide if we want to build the code for Cortex-M or the new architecture. Note that Cortex-M is the default case. The user can use the following command to rebuild the native code with specified architecture.

```
./rebuild_unicorn ARMV4T=1
```

### emulator/harness/fuzzware_harness/sparkle.py
The `sparkle.py` helps print out the value of Unicorn registers and memory content. The registers need to be modified according to the new architecture.

### emulator/harness/fuzzware_harness/tracing/snapshot_extend.py
The `snapshot_extend.py` is copied and modified based on `emulator/harness/fuzzware_harness/tracing/snapshot.py`

#### uc_reg_consts
The user needs to make sure to specify the correct Unicorn variables for the registers of the new architecture.

#### dump_state()
```
def dump_state(filename, regs, content_chunks):
    from intelhex import IntelHex
    ih = IntelHex()

    for base_addr, contents in content_chunks.items():
        ih.puts(base_addr, contents)

    with open(filename, "w") as f:

        f.write(
"""r0=0x{:x}
r1=0x{:x}
r2=0x{:x}
r3=0x{:x}
r4=0x{:x}
r5=0x{:x}
r6=0x{:x}
r7=0x{:x}
r8=0x{:x}
r9=0x{:x}
r10=0x{:x}
r11=0x{:x}
r12=0x{:x}
lr=0x{:x}
pc=0x{:x}
sp=0x{:x}
xpsr=0x{:x}
```
This function dumps the state into a snapshot file, which will later be used as input for Angr to reload the firmware state. The user needs to make sure to set up the correct register configuration.

#### mem_hook_dump_state_after_mmio_read()
This function is a callback function triggered when an MMIO access happens. It checks whether a state dump has been performed for the current (pc, address) pair. The developer needs to specify the correct Unicorn PC variable for the new architecture.

#### mem_hook_record_regs_before_mmio_read()
This function collects the register information for the snapshot. The developer needs to specify the correct Unicorn PC variable for the new architecture.

### modeling/fuzzware_modeling/base_state_snapshot_extend.py
The `base_state_snapshot` is needed for the modeling. It records the content of the registers and memory when a MMIO access happens. The snapshot will later be loaded by Angr and starts the model detection. We create this new file `base_state_snapshot_extend.py` specifically for Cortex-A support.

```
# check if it is thumb or arm mode
if (regs["cc_dep1"] & 0x20) != 0:
    entry_addr = regs[REG_NAME_PC] | 1
else:
    entry_addr = regs[REG_NAME_PC]

project = angr.Project(sio, arch="ARM", main_opts={'backend': 'hex', 'entry_point': entry_addr})
```
When loading the initial value of the pc register, we need to check if the firmware executes in thumb or arm mode. Besides, the backend architecture of the Angr project should use the corresponding parameter.

### modeling/fuzzware_modeling/liveness_plugin_extend.py
The `liveness_plugin` is for tracking the liveness of the interesting variables duing Angr's analysis. We create this new file `liveness_plugin_extend.py` so as to create a plugin that uses the new base snapshot `BaseStateSnapshotExtend`.

### modeling/fuzzware_modeling/analyze_mmio.py
```
if cfg is not None:
    if cfg['arch'] == 'armv4t':
        project, initial_state, base_snapshot = BaseStateSnapshotExtend.from_state_file(statefile, cfg)
    elif cfg['arch'] == 'cortex-m':        
        project, initial_state, base_snapshot = BaseStateSnapshot.from_state_file(statefile, cfg)
    else:
        print("Architecture not supported in analyze_mmio.py!")
        exit(0)
else:
    project, initial_state, base_snapshot = BaseStateSnapshotExtend.from_state_file(statefile, cfg)
```
During the MMIO modeling, Angr needs to load the correct base snapshot to start the analysis. The snapshot needs to be parsed from the recorded state files with correct architecture.

```
if cfg is not None:
    if cfg['arch'] == 'armv4t':
        initial_state.register_plugin('liveness', LivenessExtendPlugin(base_snapshot))
    elif cfg['arch'] == 'cortex-m':        
        initial_state.register_plugin('liveness', LivenessPlugin(base_snapshot))
    else:
        print("Architecture not supported in analyze_mmio.py!")
        exit(0)
else:
    initial_state.register_plugin('liveness', LivenessPlugin(base_snapshot))
```
The liveness plugin is architecture specific and needs to be configured correctly. 

### modeling/fuzzware_modeling/arch_specific/arm_regs.py
```
STATE_SNAPSHOT_REG_LIST = ['r0', 'r1', 'r2', 'r3', 'r4',
        'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'lr', 'pc',
        'sp', 'cpsr']
```
The snapshot needs to use the correct set of registers.

```
def translate_reg_name_to_vex_internal_name(name):
    name = name.lower()

    # Cortex-A Specific Changes
    if name == 'cpsr':
        name = 'cc_dep1'

    return name
```
In Angr's VEX IR, `cc_dep1` is a register that stores the values related to the Condition Codes (CC). It has a similar functionality to the `cpsr` register.

## 1.2 Interrupts
Note that Cortex-A is supposed to use GIC (Generic Interrupt Controller), which differs from Cortex-M's NVIC (Nested Vectored Interrupt Controller). Fuzzware's implementation of NVIC is documented in `interrupts.md`. GIC is a lot more complex than NVIC with its new features such as interrupt distribution and multi-core support. If the user wants to emulate a Cortex-A firmware that only involves basic interrupt support (priority configuration, nested interrupt handling, etc.), the user can implement the GIC based on Fuzzware's NVIC implementation. Otherwise, we would recommend using Qemu (or other more advanced emulator) instead of Unicorn as the base emulator, since it has a relatively more complete architecture functionality support. We skipped the interrupt handling support for the Tegra demo. 

# 2. Conditional compilation for the native code
For the python logic, we can make the architecture selection configurable through the `arch` field in the `config.yml`. As for the native code, we need to setup the conditional compilation for each architecture. When adding the architecture support in the `emulator/harness/fuzzware_harness/native` folder, we need to firstly mark each logic with corresponding conditional compilation flags. For example:
```
#if defined(ARMV4T)
if(uc_emu_start(uc, pc, 0, 0, 0)) {
    puts("[ERROR] Could not execute the first some steps");
    exit(-1);
}
#else
if(uc_emu_start(uc, pc | 1, 0, 0, 0)) {
    puts("[ERROR] Could not execute the first some steps");
    exit(-1);
}
#endif
```
By default, we assume the architecture is Cortex-M. Then, we need to add the configuration in `emulator/harness/fuzzware_harness/native/Makefile`. Lastly, we need to rebuild the emulator using `rebuild_unicorn.sh`. For example:

```
./rebuild_unicorn.sh ARMV4T=1
```