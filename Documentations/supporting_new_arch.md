# 1. Notes for supporting new architectures
In this section we will talk about how we partly supported the Cortex-A architecture. The user can use this documentation as a guidance if they want to support other architectures. 
## 1.1 Basic ISA support
To set up the correct ISA, several spots need to be modified.
### emulator/harness/fuzzware_harness/harness.py
**configure_unicorn()**
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
    else:
        snapshot.init_state_snapshotting(uc, args.dump_state_filename, args.dump_mmio_states, mmio_ranges, args.dumped_mmio_contexts, args.dumped_mmio_name_prefix)
    if args.dump_mmio_states:
        if args.bb_trace_file is None:
            args.bb_trace_file = "/dev/null"
```
The `snapshot` needs to be specified for each different architecture. The recorded snapshots are loaded into Angr and used for MMIO modeling.

### emulator/harness/fuzzware_harness/tracing/snapshot_extend.py
The `snapshot_extend.py` is copied and modified based on `emulator/harness/fuzzware_harness/tracing/snapshot.py`
**uc_reg_consts**
The user needs to make sure to specify the correct Unicorn variables for the registers of the new architecture.

**dump_state()** 
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

**mem_hook_dump_state_after_mmio_read()**
This function is a callback function triggered when an MMIO access happens. It checks whether a state dump has been performed for the current (pc, address) pair. The developer needs to specify the correct Unicorn PC variable for the new architecture.

**mem_hook_record_regs_before_mmio_read()**
This function collects the register information for the snapshot. The developer needs to specify the correct Unicorn PC variable for the new architecture.


### emulator/harness/fuzzware_harness/sparkle.py
The `sparkle.py` helps print out the value of Unicorn registers and memory content. The registers need to be modified according to the new architecture.

### emulator/harness/fuzzware_harness/native/native_hooks.c

## 1.2 Interrupts
### emulator/harness/fuzzware_harness/globs.py
This file specifies some parameters used for the interrupt configurations.