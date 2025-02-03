# 1. Notes for supporting new architectures
In this section we will talk about the aspects worth noting when considering utilizing Fuzzware to emulate firmware on a new architecture. The notes recorded in this documentation may not be complete. 
## 1.1 ISA support
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

### emulator/harness/fuzzware_harness/sparkle.py
The `sparkle.py` helps print out the value of Unicorn registers and memory content. The registers need to be modified according to the new architecture.





## 1.2 ISA support -- Modeling

# 2. How we partly supported Cortex-A
