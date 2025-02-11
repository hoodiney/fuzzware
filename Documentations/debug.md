# How to debug when using Fuzzware
When using Fuzzware for emulation and fuzzing, it would be of great help to inspect the details of emulation and testing. This can help the user to debug and improve the testing efficiency. In this section, we will introduce several ways to debug when using Fuzzware for binary emulation and testing.

# Unicorn hooks
Unicorn offers the `hook` feature, where the hooks are a bunch of callback functions. For example, hooks for `UC_HOOK_CODE` will be triggered at each instruction execution. We can print out the executed addresses and the status of registers to inspect the details of emulation. The following code snippet is an example of implementing and registering such a hook function. 

```
def hook_code(uc, address, size, user_data):
    xpsr = uc.reg_read(UC_ARM_REG_XPSR)
    cpsr = uc.reg_read(UC_ARM_REG_CPSR)
    print(f"Executing at 0x{address:X} instruction size: {size}, cpsr: 0x{cpsr:X}, xpsr: 0x{xpsr:X}")

uc.hook_add(UC_HOOK_CODE, hook_code)
```

With the `uc` instance passed to the hook functions, we can inspect the memory and register content, control the execution and so on. Besides `UC_HOOK_CODE`, Unicorn also offers other hook types. For example, we can use `UC_HOOK_BLOCK` for more coarse grained execution inspection (hook is only triggered for each basic block). More hook types are available in Unicorn's documentation and source code.

Moreover, inside the hook functions, we can use `ipdb` to inspect the Unicorn execution. The following code is an example that sets ipdb traces whenever encountering the three addresses: `Addr_A`, `Addr_B`, and `Addr_C`:

```
def hook_code(uc, address, size, user_data):
    if address in [Addr_A, Addr_B, Addr_C]:
        import ipdb; ipdb.set_trace()
```

# GDBServer
It would be nice to dynamically analyze the execution during firmware emulation. Fuzzware partly support the functionality of a GDBServer. Here we detail its implementation and introduce how to use it. Note that this feature is not fully supported, the more stable approach is through the Unicorn hooks. We manage to fix its support for continuing, stepping, and adding/deleting breakpoints. The GDBServer can be connected both with command line and IDA Pro.

In `emulator/harness/fuzzware_harness/gdbserver.py`, Fuzzware tries to implement a GDBServer that follows the **GDB Remote Serial Protocol**. The core of this GDBServer implementation is the breakpoint handling logic. Through the `breakpoint_handler` function, Fuzzware checks for every instruction execution if the current address is one of the breakpoints. If a breakpoint is hit, Fuzzware pauses the emulation process using a python synchronization variable `running` (as shown in the following code).

```
class GDBServer(Thread):

    def __init__(self, uc, port=3333):
        super().__init__()
        ...
        self.running = Event() # The synchronization variable 
```

An example script of using the GDBServer for debugging is shown below.

```
fuzzware emu -c /home/user/fuzzware_repo/tegra/tegra_crash_input_example/config.yml -g 1234 -b 0x001147A4 -v --prefix-input /home/user/fuzzware_repo/tegra/tegra_crash_input_example/prefix_input /home/user/fuzzware_repo/tegra/tegra_crash_input_example/crash_input
```

Using another terminal for the same docker container, the user can use `gdb-multiarch` to attach to the server and send the commands using the command line tool.

```
gdb-multiarch --ex "target remote :1234"; pkill -9 fuzzware; stty sane
```

Besides, we can also connect IDA Pro to this server. The user needs to configure in IDA Pro's `Debugger -> Process options`
# Others
## MMIO modeling errors
During fuzzing, sometimes there can be errors during MMIO modeling. Through the log files in `.../fuzzware-project/logs/worker_modeling.log` you can check if there is anything wrong with the modeling process. 
