# 1. Fuzzware Handler
Fuzzware allows users to utilize the handler feature to improve emulation usability and testing efficiency. There are mainly two ways of utilization:
1. Skipping certain functions/basic blocks.
2. Replacing certain function logics

In this section, we'll introduce how the handler mechanism is implemented, and illustrate examples of how to utilize it.

# 2. Implementation
## 2.1 Related variables, functions and files
```
func_hooks -- emulator/harness/fuzzware_harness/user_hooks/__init__.py
configure_unicorn() -- emulator/harness/fuzzware_harness/harness.py
add_func_hook() -- emulator/harness/fuzzware_harness/user_hooks/__init__.py
func_hook_handler() -- emulator/harness/fuzzware_harness/user_hooks/__init__.py
register_cond_py_handler_hook() -- emulator/harness/fuzzware_harness/native.py
register_cond_py_handler_hook() -- emulator/harness/fuzzware_harness/native/native_hooks.c
```

## 2.2 Handler registration
Inside `configure_unicorn`, this function parses the config.yml file for the handler setup.
```
    if 'handlers' in config and config['handlers']:
        for fname, handler_desc in config['handlers'].items():
            if handler_desc is None:
                handler_desc = {}
            elif isinstance(handler_desc, str):
                handler_desc = {'handler': handler_desc}
            if 'addr' in handler_desc:
                addr_val = handler_desc['addr']
                # This handler is always at a fixed address
                if isinstance(addr_val, int):
                    addr_val &= 0xFFFFFFFE # Clear thumb bit
                    uc.syms_by_addr[addr_val] = fname
            else:
                addr_val = fname
            # look in the symbol table, if required
            addr = parse_address_value(uc.symbols, addr_val, enforce=False)

            if addr is None:
                if not uc.symbols:
                    logger.error("Need symbol table in order to hook named functions!")
                    sys.exit(1)
                if fname not in uc.symbols:
                    # We can't hook this
                    logger.info(f"No symbol found for {str(fname)}")
                    continue

            if not 'do_return' in handler_desc:
                handler_desc['do_return'] = True

            if 'handler' not in handler_desc:
                handler_desc['handler'] = None

            # Actually hook the thing
            logger.info(f"Handling function {str(fname)} at {addr:#10x} with {str(handler_desc['handler'])}")
            add_func_hook(uc, addr, handler_desc['handler'], do_return=handler_desc['do_return'])
```
Here `handler_desc` is used for storing information of the registered handlers (python method path, do_return, etc.) the function `add_func_hook` is called to register the handlers.

```
def add_func_hook(uc, addr, func, do_return=True):
    """
    Add a function hook.

    If func is None (and do_return is True) this is effectively a nop-out without using a real hook!
    Makes it faster to not have to call into python for hooks we don't need.
    """

    real_addr = addr & 0xFFFFFFFE  # Drop the thumb bit
    if func:
        if isinstance(func, str):
            try:
                # Resolve the function name
                mod_name, func_name = func.rsplit('.', 1)
                if mod_name == "native":
                    patch_native_handler(uc, addr, func_name)
                    return

                mod = importlib.import_module(mod_name)
                func_obj = getattr(mod, func_name)
            except (ModuleNotFoundError, AttributeError):
                import traceback
                logger.error("Unable to hook function %s at address %#08x" % (repr(func), addr))
                traceback.print_exc()
                do_exit(uc, 1)
                sys.exit(1)
        else:
            func_obj = func

        if real_addr not in func_hooks:
            func_hooks[real_addr] = []
        func_hooks[real_addr].append(func_obj)

    if do_return:
        uc.mem_write(real_addr, THUMB_RET)
```
The `patch_native_handler` rewrites the function in the binary. If you want to utilize this feature on an architecture different from Cortex-M, you will need to provide a different function to patch the binary. If your function doesn't require binary rewriting, the module will be imported and the handler functions will be stored in `func_hooks`, mapped with the functions' addresses. The function returning instructions (e.g. "bx lr") is written to the original function address to return to the calling spot.

## 2.3 Handler calling
In function `register_cond_py_handler_hook`, `func_hook_handler` is set as a callback function which is triggered for every basic block.
```
def register_cond_py_handler_hook(uc, handler_locs):
    if not handler_locs:
        logger.warning("no function handler hooks registered, skipping registration")
        return

    arr = (ctypes.c_int64 * len(handler_locs))(*handler_locs)

    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    from .user_hooks import func_hook_handler
    callback = func_hook_handler
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_CODE_CB(uc._hookcode_cb), UC_HOOK_CODE_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)

    assert native_lib.register_cond_py_handler_hook(
        uc._uch, cb, arr, len(arr), user_data
    ) == 0
    obj_refs.append(cb)
```
`func_hook_handler` checks at each basic block if the current address belongs to one of the functions registered in `func_hooks`.

```
def func_hook_handler(uc, addr, size, user_data):
    if addr in func_hooks:
        for hook in func_hooks[addr]:
            logger.debug(f"Calling hook {hook.__name__} at {addr:#08x}")
            try:
                hook(uc)
            except:
                import traceback
                traceback.print_exc()
                do_exit(uc, 1)
```

# 3. Examples
In the tegra demo, we implemented several handlers to support our emulation. Directly providing the address means we want to skip the whole function.
```
delay_us:
    addr: 0x100e50
usb_flush_ep:
    addr: 0x1071b8
meminit_memunpack:
    addr: 0x101070
debug_output:
    addr: 0x1022ea
```

If you want to replace the original function logic with your own handler, you need to also provide the python method path.

```
j_memcpy_libc:
    addr: 0x104356
    handler: fuzzware_harness.user_hooks.tegra.tegra_handlers.j_memcpy_libc
```
The example handler for this memcpy function is as follows. It reads the input arguments following the ARM convention and then copies the required data using `uc.mem_read` and `uc.mem_write`.  
```
def j_memcpy_libc(uc):
    dst = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    num = uc.reg_read(UC_ARM_REG_R2)

    print(f"read from {src:#x} to {dst:#x}, {num:#x} bytes, till {dst+num:#x}")
    print(hex(uc.reg_read(UC_ARM_REG_SP)), )
    data = uc.mem_read(src, num)
    uc.mem_write(dst, bytes(data))
```