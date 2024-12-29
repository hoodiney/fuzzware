# Intro
Here is a documentation explaining how to set up **Fuzzware** to trigger the Fusée Gelée vulnerability in the BootROM of the Nvidia Tegra X1 chip. 

The vulnerability has been well-explained in other resources. In the following section we'll directly introduce each configuration needed to guide the fuzzer to focus on exploiting this specific vulnerability.

This demo aims to serve as an example of utilizing **Fuzzware** for specific testing tasks. In the last section, we'll summarize a general guideline to tackle specific technique issues for guiding fuzzer towards your testing targets. 

**usbd::handle_ep0_control_transfer** 

# Setup
In this section, we refer to the functions using names from `TegraX1-q3k.idc`. Setting up the correct architecture support is not included in this documentation, please refer to `../Documentations/supporting_new_arch.md` for detailed explainations.

The vulnerability is in the function `usbd::handle_ep0_control_transfer`. One possible way to trigger it is through the following execution path.

```
reset
|
normal_boot
|
main
|
try_load_from_rcm
|
usbd::ep0_stuff
|
usbd::handle_ep0_control_transfer
```

We can utilize several features of Fuzzware to guide it towards the function of our interest. The general configuration (architecture and memory layout) is skipped.
## Setup 1: Fuzzing Guidance
In the `config.yml` file, we can make use of the `boot` section. It informs Fuzzware how to boot up to the code of our interest. Here we configure that the binary is considered "booted" after entering `try_load_from_rcm`. The booting input will be used as `prefix_input` in the following fuzzing campaigns.

```
boot:
  # A list of addresses required for a successful boot
  required:
    # An address (or symbol) in this list may indicate the if/else branch of a positive check
    - 0x00101134
    - 0x0010142A
    - 0x00102896
  # A list of addresses which indicate a failed boot
  avoid:
    # if/else branch of a failed check
    - 0x00101474
    # prepare_nvtboot_launch
    - 0x00101328
  # Address at which the firmware is considered booted (successfully or unsuccessfully based on the previous config attributes)
  target: 0x00102896
```

Besides, we can also configure an `exit_at` section. It informs Fuzzware at which basic block to stop emulation. As we are not interested in the execution after function `try_load_from_rcm` returns, we mark the basic block address of `try_load_from_rcm`'s returning logic as the `exit_at` address.

```
exit_at:
    try_load_from_rcm_return: 0x102522
```
## Setup 2: Handlers
Fuzzware allows us to replace certain functions to our own handlers. We can utilize it to bypass un-related functions or replace complex functions with our handlers that have the same effects, easing the analyzing process.

```
handlers:
  sub_102CEE:
    addr: 0x102cee
    handler: fuzzware_harness.user_hooks.tegra.tegra_handlers.sub_102CEE
  rcm_send_initial_hwinfo_after_connection:
    addr: 0x102a80
    handler: fuzzware_harness.user_hooks.tegra.tegra_handlers.rcm_send_initial_hwinfo_after_connection
  delay_us:
    addr: 0x100e50
  usb_flush_ep:
    addr: 0x1071b8
  meminit_memunpack:
    addr: 0x101070
  debug_output:
    addr: 0x1022ea
  sub_114D3C:
    addr: 0x114d3c
  some_usb_charger_stuff:
    addr: 0x104282
  j_memcpy_libc:
    addr: 0x104356
    handler: fuzzware_harness.user_hooks.tegra.tegra_handlers.j_memcpy_libc
  rcm_error_and_reset_ep1:
    addr: 0x1023fc
  memset:
    addr: 0x104344
  skip_0x107848:
    addr: 0x107848
    handler: fuzzware_harness.user_hooks.tegra.tegra_handlers.skip_0x107848
  pmc_scratch0_bittest:
    addr: 0x1023be
    handler: fuzzware_harness.user_hooks.tegra.tegra_handlers.pmc_scratch0_bittest  
  # bypass security check
  sub_10256C:
    addr: 0x10256C
  sub_102AEE:
    addr: 0x102AEE
```

Reasons for the handlers are listed in the table below, reasons for skipped functions are straightforward and not listed.
| Handler                                  | Reason                                                     |
|------------------------------------------|------------------------------------------------------------|
| sub_102CEE                               | Force returning 1 to execute more interesting branch.      |
| rcm_send_initial_hwinfo_after_connection | Force returning 1 to execute more interesting branch.      |
| j_memcpy_libc                            | Replace the memcpy logic to ease execution trace analysis. |
| memset                                   | Replace the memset logic to ease execution trace analysis. |
| skip_0x107848                            | Skip the logic after 0x107848, go to 0x107857, avoiding certain crashes.             |
| pmc_scratch0_bittest                     | Force the firmware into USB recovery mode.                 |

## Setup 3: Fuzzing DMA buffers
During the firmware execution, it accesses `g_usbd_req` (0x40003970) to get the value of the USB request. We need to setup the fuzzer to provide the value for `g_usbd_req` so that the emulation can proceed. Therefore, we can mark the region `0x40003000-0x40004000` as an MMIO region (Unicorn requires the regions to be aligned with 0x1000). 

```
mmio_g_usbd_reqp:
    overlay: true
    base_addr: 0x40003000
    permissions: rw-
    size: 0x1000
```

In order to reduce the side effects of this setup, we can add restrictions to Fuzzware. We require Fuzzware provides fuzzing input for memory read to this region only inside the `usbd::handle_ep0_control_transfer` function by adding the following code to `hook_mmio_access` in `emulator/harness/fuzzware_harness/native/native_hooks.c`.  

```
if(addr >= 0x40003000 && addr <= 0x40004000) {
    if(pc > 0x10785a || pc < 0x10767c)
        return;
}
```

## Setup 4: Variable configuration
There are some hard-coded variables that are used for condition checks during the firmware emulation. We need to manually set them up as their values don't come with the binary. We can provide the values through `uc.mem_write` in the `main` function in `emulator/harness/fuzzware_harness/harness.py` before the emulation starts.

```
uc.mem_write(0x40002990, 0x40005000.to_bytes(4, byteorder='little'))
uc.mem_write(0x40002994, 0x40009000.to_bytes(4, byteorder='little'))
uc.mem_write(0x40002D30, 0x0.to_bytes(4, byteorder='little'))
uc.mem_write(0x40002E55, 0x1.to_bytes(1, byteorder='little'))
uc.mem_write(0x7000F9A0, bytes([1]))
```
`0x40005000` and `0x40009000` are the two USB DMA buffers which serve as the destination address of the vulnerable memcpy, eventually triggering the stack overflow.

# Usage
```
# start fuzzing
fuzzware pipeline tegra/

# replay crashes
fuzzware emu -v -c {CONFIG_PATH} --prefix-input {PREFIX_INPUT_PATH} {CRASH_INPUT_PATH}

# try out the crash input
fuzzware emu -v -c tegra/tegra_crash_input_example/config.yml --prefix-input tegra/tegra_crash_input_example/prefix_input tegra/tegra_crash_input_example/crash_input
```

# Expected Output
The output should exhibit how many bytes are copied to the USB DMA addresses (`0x40005000` and `0x40009000`). The emulator will signal an exception due to the sabotage of the stack frame and return addresses. An example is shown as follows.

```
read from 0x4000fcb8 to 0x40005000, 0xffff bytes, till 0x40014fff

 >>> [ 0x00000000 ] INVALID FETCH: addr= 0x0000000000000000
Execution failed with error code: 8 -> Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)

==== UC Reg state ====
r0: 0x0000001a
r1: 0x00000001
r2: 0x00010000
r3: 0x00000000
r4: 0x00000000
r5: 0x00000000
r6: 0x00000000
r7: 0x00000000
r8: 0x00000000
r9: 0x00000000
r10: 0x00115be4
r11: 0x00000000
r12: 0x00000000
lr: 0x001073c3
pc: 0x00000000
cpsr: 0x200001d3
sp: 0x4000fce0
other_sp: 0x00000000

==== UC Stack state ====
0x4000fcd0: 00000000
0x4000fcd4: 00000000
0x4000fcd8: 00000000
0x4000fcdc: 00000000
0x4000fce0: 00000000 <---- sp
0x4000fce4: 00000000
0x4000fce8: 00000000
0x4000fcec: 00000000
0x4000fcf0: 00000000
0x4000fcf4: 00000000
0x4000fcf8: 00000000
0x4000fcfc: 00000000
0x4000fd00: 00000000
0x4000fd04: 00000000
0x4000fd08: 00000000
0x4000fd0c: 00000000
0x4000fd10: 00000000
0x4000fd14: 00000000
0x4000fd18: 00000000
0x4000fd1c: 00000000
======================


==== UC Other Stack state ====
======================

Emulation crashed with signal 11
```
