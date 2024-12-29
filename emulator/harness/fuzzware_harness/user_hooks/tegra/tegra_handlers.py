from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_SP)

def sub_102CEE(uc):
    uc.reg_write(UC_ARM_REG_R0, 1)

def rcm_send_initial_hwinfo_after_connection(uc):
    uc.reg_write(UC_ARM_REG_R0, 1)

def j_memcpy_libc(uc):
    dst = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    num = uc.reg_read(UC_ARM_REG_R2)

    print(f"read from {src:#x} to {dst:#x}, {num:#x} bytes, till {dst+num:#x}")
    print(hex(uc.reg_read(UC_ARM_REG_SP)), )
    data = uc.mem_read(src, num)
    uc.mem_write(dst, bytes(data))

def memset(uc):
    addr = uc.reg_read(UC_ARM_REG_R0)
    val = uc.reg_read(UC_ARM_REG_R1)
    len = uc.reg_read(UC_ARM_REG_R2)

    print(f"memset to {addr:#x}, val {val:#x}, {len} times")
    val_byte = val & 0xff

    uc.mem_write(addr, bytes([val_byte]) * len)

def skip_0x107848(uc):
    uc.reg_write(UC_ARM_REG_PC, 0x107857)

def pmc_scratch0_bittest(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)