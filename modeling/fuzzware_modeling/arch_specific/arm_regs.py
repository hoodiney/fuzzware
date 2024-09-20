""" WIP place for ARM specific constants.
This is the result from scraping architecture-specific register name lists from the code.

TODO: Unify and replace this with archinfo
"""
STATE_SNAPSHOT_REG_LIST = ['r0', 'r1', 'r2', 'r3', 'r4',
        'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'lr', 'pc',
        'sp', 'cpsr']

SCOPE_REG_NAMES = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r10', 'r11', 'r12', 'lr', 'sp', 'pc')

REGULAR_REGISTER_NAMES = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'lr', 'sp')

NEWLY_ADDED_CONSTRAINTS_REG_NAMES = ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r10', 'r11', 'r12', 'lr')

REG_NAME_PC = 'pc'
REG_NAME_SP = 'sp'

def return_reg(state):
    return state.regs.r0

def translate_reg_name_to_vex_internal_name(name):
    name = name.lower()

    if name == 'cpsr':
        name = 'cc_dep1'

    return name

def leave_reg_untainted(name):
    return name in ['itstate', 'cc_op']

# leave the ARM flag registers untaint
def leave_reg_untainted_extend(name):
    return name in ['itstate', 'cc_op']