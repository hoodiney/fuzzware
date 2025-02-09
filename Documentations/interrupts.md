# Fuzzware interrupts
In this section, we will talk about how Fuzzware implements the interrupt mechanism for Cortex-M, i.e., the NVIC (Nested Vectored Interrupt Controller).

# Interrupt Vector Table setup
NVIC uses the vector table to store the addresses to the interrupt handling logics. In the Cortex-M architecture, the table usually locates at the beginning of the firmware. The vector table base address is stored in the VTOR (Vector Table Offset Register). Configuration of the vector table base address is detailed in `init_nvic()` in `emulator/harness/fuzzware_harness/native/core_peripherals/cortexm_nvic.c`.

```
// Set the vtor. If it is uninitialized, read it from actual (restored) process memory
if(vtor == NVIC_VTOR_NONE) {
    uc_mem_read(uc, SYSCTL_VTOR, &nvic.vtor, sizeof(nvic.vtor));
    printf("[NVIC] Recovered vtor base: %x\n", nvic.vtor); fflush(stdout);
} else {
    // We have MMIO vtor read fall through, so put vtor value in emulated memory
    uc_mem_write(uc, SYSCTL_VTOR, &nvic.vtor, sizeof(nvic.vtor));
    nvic.vtor = vtor;
}
```

# Interrupt triggering
In general, Fuzzware offers two kinds interrupt triggering mechanism: time-based or location-based. 

As for time-based triggering, Fuzzware uses a timer mechanism to manage and trigger the interrupts. Before we go into Fuzzware's implementation of the interrupt triggering, let's look at the timers. The `Timer` struct is listed in `emulator/harness/fuzzware_harness/native/timer.h`. 
```
struct Timer {
    struct Timer *next;
    uint64_t ticker_val;
    uint64_t reload_val;
    timer_cb trigger_callback;
    void *trigger_cb_user_data;
    uint32_t irq_num;
    uint8_t in_use;
    uint8_t is_active;
};

struct TimerState {
    struct Timer *active_head;
    uint64_t cur_interval;
    uint64_t cur_countdown;
    uint64_t global_ticker;
    struct Timer timers[MAX_TIMERS];
    uint32_t end_ind;
    uint32_t num_inuse;
};
```
The `reload_val` marks the timer's initial number of countdown ticks. After each reset or timeout, the timer regains the initial countdown ticks. The `ticker_val` counts down after each ticking. When its value equals 0, it marks the timer times out, and the `trigger_callback` will be called. The `irq_num` marks the interrupt number related to this timer. Details of the countdown logic is in the `timer_countdown_expired()` function in `emulator/harness/fuzzware_harness/native/timer.c`.  

For the location-based interrupt triggering, Fuzzware utilizes Unicorn hooks to trigger the interrupts, as is shown in the `add_interrupt_trigger()` function in `emulator/harness/fuzzware_harness/native/interrupt_triggers.c`.
```
...
if(trigger_mode == IRQ_TRIGGER_MODE_ADDRESS) {
    if (uc_hook_add(uc, &trigger->hook_handle, UC_HOOK_BLOCK, (void *)interrupt_trigger_tick_block_hook, trigger, addr, addr) != UC_ERR_OK) {
        perror("[INTERRUPT_TRIGGERS ERROR] Failed adding block hook.\n");
        exit(-1);
    }
}
...
```

# NVIC implementation
The core functionality of Fuzzware's interrupt handling is based on its implementation of the NVIC. We explain here the implementation of `emulator/harness/fuzzware_harness/native/core_peripherals/cortexm_nvic.c` in the following section. We skip the functions that are straightforward or already well-commented.

## nvic_set_pending
```
void nvic_set_pending(uc_engine *uc, uint32_t num, int delay_activation) {
    pend_interrupt(uc, num);
    maybe_activate(uc, false);
}
```
This function is called when a new interrupt needs to be handled. `pend_interrupt` firstly pends the interrupt and `maybe_activate` deals with the interrupt handling.

## pend_interrupt
If the pending interrupt is a high-priority or a lower same-priority interrupt, the function will call the `recalc_prios` function to recalculate current NVIC interrupt priorities.

## GET_PRIMASK
```
static inline uint8_t GET_PRIMASK() {
    return *nvic.reg_daif_ptr & CPSR_IRQ_MASK_BIT;
}
```
The DAIF register is used for checking the current processor state masking. `D` means `Debug Mask`, `A` means `Asynchronous Mask`, `I` means `IRQ Mask` and `F` means `FIQ Mask`. This function returns if the IRQ should be masked.

## GET_BASEPRI
```
static inline int32_t GET_BASEPRI() {
    return *nvic.reg_basepri_ptr;
}
```
BASEPRI is an interrupt masking register, which blocks exceptions that have the same or lower priority level while allowing exceptions with a higher priority level.

## GET_CURR_SP_MODE_IS_PSP
```
static inline uint32_t GET_CURR_SP_MODE_IS_PSP () {
    return *reg_curr_sp_mode_is_psp_ptr;
}
```
In Cortex-M, the SP (Stack Pointer) has two modes: MSP (Main Stack Mode) and PSP (Processor Stack Mode). The processor uses PSP by default (for exception handling and so on). This function returns if the current SP mode is PSP.

## calc_icsr
```
static uint32_t calc_icsr() {
    uint32_t res = 0;

    // ISRPREEMPT
    // debug state register, which we don't support

    // ISRPENDING
    // this is not the exact semantic, but we give some indication
    // (highest irq does not need to be external, could be SYSTICK / PENDSV)
    res |= (nvic.pending_irq > EXCEPTION_NO_SYSTICK) << SCB_ICSR_ISRPENDING_Pos;

    // VECTPENDING
    res |= (nvic.pending_irq << SCB_ICSR_VECTPENDING_Pos) & SCB_ICSR_VECTPENDING_Msk;

    // RETTOBASE
    res |= (nvic.num_active <= 1) << SCB_ICSR_RETTOBASE_Pos;

    // VECTACTIVE
    res |= nvic.active_irq & SCB_ICSR_VECTACTIVE_Msk;
    return res;
}
```
The ICSR (Interrupt Control and State Register) is for managing interrupt priority, triggering PendSV, etc.

## ExceptionEntry
This function deals with the interrupt handling. There are several details we need to explain a bit.

`NVIC_INTERRUPT_ENTRY_LR_BASE` (0xfffffff1u) means that current interrupt handling will return to Handler mode and uses the Main SP. 

`is_tail_chained` marks if the current interrupt handling needs tail chaining, which means directly handling the next interrupt without doing the context saving and poping again. Tail chainning means the execution is from Handler mode to Handler mode. 

`nvic.active_irq == NVIC_NONE_ACTIVE` means the execution comes from Thread mode. If this is the case, the return address should be 0xfffffff9u (`new_lr |= NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG`)

In Unicorn, its `UC_ARM_REG_CURR_SP_MODE_IS_PSP` register can be used for checking if current SP is PSP.

In `uc_reg_write(uc, UC_ARM_REG_SPSEL, &new_SPSEL_not_psp);`, `UC_ARM_REG_SPSEL=0` means using MSP, `UC_ARM_REG_SPSEL=1` means using PSP.

`new_lr |= NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG;` changes the return address to 0xfffffffdu, which means returning to Handler mode and uses stack PSP.

