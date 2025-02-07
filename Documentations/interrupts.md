# Fuzzware interrupts
In this section, we will talk about how Fuzzware implements the interrupt mechanism for Cortex-M, i.e., the NVIC（Nested Vectored Interrupt Controller）.

# Interrupt Vector Table setup
NVIC uses the vector table to store the interrupt handling logic. In the Cortex-M architecture, the table usually locates at 0x0. 

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
if(trigger_mode == IRQ_TRIGGER_MODE_ADDRESS) {
    if (uc_hook_add(uc, &trigger->hook_handle, UC_HOOK_BLOCK, (void *)interrupt_trigger_tick_block_hook, trigger, addr, addr) != UC_ERR_OK) {
        perror("[INTERRUPT_TRIGGERS ERROR] Failed adding block hook.\n");
        exit(-1);
    }
```

# NVIC implementation
