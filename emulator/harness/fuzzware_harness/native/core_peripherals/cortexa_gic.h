#include "unicorn/unicorn.h"

struct CortexaGIC {
    // We put some members to the front as they are required in the basic block hot path
    
    // Direct access pointers for interrupt disable / base priority flags
    uint8_t *reg_daif_ptr;
    int32_t *reg_basepri_ptr;

    // State for the basic block hook to detect differences
    uint8_t prev_primask;
    int32_t prev_basepri;
    // cortex-A doesn't have a priority group
    // uint8_t group_prio_mask;
    // uint8_t prigroup_shift;
    uint8_t sub_prio_mask;
    uint8_t highest_ever_enabled_exception_no;

    // dynamic state which we re-calculate upon changes
    // int active_group_prio;
    int active_irq;
    int pending_prio;
    int pending_irq;
    int num_active;

    // Vector table base address
    uint32_t vtor;

    uint32_t interrupt_count;
    bool force_stack_align;

    // cortex-A could support 1020 exceptions
    uint8_t ExceptionEnabled[1020];
    uint8_t ExceptionActive[1020];
    uint8_t ExceptionPending[1020];
    int ExceptionPriority[1020];

    // We keep track of enabled interrupts for fuzzing
    int num_enabled;
    uint8_t enabled_irqs[1020];
};

#define CPSR_IRQ_MASK_BIT (1 << 7)