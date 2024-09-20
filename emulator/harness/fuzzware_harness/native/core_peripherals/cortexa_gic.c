#include "cortexa_gic.h"

struct CortexaGIC gic __attribute__ ((aligned (64))) = {
    .prev_basepri = -1
};

/*
 * Access wrappers for interrupt-related registers
 */
static inline uint8_t GIC_GET_PRIMASK() {
    return *gic.reg_daif_ptr & CPSR_IRQ_MASK_BIT;
}

static inline int32_t GIC_GET_BASEPRI() {
    return *gic.reg_basepri_ptr;
}

// Versions of the above that assume an existing NVIC pointer
static inline uint8_t GIC_GET_PRIMASK(struct CortexaGIC *p_gic) {
    return *p_gic->reg_daif_ptr & CPSR_IRQ_MASK_BIT;
}

static inline int32_t GIC_GET_BASEPRI(struct CortexaGIC *p_gic) {
    return *p_gic->reg_basepri_ptr;
}

static bool gic_pending_exception_can_be_activated() {
    #ifdef DEBUG_NVIC
    printf("[NVIC] pending_exception_can_be_activated: nvic.pending_prio < get_boosted_prio(nvic.active_group_prio)? %d < %d ? -> %d\n", nvic.pending_prio, get_boosted_prio(nvic.active_group_prio), nvic.pending_prio < get_boosted_prio(nvic.active_group_prio)); fflush(stdout);
    #endif

    #ifdef DISABLE_NESTED_INTERRUPTS
    if(nvic.active_irq != NVIC_NONE_ACTIVE) {
        #ifdef DEBUG_NVIC
        puts("Already in handler, short-cutting exec prio to 0 to disable nesting/preemption."); fflush(stdout);
        #endif
        return 0;
    }
    #endif

    // compare the current pending irq's priority with the active one
    return gic.pending_prio < gic_get_boosted_prio(nvic.active_group_prio);
}

void gic_pend_interrupt(uc_engine *uc, int exception_no) {
    #ifdef DEBUG_GIC
    printf("[gic_pend_interrupt] exception_no=%d\n", exception_no);
    fflush(stdout);
    #endif
    if(gic.ExceptionPending[exception_no] == 0) {
        gic.ExceptionPending[exception_no] = 1;

        #ifndef DISABLE_LAZY_RECALCS
        // we only need to update if we pend a high-prio or a lower same-prio interrupt
        if(exception_no < gic.pending_irq ||
            gic.ExceptionPriority[exception_no] < gic.pending_prio) {
        #endif
            gic_recalc_prios();
        #ifndef DISABLE_LAZY_RECALCS
        }
        #endif
    }
}

static void gic_maybe_activate(uc_engine *uc, bool skip_instruction) {
    #ifdef DEBUG_NVIC
    printf("[maybe_activate] skip_instruction: %d\n", skip_instruction);
    #endif

    /*
     * We only activate an exception (preempt running exception or freshly activate)
     * in case we have a higher-prio exception (post boosting) pended.
     */
    if(gic_pending_exception_can_be_activated()) {
        GICExceptionEntry(uc, false, skip_instruction);
    }
}

void gic_set_pending(uc_engine *uc, uint32_t num, int delay_activation) {
    gic_pend_interrupt(uc, num);
    gic_maybe_activate(uc, false);
}