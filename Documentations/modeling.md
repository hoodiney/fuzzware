# 1. Fuzzware modeling
Fuzzware utilizes MMIO modeling to either model the peripheral behaviors (Constant Model and Set Model), or improve fuzzing efficiency (Passthrough Model and Bitextract Model). The MMIO behaviors that could not be classified into these four models is considered as Identity Model. In this documentation, we will detail how the MMIO modeling mechanism is implemented in Fuzzware.

# 2. Implementation
## 2.1 Related variables, functions and files
```
hook_mmio_access() -- emulator/harness/fuzzware_harness/native/native_hooks.c
get_fuzz() -- emulator/harness/fuzzware_harness/native/native_hooks.c
add_mmio_subregion_handler() -- emulator/harness/fuzzware_harness/native/native_hooks.c
linear_mmio_model_handler() -- emulator/harness/fuzzware_harness/native/native_hooks.c
constant_mmio_model_handler() -- emulator/harness/fuzzware_harness/native/native_hooks.c
bitextract_mmio_model_handler() -- emulator/harness/fuzzware_harness/native/native_hooks.c
value_set_mmio_model_handler() -- emulator/harness/fuzzware_harness/native/native_hooks.c
set_ignored_mmio_addresses() -- emulator/harness/fuzzware_harness/native/native_hooks.c
register_value_set_mmio_models() -- emulator/harness/fuzzware_harness/native/native_hooks.c
register_bitextract_mmio_models() -- emulator/harness/fuzzware_harness/native/native_hooks.c
register_linear_mmio_models() -- emulator/harness/fuzzware_harness/native/native_hooks.c
register_constant_mmio_models() -- emulator/harness/fuzzware_harness/native/native_hooks.c
```
## 2.2 Model recognization

## 2.3 Model handlers
The models (except for the Passthrough and Identity Model) are enforced through several registered handlers.

## 2.4 Model application
In **hook_mmio_access**, the **get_fuzz** function takes a fuzzing chunk and utilizes the generated model to translate it into the fake peripheral access value. The `ignored_addresses` marks the addresses related with Passthrough Models. Accesses to such addresses will be ignored. `mmio_callbacks` records the different model handlers. If there is no model for the current access, the fuzzing chunk is directly consumed (i.e. Identity Model).
```
void hook_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data)
{
    uint32_t pc = 0;
    latest_mmio_fuzz_access_index = fuzz_cursor;

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    // TODO: optimize this lookup
    for (int i = 0; i < num_ignored_addresses; ++i)
    {
        if(addr == ignored_addresses[i] && (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES || ignored_address_pcs[i] == pc)) {
            #ifdef DEBUG
            printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr, pc); fflush(stdout);
            #endif
            goto out;
        }
    }

    for (int i = 0; i < num_mmio_callbacks; ++i)
    {
        if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
                (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES || mmio_callbacks[i]->pc == pc))
        {
            if(mmio_callbacks[i]->user_data != NULL) {
                user_data = mmio_callbacks[i]->user_data;
            }

            mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
            goto out;
        }
    }

    #ifdef DEBUG
    printf("Serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x, rem bytes: %ld\n", size, addr, pc, fuzz_size-fuzz_cursor); fflush(stdout);
    #endif

    uint64_t val = 0;
    if(get_fuzz(uc, (uint8_t *)&val, size)) {
        return;
    }
    #ifdef DEBUG
    printf(", value: 0x%lx\n", val); fflush(stdout);
    #endif
    uc_mem_write(uc, addr, (uint8_t *)&val, size);


    out:

    latest_mmio_fuzz_access_size = fuzz_cursor - latest_mmio_fuzz_access_index;
    return;
}

``` 
