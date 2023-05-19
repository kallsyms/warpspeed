// simplevm.c: demonstrates Hypervisor.Framework usage in Apple Silicon
// Based on the work by @zhuowei
// @imbushuo - Nov 2020

// To build:
// Prepare the entitlement with BOTH com.apple.security.hypervisor and com.apple.vm.networking WHEN SIP IS OFF
// Prepare the entitlement com.apple.security.hypervisor and NO com.apple.vm.networking WHEN SIP IS ON
// ^ Per @never_released, tested on 11.0.1, idk why
// clang -o simplevm -O2 -framework Hypervisor -mmacosx-version-min=11.0 simplevm.c
// codesign --entitlements simplevm.entitlements --force -s - simplevm             

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>

#include <Hypervisor/Hypervisor.h>

#include "loader.h"

// Diagnostics
#define HYP_ASSERT_SUCCESS(ret) do { \
    if ((hv_return_t)(ret) != HV_SUCCESS) { \
        fprintf(stderr, "%s:%d: %s = %x\n", __FILE__, __LINE__, #ret, (ret)); \
        abort(); \
    } \
} while (0)

const char brk[4] = {0x00, 0x00, 0x20, 0xD4};

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s /path/to/bin [args...]", argv[0]);
        exit(1);
    }

    struct load_results res = {};
    load(argv[1], false, &res);
    setup_stack64(argv[1], &res);

    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vcpu_exit;

    HYP_ASSERT_SUCCESS(hv_vm_create(NULL));
    HYP_ASSERT_SUCCESS(hv_vcpu_create(&vcpu, &vcpu_exit, NULL));

    // enable fpu
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, (1 << 20) | (1 << 21)));
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, (1 << 6)));

    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, 0x1));
    
    // ghost: TODO: SCTLR_EL1? caches and such?

    for (int i = 0; i < res.n_mappings; i++) {
        int prot = 0;
        // ghost: TODO: necessary?
        if (res.mappings[i].prot & PROT_READ) {
            prot |= HV_MEMORY_READ;
        }
        if (res.mappings[i].prot & PROT_WRITE) {
            prot |= HV_MEMORY_WRITE;
        }
        if (res.mappings[i].prot & PROT_EXEC) {
            prot |= HV_MEMORY_EXEC;
        }
        fprintf(stderr, "mapping %p -> %p len:0x%lx prot:%x\n", res.mappings[i].hyper, res.mappings[i].guest, res.mappings[i].len, prot);
        HYP_ASSERT_SUCCESS(hv_vm_map(res.mappings[i].hyper, (hv_ipa_t)res.mappings[i].guest, res.mappings[i].len, prot));
    }

    // Configure initial VBAR_EL1 to BRKs
#define PAGE_SIZE 16384
    uint32_t *vbar = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < (PAGE_SIZE / sizeof(brk)); i++) {
        memcpy(vbar + i, brk, sizeof(brk));
    }
    HYP_ASSERT_SUCCESS(hv_vm_map(vbar, (hv_ipa_t)0xdead0000, PAGE_SIZE, HV_MEMORY_READ | HV_MEMORY_EXEC));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, 0xdead0000));

    // Set initial PC, and SP
    fprintf(stderr, "starting at pc=%p, sp=%p\n", res.entry_point, res.stack_top);
    fprintf(stderr, "*pc=%lx\n", *(uint32_t*)res.entry_point);
    //memcpy(res.entry_point, brk, 4);

    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, res.entry_point));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, res.stack_top));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c0));

    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_exceptions(vcpu, true));

    while (true) {
        HYP_ASSERT_SUCCESS(hv_vcpu_run(vcpu));
        if (vcpu_exit->reason == HV_EXIT_REASON_EXCEPTION) {
            // https://developer.arm.com/documentation/ddi0601/2022-03/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-
            uint64_t syndrome = vcpu_exit->exception.syndrome;
            uint8_t ec = (syndrome >> 26) & 0x3f;
            if (ec == 0x16) {
                // Exception Class 0x16 is
                // "HVC instruction execution in AArch64 state, when HVC is not disabled."
                uint64_t x0;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                printf("VM made an HVC call! x0 register holds 0x%llx\n", x0);
                break;
            } else if (ec == 0x17) {
                // Exception Class 0x17 is
                // "SMC instruction execution in AArch64 state, when SMC is not disabled."

                uint64_t x0;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                printf("VM made an SMC call! x0 register holds 0x%llx\n", x0);
                printf("Return to get on next instruction.\n");

                // ARM spec says trapped SMC have different return path, so it is required
                // to increment elr_el2 by 4 (one instruction.)
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                pc += 4;
                HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
            } else if (ec == 0x3C) {
                // Exception Class 0x3C is BRK in AArch64 state
                printf("VM made an BRK call!\n");
                printf("Reg dump:\n");
                for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
                    uint64_t s;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &s));
                    printf("X%d: 0x%llx\n", reg, s);
                    /* if (reg < 2) { */
                    /*     printf("s: %s\n", s); */
                    /* } */
                }
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                printf("PC: 0x%llx\n", pc);
                uint64_t elr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr));
                printf("ELR_EL1: 0x%llx\n", elr);
                uint64_t far;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far));
                printf("FAR_EL1: 0x%llx\n", far);
                uint64_t x;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &x));
                printf("ESR: 0x%llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &x));
                printf("sctlr %llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, &x));
                printf("cpacr %llx\n", x);
                break;
            } else {
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                fprintf(stderr, "Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx\n",
                    syndrome,
                    ec,
                    vcpu_exit->exception.virtual_address,
                    vcpu_exit->exception.physical_address,
                    pc
                );
                printf("Reg dump:\n");
                for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
                    uint64_t s;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &s));
                    printf("X%d: 0x%llx\n", reg, s);
                }
                printf("PC: 0x%llx\n", pc);
                uint64_t elr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr));
                printf("ELR_EL1: 0x%llx\n", elr);
                uint64_t far;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far));
                printf("FAR_EL1: 0x%llx\n", far);
                break;
            }
        } else {
            fprintf(stderr, "Unexpected VM exit reason: %d\n", vcpu_exit->reason);
            break;
        }
    }

    hv_vcpu_destroy(vcpu);
    hv_vm_destroy();

    return 0;
}
