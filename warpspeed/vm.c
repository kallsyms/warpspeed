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
#include <fcntl.h>
#include <unistd.h>

#include <Hypervisor/Hypervisor.h>

#include "loader.h"

// Diagnostics
#define HYP_ASSERT_SUCCESS(ret) do { \
    if ((hv_return_t)(ret) != HV_SUCCESS) { \
        fprintf(stderr, "%s:%d: %s = %x\n", __FILE__, __LINE__, #ret, (ret)); \
        abort(); \
    } \
} while (0)

const char brk_insns[4] = {0x00, 0x00, 0x20, 0xD4};
const char hvc_insns[4] = {0x02, 0x00, 0x00, 0xD4};

#define HV_PAGE_SIZE 16384
#define PAGING_PA   (0x10000)
#define VBAR_ADDR (0xffffffffffff0000ULL)
#define VBAR_PA (0x20000)

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

    // Configure initial VBAR_EL1 to BRKs
    uint32_t *vbar = mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < (HV_PAGE_SIZE / sizeof(hvc_insns)); i++) {
        memcpy(vbar + i, hvc_insns, sizeof(hvc_insns));
    }
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = vbar,
        .guest_pa = (void*)VBAR_PA,
        .guest_va = (void*)VBAR_ADDR,
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_EXEC,
    };

    // Configure 1:1 translation tables
    uint64_t *page_tables = mmap(0, HV_PAGE_SIZE * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    HYP_ASSERT_SUCCESS(hv_vm_map(page_tables, (hv_ipa_t)PAGING_PA, HV_PAGE_SIZE * 4, PROT_READ | PROT_WRITE));

    uint64_t dyn_pa_base = 0x13370000;  // if guest_pa is not explicitly set, the next available physical address to use
    uint16_t tblidx = 1;
    for (int i = 0; i < res.n_mappings; i++) {
        struct vm_mmap m = res.mappings[i];
        if (!m.guest_pa) {
            m.guest_pa = dyn_pa_base;
            dyn_pa_base += m.len;
        }
        fprintf(stderr, "mapping %p -> %p -> %p len:0x%lx prot:%x\n", m.hyper, m.guest_pa, m.guest_va, m.len);
        HYP_ASSERT_SUCCESS(hv_vm_map(m.hyper, (hv_ipa_t)m.guest_pa, m.len, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));

        for (size_t offset = 0; offset < m.len; offset += 0x1000) {
            uint64_t pa = (uint64_t)m.guest_pa + offset;
            if (pa > (1ULL << 48)) {
                fprintf(stderr, "pa too big\n");
                exit(1);
            }
            if (pa & ((1 << 12) - 1)) {
                fprintf(stderr, "low bits in pa set\n");
                exit(1);
            }
            uint64_t va = (uint64_t)m.guest_va + offset;

            uint16_t l0idx = (va >> 39) & 0x1ff;
            uint16_t l1idx = (va >> 30) & 0x1ff;
            uint16_t l2idx = (va >> 21) & 0x1ff;
            uint16_t l3idx = (va >> 12) & 0x1ff;

            uint64_t *l0pt = page_tables;
            if (!l0pt[l0idx]) {
                fprintf(stderr, "creating l1pt at offset %d for l0idx %d\n", tblidx, l0idx);
                l0pt[l0idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
                fprintf(stderr, "l1pt descriptor: %p\n", l0pt[l0idx]);
                tblidx++;
            }
            uint64_t *l1pt = (uint64_t*)((l0pt[l0idx] & ~((1<<12)-1)) - PAGING_PA + (uint64_t)page_tables);
            if (!l1pt[l1idx]) {
                fprintf(stderr, "creating l2pt at offset %d for l1idx %d\n", tblidx, l1idx);
                l1pt[l1idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
                fprintf(stderr, "l2pt descriptor: %p\n", l1pt[l1idx]);
                tblidx++;
            }
            uint64_t *l2pt = (uint64_t*)((l1pt[l1idx] & ~((1<<12)-1)) - PAGING_PA + (uint64_t)page_tables);
            if (!l2pt[l2idx]) {
                fprintf(stderr, "creating l3pt at offset %d for l2idx %d\n", tblidx, l2idx);
                l2pt[l2idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
                fprintf(stderr, "l3pt descriptor: %p\n", l2pt[l2idx]);
                tblidx++;
            }
            uint64_t *l3pt = (uint64_t*)((l2pt[l2idx] & ~((1<<12)-1)) - PAGING_PA + (uint64_t)page_tables);
            // ghost: TODO: these are all rwx effectively
            l3pt[l3idx] = (uint64_t)pa | 0b11 | (1 << 5) | (0b01 << 6) | (0b11 << 8) | (1 << 10);
            // privileged?
            //if (va > (1ULL << 48)) {
                l3pt[l3idx] &= ~(0b11 << 6);
            //}
            //fprintf(stderr, "page descriptor (idx %d): %p\n", l3idx, l3pt[l3idx]);
        }
    }

    // https://github.com/Impalabs/hyperpom/blob/85a4df8b6af2babf3689bd4c486fcbbd4c831f8a/src/memory.rs#L1836
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, 0x44));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, 0x10 | (0x10 << 16) | (0b10 << 30) | (1ULL << 39) | (1ULL << 40)));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, PAGING_PA));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, PAGING_PA));  // ghost: this should use 2 tables but ^ needs refactoring before that
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, 0x1005));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, (3 << 20)));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c4));  // ghost: figure out why 3c0 causes faults
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, VBAR_ADDR));

    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, res.entry_point));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, res.stack_top));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, res.stack_top)); // ghost: when we go back to el0, remove

    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_exceptions(vcpu, true));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_reg_accesses(vcpu, true));

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
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                printf("PC: 0x%llx\n", pc);
                uint64_t elr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr));
                printf("ELR_EL1: 0x%llx\n", elr);
                uint64_t esr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr));
                printf("ESR: 0x%llx\n", esr);

                if (esr == 0x56000080) {  // SVC in aarch64
                    uint64_t args[6];
                    for (int i = HV_REG_X0; i < HV_REG_X6; i++) {
                        HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, i, &args[i - HV_REG_X0]));
                    }
                    uint64_t num;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X16, &num));
                    printf("forwarding syscall %d(%p, %p, %p, %p, %p, %p)\n", num, args[0], args[1], args[2], args[3], args[4], args[5]);
                    uint64_t ret = syscall(num, args[0], args[1], args[2], args[3], args[4], args[5]);
                    printf("ret: %p\n", ret);
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, elr));
                    continue;
                }

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
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &x));
                printf("ttbr0 %llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, &x));
                printf("tcr %llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_PAR_EL1, &x));
                printf("par %llx\n", x);

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
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &x));
                printf("ttbr0 %llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, &x));
                printf("tcr %llx\n", x);
                break;
            } else {
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                fprintf(stderr, "Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx\n",
                    syndrome,
                    ec,
                    vcpu_exit->exception.virtual_address,
                    vcpu_exit->exception.physical_address
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
                uint64_t x;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &x));
                printf("ESR: 0x%llx\n", x);
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
