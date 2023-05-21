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
const char asdf[] = {
    /* 0xdf, 0x3f, 0x03, 0xd5,  // ISB */
    /* 0x00, 0x10, 0x38, 0xd5, // mrs x0, SCTLR_EL1 */
    /* 0x00, 0x00, 0x40, 0xb2, // orr x0, x0, 1 */
    /* 0x00, 0x10, 0x18, 0xd5, // msr SCTLR_EL1, x0 */
    /* 0xdf, 0x3f, 0x03, 0xd5,  // ISB */
    0xa0,0xd5,0xbb,0xd2,0x00,0xc0,0x18,0xd5,0xe0,0x1f,0x80,0xd2,0x00,0xa2,0x18,0xd5,0x20,0x00,0xc0,0xd2,0x20,0xa3,0xb6,0xf2,0x20,0xa3,0x86,0xf2,0x40,0x20,0x18,0xd5,0x20,0x08,0xa0,0xd2,0x00,0x20,0x18,0xd5,0x20,0x20,0x18,0xd5,0xdf,0x3f,0x03,0xd5,0x00,0x10,0x38,0xd5,0x00,0x00,0x40,0xb2,0x00,0x10,0x18,0xd5,0xdf,0x3f,0x03,0xd5
};

#define HV_PAGE_SIZE 16384

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
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, (1 << 20) | (1 << 21)));

    // Configure initial VBAR_EL1 to BRKs
    uint32_t *vbar = mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < (HV_PAGE_SIZE / sizeof(hvc_insns)); i++) {
        memcpy(vbar + i, hvc_insns, sizeof(hvc_insns));
    }
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, 0xdead0000));
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = vbar,
        .guest = (void*)0xdead0000,
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_EXEC,
    };

    // test
    void *reconfig = mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = reconfig,
        .guest = (void*)0x4000,
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_EXEC,
    };

    // Configure 1:1 translation tables
    uint64_t *page_tables = mmap(0, HV_PAGE_SIZE * 10, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#define PAGING_PA   (0x410000)
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = page_tables,
        .guest = (void*)PAGING_PA,
        .len = HV_PAGE_SIZE * 10,
        .prot = PROT_READ | PROT_EXEC,
    };

#define PT_USER     (1<<6)      // unprivileged, EL0 access allowed
#define PT_AF       (1<<10)     // accessed flag
#define PT_ISH      (3<<8)      // inner shareable
// defined in MAIR register
#define PT_MEM      (0<<2)      // normal memory

    uint16_t tblidx = 1;
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

        uint16_t l0idx = ((uint64_t)res.mappings[i].guest >> 30) & 0x1ff;
        uint16_t l1idx = ((uint64_t)res.mappings[i].guest >> 21) & 0x1ff;
        uint16_t l2idx = ((uint64_t)res.mappings[i].guest >> 12) & 0x1ff;

        uint64_t *l0pt = page_tables;
        if (!l0pt[l0idx]) {
            fprintf(stderr, "creating l1pt at offset %d for l0idx %d\n", tblidx, l0idx);
            l0pt[l0idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
            tblidx++;
        }
        uint64_t *l1pt = (uint64_t*)((l0pt[l0idx] & ~0xfff) - PAGING_PA + (uint64_t)page_tables);
        if (!l1pt[l1idx]) {
            fprintf(stderr, "creating l2pt at offset %d for l1idx %d\n", tblidx, l1idx);
            l1pt[l1idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
            tblidx++;
        }
        uint64_t *l2pt = (uint64_t*)((l1pt[l1idx] & ~0xfff) - PAGING_PA + (uint64_t)page_tables);
        l2pt[l2idx] = (uint64_t)res.mappings[i].guest | 0b11 | PT_AF | PT_USER | PT_ISH | PT_MEM;
    }

    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, 0xff));
    unsigned long r=  (0b00LL << 37) | // TBI=0, no tagging
        (0b0001LL << 32) |      // ghost: set to 36 bit = 64GB
        (0b10LL << 30) | // TG1=4k
        (0b11LL << 28) | // SH1=3 inner
        (0b01LL << 26) | // ORGN1=1 write back
        (0b01LL << 24) | // IRGN1=1 write back
        (0b0LL  << 23) | // EPD1 enable higher half
        (25LL   << 16) | // T1SZ=25, 3 levels (512G)
        (0b00LL << 14) | // TG0=4k
        (0b11LL << 12) | // SH0=3 inner
        (0b01LL << 10) | // ORGN0=1 write back
        (0b01LL << 8) |  // IRGN0=1 write back
        (0b0LL  << 7) |  // EPD0 enable lower half
        (25LL   << 0);   // T0SZ=25, 3 levels (512G)

    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, r)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, PAGING_PA)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, PAGING_PA)); */

    // 0x30100180 is the default SCTLR_EL1 the framework starts with
    // enable MMU (1<<0)
    // disable some other alignment checking (1<<6) nAA
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, 0x30100180 | (1 << 6)));
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, (1 << 0) | (1 << 26)));

    // Set initial PC, and SP
    fprintf(stderr, "starting at pc=%p, sp=%p\n", res.entry_point, res.stack_top);
    fprintf(stderr, "*pc=%lx\n", *(uint32_t*)res.entry_point);
    memcpy(res.entry_point, brk_insns, 4);

    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, res.entry_point)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, res.stack_top)); */

    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c4));
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64PFR1_EL1, 0x0000000000000020));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, 0x0000000030c50838));
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64DFR0_EL1, 0x0000000010305408));
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64ISAR0_EL1, 0x0000100010211120)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64ISAR1_EL1, 0x0000000000100001)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR0_EL1, 0x0000000000101125)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR1_EL1, 0x0000000010212122)); */
    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR2_EL1, 0x0000000000001011)); */

    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, 0x4000));
    memcpy(reconfig, asdf, sizeof(asdf));
    memcpy(reconfig+sizeof(asdf), hvc_insns, sizeof(hvc_insns));

    //HYP_ASSERT_SUCCESS(hv_vcpu_set_trap_debug_exceptions(vcpu, true));

    const char basedir[] = "/tmp/mem";
    for (int i = 0; i < res.n_mappings; i++) {
        struct vm_mmap m = res.mappings[i];
        char path[1024] = {0};
        snprintf(path, sizeof(path), "%s/%p", basedir, m.guest);
        int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0777);
        if (fd < 0) {
            printf("failed to open %s: %s\n", path, strerror(errno));
            exit(1);
        }
        size_t n = 0;
        while (n < m.len) {
            int foo = write(fd, m.hyper + n, m.len - n);
            if (foo < 0) {
                printf("failed to write %s\n", path);
                exit(1);
            }
            n += foo;
        }
        close(fd);
    }

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
