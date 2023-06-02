#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach/vm_region.h>
#include <mach/mach_vm.h>
#include <mach/mach.h>

#include <Hypervisor/Hypervisor.h>

#include "common.h"
#include "dyld_cache_format.h"
#include "loader.h"
#include "print_helpers.h"

// fwd decl of shared_cache.c
vm_address_t map_shared_cache(struct load_results *res);

// Diagnostics
const char brk_insns[4] = {0x00, 0x00, 0x20, 0xD4};
const char hvc_insns[4] = {0x02, 0x00, 0x00, 0xD4};

#define HV_PAGE_SIZE 16384
#define PAGE_ALIGN(x) (x & ~(HV_PAGE_SIZE-1))
#define PAGE_ROUNDUP(x) (((((x)-1) / HV_PAGE_SIZE)+1) * HV_PAGE_SIZE)
#define PAGING_PA   (0x20000)
#define VBAR_ADDR (0xffffffffffff0000ULL)
#define VBAR_PA (0x10000)

// ghost: TODO Multiple return vals
extern uint64_t syscall_t(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7, uint64_t num);

uint64_t dyn_pa_base = 0x13370000;  // if guest_pa is not explicitly set, the next available physical address to use
size_t tblidx = 1;
uint64_t *page_tables;

void do_map(struct vm_mmap m) {
    if (!m.guest_pa) {
        m.guest_pa = dyn_pa_base;
        dyn_pa_base += m.len;
    }
    LOG("mapping %p -> %p -> %p len:0x%lx\n", m.hyper, m.guest_pa, m.guest_va, m.len);
    HYP_ASSERT_SUCCESS(hv_vm_map(m.hyper, (hv_ipa_t)m.guest_pa, m.len, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC));

    for (size_t offset = 0; offset < m.len; offset += 0x1000) {
        uint64_t pa = (uint64_t)m.guest_pa + offset;
        if (pa > (1ULL << 48)) {
            printf("pa too big\n");
            exit(1);
        }
        if (pa & ((1 << 12) - 1)) {
            printf("low bits in pa set\n");
            exit(1);
        }
        uint64_t va = (uint64_t)m.guest_va + offset;

        uint16_t l0idx = (va >> 39) & 0x1ff;
        uint16_t l1idx = (va >> 30) & 0x1ff;
        uint16_t l2idx = (va >> 21) & 0x1ff;
        uint16_t l3idx = (va >> 12) & 0x1ff;

        uint64_t *l0pt = page_tables;
        if (!l0pt[l0idx]) {
            LOG("creating l1pt at offset %d for l0idx %d\n", tblidx, l0idx);
            l0pt[l0idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
            LOG("l1pt descriptor: %p\n", l0pt[l0idx]);
            tblidx++;
        }
        uint64_t *l1pt = (uint64_t*)((l0pt[l0idx] & ~((1<<12)-1)) - PAGING_PA + (uint64_t)page_tables);
        if (!l1pt[l1idx]) {
            LOG("creating l2pt at offset %d for l1idx %d\n", tblidx, l1idx);
            l1pt[l1idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
            LOG("l2pt descriptor: %p\n", l1pt[l1idx]);
            tblidx++;
        }
        uint64_t *l2pt = (uint64_t*)((l1pt[l1idx] & ~((1<<12)-1)) - PAGING_PA + (uint64_t)page_tables);
        if (!l2pt[l2idx]) {
            //LOG("creating l3pt at offset %d for l2idx %d\n", tblidx, l2idx);
            l2pt[l2idx] = (uint64_t)(PAGING_PA + tblidx * (512 * sizeof(uint64_t)))| 0b11;
            //LOG("l3pt descriptor: %p\n", l2pt[l2idx]);
            tblidx++;
        }
        uint64_t *l3pt = (uint64_t*)((l2pt[l2idx] & ~((1<<12)-1)) - PAGING_PA + (uint64_t)page_tables);
        // ghost: TODO: these are all rwx effectively
        l3pt[l3idx] = (uint64_t)pa | 0b11 | (1 << 5) | (0b01 << 6) | (0b11 << 8) | (1 << 10);
        // privileged?
        //if (va > (1ULL << 48)) {
            l3pt[l3idx] &= ~(0b11 << 6);
        //}
        //LOG("page descriptor (idx %d): %p\n", l3idx, l3pt[l3idx]);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/bin [args...]", argv[0]);
        exit(1);
    }

    struct load_results res = {};
    res.argc = argc - 1;
    uint64_t *guest_argv = mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    res.argv = guest_argv;
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = guest_argv,
        .guest_va = guest_argv,
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_EXEC,
    };
    char *argchar = &guest_argv[res.argc];

    for (int i = 0; i < res.argc; i++) {
        const char *arg = argv[i + 1];
        guest_argv[i] = strcpy(argchar, arg);
        argchar += strlen(arg) + 1;
    }

    res.envc = 1;
    // ghost TODO: pass in via applep
    // https://github.com/apple-oss-distributions/libpthread/blob/67e155c94093be9a204b69637d198eceff2c7c46/src/pthread.c#LL1978C16-L1978C16
    // this doesn't work rn
    char *PTHREAD_PTR_MUNGE_TOKEN_env = "PTHREAD_PTR_MUNGE_TOKEN=1234";

    uint64_t *env = mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    res.envp = env;
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = env,
        .guest_va = env,
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_EXEC,
    };
    char *envchar = &env[res.envc];
    env[0] = strcpy(envchar, PTHREAD_PTR_MUNGE_TOKEN_env);
    envchar += strlen(PTHREAD_PTR_MUNGE_TOKEN_env) + 1;

    load(argv[1], false, &res);
    setup_stack64(argv[1], &res);

    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vcpu_exit;

    HYP_ASSERT_SUCCESS(hv_vm_create(NULL));
    HYP_ASSERT_SUCCESS(hv_vcpu_create(&vcpu, &vcpu_exit, NULL));

    // Configure initial VBAR_EL1 to HVCs
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

    // TLS
    uint64_t tpidrro_el0;
    asm volatile("mrs %0, tpidrro_el0": "=r"(tpidrro_el0));
    LOG("hv tls %p\n", tpidrro_el0);
    void *tls= mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    // ghost: TODO: do we need to copy anything out of the hv's tls? pid/tid?
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDRRO_EL0, tpidrro_el0));
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = (void*)tls,
        .guest_va = PAGE_ALIGN(tpidrro_el0),
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_WRITE,
    };

    vm_address_t shared_cache_base = map_shared_cache(&res);

    // shared region
    // Configure 1:1 translation tables
    page_tables = mmap(0, HV_PAGE_SIZE * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    HYP_ASSERT_SUCCESS(hv_vm_map(page_tables, (hv_ipa_t)PAGING_PA, HV_PAGE_SIZE * 1024, PROT_READ | PROT_WRITE));

    for (int i = 0; i < res.n_mappings; i++) {
        do_map(res.mappings[i]);
    }

    // pthread token == 0 bypass
    memcpy(0x2803f9df8, brk_insns, sizeof(brk_insns));
    // objc init "task_restartable_ranges_register" bypass
    memcpy(0x28005e554, brk_insns, sizeof(brk_insns));

    // https://github.com/Impalabs/hyperpom/blob/85a4df8b6af2babf3689bd4c486fcbbd4c831f8a/src/memory.rs#L1836
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, 0xff));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, 0x10 | (0x10 << 16) | (0b10 << 30) | (1ULL << 39) | (1ULL << 40)));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, PAGING_PA));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, PAGING_PA));  // ghost: this should use 2 tables but ^ needs refactoring before that
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, 0x1005));
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, (3 << 20)));
    // (1 << 0) = SP_ELn
    // (0 << 1) = 64-bit
    // (0b01 << 2) = EL1
    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c5));  // ghost: figure out why 3c0 (running in el0) causes faults
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, VBAR_ADDR));

    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, res.entry_point));
    //HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, res.stack_top));
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
                uint64_t elr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr));
                uint64_t esr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr));
                uint64_t cpsr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr));

                if (esr == 0x56000080) {  // SVC in aarch64
                    LOG("ELR_EL1: 0x%llx\n", elr);
                    uint64_t lr;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_LR, &lr));
                    LOG("LR: %p\n", lr);

                    uint64_t args[8];
                    for (int i = HV_REG_X0; i < HV_REG_X8; i++) {
                        HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, i, &args[i - HV_REG_X0]));
                    }

                    uint64_t cflags, ret0, ret1;
                    bool handled = false;

                    uint64_t num;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X16, &num));
                    switch (num) {
                        case 0x5:
                            LOG("open(%s)\n", args[0]);
                            break;
                        case 0x126:  // shared_region_check_np
                                     // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/vm/vm_unix.c#L2017
                            if (args[0] != -1ull) {
                                LOG("returning %p for shared region base\n", shared_cache_base);
                                *(uint64_t*)args[0] = shared_cache_base;
                            }
                            ret0 = 0;
                            ret1 = 0;
                            cflags = 0;
                            handled = true;
                            break;
                        case 0x150: // proc_info
                            if (args[0] == 0xf) {
                                // "Handle" PROC_INFO_CALL_SET_DYLD_IMAGES
                                // ghost TODO: this may be unused?
                                LOG("Stub PROC_INFO_CALL_SET_DYLD_IMAGES\n");
                                ret0 = 0;
                                ret1 = 0;
                                cflags = 0;
                                handled = true;
                            }
                            break;
                        case 0xffffffffffffffd1: { // mach_msg2
                            // ghost - intercept TASK_DYLD_INFO
                            // ghost: fail this to get around https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/dyldMain.cpp#L889
                            uint32_t flavor = *(uint32_t*)((void*)args[0] + 0x20);
                            // TODO: actually check for this being task_info
                            if (flavor == 0x11) {
                                LOG("Returning NOT_FOUND for TASK_DYLD_INFO\n");
                                ret0 = KERN_NOT_FOUND;
                                ret1 = 0;
                                cflags = 0xa0000000;
                                handled = true;
                            }
                            break;
                        }
                        case 0x10a:
                            if (!strcmp(args[0], "com.apple.featureflags.shm")) {
                                LOG("HACK denying shmget of %s\n", args[0]);
                                ret0 = KERN_DENIED;
                                ret1 = 0;
                                cflags = 0xa0000000;
                                handled = true;
                            }
                            break;
                    }
                    if (!handled) {
                        LOG("forwarding syscall %p(%p, %p, %p, %p, %p, %p, %p, %p)\n", num, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
                        ret0 = syscall_t(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], num);
                        asm volatile ("mov %0, x1" : "=r"(ret1));
                        asm volatile ("mrs %0, NZCV" : "=r"(cflags));
                        switch (num) {
                            case 0xc5: { // mmap
                                uint64_t addr = ret0;
                                size_t size = PAGE_ROUNDUP(args[1]);
                                struct vm_mmap m = (struct vm_mmap){
                                    .hyper = (void*)addr,
                                    .guest_va = (void*)addr,
                                    .len = size,
                                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                };
                                do_map(m);
                                break;
                            }
                            case 0xfffffffffffffff6: { // mach_vm_allocate
                                uint64_t addr = *(uint64_t*)args[1];
                                size_t size = args[2];
                                struct vm_mmap m = (struct vm_mmap){
                                    .hyper = (void*)addr,
                                    .guest_va = (void*)addr,
                                    .len = size,
                                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                };
                                do_map(m);
                                break;
                            }
                            case 0xfffffffffffffff1: { // mach_vm_map
                                uint64_t addr = *(uint64_t*)args[1];
                                size_t size = args[2];
                                struct vm_mmap m = (struct vm_mmap){
                                    .hyper = (void*)addr,
                                    .guest_va = (void*)addr,
                                    .len = size,
                                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                };
                                do_map(m);
                                break;
                            }
                        }
                    }
                    LOG("ret: %p %p %p\n", ret0, ret1, cflags);
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X0, ret0));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X1, ret1));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, (cpsr & (~(0b1111ULL << 28))) | cflags));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, elr));
                    continue;
                }

                printf("FAULT!\n");

                uint64_t far;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far));
                printf("Reg dump:\n");
                print_vm_registers(vcpu, true);

                break;
            } else if (ec == 0x17) {
                // Exception Class 0x17 is
                // "SMC instruction execution in AArch64 state, when SMC is not disabled."

                uint64_t x0;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                LOG("VM made an SMC call! x0 register holds 0x%llx\n", x0);
                LOG("Return to get on next instruction.\n");

                // ARM spec says trapped SMC have different return path, so it is required
                // to increment elr_el2 by 4 (one instruction.)
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                pc += 4;
                HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
            } else if (ec == 0x3C) {
                // Exception Class 0x3C is BRK in AArch64 state
                LOG("VM made an BRK call!\n");
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                LOG("PC: 0x%llx\n", pc);
                if ((pc & 0xfff) == 0xdf8) {
                    // skip over token == 0 check in pthread
                    LOG("Bypass: pthread token == 0\n");
                    pc += 4;
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
                    continue;
                } else if ((pc & 0xfff) == 0x554) {
                    LOG("Bypass: objc restartable ranges\n");
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, 0x28005e570));
                    continue;
                }

                printf("Unexpected BRK\n");
                printf("Reg dump:\n");
                print_vm_registers(vcpu, true);
                break;
            } else {
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                printf("Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx\n",
                    syndrome,
                    ec,
                    vcpu_exit->exception.virtual_address,
                    vcpu_exit->exception.physical_address
                );
                printf("Reg dump:\n");
                print_vm_registers(vcpu, true);
                break;
            }
        } else {
            LOG("Unexpected VM exit reason: %d\n", vcpu_exit->reason);
            break;
        }
    }

    hv_vcpu_destroy(vcpu);
    hv_vm_destroy();

    return 0;
}
