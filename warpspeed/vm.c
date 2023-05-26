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
#include "loader.h"

// Diagnostics
#define HYP_ASSERT_SUCCESS(ret) do { \
    if ((hv_return_t)(ret) != HV_SUCCESS) { \
        LOG("%s:%d: %s = %x\n", __FILE__, __LINE__, #ret, (ret)); \
        abort(); \
    } \
} while (0)

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
extern int     __shared_region_check_np(uint64_t *startaddress);

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
            LOG("pa too big\n");
            exit(1);
        }
        if (pa & ((1 << 12) - 1)) {
            LOG("low bits in pa set\n");
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

typedef struct {
	char     magic[16];
	uint32_t mappingOffset;
	uint32_t mappingCount;
	uint32_t imagesOffsetOld;
	uint32_t imagesCountOld;
	uint64_t dyldBaseAddress;
	uint64_t codeSignatureOffset;
	uint64_t codeSignatureSize;
	uint64_t slideInfoOffset;
	uint64_t slideInfoSize;
	uint64_t localSymbolsOffset;
	uint64_t localSymbolsSize;
	uint8_t  uuid[16];
	uint64_t cacheType;
	uint32_t branchPoolsOffset;
	uint32_t branchPoolsCount;
	uint64_t accelerateInfoAddr;
	uint64_t accelerateInfoSize;
	uint64_t imagesTextOffset;
	uint64_t imagesTextCount;
} cache_hdr_t;

typedef struct {
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint32_t maxProt;
	uint32_t initProt;
} cache_map_t;

int main(int argc, char **argv)
{
    if (argc < 2) {
        LOG("Usage: %s /path/to/bin [args...]", argv[0]);
        exit(1);
    }

    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vcpu_exit;

    HYP_ASSERT_SUCCESS(hv_vm_create(NULL));
    HYP_ASSERT_SUCCESS(hv_vcpu_create(&vcpu, &vcpu_exit, NULL));

    struct load_results res = {};
    res.envc = 1;

    char *DYLD_SHARED_REGION_env = "DYLD_SHARED_REGION=avoid";

    uint64_t *env = mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    res.envp = env;
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = env,
        .guest_va = env,
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_EXEC,
    };
    char *envchar = &env[res.envc];
    env[0] = strcpy(envchar, DYLD_SHARED_REGION_env);
    envchar += strlen(DYLD_SHARED_REGION_env) + 1;

    load(argv[1], false, &res);
    setup_stack64(argv[1], &res);

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
    LOG("tls %p\n", tpidrro_el0);
    void *tls= mmap(0, HV_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    // copy out of the host TLS to ensure tid and similar are correct
    // ghost: TODO: do we need to zero anything? locks?
    memcpy(tls, PAGE_ALIGN(tpidrro_el0), HV_PAGE_SIZE);
    HYP_ASSERT_SUCCESS(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDRRO_EL0, tpidrro_el0));
    res.mappings[res.n_mappings++] = (struct vm_mmap) {
        .hyper = (void*)tls,
        .guest_va = PAGE_ALIGN(tpidrro_el0),
        .len = HV_PAGE_SIZE,
        .prot = PROT_READ | PROT_WRITE,
    };

    /* // shared region */
    /* uint64_t shared_base; */
    /* __shared_region_check_np(&shared_base); */
    /* LOG("shared base: %p\n", shared_base); */
    /* int fd = open("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e", O_RDONLY); */
    /* if (fd < 0) { */
    /*     LOG("error opening cache: %s", strerror(errno)); */
    /*     exit(1); */
    /* } */
    /* void *shared_cache = mmap(0, 0x5f3f8000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0); */
    /* res.mappings[res.n_mappings++] = (struct vm_mmap) { */
    /*     .hyper = (void*)shared_cache, */
    /*     .guest_va = (void*)shared_cache, */
    /*     .len = 0x5f3f8000, */
    /*     .prot = PROT_READ | PROT_WRITE | PROT_EXEC, */
    /* }; */
    /* LOG("shared cache mapped at %p\n", shared_cache); */
    /* uint64_t shared_offset = shared_cache - shared_base; */

    /* mach_port_t self = mach_task_self(); */
    /* vm_region_basic_info_data_64_t info; */
    /* mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64; */
    /* mach_vm_address_t region_address = (mach_vm_address_t)shared_base + 0x5f3f8000; */
    /* mach_vm_size_t region_size = 0; */
    /* mach_port_t object_name; */

    /* while (region_address < 0x300000000) { */
    /*     kern_return_t result = mach_vm_region(self, &region_address, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name); */
    /*     if (result != KERN_SUCCESS) { */
    /*         exit(1); */
    /*     } */

    /*     uint64_t valid_start = 0; */
    /*     uint64_t valid_len = 0; */
    /*     for (uint64_t addr = region_address; addr < region_address + region_size; addr += HV_PAGE_SIZE) { */
    /*         char tmp; */
    /*         mach_vm_size_t outsize = 0; */
    /*         bool addr_ok = (mach_vm_read_overwrite(self, addr, 1, &tmp, &outsize) == KERN_SUCCESS); */
    /*         if (addr_ok) { */
    /*             if (valid_start == 0) { */
    /*                 valid_start = addr; */
    /*             } */
    /*             valid_len += HV_PAGE_SIZE; */
    /*         } else if (valid_start && !addr_ok) { */
    /*             LOG("adding contiguous mapping %p-%p\n", valid_start, valid_start+valid_len); */
    /*             void *shared_copy = mmap(valid_start + shared_offset, valid_len, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0); */
    /*             LOG("%p\n", shared_copy); */
    /*             memcpy(shared_copy, valid_start, valid_len); */
    /*             res.mappings[res.n_mappings++] = (struct vm_mmap) { */
    /*                 .hyper = (void*)shared_copy, */
    /*                 .guest_va = (void*)shared_copy, */
    /*                 .len = valid_len, */
    /*                 .prot = PROT_READ | PROT_WRITE | PROT_EXEC, */
    /*             }; */
    /*             valid_start = 0; */
    /*             valid_len = 0; */
    /*         } */
    /*     } */

    /*     if (valid_start) { */
    /*         LOG("adding contiguous mapping %p-%p\n", valid_start, valid_start+valid_len); */
    /*         void *shared_copy = mmap(valid_start + shared_offset, valid_len, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0); */
    /*         LOG("%p\n", shared_copy); */
    /*         memcpy(shared_copy, valid_start, valid_len); */
    /*         res.mappings[res.n_mappings++] = (struct vm_mmap) { */
    /*             .hyper = (void*)shared_copy, */
    /*             .guest_va = (void*)shared_copy, */
    /*             .len = valid_len, */
    /*             .prot = PROT_READ | PROT_WRITE | PROT_EXEC, */
    /*         }; */
    /*     } */

    /*     region_address = region_address + region_size; */
    /* } */

    // Configure 1:1 translation tables
    page_tables = mmap(0, HV_PAGE_SIZE * 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    HYP_ASSERT_SUCCESS(hv_vm_map(page_tables, (hv_ipa_t)PAGING_PA, HV_PAGE_SIZE * 8192, PROT_READ | PROT_WRITE));

    for (int i = 0; i < res.n_mappings; i++) {
        do_map(res.mappings[i]);
    }

    /* // ghost: dyld private hack: trap when we'd be setting result->slide (https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/SharedCacheRuntime.cpp#LL983C16-L983C16) */
    /* memcpy(res.entry_point + (0x000352c0 - 0x00004950), brk_insns, sizeof(brk_insns)); */
    // to overwrite archs keysOff=1, osBinariesOnly=1 in https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/DyldProcessConfig.cpp#L652
    memcpy(res.entry_point + (0x00009514 - 0x00004950), brk_insns, sizeof(brk_insns));
    // dbg hasExportedSymbol
    memcpy(res.entry_point + (0x0001e938 - 0x00004950), brk_insns, sizeof(brk_insns));
    //memcpy(res.entry_point + (0x0001ea70 - 0x00004950), brk_insns, sizeof(brk_insns));

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
                LOG("ELR_EL1: 0x%llx\n", elr);
                uint64_t esr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr));
                LOG("ESR: 0x%llx\n", esr);
                uint64_t cpsr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr));

                LOG("Reg dump:\n");
                for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
                    uint64_t s;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &s));
                    LOG("X%d: 0x%llx\n", reg, s);
                }

                if (esr == 0x56000080) {  // SVC in aarch64
                    uint64_t args[8];
                    for (int i = HV_REG_X0; i < HV_REG_X8; i++) {
                        HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, i, &args[i - HV_REG_X0]));
                    }
                    uint64_t num;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X16, &num));
                    LOG("forwarding syscall %p(%p, %p, %p, %p, %p, %p, %p, %p)\n", num, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
                    uint64_t cflags, ret0, ret1;
                    switch (num) {
                        /* case 0x126:  // shared_region_check_np */
                        /*     //*(uint64_t*)args[0] = shared_cache; */
                        /*     ret0 = EFAULT; */
                        /*     ret1 = 0; */
                        /*     cflags = (1 << 29); */
                        /*     break; */
                        /* case 0x150: // proc_info (PROC_INFO_CALL_SET_DYLD_IMAGES is what we really care about) */
                        /*     assert(args[0] == 0xf); */
                        /*     ret0 = 0; */
                        /*     ret1 = 0; */
                        /*     cflags = 0; */
                        /*     break; */
                        /* case 0x203:  // ulock_wait -- ghost hack for mapping dyld ourselves causing kernel to -EFAULT */
                        /*     *(uint32_t*)args[1] = 0; */
                        /*     ret0 = 0; */
                        /*     ret1 = 0; */
                        /*     cflags = 0; */
                        /*     break; */
                        default: {
                            if (num == 92 && args[1] == 0x62) {
                                // fcntl(fd, F_CHECK_LV)
                                // ghost: alternatively `codesign -s - /usr/local/lib/libSystem.B.dylib`
                                ret0 = 0;
                                ret1 = 0;
                                cflags = 0;
                                break;
                            } else if (num == 0xc5 && (args[0] & 0x3fff) != 0) {
                                LOG("fixing up mmap\n");
                                // ghost: mmap fixup for dyld loading non-aligned segments
                                uint64_t aligned_addr = PAGE_ALIGN(args[0]);
                                size_t aligned_size = PAGE_ROUNDUP(args[1]);
                                // map aligned addr/size from no fd
                                ret0 = syscall_t(aligned_addr, aligned_size, args[2], MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0, 0, 0, num);
                                asm volatile ("mov %0, x1" : "=r"(ret1));
                                asm volatile ("mrs %0, NZCV" : "=r"(cflags));
                                LOG("aligned mmap returned %p\n", ret0);
                                struct vm_mmap m = (struct vm_mmap){
                                    .hyper = (void*)ret0,
                                    .guest_va = (void*)ret0,
                                    .len = aligned_size,
                                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                };
                                do_map(m);
                                // then read into correct offset if fd was set
                                if (args[4] > 0) {
                                    // ghost: todo: ensure this is a full read
                                    pread(args[4], ret0 + (args[0] - aligned_addr), args[1], (args[0] - aligned_addr));
                                }
                                break;
                            }
                            ret0 = syscall_t(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], num);
                            asm volatile ("mov %0, x1" : "=r"(ret1));
                            asm volatile ("mrs %0, NZCV" : "=r"(cflags));
                            switch (num) {
                                case 5: {  // open
                                    LOG("open(%s)\n", args[0]);
                                    break;
                                }
                                case 0xc5: { // mmap
                                    uint64_t addr = ret0;
                                    LOG("mmap returned %p\n", addr);
                                    if (!(cflags & (1<<29))) {
                                        size_t size = PAGE_ROUNDUP(args[1]);
                                        struct vm_mmap m = (struct vm_mmap){
                                            .hyper = (void*)addr,
                                            .guest_va = (void*)addr,
                                            .len = size,
                                            .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                        };
                                        do_map(m);
                                    }
                                    break;
                                }
                                /* case 0xffffffffffffffd1: { // mach_msg2 */
                                /*     // ghost - TASK_DYLD_INFO hack */
                                /*     // let the kernel return a correct version, then adjust the addr */
                                /*     // commented code below is if we need to stub the trap entirely */
                                /*     /1* uint32_t flavor = *(uint32_t*)((void*)args[0] + 0x20); *1/ */
                                /*     /1* assert(flavor == 0x11); *1/ */
                                /*     /1* // drop in a fake task_dyld_info *1/ */
                                /*     /1* // magic values here are copied from what xnu does for real. no idea. *1/ */
                                /*     /1* *(mach_msg_header_t*)args[0] = (mach_msg_header_t) { *1/ */
                                /*     /1*     .msgh_bits = 0x1200, *1/ */
                                /*     /1*     .msgh_size = 0x3c, *1/ */
                                /*     /1*     .msgh_remote_port = 0, *1/ */
                                /*     /1*     .msgh_local_port = ((mach_msg_header_t*)args[0])->msgh_remote_port, *1/ */
                                /*     /1*     .msgh_id = ((mach_msg_header_t*)args[0])->msgh_id + 100, *1/ */
                                /*     /1* }; *1/ */
                                /*     uint32_t *inner = args[0] + sizeof(mach_msg_header_t); */
                                /*     /1* inner[0] = 0; *1/ */
                                /*     /1* inner[1] = 1; *1/ */
                                /*     /1* inner[2] = 0; *1/ */
                                /*     /1* inner[3] = 5;  // sizeof(task_dyld_info) / sizeof(natural_t) *1/ */
                                /*     struct task_dyld_info *out = &inner[4]; */
                                /*     LOG("%d\n", *(uint32_t*)out->all_image_info_addr); */
                                /*     out->all_image_info_addr += shared_offset; */
                                /*     LOG("adjusted all_image_info to %p\n", out->all_image_info_addr); */
                                /*     LOG("%d\n", *(uint32_t*)out->all_image_info_addr); */
                                /*     /1* out->all_image_info_size = 0x170; *1/ */
                                /*     /1* out->all_image_info_format = 1; *1/ */
                                /*     /1* ret0 = 0; *1/ */
                                /*     /1* ret1 = 0x200000003; *1/ */
                                /*     /1* cflags = 0xa0000000; *1/ */
                                /*     break; */
                                /* } */
                                case 0xfffffffffffffff6: { // mach_vm_allocate
                                    uint64_t addr = *(uint64_t*)args[1];
                                    size_t size = args[2];
                                    struct vm_mmap m = (struct vm_mmap){
                                        .hyper = (void*)addr,
                                        .guest_va = (void*)addr,
                                        .len = size,
                                        .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                    };
                                    if (size < 0x10000000) {
                                        // ghost: hack - skip actually allocating large region pre-allocs that dyld does
                                        // the subsequent mmap will take care of the mapping.
                                        // https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/Loader.cpp#L1244
                                        do_map(m);
                                    }
                                    break;
                                }
                                default:
                                    break;
                            }
                            break;
                        }
                    }
                    LOG("ret: %p %p %p\n", ret0, ret1, cflags);
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X0, ret0));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X1, ret1));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, (cpsr & (~(0b1111ULL << 28))) | cflags));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, elr));

                    /* uint64_t x; */
                    /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL1, &x)); */
                    /* LOG("stack:\n"); */
                    /* for (int offset = 0; offset > -0x20; offset -= 1) { */
                    /*     LOG("%d: %p\n", offset, ((uint64_t*)x)[offset]); */
                    /* } */
                    continue;
                }

                uint64_t far;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far));
                LOG("FAR_EL1: 0x%llx\n", far);
                uint64_t x;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &x));
                LOG("ESR: 0x%llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &x));
                /* LOG("sctlr %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, &x)); */
                /* LOG("cpacr %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &x)); */
                /* LOG("ttbr0 %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, &x)); */
                /* LOG("tcr %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_PAR_EL1, &x)); */
                LOG("par %llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL1, &x));
                /* LOG("stack:\n"); */
                /* for (int offset = 0; offset > -0x20; offset -= 1) { */
                /*     LOG("%d: %p\n", offset, ((uint64_t*)x)[offset]); */
                /* } */

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
                if ((pc & 0xfff) == 0x2c0) {
                    /* uint64_t x8; */
                    /* HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X19, &x8)); */
                    /* uint64_t *x19; */
                    /* HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X19, &x19)); */
/* #define NEW_SLIDE (0x100000000ULL) */
                    /* LOG("overwriting dyld private map result->slide to %p\n", NEW_SLIDE); */
                    /* *x19 = x8; */
                    /* *(x19 + 1)= NEW_SLIDE; */
                    /* pc += 4; */
                    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc)); */
                    /* continue; */
                } else if ((pc & 0xfff) == 0x508) {
                    uint64_t x0;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X1, x0));
                    LOG("arch: %s\n", x0);
                    pc += 4;
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
                    continue;
                } else if ((pc & 0xfff) == 0x268) {  // compatibleSlice
                    uint64_t x;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X6, &x));
                    LOG("compat x6: %p\n", x);
                    *(uint32_t*)pc = 0xd503237f;  // put the real insn back
                    /* pc += 4; */
                    /* HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc)); */
                    continue;
                } else if ((pc & 0xfff) == 0x514) {
                    // overwrite keysOff = true, platform = false
                    // otherise "mach-o file, but is an incompatible architecture (have 'arm64e', need 'arm64')"
                    // https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/common/MachOFile.cpp#L2654
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X2, 1));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X3, 0));
                    pc += 4;
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
                    continue;
                } else if ((pc & 0xfff) == 0x938) {
                    // hasExportedSymbol
                    uint64_t x;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X3, &x));
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_X24, x));
                    uint64_t x0;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_X0, &x0));
                    uint16_t pathoff = *(uint16_t*)(x0 + 0x10);
                    fprintf(stderr, "hasExportedSymbol: %s in %s\n", x, x0 + pathoff);
                    pc += 4;
                    HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc));
                    continue;
                }
                fprintf(stderr, "UNEXPECTED\n");
                LOG("Reg dump:\n");
                for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
                    uint64_t s;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &s));
                    LOG("X%d: 0x%llx\n", reg, s);
                    /* if (reg == HV_REG_X19) { */
                    /*     LOG("msg: %s\n", (char*)s); */
                    /* } */
                }
                LOG("PC: 0x%llx\n", pc);
                uint64_t elr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr));
                LOG("ELR_EL1: 0x%llx\n", elr);
                uint64_t far;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far));
                LOG("FAR_EL1: 0x%llx\n", far);
                uint64_t x;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &x));
                LOG("ESR: 0x%llx\n", x);
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &x));
                /* LOG("sctlr %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, &x)); */
                /* LOG("cpacr %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, &x)); */
                /* LOG("ttbr0 %llx\n", x); */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, &x)); */
                /* LOG("tcr %llx\n", x); */
                // ghost: continue here in case this entire thing is being run under lldb, which would insert a brk
                // at __dyld_debugger_notification for its own purposes
                /* pc += 4; */
                /* HYP_ASSERT_SUCCESS(hv_vcpu_set_reg(vcpu, HV_REG_PC, pc)); */
                break;
            } else {
                uint64_t pc;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
                LOG("Unexpected VM exception: 0x%llx, EC 0x%x, VirtAddr 0x%llx, IPA 0x%llx\n",
                    syndrome,
                    ec,
                    vcpu_exit->exception.virtual_address,
                    vcpu_exit->exception.physical_address
                );
                LOG("Reg dump:\n");
                for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
                    uint64_t s;
                    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &s));
                    LOG("X%d: 0x%llx\n", reg, s);
                }
                LOG("PC: 0x%llx\n", pc);
                uint64_t elr;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr));
                LOG("ELR_EL1: 0x%llx\n", elr);
                uint64_t far;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &far));
                LOG("FAR_EL1: 0x%llx\n", far);
                uint64_t x;
                HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &x));
                LOG("ESR: 0x%llx\n", x);
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
