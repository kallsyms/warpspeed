#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <Hypervisor/Hypervisor.h>
#include <libunwind.h>

#include "common.h"

void print_aarch64_cpsr_flags(uint32_t cpsr) {
  printf("CPSR Flags:\n");
  printf("    Negative (N) Flag: %d\n", (cpsr >> 31) & 1);
  printf("    Zero (Z) Flag: %d\n", (cpsr >> 30) & 1);
  printf("    Carry (C) Flag: %d\n", (cpsr >> 29) & 1);
  printf("    Overflow (V) Flag: %d\n", (cpsr >> 28) & 1);
}

void print_aarch64_pstate(uint32_t pstate) {
  printf("CPSR/PSTATE Register:\n");
  printf("    Negative (N) Flag: %d\n", (pstate >> 31) & 1);
  printf("    Zero (Z) Flag: %d\n", (pstate >> 30) & 1);
  printf("    Carry (C) Flag: %d\n", (pstate >> 29) & 1);
  printf("    Overflow (V) Flag: %d\n", (pstate >> 28) & 1);
  printf("    Debug (D) Flag: %d\n", (pstate >> 9) & 1);
  printf("    Interrupt (I) Flag: %d\n", (pstate >> 7) & 1);
  printf("    Mask (A) Flag: %d\n", (pstate >> 8) & 1);
  printf("    Mode (M) Field: %d\n", (pstate >> 0) & 0x1F);
}

void print_aarch64_sctlr(uint64_t sctlr) {
  printf("  SCTLR: 0x%08llx:\n", sctlr);
  printf("    Alignment Fault (A) Bit: %llu\n", (sctlr >> 1) & 1);
  printf("    Instruction Cache (C) Bit: %llu\n", (sctlr >> 2) & 1);
  printf("    Data Cache (D) Bit: %llu\n", (sctlr >> 3) & 1);
  printf("    Instruction and Data Caches (I) Bit: %llu\n", (sctlr >> 12) & 1);
  printf("    Stack Alignment Check (SA) Bit: %llu\n", (sctlr >> 22) & 1);
  printf("    Exception Endianness (E) Bit: %llu\n", (sctlr >> 25) & 1);
  printf("    User Access Override (U) Bit: %llu\n", (sctlr >> 26) & 1);
  printf("    Big Endian (EE) Bit: %llu\n", (sctlr >> 31) & 1);
}

void print_aarch64_esr(uint32_t level, uint64_t esr) {
  printf("ESR %d Register: 0x%llx\n", level, esr);
  printf("    Exception Class (EC) Field: 0x%llx\n", (esr >> 26) & 0x3F);
  printf("    \t");
  switch (esr >> 26 & 0x3F) {
  case 0x15:
    printf("Exception class: Instruction Abort\n");
    // Handle Instruction Abort exception
    break;
  case 0x20:
    printf("Exception class: PC Alignment Fault\n");
    // Handle PC Alignment Fault exception
    break;
  case 0x25:
    printf("Exception class: Data Abort\n");
    // Handle Data Abort exception
    break;
  case 0x26:
    printf("Exception class: SP Alignment Fault\n");
    // Handle SP Alignment Fault exception
    break;
  case 0x3C:
    printf("Exception class: Breakpoint\n");
    // Handle Breakpoint exception
    break;
  case 0x3D:
    printf("Exception class: Software Step\n");
    // Handle Software Step exception
    break;
  case 0x3E:
    printf("Exception class: Watchpoint\n");
    // Handle Watchpoint exception
    break;
  default:
    printf("Unknown exception class\n");
    // Handle other exception classes or provide an error message
    break;
  }
  printf("    IL (Instruction Length) Bit: %llx\n", (esr >> 25) & 1);
  printf("    ISS (Instruction Specific Syndrome) Field: 0x%llx\n",
         esr & 0x1FFFFFF);
}

void print_aarch64_cpacr(uint64_t cpacr) {
  printf("CPACR Register:\n");
  printf("    CP0 Access Permission: %llu\n", (cpacr >> 0) & 0b11);
  printf("    CP1 Access Permission: %llu\n", (cpacr >> 2) & 0b11);
  printf("    CP2 Access Permission: %llu\n", (cpacr >> 4) & 0b11);
  printf("    CP3 Access Permission: %llu\n", (cpacr >> 6) & 0b11);
  return;
}

__attribute__((always_inline)) void print_aarch64_el1_regs(hv_vcpu_t *vcpu) {
  uint64_t scratch;
  uint64_t cpsr;
  uint64_t reg_value;

  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &scratch));
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL1, &reg_value));
  printf("\tSCTLR:\t\t0x%08llx\t\tSP:\t0x%08llx\n", scratch, reg_value);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr));
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, &scratch));
  printf("\tCPSR:\t\t0x%0llx\t\tSPSR:\t0x%08llx\n", cpsr, scratch);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, &reg_value));
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_PAR_EL1, &scratch));
  printf("\tFAR:\t\t0x%0llx\t\tPAR:\t0x%08llx\n", reg_value, scratch);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &reg_value));
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &scratch));
  printf("\tESR:\t\t0x%llx\t\tELR:\t0x%08llx\n", reg_value, scratch);
  printf("\n");
  print_aarch64_esr(1, reg_value);
  printf("\n");
  print_aarch64_pstate(cpsr);
  printf("\n");
}

__attribute__((always_inline)) void
print_aarch64_registers_wide(hv_vcpu_t *vcpu, uint32_t reg_start,
                             uint32_t reg_end) {
  uint64_t reg_value;
  for (uint32_t reg = reg_start; reg <= reg_end; reg++) {
    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &reg_value));
    printf("\tX%2d:  0x%016llx", reg, reg_value);
    if (((reg + 1) % 4) == 0) {
      printf("\n");
    } else {
      printf("  ");
    }
  }
  printf("\n");
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &reg_value));
  printf("\tPC:\t\t0x%llx\n", reg_value);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_LR, &reg_value));
  printf("\tLR:\t\t0x%llx\n", reg_value);

  printf("\n");
  print_aarch64_el1_regs(vcpu);
}

__attribute__((always_inline)) void print_vm_registers(hv_vcpu_t *vcpu,
                                                       bool wide) {
  printf("VM Register State:\n");
  if (wide) {
    print_aarch64_registers_wide(vcpu, 0, 31);
    return;
  }
  uint64_t reg_value;
  // print user registers
  for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(*vcpu, reg, &reg_value));
    printf("\tX%d:\t\t0x%llx\n", reg, reg_value);
  }
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &reg_value));
  printf("\tPC:\t\t0x%llx\n", reg_value);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_LR, &reg_value));
  printf("\tLR:\t\t0x%llx\n", reg_value);
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &reg_value));
  printf("\tSP:\t\t0x%llx\n", reg_value);
  printf("\n");
  print_aarch64_el1_regs(vcpu);
  printf("\n");
}

__attribute__((always_inline)) void
print_aarch64_stack_trace(hv_vcpu_t *vcpu, uint32_t max_frames) {
  unw_cursor_t cursor;
  unw_context_t context;
  unw_word_t ip;
  char sym[4096];

  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  printf("Backtrace:\n");

  // Initialize the cursor with the remote context from the vcpu.
  uint64_t pc;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc));
  uint64_t sp;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL1, &sp));  // ghost TODO: sp_el0
  uint64_t lr;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_LR, &lr));
  uint64_t fp;
  HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, HV_REG_FP, &fp));

  for (uint32_t reg = HV_REG_X0; reg <= HV_REG_X30; reg++) {
    uint64_t reg_value;
    HYP_ASSERT_SUCCESS(hv_vcpu_get_reg(vcpu, reg, &reg_value));
    unw_set_reg(&cursor, UNW_ARM64_X0 + (reg - HV_REG_X0), reg_value);
  }
  unw_set_reg(&cursor, UNW_REG_IP, pc);
  unw_set_reg(&cursor, UNW_ARM64_SP, sp);
  unw_set_reg(&cursor, UNW_ARM64_FP, fp);
  unw_set_reg(&cursor, UNW_ARM64_LR, lr);

  uint32_t count = 0;
  while (unw_step(&cursor) > 0 && count < max_frames) {
    unw_word_t offset, pc;
    if (unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
      printf("ERROR: cannot read program counter\n");
      return;
    }

    printf("\t0x%lx: ", pc);

    if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0)
      printf("(%s+0x%lx)\n", sym, offset);
    else {
      printf("-- no symbol name found\n");
    }
    count++;
  }
}
