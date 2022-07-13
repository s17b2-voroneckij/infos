#ifndef UNWIND_PNACL_H
#define UNWIND_PNACL_H

#define STACK_GROWS_DOWNWARD 1

/* Define: __builtin_dwarf_sp_column */
#if defined(__x86_64__)
#define __builtin_dwarf_sp_column() 7
#elif defined(__i386__)
#define __builtin_dwarf_sp_column() 4
#elif defined(__arm__)
#define __builtin_dwarf_sp_column() 13
#elif defined(__mips__)
#define __builtin_dwarf_sp_column() 29
#else
#error "Unknown platform"
#endif

/* Define: DWARF_FRAME_REGISTERS */
#ifdef DWARF_FRAME_REGISTERS
#undef DWARF_FRAME_REGISTERS
#endif

#if defined(__x86_64__) || defined(__i386__)
#define DWARF_FRAME_REGISTERS 17
#elif defined(__arm__)
/*
 * r0-15, and map 256-287 for d0-d31 into regno 16 -> 48.
 * See:
 *http://infocenter.arm.com/help/topic/com.arm.doc.ihi0040b/IHI0040B_aadwarf.pdf
 */
#define DWARF_FRAME_REGISTERS 48
#elif defined(__mips__)
/*
 * Number of hardware registers we use in PNaCl. We have:
 *
 *  - 32 integer registers
 *  - 32 floating point registers
 *  - 8 condition code registers
 *  - 2 accumulator registers (hi and lo)
 */
#define DWARF_FRAME_REGISTERS 74
#else
#error "Unknown platform"
#endif


/* Define:__builtin_init_dwarf_reg_size_table */

/* TODO(mseaborn): Reduce the difference between architectures here.

   We could remove the need for the ARM/MIPS macro definitions of
   __builtin_init_dwarf_reg_size_table() below by passing
   --pnacl-frontend-target to Clang when compiling libgcc_eh, or by
   using GCC instead.

   PNaCl currently uses GCC for building libgcc_eh to avoid some LLVM
   bugs (see http://llvm.org/bugs/show_bug.cgi?id=8541).  We could
   switch back to using LLVM if these were fixed.

   It might be better to switch to using libunwind instead of libgcc_eh
   (see https://code.google.com/p/nativeclient/issues/detail?id=2749).  */

#if defined(__i386__) || defined(__x86_64__)
/* Assume we are compiling with GCC, which provides a working
   definition of __builtin_init_dwarf_reg_size_table().  */

#elif defined(__arm__)
#define __builtin_init_dwarf_reg_size_table(table) do {                 \
  int i;                                                                \
  /* Integer registers are 32bit. */                                    \
  for (i = 0; i < 16; ++i)                                              \
    table[i] = 4;                                                       \
  /* The rest are VFPv3/NEON (64bit). */                                \
  for (i = 16; i < DWARF_FRAME_REGISTERS; ++i)                          \
    table[i] = 8;                                                       \
} while (0)

#elif defined(__mips__)
/* All regs are 32bit = 4 bytes */
#define __builtin_init_dwarf_reg_size_table(table) do { \
  int i; \
  for (i = 0; i < DWARF_FRAME_REGISTERS; ++i) \
    table[i] = 4; \
} while (0)

#else
#error "Unknown platform"
#endif

/* This corresponds to:  __builtin_eh_return_data_regno(0)  */
#if defined(__x86_64__)
#define pnacl_unwind_result0_reg() 0
#elif defined(__i386__)
#define pnacl_unwind_result0_reg() 0
#elif defined(__arm__)
#define pnacl_unwind_result0_reg() 4
#elif defined(__mips__)
#define pnacl_unwind_result0_reg() 4
#else
#error "unknown platform"
#endif

/* This corresponds to:   __builtin_eh_return_data_regno(1) */
#if defined(__x86_64__)
#define pnacl_unwind_result1_reg() 1
#elif defined(__i386__)
#define pnacl_unwind_result1_reg() 2
#elif defined(__arm__)
#define pnacl_unwind_result1_reg() 5
#elif defined(__mips__)
#define pnacl_unwind_result1_reg() 5
#else
#error "unknown platform"
#endif

#endif /* UNWIND_PNACL_H */
