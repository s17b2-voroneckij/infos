/* DWARF2 exception handling and frame unwind runtime interface routines.
   Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
   2008, 2009, 2010  Free Software Foundation, Inc.

   This file is part of GCC.

   GCC is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GCC is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

#include <infos/util/lock-c.h>
#include <infos/unwind/tconfig.h>
#include <infos/unwind/tsystem.h>
#include <infos/unwind/coretypes.h>
#include <infos/unwind/tm.h>
#include <infos/unwind/dwarf2.h>
#include <infos/unwind/unwind.h>
#ifdef __USING_SJLJ_EXCEPTIONS__
# define NO_SIZE_OF_ENCODED_VALUE
#endif
#include <infos/unwind/unwind-pe.h>
#include <infos/unwind/unwind-dw2-fde.h>
#include <infos/unwind/gthr.h>
#include <infos/unwind/unwind-dw2.h>

#ifndef __USING_SJLJ_EXCEPTIONS__

#ifndef STACK_GROWS_DOWNWARD
#define STACK_GROWS_DOWNWARD 0
#else
#undef STACK_GROWS_DOWNWARD
#define STACK_GROWS_DOWNWARD 1
#endif

/* Dwarf frame registers used for pre gcc 3.0 compiled glibc.  */
#ifndef PRE_GCC3_DWARF_FRAME_REGISTERS
#define PRE_GCC3_DWARF_FRAME_REGISTERS DWARF_FRAME_REGISTERS
#endif

/* @LOCALMOD-BEGIN */
#if defined(__arm__)
/*
 * Override DWARF_REG_TO_UNWIND_COLUMN to map high ARM register numbers
 * into lower and obsolete register numbers. See unwind-pnacl.h.
 */
int DWARF_REG_TO_UNWIND_COLUMN(int REGNO) {
  if (REGNO >= 0 && REGNO < 16)
    return REGNO;
  if (REGNO >= 256 && REGNO < 287)
    return (REGNO - 256 + 16);
  /*
   * Otherwise, assume REGNO is already mapped down from 256-287 -> 16-48.
   * The normal 16-48 ARM dwarf registers are obsolete
   * so this is sort of okay.
   */
  if (REGNO < DWARF_FRAME_REGISTERS)
    return REGNO;
  abort();
}

#else
#ifndef DWARF_REG_TO_UNWIND_COLUMN
#define DWARF_REG_TO_UNWIND_COLUMN(REGNO) (REGNO)
#endif
#endif  // __arm__
/* @LOCALMOD-END


/* This is the register and unwind state for a particular frame.  This
   provides the information necessary to unwind up past a frame and return
   to its caller.  */
struct _Unwind_Context
{
  void *reg[DWARF_FRAME_REGISTERS+1];
  void *cfa;
  void *ra;
  void *lsda;
  struct dwarf_eh_bases bases;
  /* Signal frame context.  */
#define SIGNAL_FRAME_BIT ((~(_Unwind_Word) 0 >> 1) + 1)
  /* Context which has version/args_size/by_value fields.  */
#define EXTENDED_CONTEXT_BIT ((~(_Unwind_Word) 0 >> 2) + 1)
  _Unwind_Word flags;
  /* 0 for now, can be increased when further fields are added to
     struct _Unwind_Context.  */
  _Unwind_Word version;
  _Unwind_Word args_size;
  char by_value[DWARF_FRAME_REGISTERS+1];
};

/* Byte size of every register managed by these routines.  */
static unsigned char dwarf_reg_size_table[DWARF_FRAME_REGISTERS+1];


/* Read unaligned data from the instruction buffer.  */

union unaligned
{
  void *p;
  unsigned u2 __attribute__ ((mode (HI)));
  unsigned u4 __attribute__ ((mode (SI)));
  unsigned u8 __attribute__ ((mode (DI)));
  signed s2 __attribute__ ((mode (HI)));
  signed s4 __attribute__ ((mode (SI)));
  signed s8 __attribute__ ((mode (DI)));
} __attribute__ ((packed));

static void uw_update_context (struct _Unwind_Context *, _Unwind_FrameState *);
static _Unwind_Reason_Code uw_frame_state_for (struct _Unwind_Context *,
					       _Unwind_FrameState *);

static inline void *
read_pointer (const void *p) { const union unaligned *up = p; return up->p; }

static inline int
read_1u (const void *p) { return *(const unsigned char *) p; }

static inline int
read_1s (const void *p) { return *(const signed char *) p; }

static inline int
read_2u (const void *p) { const union unaligned *up = p; return up->u2; }

static inline int
read_2s (const void *p) { const union unaligned *up = p; return up->s2; }

static inline unsigned int
read_4u (const void *p) { const union unaligned *up = p; return up->u4; }

static inline int
read_4s (const void *p) { const union unaligned *up = p; return up->s4; }

static inline unsigned long
read_8u (const void *p) { const union unaligned *up = p; return up->u8; }

static inline unsigned long
read_8s (const void *p) { const union unaligned *up = p; return up->s8; }

static inline _Unwind_Word
_Unwind_IsSignalFrame (struct _Unwind_Context *context)
{
  return (context->flags & SIGNAL_FRAME_BIT) ? 1 : 0;
}

static inline void
_Unwind_SetSignalFrame (struct _Unwind_Context *context, int val)
{
  if (val)
    context->flags |= SIGNAL_FRAME_BIT;
  else
    context->flags &= ~SIGNAL_FRAME_BIT;
}

static inline _Unwind_Word
_Unwind_IsExtendedContext (struct _Unwind_Context *context)
{
  return context->flags & EXTENDED_CONTEXT_BIT;
}

/* Get the value of register INDEX as saved in CONTEXT.  */

inline _Unwind_Word
_Unwind_GetGR (struct _Unwind_Context *context, int index)
{
  int size;
  void *ptr;

#ifdef DWARF_ZERO_REG
  if (index == DWARF_ZERO_REG)
    return 0;
#endif

  index = DWARF_REG_TO_UNWIND_COLUMN (index);
  gcc_assert (index < (int) sizeof(dwarf_reg_size_table));
  size = dwarf_reg_size_table[index];
  ptr = context->reg[index];

  if (_Unwind_IsExtendedContext (context) && context->by_value[index])
    return (_Unwind_Word) (_Unwind_Internal_Ptr) ptr;

  /* This will segfault if the register hasn't been saved.  */
  if (size == sizeof(_Unwind_Ptr))
    return * (_Unwind_Ptr *) ptr;
  else
    {
      gcc_assert (size == sizeof(_Unwind_Word));
      return * (_Unwind_Word *) ptr;
    }
}

static inline void *
_Unwind_GetPtr (struct _Unwind_Context *context, int index)
{
  return (void *)(_Unwind_Ptr) _Unwind_GetGR (context, index);
}

/* Get the value of the CFA as saved in CONTEXT.  */

_Unwind_Word
_Unwind_GetCFA (struct _Unwind_Context *context)
{
  return (_Unwind_Ptr) context->cfa;
}

/* Overwrite the saved value for register INDEX in CONTEXT with VAL.  */

inline void
_Unwind_SetGR (struct _Unwind_Context *context, int index, _Unwind_Word val)
{
  int size;
  void *ptr;

  index = DWARF_REG_TO_UNWIND_COLUMN (index);
  gcc_assert (index < (int) sizeof(dwarf_reg_size_table));
  size = dwarf_reg_size_table[index];

  if (_Unwind_IsExtendedContext (context) && context->by_value[index])
    {
      context->reg[index] = (void *) (_Unwind_Internal_Ptr) val;
      return;
    }

  ptr = context->reg[index];

  if (size == sizeof(_Unwind_Ptr))
    * (_Unwind_Ptr *) ptr = val;
  else
    {
      gcc_assert (size == sizeof(_Unwind_Word));
      * (_Unwind_Word *) ptr = val;
    }
}

/* @LOCALMOD-START */
/*
 * new ABI functions to support a platform independent version
 * of libstdc++
 */

/* abstract away __builtin_eh_return_data_regno(0) 
 * this needs to be better researched and documented 
 * the index is likely influenced by  DWARF_FRAME_REGNUM(REG) and
 * EH_RETURN_DATA_REGNO
 * c.f.: expand_builtin_eh_return_data_regno()
 *
 * NOTE: when gcc restores registers it relies on epilog code
 * of the function containing the call to __builtin_eh_return
 * (usually via the uw_install_context(CURRENT, TARGET) macro).
 *
 * If the epilog code does NOT restore the two result regs we
 * are toast - there is run-time check which sadly
 * results in a silent abort built into uw_install_context_1()
 * look for the first gcc_assert
 */
 
inline void
_Unwind_PNaClSetResult0 (struct _Unwind_Context *context, _Unwind_Word val) {
  _Unwind_SetGR(context, pnacl_unwind_result0_reg(), val);
}

/* abstract away __builtin_eh_return_data_regno(1) */
inline  void
_Unwind_PNaClSetResult1 (struct _Unwind_Context *context, _Unwind_Word val) {
  _Unwind_SetGR(context, pnacl_unwind_result1_reg(), val);
}
/* @LOCALMOD-END */


/* Get the pointer to a register INDEX as saved in CONTEXT.  */

static inline void *
_Unwind_GetGRPtr (struct _Unwind_Context *context, int index)
{
  index = DWARF_REG_TO_UNWIND_COLUMN (index);
  if (_Unwind_IsExtendedContext (context) && context->by_value[index])
    return &context->reg[index];
  return context->reg[index];
}

/* Set the pointer to a register INDEX as saved in CONTEXT.  */

static inline void
_Unwind_SetGRPtr (struct _Unwind_Context *context, int index, void *p)
{
  index = DWARF_REG_TO_UNWIND_COLUMN (index);
  if (_Unwind_IsExtendedContext (context))
    context->by_value[index] = 0;
  context->reg[index] = p;
}

/* Overwrite the saved value for register INDEX in CONTEXT with VAL.  */

static inline void
_Unwind_SetGRValue (struct _Unwind_Context *context, int index,
		    _Unwind_Word val)
{
  index = DWARF_REG_TO_UNWIND_COLUMN (index);
  gcc_assert (index < (int) sizeof(dwarf_reg_size_table));
  gcc_assert (dwarf_reg_size_table[index] == sizeof (_Unwind_Ptr));

  context->by_value[index] = 1;
  context->reg[index] = (void *) (_Unwind_Internal_Ptr) val;
}

/* Return nonzero if register INDEX is stored by value rather than
   by reference.  */

static inline int
_Unwind_GRByValue (struct _Unwind_Context *context, int index)
{
  index = DWARF_REG_TO_UNWIND_COLUMN (index);
  return context->by_value[index];
}

/* Retrieve the return address for CONTEXT.  */

inline _Unwind_Ptr
_Unwind_GetIP (struct _Unwind_Context *context)
{
  return (_Unwind_Ptr) context->ra;
}

/* Retrieve the return address and flag whether that IP is before
   or after first not yet fully executed instruction.  */

inline _Unwind_Ptr
_Unwind_GetIPInfo (struct _Unwind_Context *context, int *ip_before_insn)
{
  *ip_before_insn = _Unwind_IsSignalFrame (context);
  return (_Unwind_Ptr) context->ra;
}

/* Overwrite the return address for CONTEXT with VAL.  */

inline void
_Unwind_SetIP (struct _Unwind_Context *context, _Unwind_Ptr val)
{
  context->ra = (void *) val;
}

void *
_Unwind_GetLanguageSpecificData (struct _Unwind_Context *context)
{
  return context->lsda;
}

_Unwind_Ptr
_Unwind_GetRegionStart (struct _Unwind_Context *context)
{
  return (_Unwind_Ptr) context->bases.func;
}

void *
_Unwind_FindEnclosingFunction (void *pc)
{
  struct dwarf_eh_bases bases;
  const struct dwarf_fde *fde = _Unwind_Find_FDE (pc-1, &bases);
  if (fde)
    return bases.func;
  else
    return NULL;
}

#ifndef __ia64__
_Unwind_Ptr
_Unwind_GetDataRelBase (struct _Unwind_Context *context)
{
  return (_Unwind_Ptr) context->bases.dbase;
}

_Unwind_Ptr
_Unwind_GetTextRelBase (struct _Unwind_Context *context)
{
  return (_Unwind_Ptr) context->bases.tbase;
}
#endif

#ifdef MD_UNWIND_SUPPORT
#include MD_UNWIND_SUPPORT
#endif

/* Extract any interesting information from the CIE for the translation
   unit F belongs to.  Return a pointer to the byte after the augmentation,
   or NULL if we encountered an undecipherable augmentation.  */

static const unsigned char *
extract_cie_info (const struct dwarf_cie *cie, struct _Unwind_Context *context,
		  _Unwind_FrameState *fs)
{
  const unsigned char *aug = cie->augmentation;
  const unsigned char *p = aug + strlen ((const char *)aug) + 1;
  const unsigned char *ret = NULL;
  _uleb128_t utmp;
  _sleb128_t stmp;

  /* g++ v2 "eh" has pointer immediately following augmentation string,
     so it must be handled first.  */
  if (aug[0] == 'e' && aug[1] == 'h')
    {
      fs->eh_ptr = read_pointer (p);
      p += sizeof (void *);
      aug += 2;
    }

  /* After the augmentation resp. pointer for "eh" augmentation
     follows for CIE version >= 4 address size byte and
     segment size byte.  */
  if (__builtin_expect (cie->version >= 4, 0))
    {
      if (p[0] != sizeof (void *) || p[1] != 0)
	return NULL;
      p += 2;
    }
  /* Immediately following this are the code and
     data alignment and return address column.  */
  p = read_uleb128 (p, &utmp);
  fs->code_align = (_Unwind_Word)utmp;
  p = read_sleb128 (p, &stmp);
  fs->data_align = (_Unwind_Sword)stmp;
  if (cie->version == 1)
    fs->retaddr_column = *p++;
  else
    {
      p = read_uleb128 (p, &utmp);
      fs->retaddr_column = (_Unwind_Word)utmp;
    }
  fs->lsda_encoding = DW_EH_PE_omit;

  /* If the augmentation starts with 'z', then a uleb128 immediately
     follows containing the length of the augmentation field following
     the size.  */
  if (*aug == 'z')
    {
      p = read_uleb128 (p, &utmp);
      ret = p + utmp;

      fs->saw_z = 1;
      ++aug;
    }

  /* Iterate over recognized augmentation subsequences.  */
  while (*aug != '\0')
    {
      /* "L" indicates a byte showing how the LSDA pointer is encoded.  */
      if (aug[0] == 'L')
	{
	  fs->lsda_encoding = *p++;
	  aug += 1;
	}

      /* "R" indicates a byte indicating how FDE addresses are encoded.  */
      else if (aug[0] == 'R')
	{
	  fs->fde_encoding = *p++;
	  aug += 1;
	}

      /* "P" indicates a personality routine in the CIE augmentation.  */
      else if (aug[0] == 'P')
	{
	  _Unwind_Ptr personality;

	  p = read_encoded_value (context, *p, p + 1, &personality);
	  fs->personality = (_Unwind_Personality_Fn) personality;
	  aug += 1;
	}

      /* "S" indicates a signal frame.  */
      else if (aug[0] == 'S')
	{
	  fs->signal_frame = 1;
	  aug += 1;
	}

      /* Otherwise we have an unknown augmentation string.
	 Bail unless we saw a 'z' prefix.  */
      else
	return ret;
    }

  return ret ? ret : p;
}


/* Decode a DW_OP stack program.  Return the top of stack.  Push INITIAL
   onto the stack to start.  */

static _Unwind_Word
execute_stack_op (const unsigned char *op_ptr, const unsigned char *op_end,
		  struct _Unwind_Context *context, _Unwind_Word initial)
{
  _Unwind_Word stack[64];	/* ??? Assume this is enough.  */
  int stack_elt;

  stack[0] = initial;
  stack_elt = 1;

  while (op_ptr < op_end)
    {
      enum dwarf_location_atom op = *op_ptr++;
      _Unwind_Word result;
      _uleb128_t reg, utmp;
      _sleb128_t offset, stmp;

      switch (op)
	{
	case DW_OP_lit0:
	case DW_OP_lit1:
	case DW_OP_lit2:
	case DW_OP_lit3:
	case DW_OP_lit4:
	case DW_OP_lit5:
	case DW_OP_lit6:
	case DW_OP_lit7:
	case DW_OP_lit8:
	case DW_OP_lit9:
	case DW_OP_lit10:
	case DW_OP_lit11:
	case DW_OP_lit12:
	case DW_OP_lit13:
	case DW_OP_lit14:
	case DW_OP_lit15:
	case DW_OP_lit16:
	case DW_OP_lit17:
	case DW_OP_lit18:
	case DW_OP_lit19:
	case DW_OP_lit20:
	case DW_OP_lit21:
	case DW_OP_lit22:
	case DW_OP_lit23:
	case DW_OP_lit24:
	case DW_OP_lit25:
	case DW_OP_lit26:
	case DW_OP_lit27:
	case DW_OP_lit28:
	case DW_OP_lit29:
	case DW_OP_lit30:
	case DW_OP_lit31:
	  result = op - DW_OP_lit0;
	  break;

	case DW_OP_addr:
	  result = (_Unwind_Word) (_Unwind_Ptr) read_pointer (op_ptr);
	  op_ptr += sizeof (void *);
	  break;

	case DW_OP_GNU_encoded_addr:
	  {
	    _Unwind_Ptr presult;
	    op_ptr = read_encoded_value (context, *op_ptr, op_ptr+1, &presult);
	    result = presult;
	  }
	  break;

	case DW_OP_const1u:
	  result = read_1u (op_ptr);
	  op_ptr += 1;
	  break;
	case DW_OP_const1s:
	  result = read_1s (op_ptr);
	  op_ptr += 1;
	  break;
	case DW_OP_const2u:
	  result = read_2u (op_ptr);
	  op_ptr += 2;
	  break;
	case DW_OP_const2s:
	  result = read_2s (op_ptr);
	  op_ptr += 2;
	  break;
	case DW_OP_const4u:
	  result = read_4u (op_ptr);
	  op_ptr += 4;
	  break;
	case DW_OP_const4s:
	  result = read_4s (op_ptr);
	  op_ptr += 4;
	  break;
	case DW_OP_const8u:
	  result = read_8u (op_ptr);
	  op_ptr += 8;
	  break;
	case DW_OP_const8s:
	  result = read_8s (op_ptr);
	  op_ptr += 8;
	  break;
	case DW_OP_constu:
	  op_ptr = read_uleb128 (op_ptr, &utmp);
	  result = (_Unwind_Word)utmp;
	  break;
	case DW_OP_consts:
	  op_ptr = read_sleb128 (op_ptr, &stmp);
	  result = (_Unwind_Sword)stmp;
	  break;

	case DW_OP_reg0:
	case DW_OP_reg1:
	case DW_OP_reg2:
	case DW_OP_reg3:
	case DW_OP_reg4:
	case DW_OP_reg5:
	case DW_OP_reg6:
	case DW_OP_reg7:
	case DW_OP_reg8:
	case DW_OP_reg9:
	case DW_OP_reg10:
	case DW_OP_reg11:
	case DW_OP_reg12:
	case DW_OP_reg13:
	case DW_OP_reg14:
	case DW_OP_reg15:
	case DW_OP_reg16:
	case DW_OP_reg17:
	case DW_OP_reg18:
	case DW_OP_reg19:
	case DW_OP_reg20:
	case DW_OP_reg21:
	case DW_OP_reg22:
	case DW_OP_reg23:
	case DW_OP_reg24:
	case DW_OP_reg25:
	case DW_OP_reg26:
	case DW_OP_reg27:
	case DW_OP_reg28:
	case DW_OP_reg29:
	case DW_OP_reg30:
	case DW_OP_reg31:
	  result = _Unwind_GetGR (context, op - DW_OP_reg0);
	  break;
	case DW_OP_regx:
	  op_ptr = read_uleb128 (op_ptr, &reg);
	  result = _Unwind_GetGR (context, reg);
	  break;

	case DW_OP_breg0:
	case DW_OP_breg1:
	case DW_OP_breg2:
	case DW_OP_breg3:
	case DW_OP_breg4:
	case DW_OP_breg5:
	case DW_OP_breg6:
	case DW_OP_breg7:
	case DW_OP_breg8:
	case DW_OP_breg9:
	case DW_OP_breg10:
	case DW_OP_breg11:
	case DW_OP_breg12:
	case DW_OP_breg13:
	case DW_OP_breg14:
	case DW_OP_breg15:
	case DW_OP_breg16:
	case DW_OP_breg17:
	case DW_OP_breg18:
	case DW_OP_breg19:
	case DW_OP_breg20:
	case DW_OP_breg21:
	case DW_OP_breg22:
	case DW_OP_breg23:
	case DW_OP_breg24:
	case DW_OP_breg25:
	case DW_OP_breg26:
	case DW_OP_breg27:
	case DW_OP_breg28:
	case DW_OP_breg29:
	case DW_OP_breg30:
	case DW_OP_breg31:
	  op_ptr = read_sleb128 (op_ptr, &offset);
	  result = _Unwind_GetGR (context, op - DW_OP_breg0) + offset;
	  break;
	case DW_OP_bregx:
	  op_ptr = read_uleb128 (op_ptr, &reg);
	  op_ptr = read_sleb128 (op_ptr, &offset);
	  result = _Unwind_GetGR (context, reg) + (_Unwind_Word)offset;
	  break;

	case DW_OP_dup:
	  gcc_assert (stack_elt);
	  result = stack[stack_elt - 1];
	  break;

	case DW_OP_drop:
	  gcc_assert (stack_elt);
	  stack_elt -= 1;
	  goto no_push;

	case DW_OP_pick:
	  offset = *op_ptr++;
	  gcc_assert (offset < stack_elt - 1);
	  result = stack[stack_elt - 1 - offset];
	  break;

	case DW_OP_over:
	  gcc_assert (stack_elt >= 2);
	  result = stack[stack_elt - 2];
	  break;

	case DW_OP_swap:
	  {
	    _Unwind_Word t;
	    gcc_assert (stack_elt >= 2);
	    t = stack[stack_elt - 1];
	    stack[stack_elt - 1] = stack[stack_elt - 2];
	    stack[stack_elt - 2] = t;
	    goto no_push;
	  }

	case DW_OP_rot:
	  {
	    _Unwind_Word t1, t2, t3;

	    gcc_assert (stack_elt >= 3);
	    t1 = stack[stack_elt - 1];
	    t2 = stack[stack_elt - 2];
	    t3 = stack[stack_elt - 3];
	    stack[stack_elt - 1] = t2;
	    stack[stack_elt - 2] = t3;
	    stack[stack_elt - 3] = t1;
	    goto no_push;
	  }

	case DW_OP_deref:
	case DW_OP_deref_size:
	case DW_OP_abs:
	case DW_OP_neg:
	case DW_OP_not:
	case DW_OP_plus_uconst:
	  /* Unary operations.  */
	  gcc_assert (stack_elt);
	  stack_elt -= 1;

	  result = stack[stack_elt];

	  switch (op)
	    {
	    case DW_OP_deref:
	      {
		void *ptr = (void *) (_Unwind_Ptr) result;
		result = (_Unwind_Ptr) read_pointer (ptr);
	      }
	      break;

	    case DW_OP_deref_size:
	      {
		void *ptr = (void *) (_Unwind_Ptr) result;
		switch (*op_ptr++)
		  {
		  case 1:
		    result = read_1u (ptr);
		    break;
		  case 2:
		    result = read_2u (ptr);
		    break;
		  case 4:
		    result = read_4u (ptr);
		    break;
		  case 8:
		    result = read_8u (ptr);
		    break;
		  default:
		    gcc_unreachable ();
		  }
	      }
	      break;

	    case DW_OP_abs:
	      if ((_Unwind_Sword) result < 0)
		result = -result;
	      break;
	    case DW_OP_neg:
	      result = -result;
	      break;
	    case DW_OP_not:
	      result = ~result;
	      break;
	    case DW_OP_plus_uconst:
	      op_ptr = read_uleb128 (op_ptr, &utmp);
	      result += (_Unwind_Word)utmp;
	      break;

	    default:
	      gcc_unreachable ();
	    }
	  break;

	case DW_OP_and:
	case DW_OP_div:
	case DW_OP_minus:
	case DW_OP_mod:
	case DW_OP_mul:
	case DW_OP_or:
	case DW_OP_plus:
	case DW_OP_shl:
	case DW_OP_shr:
	case DW_OP_shra:
	case DW_OP_xor:
	case DW_OP_le:
	case DW_OP_ge:
	case DW_OP_eq:
	case DW_OP_lt:
	case DW_OP_gt:
	case DW_OP_ne:
	  {
	    /* Binary operations.  */
	    _Unwind_Word first, second;
	    gcc_assert (stack_elt >= 2);
	    stack_elt -= 2;

	    second = stack[stack_elt];
	    first = stack[stack_elt + 1];

	    switch (op)
	      {
	      case DW_OP_and:
		result = second & first;
		break;
	      case DW_OP_div:
		result = (_Unwind_Sword) second / (_Unwind_Sword) first;
		break;
	      case DW_OP_minus:
		result = second - first;
		break;
	      case DW_OP_mod:
		result = second % first;
		break;
	      case DW_OP_mul:
		result = second * first;
		break;
	      case DW_OP_or:
		result = second | first;
		break;
	      case DW_OP_plus:
		result = second + first;
		break;
	      case DW_OP_shl:
		result = second << first;
		break;
	      case DW_OP_shr:
		result = second >> first;
		break;
	      case DW_OP_shra:
		result = (_Unwind_Sword) second >> first;
		break;
	      case DW_OP_xor:
		result = second ^ first;
		break;
	      case DW_OP_le:
		result = (_Unwind_Sword) second <= (_Unwind_Sword) first;
		break;
	      case DW_OP_ge:
		result = (_Unwind_Sword) second >= (_Unwind_Sword) first;
		break;
	      case DW_OP_eq:
		result = (_Unwind_Sword) second == (_Unwind_Sword) first;
		break;
	      case DW_OP_lt:
		result = (_Unwind_Sword) second < (_Unwind_Sword) first;
		break;
	      case DW_OP_gt:
		result = (_Unwind_Sword) second > (_Unwind_Sword) first;
		break;
	      case DW_OP_ne:
		result = (_Unwind_Sword) second != (_Unwind_Sword) first;
		break;

	      default:
		gcc_unreachable ();
	      }
	  }
	  break;

	case DW_OP_skip:
	  offset = read_2s (op_ptr);
	  op_ptr += 2;
	  op_ptr += offset;
	  goto no_push;

	case DW_OP_bra:
	  gcc_assert (stack_elt);
	  stack_elt -= 1;

	  offset = read_2s (op_ptr);
	  op_ptr += 2;
	  if (stack[stack_elt] != 0)
	    op_ptr += offset;
	  goto no_push;

	case DW_OP_nop:
	  goto no_push;

	default:
	  gcc_unreachable ();
	}

      /* Most things push a result value.  */
      gcc_assert ((size_t) stack_elt < sizeof(stack)/sizeof(*stack));
      stack[stack_elt++] = result;
    no_push:;
    }

  /* We were executing this program to get a value.  It should be
     at top of stack.  */
  gcc_assert (stack_elt);
  stack_elt -= 1;
  return stack[stack_elt];
}


/* Decode DWARF 2 call frame information. Takes pointers the
   instruction sequence to decode, current register information and
   CIE info, and the PC range to evaluate.  */

static void
execute_cfa_program (const unsigned char *insn_ptr,
		     const unsigned char *insn_end,
		     struct _Unwind_Context *context,
		     _Unwind_FrameState *fs)
{
  struct frame_state_reg_info *unused_rs = NULL;

  /* Don't allow remember/restore between CIE and FDE programs.  */
  fs->regs.prev = NULL;

  /* The comparison with the return address uses < rather than <= because
     we are only interested in the effects of code before the call; for a
     noreturn function, the return address may point to unrelated code with
     a different stack configuration that we are not interested in.  We
     assume that the call itself is unwind info-neutral; if not, or if
     there are delay instructions that adjust the stack, these must be
     reflected at the point immediately before the call insn.
     In signal frames, return address is after last completed instruction,
     so we add 1 to return address to make the comparison <=.  */
  while (insn_ptr < insn_end
	 && fs->pc < context->ra + _Unwind_IsSignalFrame (context))
    {
      unsigned char insn = *insn_ptr++;
      _uleb128_t reg, utmp;
      _sleb128_t offset, stmp;

      if ((insn & 0xc0) == DW_CFA_advance_loc)
	fs->pc += (insn & 0x3f) * fs->code_align;
      else if ((insn & 0xc0) == DW_CFA_offset)
	{
	  reg = insn & 0x3f;
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  offset = (_Unwind_Sword) utmp * fs->data_align;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_OFFSET;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.offset = offset;
	}
      else if ((insn & 0xc0) == DW_CFA_restore)
	{
	  reg = insn & 0x3f;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how = REG_UNSAVED;
	}
      else switch (insn)
	{
	case DW_CFA_set_loc:
	  {
	    _Unwind_Ptr pc;

	    insn_ptr = read_encoded_value (context, fs->fde_encoding,
					   insn_ptr, &pc);
	    fs->pc = (void *) pc;
	  }
	  break;

	case DW_CFA_advance_loc1:
	  fs->pc += read_1u (insn_ptr) * fs->code_align;
	  insn_ptr += 1;
	  break;
	case DW_CFA_advance_loc2:
	  fs->pc += read_2u (insn_ptr) * fs->code_align;
	  insn_ptr += 2;
	  break;
	case DW_CFA_advance_loc4:
	  fs->pc += read_4u (insn_ptr) * fs->code_align;
	  insn_ptr += 4;
	  break;

	case DW_CFA_offset_extended:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  offset = (_Unwind_Sword) utmp * fs->data_align;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_OFFSET;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.offset = offset;
	  break;

	case DW_CFA_restore_extended:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  /* FIXME, this is wrong; the CIE might have said that the
	     register was saved somewhere.  */
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN(reg)].how = REG_UNSAVED;
	  break;

	case DW_CFA_same_value:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN(reg)].how = REG_UNSAVED;
	  break;

	case DW_CFA_undefined:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN(reg)].how = REG_UNDEFINED;
	  break;

	case DW_CFA_nop:
	  break;

	case DW_CFA_register:
	  {
	    _uleb128_t reg2;
	    insn_ptr = read_uleb128 (insn_ptr, &reg);
	    insn_ptr = read_uleb128 (insn_ptr, &reg2);
	    fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how = REG_SAVED_REG;
	    fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.reg =
	      (_Unwind_Word)reg2;
	  }
	  break;

	case DW_CFA_remember_state:
	  {
	    struct frame_state_reg_info *new_rs;
	    if (unused_rs)
	      {
		new_rs = unused_rs;
		unused_rs = unused_rs->prev;
	      }
	    else
	      new_rs = alloca (sizeof (struct frame_state_reg_info));

	    *new_rs = fs->regs;
	    fs->regs.prev = new_rs;
	  }
	  break;

	case DW_CFA_restore_state:
	  {
	    struct frame_state_reg_info *old_rs = fs->regs.prev;
	    fs->regs = *old_rs;
	    old_rs->prev = unused_rs;
	    unused_rs = old_rs;
	  }
	  break;

	case DW_CFA_def_cfa:
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  fs->regs.cfa_reg = (_Unwind_Word)utmp;
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  fs->regs.cfa_offset = (_Unwind_Word)utmp;
	  fs->regs.cfa_how = CFA_REG_OFFSET;
	  break;

	case DW_CFA_def_cfa_register:
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  fs->regs.cfa_reg = (_Unwind_Word)utmp;
	  fs->regs.cfa_how = CFA_REG_OFFSET;
	  break;

	case DW_CFA_def_cfa_offset:
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  fs->regs.cfa_offset = utmp;
	  /* cfa_how deliberately not set.  */
	  break;

	case DW_CFA_def_cfa_expression:
	  fs->regs.cfa_exp = insn_ptr;
	  fs->regs.cfa_how = CFA_EXP;
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  insn_ptr += utmp;
	  break;

	case DW_CFA_expression:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how = REG_SAVED_EXP;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.exp = insn_ptr;
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  insn_ptr += utmp;
	  break;

	  /* Dwarf3.  */
	case DW_CFA_offset_extended_sf:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  insn_ptr = read_sleb128 (insn_ptr, &stmp);
	  offset = stmp * fs->data_align;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_OFFSET;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.offset = offset;
	  break;

	case DW_CFA_def_cfa_sf:
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  fs->regs.cfa_reg = (_Unwind_Word)utmp;
	  insn_ptr = read_sleb128 (insn_ptr, &stmp);
	  fs->regs.cfa_offset = (_Unwind_Sword)stmp;
	  fs->regs.cfa_how = CFA_REG_OFFSET;
	  fs->regs.cfa_offset *= fs->data_align;
	  break;

	case DW_CFA_def_cfa_offset_sf:
	  insn_ptr = read_sleb128 (insn_ptr, &stmp);
	  fs->regs.cfa_offset = (_Unwind_Sword)stmp;
	  fs->regs.cfa_offset *= fs->data_align;
	  /* cfa_how deliberately not set.  */
	  break;

	case DW_CFA_val_offset:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  offset = (_Unwind_Sword) utmp * fs->data_align;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_VAL_OFFSET;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.offset = offset;
	  break;

	case DW_CFA_val_offset_sf:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  insn_ptr = read_sleb128 (insn_ptr, &stmp);
	  offset = stmp * fs->data_align;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_VAL_OFFSET;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.offset = offset;
	  break;

	case DW_CFA_val_expression:
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_VAL_EXP;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.exp = insn_ptr;
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  insn_ptr += utmp;
	  break;

	case DW_CFA_GNU_window_save:
	  /* ??? Hardcoded for SPARC register window configuration.  */
	  for (reg = 16; reg < 32; ++reg)
	    {
	      fs->regs.reg[reg].how = REG_SAVED_OFFSET;
	      fs->regs.reg[reg].loc.offset = (reg - 16) * sizeof (void *);
	    }
	  break;

	case DW_CFA_GNU_args_size:
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  context->args_size = (_Unwind_Word)utmp;
	  break;

	case DW_CFA_GNU_negative_offset_extended:
	  /* Obsoleted by DW_CFA_offset_extended_sf, but used by
	     older PowerPC code.  */
	  insn_ptr = read_uleb128 (insn_ptr, &reg);
	  insn_ptr = read_uleb128 (insn_ptr, &utmp);
	  offset = (_Unwind_Word) utmp * fs->data_align;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].how
	    = REG_SAVED_OFFSET;
	  fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (reg)].loc.offset = -offset;
	  break;

	default:
	  gcc_unreachable ();
	}
    }
}

/* Given the _Unwind_Context CONTEXT for a stack frame, look up the FDE for
   its caller and decode it into FS.  This function also sets the
   args_size and lsda members of CONTEXT, as they are really information
   about the caller's frame.  */

extern void __irq0();
extern void __irq255();
extern void* get_syscall_rip();

static _Unwind_Reason_Code
uw_frame_state_for (struct _Unwind_Context *context, _Unwind_FrameState *fs)
{
  const struct dwarf_fde *fde;
  const struct dwarf_cie *cie;
  const unsigned char *aug, *insn, *end;

  memset (fs, 0, sizeof (*fs));
  context->args_size = 0;
  context->lsda = 0;

  if (context->ra == 0)
    return _URC_END_OF_STACK;
  
  if (context->ra > &__irq0 && context->ra < &__irq255) {
	context->ra = get_syscall_rip();
  }

  fde = _Unwind_Find_FDE (context->ra + _Unwind_IsSignalFrame (context) - 1,
			  &context->bases);
  if (fde == NULL)
    {
#ifdef MD_FALLBACK_FRAME_STATE_FOR
      /* Couldn't find frame unwind info for this function.  Try a
	 target-specific fallback mechanism.  This will necessarily
	 not provide a personality routine or LSDA.  */
      return MD_FALLBACK_FRAME_STATE_FOR (context, fs);
#else
      return _URC_END_OF_STACK;
#endif
    }

  fs->pc = context->bases.func;

  cie = get_cie (fde);
  insn = extract_cie_info (cie, context, fs);
  if (insn == NULL)
    /* CIE contained unknown augmentation.  */
    return _URC_FATAL_PHASE1_ERROR;

  /* First decode all the insns in the CIE.  */
  end = (const unsigned char *) next_fde ((const struct dwarf_fde *) cie);
  execute_cfa_program (insn, end, context, fs);

  /* Locate augmentation for the fde.  */
  aug = (const unsigned char *) fde + sizeof (*fde);
  aug += 2 * size_of_encoded_value (fs->fde_encoding);
  insn = NULL;
  if (fs->saw_z)
    {
      _uleb128_t i;
      aug = read_uleb128 (aug, &i);
      insn = aug + i;
    }
  if (fs->lsda_encoding != DW_EH_PE_omit)
    {
      _Unwind_Ptr lsda;

      aug = read_encoded_value (context, fs->lsda_encoding, aug, &lsda);
      context->lsda = (void *) lsda;
    }

  /* Then the insns in the FDE up to our target PC.  */
  if (insn == NULL)
    insn = aug;
  end = (const unsigned char *) next_fde (fde);
  execute_cfa_program (insn, end, context, fs);

  return _URC_NO_REASON;
}

typedef struct frame_state
{
  void *cfa;
  void *eh_ptr;
  long cfa_offset;
  long args_size;
  long reg_or_offset[PRE_GCC3_DWARF_FRAME_REGISTERS+1];
  unsigned short cfa_reg;
  unsigned short retaddr_column;
  char saved[PRE_GCC3_DWARF_FRAME_REGISTERS+1];
} frame_state;

struct frame_state * __frame_state_for (void *, struct frame_state *);

/* Called from pre-G++ 3.0 __throw to find the registers to restore for
   a given PC_TARGET.  The caller should allocate a local variable of
   `struct frame_state' and pass its address to STATE_IN.  */

struct frame_state *
__frame_state_for (void *pc_target, struct frame_state *state_in)
{
  struct _Unwind_Context context;
  _Unwind_FrameState fs;
  int reg;

  memset (&context, 0, sizeof (struct _Unwind_Context));
  context.flags = EXTENDED_CONTEXT_BIT;
  context.ra = pc_target + 1;

  if (uw_frame_state_for (&context, &fs) != _URC_NO_REASON)
    return 0;

  /* We have no way to pass a location expression for the CFA to our
     caller.  It wouldn't understand it anyway.  */
  if (fs.regs.cfa_how == CFA_EXP)
    return 0;

  for (reg = 0; reg < PRE_GCC3_DWARF_FRAME_REGISTERS + 1; reg++)
    {
      state_in->saved[reg] = fs.regs.reg[reg].how;
      switch (state_in->saved[reg])
	{
	case REG_SAVED_REG:
	  state_in->reg_or_offset[reg] = fs.regs.reg[reg].loc.reg;
	  break;
	case REG_SAVED_OFFSET:
	  state_in->reg_or_offset[reg] = fs.regs.reg[reg].loc.offset;
	  break;
	default:
	  state_in->reg_or_offset[reg] = 0;
	  break;
	}
    }

  state_in->cfa_offset = fs.regs.cfa_offset;
  state_in->cfa_reg = fs.regs.cfa_reg;
  state_in->retaddr_column = fs.retaddr_column;
  state_in->args_size = context.args_size;
  state_in->eh_ptr = fs.eh_ptr;

  return state_in;
}

typedef union { _Unwind_Ptr ptr; _Unwind_Word word; } _Unwind_SpTmp;

static inline void
_Unwind_SetSpColumn (struct _Unwind_Context *context, void *cfa,
		     _Unwind_SpTmp *tmp_sp)
{
  int size = dwarf_reg_size_table[__builtin_dwarf_sp_column ()];

  if (size == sizeof(_Unwind_Ptr))
    tmp_sp->ptr = (_Unwind_Ptr) cfa;
  else
    {
      gcc_assert (size == sizeof(_Unwind_Word));
      tmp_sp->word = (_Unwind_Ptr) cfa;
    }
  _Unwind_SetGRPtr (context, __builtin_dwarf_sp_column (), tmp_sp);
}

static void
uw_update_context_1 (struct _Unwind_Context *context, _Unwind_FrameState *fs)
{
  struct _Unwind_Context orig_context = *context;
  void *cfa;
  long i;

#ifdef EH_RETURN_STACKADJ_RTX
  /* Special handling here: Many machines do not use a frame pointer,
     and track the CFA only through offsets from the stack pointer from
     one frame to the next.  In this case, the stack pointer is never
     stored, so it has no saved address in the context.  What we do
     have is the CFA from the previous stack frame.

     In very special situations (such as unwind info for signal return),
     there may be location expressions that use the stack pointer as well.

     Do this conditionally for one frame.  This allows the unwind info
     for one frame to save a copy of the stack pointer from the previous
     frame, and be able to use much easier CFA mechanisms to do it.
     Always zap the saved stack pointer value for the next frame; carrying
     the value over from one frame to another doesn't make sense.  */

  _Unwind_SpTmp tmp_sp;

  if (!_Unwind_GetGRPtr (&orig_context, __builtin_dwarf_sp_column ()))
    _Unwind_SetSpColumn (&orig_context, context->cfa, &tmp_sp);
  _Unwind_SetGRPtr (context, __builtin_dwarf_sp_column (), NULL);
#endif

  /* Compute this frame's CFA.  */
  switch (fs->regs.cfa_how)
    {
    case CFA_REG_OFFSET:
      cfa = _Unwind_GetPtr (&orig_context, fs->regs.cfa_reg);
      cfa += fs->regs.cfa_offset;
      break;

    case CFA_EXP:
      {
	const unsigned char *exp = fs->regs.cfa_exp;
	_uleb128_t len;

	exp = read_uleb128 (exp, &len);
	cfa = (void *) (_Unwind_Ptr)
	  execute_stack_op (exp, exp + len, &orig_context, 0);
	break;
      }

    default:
      gcc_unreachable ();
    }
  context->cfa = cfa;

  /* Compute the addresses of all registers saved in this frame.  */
  for (i = 0; i < DWARF_FRAME_REGISTERS + 1; ++i)
    switch (fs->regs.reg[i].how)
      {
      case REG_UNSAVED:
      case REG_UNDEFINED:
	break;

      case REG_SAVED_OFFSET:
	_Unwind_SetGRPtr (context, i,
			  (void *) (cfa + fs->regs.reg[i].loc.offset));
	break;

      case REG_SAVED_REG:
	if (_Unwind_GRByValue (&orig_context, fs->regs.reg[i].loc.reg))
	  _Unwind_SetGRValue (context, i,
			      _Unwind_GetGR (&orig_context,
					     fs->regs.reg[i].loc.reg));
	else
	  _Unwind_SetGRPtr (context, i,
			    _Unwind_GetGRPtr (&orig_context,
					      fs->regs.reg[i].loc.reg));
	break;

      case REG_SAVED_EXP:
	{
	  const unsigned char *exp = fs->regs.reg[i].loc.exp;
	  _uleb128_t len;
	  _Unwind_Ptr val;

	  exp = read_uleb128 (exp, &len);
	  val = execute_stack_op (exp, exp + len, &orig_context,
				  (_Unwind_Ptr) cfa);
	  _Unwind_SetGRPtr (context, i, (void *) val);
	}
	break;

      case REG_SAVED_VAL_OFFSET:
	_Unwind_SetGRValue (context, i,
			    (_Unwind_Internal_Ptr)
			    (cfa + fs->regs.reg[i].loc.offset));
	break;

      case REG_SAVED_VAL_EXP:
	{
	  const unsigned char *exp = fs->regs.reg[i].loc.exp;
	  _uleb128_t len;
	  _Unwind_Ptr val;

	  exp = read_uleb128 (exp, &len);
	  val = execute_stack_op (exp, exp + len, &orig_context,
				  (_Unwind_Ptr) cfa);
	  _Unwind_SetGRValue (context, i, val);
	}
	break;
      }

  _Unwind_SetSignalFrame (context, fs->signal_frame);

#ifdef MD_FROB_UPDATE_CONTEXT
  MD_FROB_UPDATE_CONTEXT (context, fs);
#endif
}

/* CONTEXT describes the unwind state for a frame, and FS describes the FDE
   of its caller.  Update CONTEXT to refer to the caller as well.  Note
   that the args_size and lsda members are not updated here, but later in
   uw_frame_state_for.  */

static void
uw_update_context (struct _Unwind_Context *context, _Unwind_FrameState *fs)
{
  uw_update_context_1 (context, fs);

  /* In general this unwinder doesn't make any distinction between
     undefined and same_value rule.  Call-saved registers are assumed
     to have same_value rule by default and explicit undefined
     rule is handled like same_value.  The only exception is
     DW_CFA_undefined on retaddr_column which is supposed to
     mark outermost frame in DWARF 3.  */
  if (fs->regs.reg[DWARF_REG_TO_UNWIND_COLUMN (fs->retaddr_column)].how
      == REG_UNDEFINED)
    /* uw_frame_state_for uses context->ra == 0 check to find outermost
       stack frame.  */
    context->ra = 0;
  else
    /* Compute the return address now, since the return address column
       can change from frame to frame.  */
    context->ra = __builtin_extract_return_addr
      (_Unwind_GetPtr (context, fs->retaddr_column));
}

static void
uw_advance_context (struct _Unwind_Context *context, _Unwind_FrameState *fs)
{
  uw_update_context (context, fs);
}

/* Fill in CONTEXT for top-of-stack.  The only valid registers at this
   level will be the return address and the CFA.  */

#define uw_init_context(CONTEXT)					   \
  do									   \
    {									   \
      /* Do any necessary initialization to access arbitrary stack frames. \
	 On the SPARC, this means flushing the register windows.  */	   \
      __builtin_unwind_init ();						   \
      uw_init_context_1 (CONTEXT, __builtin_dwarf_cfa (),		   \
			 __builtin_return_address (0));			   \
    }									   \
  while (0)

static inline void
init_dwarf_reg_size_table (void)
{
  __builtin_init_dwarf_reg_size_table (dwarf_reg_size_table);
}

static void __attribute__((noinline))
uw_init_context_1 (struct _Unwind_Context *context,
		   void *outer_cfa, void *outer_ra)
{
  void *ra = __builtin_extract_return_addr (__builtin_return_address (0));
  _Unwind_FrameState fs;
  _Unwind_SpTmp sp_slot;
  _Unwind_Reason_Code code;

  memset (context, 0, sizeof (struct _Unwind_Context));
  context->ra = ra;
  context->flags = EXTENDED_CONTEXT_BIT;

  code = uw_frame_state_for (context, &fs);
  gcc_assert (code == _URC_NO_REASON);

#if __GTHREADS
  {
    static __gthread_once_t once_regsizes = __GTHREAD_ONCE_INIT;
    if (__gthread_once (&once_regsizes, init_dwarf_reg_size_table) != 0
	&& dwarf_reg_size_table[0] == 0)
      init_dwarf_reg_size_table ();
  }
#else
  if (dwarf_reg_size_table[0] == 0)
    init_dwarf_reg_size_table ();
#endif

  /* Force the frame state to use the known cfa value.  */
  _Unwind_SetSpColumn (context, outer_cfa, &sp_slot);
  fs.regs.cfa_how = CFA_REG_OFFSET;
  fs.regs.cfa_reg = __builtin_dwarf_sp_column ();
  fs.regs.cfa_offset = 0;

  uw_update_context_1 (context, &fs);

  /* If the return address column was saved in a register in the
     initialization context, then we can't see it in the given
     call frame data.  So have the initialization context tell us.  */
  context->ra = __builtin_extract_return_addr (outer_ra);
}

static void _Unwind_DebugHook (void *, void *)
  __attribute__ ((__noinline__, __used__, __noclone__));

/* This function is called during unwinding.  It is intended as a hook
   for a debugger to intercept exceptions.  CFA is the CFA of the
   target frame.  HANDLER is the PC to which control will be
   transferred.  */
static void
_Unwind_DebugHook (void *cfa __attribute__ ((__unused__)),
		   void *handler __attribute__ ((__unused__)))
{
  asm ("");
}

/* Install TARGET into CURRENT so that we can return to it.  This is a
   macro because __builtin_eh_return must be invoked in the context of
   our caller.  */

#define uw_install_context(CURRENT, TARGET)				\
  do									\
    {									\
      long offset = uw_install_context_1 ((CURRENT), (TARGET));		\
      void *handler = __builtin_frob_return_addr ((TARGET)->ra);	\
      _Unwind_DebugHook ((TARGET)->cfa, handler);			\
      __builtin_eh_return (offset, handler);				\
    }									\
  while (0)

static long
uw_install_context_1 (struct _Unwind_Context *current,
		      struct _Unwind_Context *target)
{
  long i;
  _Unwind_SpTmp sp_slot;

  /* If the target frame does not have a saved stack pointer,
     then set up the target's CFA.  */
  if (!_Unwind_GetGRPtr (target, __builtin_dwarf_sp_column ()))
    _Unwind_SetSpColumn (target, target->cfa, &sp_slot);

  for (i = 0; i < DWARF_FRAME_REGISTERS; ++i)
    {
      void *c = current->reg[i];
      void *t = target->reg[i];

      gcc_assert (current->by_value[i] == 0);
      if (target->by_value[i] && c)
	{
	  _Unwind_Word w;
	  _Unwind_Ptr p;
	  if (dwarf_reg_size_table[i] == sizeof (_Unwind_Word))
	    {
	      w = (_Unwind_Internal_Ptr) t;
	      memcpy (c, &w, sizeof (_Unwind_Word));
	    }
	  else
	    {
	      gcc_assert (dwarf_reg_size_table[i] == sizeof (_Unwind_Ptr));
	      p = (_Unwind_Internal_Ptr) t;
	      memcpy (c, &p, sizeof (_Unwind_Ptr));
	    }
	}
      else if (t && c && t != c)
	memcpy (c, t, dwarf_reg_size_table[i]);
    }

  /* If the current frame doesn't have a saved stack pointer, then we
     need to rely on EH_RETURN_STACKADJ_RTX to get our target stack
     pointer value reloaded.  */
  if (!_Unwind_GetGRPtr (current, __builtin_dwarf_sp_column ()))
    {
      void *target_cfa;

      target_cfa = _Unwind_GetPtr (target, __builtin_dwarf_sp_column ());

      /* We adjust SP by the difference between CURRENT and TARGET's CFA.  */
      if (STACK_GROWS_DOWNWARD)
	return target_cfa - current->cfa + target->args_size;
      else
	return current->cfa - target_cfa - target->args_size;
    }
  return 0;
}

static inline _Unwind_Ptr
uw_identify_context (struct _Unwind_Context *context)
{
  /* The CFA is not sufficient to disambiguate the context of a function
     interrupted by a signal before establishing its frame and the context
     of the signal itself.  */
  if (STACK_GROWS_DOWNWARD)
    return _Unwind_GetCFA (context) - _Unwind_IsSignalFrame (context);
  else
    return _Unwind_GetCFA (context) + _Unwind_IsSignalFrame (context);
}

extern void _Unwind_ReturnToUser(struct _Unwind_Exception *exc);

static _Unwind_Reason_Code
_Unwind_RaiseException_Phase2(struct _Unwind_Exception *exc,
			      struct _Unwind_Context *context)
{
  _Unwind_Reason_Code code;

  while (1)
    {
      _Unwind_FrameState fs;
      int match_handler;

      code = uw_frame_state_for (context, &fs);
      if (context->ra == get_syscall_rip()) {
          _Unwind_ReturnToUser(exc);
      }

      /* Identify when we've reached the designated handler context.  */
      match_handler = (uw_identify_context (context) == exc->private_2
		       ? _UA_HANDLER_FRAME : 0);

      if (code != _URC_NO_REASON)
	/* Some error encountered.  Usually the unwinder doesn't
	   diagnose these and merely crashes.  */
	return _URC_FATAL_PHASE2_ERROR;

      /* Unwind successful.  Run the personality routine, if any.  */
      if (fs.personality)
	{
	  code = (*fs.personality) (1, _UA_CLEANUP_PHASE | match_handler,
				    exc->exception_class, exc, context);
	  if (code == _URC_INSTALL_CONTEXT)
	    break;
	  if (code != _URC_CONTINUE_UNWIND) 
	    return _URC_FATAL_PHASE2_ERROR;
	}

      /* Don't let us unwind past the handler context.  */
      gcc_assert (!match_handler);

      uw_update_context (context, &fs);
    }

  return code;
}

/* Raise an exception, passing along the given exception object.  */

_Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_RaiseException(struct _Unwind_Exception *exc)
{
  struct _Unwind_Context this_context, cur_context;
  _Unwind_Reason_Code code;

  /* Set up this_context to describe the current stack frame.  */
  uw_init_context (&this_context);
  cur_context = this_context;

  /* Phase 1: Search.  Unwind the stack, calling the personality routine
     with the _UA_SEARCH_PHASE flag set.  Do not modify the stack yet.  */
  while (1)
    {
      _Unwind_FrameState fs;

      /* Set up fs to describe the FDE for the caller of cur_context.  The
	 first time through the loop, that means __cxa_throw.  */
      code = uw_frame_state_for (&cur_context, &fs);
      if (cur_context.ra == get_syscall_rip()) {
          break;
      }
      if (code == _URC_END_OF_STACK)
	/* Hit end of stack with no handler found.  */
	return _URC_END_OF_STACK;

      if (code != _URC_NO_REASON)
	/* Some error encountered.  Usually the unwinder doesn't
	   diagnose these and merely crashes.  */
	return _URC_FATAL_PHASE1_ERROR;

      /* Unwind successful.  Run the personality routine, if any.  */
      if (fs.personality)
	{
	  code = (*fs.personality) (1, _UA_SEARCH_PHASE, exc->exception_class,
				    exc, &cur_context);
	  if (code == _URC_HANDLER_FOUND)
	    break;
	  else if (code != _URC_CONTINUE_UNWIND)
	    return _URC_FATAL_PHASE1_ERROR;
	}

      /* Update cur_context to describe the same frame as fs.  */
      uw_update_context (&cur_context, &fs);
    }

  /* Indicate to _Unwind_Resume and associated subroutines that this
     is not a forced unwind.  Further, note where we found a handler.  */
  exc->private_1 = 0;
  exc->private_2 = uw_identify_context (&cur_context);

  cur_context = this_context;
  code = _Unwind_RaiseException_Phase2 (exc, &cur_context);
  if (code != _URC_INSTALL_CONTEXT)
    return code;

  uw_install_context (&this_context, &cur_context);
}


/* Subroutine of _Unwind_ForcedUnwind also invoked from _Unwind_Resume.  */

static _Unwind_Reason_Code
_Unwind_ForcedUnwind_Phase2 (struct _Unwind_Exception *exc,
			     struct _Unwind_Context *context)
{
  _Unwind_Stop_Fn stop = (_Unwind_Stop_Fn) (_Unwind_Ptr) exc->private_1;
  void *stop_argument = (void *) (_Unwind_Ptr) exc->private_2;
  _Unwind_Reason_Code code, stop_code;

  while (1)
    {
      _Unwind_FrameState fs;
      int action;

      /* Set up fs to describe the FDE for the caller of cur_context.  */
      code = uw_frame_state_for (context, &fs);
      if (code != _URC_NO_REASON && code != _URC_END_OF_STACK)
	return _URC_FATAL_PHASE2_ERROR;

      /* Unwind successful.  */
      action = _UA_FORCE_UNWIND | _UA_CLEANUP_PHASE;
      if (code == _URC_END_OF_STACK)
	action |= _UA_END_OF_STACK;
      stop_code = (*stop) (1, action, exc->exception_class, exc,
			   context, stop_argument);
      if (stop_code != _URC_NO_REASON)
	return _URC_FATAL_PHASE2_ERROR;

      /* Stop didn't want to do anything.  Invoke the personality
	 handler, if applicable, to run cleanups.  */
      if (code == _URC_END_OF_STACK)
	break;
	
      if (fs.personality)
	{
	  code = (*fs.personality) (1, _UA_FORCE_UNWIND | _UA_CLEANUP_PHASE,
				    exc->exception_class, exc, context);
	  if (code == _URC_INSTALL_CONTEXT)
	    break;
	  if (code != _URC_CONTINUE_UNWIND) 
	    return _URC_FATAL_PHASE2_ERROR;
	}

      /* Update cur_context to describe the same frame as fs, and discard
	 the previous context if necessary.  */
      uw_advance_context (context, &fs);
    }

  return code;
}


/* Raise an exception for forced unwinding.  */

_Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_ForcedUnwind (struct _Unwind_Exception *exc,
		      _Unwind_Stop_Fn stop, void * stop_argument)
{
  struct _Unwind_Context this_context, cur_context;
  _Unwind_Reason_Code code;

  uw_init_context (&this_context);
  cur_context = this_context;

  exc->private_1 = (_Unwind_Ptr) stop;
  exc->private_2 = (_Unwind_Ptr) stop_argument;

  code = _Unwind_ForcedUnwind_Phase2 (exc, &cur_context);
  if (code != _URC_INSTALL_CONTEXT)
    return code;

  uw_install_context (&this_context, &cur_context);
}


/* Resume propagation of an existing exception.  This is used after
   e.g. executing cleanup code, and not to implement rethrowing.  */

void LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_Resume (struct _Unwind_Exception *exc)
{
  struct _Unwind_Context this_context, cur_context;
  _Unwind_Reason_Code code;

  uw_init_context (&this_context);
  cur_context = this_context;

  /* Choose between continuing to process _Unwind_RaiseException
     or _Unwind_ForcedUnwind.  */
  if (exc->private_1 == 0)
    code = _Unwind_RaiseException_Phase2 (exc, &cur_context);
  else
    code = _Unwind_ForcedUnwind_Phase2 (exc, &cur_context);

  gcc_assert (code == _URC_INSTALL_CONTEXT);

  uw_install_context (&this_context, &cur_context);
}


/* Resume propagation of an FORCE_UNWIND exception, or to rethrow
   a normal exception that was handled.  */

_Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_Resume_or_Rethrow (struct _Unwind_Exception *exc)
{
  struct _Unwind_Context this_context, cur_context;
  _Unwind_Reason_Code code;

  /* Choose between continuing to process _Unwind_RaiseException
     or _Unwind_ForcedUnwind.  */
  if (exc->private_1 == 0)
    return _Unwind_RaiseException (exc);

  uw_init_context (&this_context);
  cur_context = this_context;

  code = _Unwind_ForcedUnwind_Phase2 (exc, &cur_context);

  gcc_assert (code == _URC_INSTALL_CONTEXT);

  uw_install_context (&this_context, &cur_context);
}


/* A convenience function that calls the exception_cleanup field.  */

void
_Unwind_DeleteException (struct _Unwind_Exception *exc)
{
  if (exc->exception_cleanup)
    (*exc->exception_cleanup) (_URC_FOREIGN_EXCEPTION_CAUGHT, exc);
}


/* Perform stack backtrace through unwind data.  */

_Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_Backtrace(_Unwind_Trace_Fn trace, void * trace_argument)
{
  struct _Unwind_Context context;
  _Unwind_Reason_Code code;

  uw_init_context (&context);

  while (1)
    {
      _Unwind_FrameState fs;

      /* Set up fs to describe the FDE for the caller of context.  */
      code = uw_frame_state_for (&context, &fs);
      if (code != _URC_NO_REASON && code != _URC_END_OF_STACK)
	return _URC_FATAL_PHASE1_ERROR;

      /* Call trace function.  */
      if ((*trace) (&context, trace_argument) != _URC_NO_REASON)
	return _URC_FATAL_PHASE1_ERROR;

      /* We're done at end of stack.  */	
      if (code == _URC_END_OF_STACK)
	break;

      /* Update context to describe the same frame as fs.  */
      uw_update_context (&context, &fs);
    }

  return code;
}

#if defined (USE_GAS_SYMVER) && defined (SHARED) && defined (USE_LIBUNWIND_EXCEPTIONS)
alias (_Unwind_Backtrace);
alias (_Unwind_DeleteException);
alias (_Unwind_FindEnclosingFunction);
alias (_Unwind_ForcedUnwind);
alias (_Unwind_GetDataRelBase);
alias (_Unwind_GetTextRelBase);
alias (_Unwind_GetCFA);
alias (_Unwind_GetGR);
alias (_Unwind_GetIP);
alias (_Unwind_GetLanguageSpecificData);
alias (_Unwind_GetRegionStart);
alias (_Unwind_RaiseException);
alias (_Unwind_Resume);
alias (_Unwind_Resume_or_Rethrow);
alias (_Unwind_SetGR);
// @LOCALMOD-BEGIN
alias (_Unwind_PNaClSetResult0);
alias (_Unwind_PNaClSetResult1);
// @LOCALMOD-END
alias (_Unwind_SetIP);
#endif

#endif /* !USING_SJLJ_EXCEPTIONS */


/* The unseen_objects list contains objects that have been registered
   but not yet categorized in any way.  The seen_objects list has had
   its pc_begin and count fields initialized at minimum, and is sorted
   by decreasing value of pc_begin.  */
static struct object *unseen_objects;
static struct object *seen_objects;


static struct mutex object_mutex;

/* Called from crtbegin.o to register the unwind info for an object.  */

void
__register_frame_info_bases (const void *begin, struct object *ob,
			     void *tbase, void *dbase)
{
  /* If .eh_frame is empty, don't register at all.  */
  if ((const uword *) begin == 0 || *(const uword *) begin == 0)
    return;

  ob->pc_begin = (void *)-1;
  ob->tbase = tbase;
  ob->dbase = dbase;
  ob->u.single = begin;
  ob->s.i = 0;
  ob->s.b.encoding = DW_EH_PE_omit;
#ifdef DWARF2_OBJECT_END_PTR_EXTENSION
  ob->fde_end = NULL;
#endif


  mutex_lock(&object_mutex);

  ob->next = unseen_objects;
  unseen_objects = ob;

  mutex_unlock(&object_mutex);
}

void
__register_frame_info (const void *begin, struct object *ob)
{
  __register_frame_info_bases (begin, ob, 0, 0);
}

void
__register_frame (void *begin, void *end)
{
  //struct object *ob;

  /* If .eh_frame is empty, don't register at all.  */
  if (*(uword *) begin == 0)
    return;

  struct object *ob = malloc (sizeof (struct object));
  __register_frame_info (begin, ob);
  ob->pc_end = end;
}

void init_unwinding(const void* eh_start, const void* next_start) {
    __register_frame(eh_start, next_start);
}

/* Similar, but BEGIN is actually a pointer to a table of unwind entries
   for different translation units.  Called from the file generated by
   collect2.  */

void
__register_frame_info_table_bases (void *begin, struct object *ob,
				   void *tbase, void *dbase)
{
  ob->pc_begin = (void *)-1;
  ob->tbase = tbase;
  ob->dbase = dbase;
  ob->u.array = begin;
  ob->s.i = 0;
  ob->s.b.from_array = 1;
  ob->s.b.encoding = DW_EH_PE_omit;

  mutex_lock(&object_mutex);

  ob->next = unseen_objects;
  unseen_objects = ob;

  mutex_unlock(&object_mutex);
}

void
__register_frame_info_table (void *begin, struct object *ob)
{
  __register_frame_info_table_bases (begin, ob, 0, 0);
}

void
__register_frame_table (void *begin)
{
  static struct object ob;// = malloc (sizeof (struct object));
  __register_frame_info_table (begin, &ob);
}

/* Called from crtbegin.o to deregister the unwind info for an object.  */
/* ??? Glibc has for a while now exported __register_frame_info and
   __deregister_frame_info.  If we call __register_frame_info_bases
   from crtbegin (wherein it is declared weak), and this object does
   not get pulled from libgcc.a for other reasons, then the
   invocation of __deregister_frame_info will be resolved from glibc.
   Since the registration did not happen there, we'll die.

   Therefore, declare a new deregistration entry point that does the
   exact same thing, but will resolve to the same library as
   implements __register_frame_info_bases.  */

void *
__deregister_frame_info_bases (const void *begin)
{
  struct object **p;
  struct object *ob = 0;

  /* If .eh_frame is empty, we haven't registered.  */
  if ((const uword *) begin == 0 || *(const uword *) begin == 0)
    return ob;

  mutex_lock(&object_mutex);

  for (p = &unseen_objects; *p ; p = &(*p)->next)
    if ((*p)->u.single == begin)
      {
	ob = *p;
	*p = ob->next;
	goto out;
      }

  for (p = &seen_objects; *p ; p = &(*p)->next)
    if ((*p)->s.b.sorted)
      {
	if ((*p)->u.sort->orig_data == begin)
	  {
	    ob = *p;
	    *p = ob->next;
	    free (ob->u.sort);
	    goto out;
	  }
      }
    else
      {
	if ((*p)->u.single == begin)
	  {
	    ob = *p;
	    *p = ob->next;
	    goto out;
	  }
      }

 out:
  mutex_unlock(&object_mutex);
  //gcc_assert ((int)ob);
  return (void *) ob;
}

void *
__deregister_frame_info (const void *begin)
{
  return __deregister_frame_info_bases (begin);
}

void
__deregister_frame (void *begin)
{
  /* If .eh_frame is empty, we haven't registered.  */
  if (*(uword *) begin != 0)
    free (__deregister_frame_info (begin));
}


/* Like base_of_encoded_value, but take the base from a struct object
   instead of an _Unwind_Context.  */

static _Unwind_Ptr
base_from_object (unsigned char encoding, struct object *ob)
{
  if (encoding == DW_EH_PE_omit)
    return 0;

  switch (encoding & 0x70)
    {
    case DW_EH_PE_absptr:
    case DW_EH_PE_pcrel:
    case DW_EH_PE_aligned:
      return 0;

    case DW_EH_PE_textrel:
      return (_Unwind_Ptr) ob->tbase;
    case DW_EH_PE_datarel:
      return (_Unwind_Ptr) ob->dbase;
    default:
      gcc_unreachable ();
    }
}

/* Return the FDE pointer encoding from the CIE.  */
/* ??? This is a subset of extract_cie_info from unwind-dw2.c.  */

static int
get_cie_encoding (const struct dwarf_cie *cie)
{
  const unsigned char *aug, *p;
  _Unwind_Ptr dummy;
  _uleb128_t utmp;
  _sleb128_t stmp;

  aug = cie->augmentation;
  p = aug + strlen ((const char *)aug) + 1; /* Skip the augmentation string.  */
  if (__builtin_expect (cie->version >= 4, 0))
    {
      if (p[0] != sizeof (void *) || p[1] != 0)
	return DW_EH_PE_omit;		/* We are not prepared to handle unexpected
					   address sizes or segment selectors.  */
      p += 2;				/* Skip address size and segment size.  */
    }

  if (aug[0] != 'z')
    return DW_EH_PE_absptr;

  p = read_uleb128 (p, &utmp);		/* Skip code alignment.  */
  p = read_sleb128 (p, &stmp);		/* Skip data alignment.  */
  if (cie->version == 1)		/* Skip return address column.  */
    p++;
  else
    p = read_uleb128 (p, &utmp);

  aug++;				/* Skip 'z' */
  p = read_uleb128 (p, &utmp);		/* Skip augmentation length.  */
  while (1)
    {
      /* This is what we're looking for.  */
      if (*aug == 'R')
	return *p;
      /* Personality encoding and pointer.  */
      else if (*aug == 'P')
	{
	  /* ??? Avoid dereferencing indirect pointers, since we're
	     faking the base address.  Gotta keep DW_EH_PE_aligned
	     intact, however.  */
	  p = read_encoded_value_with_base (*p & 0x7F, 0, p + 1, &dummy);
	}
      /* LSDA encoding.  */
      else if (*aug == 'L')
	p++;
      /* Otherwise end of string, or unknown augmentation.  */
      else
	return DW_EH_PE_absptr;
      aug++;
    }
}

static inline int
get_fde_encoding (const struct dwarf_fde *f)
{
  return get_cie_encoding (get_cie (f));
}


/* Sorting an array of FDEs by address.
   (Ideally we would have the linker sort the FDEs so we don't have to do
   it at run time. But the linkers are not yet prepared for this.)  */

/* Comparison routines.  Three variants of increasing complexity.  */

static int
fde_unencoded_compare (struct object *ob __attribute__((unused)),
		       const fde *x, const fde *y)
{
  _Unwind_Ptr x_ptr, y_ptr;
  memcpy (&x_ptr, x->pc_begin, sizeof (_Unwind_Ptr));
  memcpy (&y_ptr, y->pc_begin, sizeof (_Unwind_Ptr));

  if (x_ptr > y_ptr)
    return 1;
  if (x_ptr < y_ptr)
    return -1;
  return 0;
}

static int
fde_single_encoding_compare (struct object *ob, const fde *x, const fde *y)
{
  _Unwind_Ptr base, x_ptr, y_ptr;

  base = base_from_object (ob->s.b.encoding, ob);
  read_encoded_value_with_base (ob->s.b.encoding, base, x->pc_begin, &x_ptr);
  read_encoded_value_with_base (ob->s.b.encoding, base, y->pc_begin, &y_ptr);

  if (x_ptr > y_ptr)
    return 1;
  if (x_ptr < y_ptr)
    return -1;
  return 0;
}

static int
fde_mixed_encoding_compare (struct object *ob, const fde *x, const fde *y)
{
  int x_encoding, y_encoding;
  _Unwind_Ptr x_ptr, y_ptr;

  x_encoding = get_fde_encoding (x);
  read_encoded_value_with_base (x_encoding, base_from_object (x_encoding, ob),
				x->pc_begin, &x_ptr);

  y_encoding = get_fde_encoding (y);
  read_encoded_value_with_base (y_encoding, base_from_object (y_encoding, ob),
				y->pc_begin, &y_ptr);

  if (x_ptr > y_ptr)
    return 1;
  if (x_ptr < y_ptr)
    return -1;
  return 0;
}

typedef int (*fde_compare_t) (struct object *, const fde *, const fde *);


/* This is a special mix of insertion sort and heap sort, optimized for
   the data sets that actually occur. They look like
   101 102 103 127 128 105 108 110 190 111 115 119 125 160 126 129 130.
   I.e. a linearly increasing sequence (coming from functions in the text
   section), with additionally a few unordered elements (coming from functions
   in gnu_linkonce sections) whose values are higher than the values in the
   surrounding linear sequence (but not necessarily higher than the values
   at the end of the linear sequence!).
   The worst-case total run time is O(N) + O(n log (n)), where N is the
   total number of FDEs and n is the number of erratic ones.  */

struct fde_accumulator
{
  struct fde_vector *linear;
  struct fde_vector *erratic;
};

static inline int
start_fde_sort (struct fde_accumulator *accu, size_t count)
{
  size_t size;
  if (! count)
    return 0;

  size = sizeof (struct fde_vector) + sizeof (const fde *) * count;
  if ((accu->linear = malloc (size)))
    {
      accu->linear->count = 0;
      if ((accu->erratic = malloc (size)))
	accu->erratic->count = 0;
      return 1;
    }
  else
    return 0;
}

static inline void
fde_insert (struct fde_accumulator *accu, const fde *this_fde)
{
  if (accu->linear)
    accu->linear->array[accu->linear->count++] = this_fde;
}

/* Split LINEAR into a linear sequence with low values and an erratic
   sequence with high values, put the linear one (of longest possible
   length) into LINEAR and the erratic one into ERRATIC. This is O(N).

   Because the longest linear sequence we are trying to locate within the
   incoming LINEAR array can be interspersed with (high valued) erratic
   entries.  We construct a chain indicating the sequenced entries.
   To avoid having to allocate this chain, we overlay it onto the space of
   the ERRATIC array during construction.  A final pass iterates over the
   chain to determine what should be placed in the ERRATIC array, and
   what is the linear sequence.  This overlay is safe from aliasing.  */

static inline void
fde_split (struct object *ob, fde_compare_t fde_compare,
	   struct fde_vector *linear, struct fde_vector *erratic)
{
  static const fde *marker;
  size_t count = linear->count;
  const fde *const *chain_end = &marker;
  size_t i, j, k;

  /* This should optimize out, but it is wise to make sure this assumption
     is correct. Should these have different sizes, we cannot cast between
     them and the overlaying onto ERRATIC will not work.  */
  gcc_assert (sizeof (const fde *) == sizeof (const fde **));

  for (i = 0; i < count; i++)
    {
      const fde *const *probe;

      for (probe = chain_end;
	   probe != &marker && fde_compare (ob, linear->array[i], *probe) < 0;
	   probe = chain_end)
	{
	  chain_end = (const fde *const*) erratic->array[probe - linear->array];
	  erratic->array[probe - linear->array] = NULL;
	}
      erratic->array[i] = (const fde *) chain_end;
      chain_end = &linear->array[i];
    }

  /* Each entry in LINEAR which is part of the linear sequence we have
     discovered will correspond to a non-NULL entry in the chain we built in
     the ERRATIC array.  */
  for (i = j = k = 0; i < count; i++)
    if (erratic->array[i])
      linear->array[j++] = linear->array[i];
    else
      erratic->array[k++] = linear->array[i];
  linear->count = j;
  erratic->count = k;
}

#define SWAP(x,y) do { const fde * tmp = x; x = y; y = tmp; } while (0)

/* Convert a semi-heap to a heap.  A semi-heap is a heap except possibly
   for the first (root) node; push it down to its rightful place.  */

static void
frame_downheap (struct object *ob, fde_compare_t fde_compare, const fde **a,
		int lo, int hi)
{
  int i, j;

  for (i = lo, j = 2*i+1;
       j < hi;
       j = 2*i+1)
    {
      if (j+1 < hi && fde_compare (ob, a[j], a[j+1]) < 0)
	++j;

      if (fde_compare (ob, a[i], a[j]) < 0)
	{
	  SWAP (a[i], a[j]);
	  i = j;
	}
      else
	break;
    }
}

/* This is O(n log(n)).  BSD/OS defines heapsort in stdlib.h, so we must
   use a name that does not conflict.  */

static void
frame_heapsort (struct object *ob, fde_compare_t fde_compare,
		struct fde_vector *erratic)
{
  /* For a description of this algorithm, see:
     Samuel P. Harbison, Guy L. Steele Jr.: C, a reference manual, 2nd ed.,
     p. 60-61.  */
  const fde ** a = erratic->array;
  /* A portion of the array is called a "heap" if for all i>=0:
     If i and 2i+1 are valid indices, then a[i] >= a[2i+1].
     If i and 2i+2 are valid indices, then a[i] >= a[2i+2].  */
  size_t n = erratic->count;
  int m;

  /* Expand our heap incrementally from the end of the array, heapifying
     each resulting semi-heap as we go.  After each step, a[m] is the top
     of a heap.  */
  for (m = n/2-1; m >= 0; --m)
    frame_downheap (ob, fde_compare, a, m, n);

  /* Shrink our heap incrementally from the end of the array, first
     swapping out the largest element a[0] and then re-heapifying the
     resulting semi-heap.  After each step, a[0..m) is a heap.  */
  for (m = n-1; m >= 1; --m)
    {
      SWAP (a[0], a[m]);
      frame_downheap (ob, fde_compare, a, 0, m);
    }
#undef SWAP
}

/* Merge V1 and V2, both sorted, and put the result into V1.  */
static inline void
fde_merge (struct object *ob, fde_compare_t fde_compare,
	   struct fde_vector *v1, struct fde_vector *v2)
{
  size_t i1, i2;
  const fde * fde2;

  i2 = v2->count;
  if (i2 > 0)
    {
      i1 = v1->count;
      do
	{
	  i2--;
	  fde2 = v2->array[i2];
	  while (i1 > 0 && fde_compare (ob, v1->array[i1-1], fde2) > 0)
	    {
	      v1->array[i1+i2] = v1->array[i1-1];
	      i1--;
	    }
	  v1->array[i1+i2] = fde2;
	}
      while (i2 > 0);
      v1->count += v2->count;
    }
}

static inline void
end_fde_sort (struct object *ob, struct fde_accumulator *accu, size_t count)
{
  fde_compare_t fde_compare;

  gcc_assert (!accu->linear || accu->linear->count == count);

  if (ob->s.b.mixed_encoding)
    fde_compare = fde_mixed_encoding_compare;
  else if (ob->s.b.encoding == DW_EH_PE_absptr)
    fde_compare = fde_unencoded_compare;
  else
    fde_compare = fde_single_encoding_compare;

  if (accu->erratic)
    {
      fde_split (ob, fde_compare, accu->linear, accu->erratic);
      gcc_assert (accu->linear->count + accu->erratic->count == count);
      frame_heapsort (ob, fde_compare, accu->erratic);
      fde_merge (ob, fde_compare, accu->linear, accu->erratic);
      free (accu->erratic);
    }
  else
    {
      /* We've not managed to malloc an erratic array,
	 so heap sort in the linear one.  */
      frame_heapsort (ob, fde_compare, accu->linear);
    }
}


/* Update encoding, mixed_encoding, and pc_begin for OB for the
   fde array beginning at THIS_FDE.  Return the number of fdes
   encountered along the way.  */

static size_t
classify_object_over_fdes (struct object *ob, const fde *this_fde)
{
  const struct dwarf_cie *last_cie = 0;
  size_t count = 0;
  int encoding = DW_EH_PE_absptr;
  _Unwind_Ptr base = 0;

  for (; ! last_fde (ob, this_fde); this_fde = next_fde (this_fde))
    {
      const struct dwarf_cie *this_cie;
      _Unwind_Ptr mask, pc_begin;
      /* Skip CIEs.  */
      if (this_fde->CIE_delta == 0)
	continue;

      /* Determine the encoding for this FDE.  Note mixed encoded
	 objects for later.  */
      this_cie = get_cie (this_fde);
      if (this_cie != last_cie)
	{
	  last_cie = this_cie;
	  encoding = get_cie_encoding (this_cie);
	  if (encoding == DW_EH_PE_omit)
	    return -1;
	  base = base_from_object (encoding, ob);
	  if (ob->s.b.encoding == DW_EH_PE_omit)
	    ob->s.b.encoding = encoding;
	  else if (ob->s.b.encoding != encoding)
	    ob->s.b.mixed_encoding = 1;
	}

      read_encoded_value_with_base (encoding, base, this_fde->pc_begin,
				    &pc_begin);

      /* Take care to ignore link-once functions that were removed.
	 In these cases, the function address will be NULL, but if
	 the encoding is smaller than a pointer a true NULL may not
	 be representable.  Assume 0 in the representable bits is NULL.  */
      mask = size_of_encoded_value (encoding);
      if (mask < sizeof (void *))
	mask = (((_Unwind_Ptr) 1) << (mask << 3)) - 1;
      else
	mask = -1;

      if ((pc_begin & mask) == 0)
	continue;

      count += 1;
      if ((void *) pc_begin < ob->pc_begin)
	ob->pc_begin = (void *) pc_begin;
    }

  return count;
}

static void
add_fdes (struct object *ob, struct fde_accumulator *accu, const fde *this_fde)
{
  const struct dwarf_cie *last_cie = 0;
  int encoding = ob->s.b.encoding;
  _Unwind_Ptr base = base_from_object (ob->s.b.encoding, ob);

  for (; ! last_fde (ob, this_fde); this_fde = next_fde (this_fde))
    {
      const struct dwarf_cie *this_cie;

      /* Skip CIEs.  */
      if (this_fde->CIE_delta == 0)
	continue;

      if (ob->s.b.mixed_encoding)
	{
	  /* Determine the encoding for this FDE.  Note mixed encoded
	     objects for later.  */
	  this_cie = get_cie (this_fde);
	  if (this_cie != last_cie)
	    {
	      last_cie = this_cie;
	      encoding = get_cie_encoding (this_cie);
	      base = base_from_object (encoding, ob);
	    }
	}

      if (encoding == DW_EH_PE_absptr)
	{
	  _Unwind_Ptr ptr;
	  memcpy (&ptr, this_fde->pc_begin, sizeof (_Unwind_Ptr));
	  if (ptr == 0)
	    continue;
	}
      else
	{
	  _Unwind_Ptr pc_begin, mask;

	  read_encoded_value_with_base (encoding, base, this_fde->pc_begin,
					&pc_begin);

	  /* Take care to ignore link-once functions that were removed.
	     In these cases, the function address will be NULL, but if
	     the encoding is smaller than a pointer a true NULL may not
	     be representable.  Assume 0 in the representable bits is NULL.  */
	  mask = size_of_encoded_value (encoding);
	  if (mask < sizeof (void *))
	    mask = (((_Unwind_Ptr) 1) << (mask << 3)) - 1;
	  else
	    mask = -1;

	  if ((pc_begin & mask) == 0)
	    continue;
	}

      fde_insert (accu, this_fde);
    }
}

/* Set up a sorted array of pointers to FDEs for a loaded object.  We
   count up the entries before allocating the array because it's likely to
   be faster.  We can be called multiple times, should we have failed to
   allocate a sorted fde array on a previous occasion.  */

static inline void
init_object (struct object* ob)
{
  struct fde_accumulator accu;
  size_t count;

  count = ob->s.b.count;
  if (count == 0)
    {
      if (ob->s.b.from_array)
	{
	  fde **p = ob->u.array;
	  for (count = 0; *p; ++p)
	    {
	      size_t cur_count = classify_object_over_fdes (ob, *p);
	      if (cur_count == (size_t) -1)
		goto unhandled_fdes;
	      count += cur_count;
	    }
	}
      else
	{
	  count = classify_object_over_fdes (ob, ob->u.single);
	  if (count == (size_t) -1)
	    {
	      static fde terminator;
	    unhandled_fdes:
	      ob->s.i = 0;
	      ob->s.b.encoding = DW_EH_PE_omit;
	      ob->u.single = &terminator;
	      return;
	    }
	}

      /* The count field we have in the main struct object is somewhat
	 limited, but should suffice for virtually all cases.  If the
	 counted value doesn't fit, re-write a zero.  The worst that
	 happens is that we re-count next time -- admittedly non-trivial
	 in that this implies some 2M fdes, but at least we function.  */
      ob->s.b.count = count;
      if (ob->s.b.count != count)
	ob->s.b.count = 0;
    }

  if (!start_fde_sort (&accu, count))
    return;

  if (ob->s.b.from_array)
    {
      fde **p;
      for (p = ob->u.array; *p; ++p)
	add_fdes (ob, &accu, *p);
    }
  else
    add_fdes (ob, &accu, ob->u.single);

  end_fde_sort (ob, &accu, count);

  /* Save the original fde pointer, since this is the key by which the
     DSO will deregister the object.  */
  accu.linear->orig_data = ob->u.single;
  ob->u.sort = accu.linear;

  ob->s.b.sorted = 1;
}

/* A linear search through a set of FDEs for the given PC.  This is
   used when there was insufficient memory to allocate and sort an
   array.  */

static const fde *
linear_search_fdes (struct object *ob, const fde *this_fde, void *pc)
{
  const struct dwarf_cie *last_cie = 0;
  int encoding = ob->s.b.encoding;
  _Unwind_Ptr base = base_from_object (ob->s.b.encoding, ob);

  for (; ! last_fde (ob, this_fde); this_fde = next_fde (this_fde))
    {
      const struct dwarf_cie *this_cie;
      _Unwind_Ptr pc_begin, pc_range;

      /* Skip CIEs.  */
      if (this_fde->CIE_delta == 0)
	continue;

      if (ob->s.b.mixed_encoding)
	{
	  /* Determine the encoding for this FDE.  Note mixed encoded
	     objects for later.  */
	  this_cie = get_cie (this_fde);
	  if (this_cie != last_cie)
	    {
	      last_cie = this_cie;
	      encoding = get_cie_encoding (this_cie);
	      base = base_from_object (encoding, ob);
	    }
	}

      if (encoding == DW_EH_PE_absptr)
	{
	  const _Unwind_Ptr *pc_array = (const _Unwind_Ptr *) this_fde->pc_begin;
	  pc_begin = pc_array[0];
	  pc_range = pc_array[1];
	  if (pc_begin == 0)
	    continue;
	}
      else
	{
	  _Unwind_Ptr mask;
	  const unsigned char *p;

	  p = read_encoded_value_with_base (encoding, base,
					    this_fde->pc_begin, &pc_begin);
	  read_encoded_value_with_base (encoding & 0x0F, 0, p, &pc_range);

	  /* Take care to ignore link-once functions that were removed.
	     In these cases, the function address will be NULL, but if
	     the encoding is smaller than a pointer a true NULL may not
	     be representable.  Assume 0 in the representable bits is NULL.  */
	  mask = size_of_encoded_value (encoding);
	  if (mask < sizeof (void *))
	    mask = (((_Unwind_Ptr) 1) << (mask << 3)) - 1;
	  else
	    mask = -1;

	  if ((pc_begin & mask) == 0)
	    continue;
	}

      if ((_Unwind_Ptr) pc - pc_begin < pc_range)
	return this_fde;
    }

  return NULL;
}

/* Binary search for an FDE containing the given PC.  Here are three
   implementations of increasing complexity.  */

static inline const fde *
binary_search_unencoded_fdes (struct object *ob, void *pc)
{
  struct fde_vector *vec = ob->u.sort;
  size_t lo, hi;

  for (lo = 0, hi = vec->count; lo < hi; )
    {
      size_t i = (lo + hi) / 2;
      const fde *const f = vec->array[i];
      void *pc_begin;
      uaddr pc_range;
      memcpy (&pc_begin, (const void * const *) f->pc_begin, sizeof (void *));
      memcpy (&pc_range, (const uaddr *) f->pc_begin + 1, sizeof (uaddr));

      if (pc < pc_begin)
	hi = i;
      else if (pc >= pc_begin + pc_range)
	lo = i + 1;
      else
	return f;
    }

  return NULL;
}

static inline const fde *
binary_search_single_encoding_fdes (struct object *ob, void *pc)
{
  struct fde_vector *vec = ob->u.sort;
  int encoding = ob->s.b.encoding;
  _Unwind_Ptr base = base_from_object (encoding, ob);
  size_t lo, hi;

  for (lo = 0, hi = vec->count; lo < hi; )
    {
      size_t i = (lo + hi) / 2;
      const fde *f = vec->array[i];
      _Unwind_Ptr pc_begin, pc_range;
      const unsigned char *p;

      p = read_encoded_value_with_base (encoding, base, f->pc_begin,
					&pc_begin);
      read_encoded_value_with_base (encoding & 0x0F, 0, p, &pc_range);

      if ((_Unwind_Ptr) pc < pc_begin)
	hi = i;
      else if ((_Unwind_Ptr) pc >= pc_begin + pc_range)
	lo = i + 1;
      else
	return f;
    }

  return NULL;
}

static inline const fde *
binary_search_mixed_encoding_fdes (struct object *ob, void *pc)
{
  struct fde_vector *vec = ob->u.sort;
  size_t lo, hi;

  for (lo = 0, hi = vec->count; lo < hi; )
    {
      size_t i = (lo + hi) / 2;
      const fde *f = vec->array[i];
      _Unwind_Ptr pc_begin, pc_range;
      const unsigned char *p;
      int encoding;

      encoding = get_fde_encoding (f);
      p = read_encoded_value_with_base (encoding,
					base_from_object (encoding, ob),
					f->pc_begin, &pc_begin);
      read_encoded_value_with_base (encoding & 0x0F, 0, p, &pc_range);

      if ((_Unwind_Ptr) pc < pc_begin)
	hi = i;
      else if ((_Unwind_Ptr) pc >= pc_begin + pc_range)
	lo = i + 1;
      else
	return f;
    }

  return NULL;
}

static const fde *
search_object (struct object* ob, void *pc)
{
  /* If the data hasn't been sorted, try to do this now.  We may have
     more memory available than last time we tried.  */
  if (! ob->s.b.sorted)
    {
      init_object (ob);

      /* Despite the above comment, the normal reason to get here is
	 that we've not processed this object before.  A quick range
	 check is in order.  */
      if (pc < ob->pc_begin)
	return NULL;
    }

  if (ob->s.b.sorted)
    {
      if (ob->s.b.mixed_encoding)
	return binary_search_mixed_encoding_fdes (ob, pc);
      else if (ob->s.b.encoding == DW_EH_PE_absptr)
	return binary_search_unencoded_fdes (ob, pc);
      else
	return binary_search_single_encoding_fdes (ob, pc);
    }
  else
    {
      /* Long slow laborious linear search, cos we've no memory.  */
      if (ob->s.b.from_array)
	{
	  fde **p;
	  for (p = ob->u.array; *p ; p++)
	    {
	      const fde *f = linear_search_fdes (ob, *p, pc);
	      if (f)
		return f;
	    }
	  return NULL;
	}
      else
	return linear_search_fdes (ob, ob->u.single, pc);
    }
}

const fde *
_Unwind_Find_FDE (void *pc, struct dwarf_eh_bases *bases)
{
  struct object *ob;
  const fde *f = NULL;

  mutex_lock(&object_mutex);

  /* Linear search through the classified objects, to find the one
     containing the pc.  Note that pc_begin is sorted descending, and
     we expect objects to be non-overlapping.  */
  for (ob = seen_objects; ob; ob = ob->next)
    if (pc >= ob->pc_begin)
      {
	f = search_object (ob, pc);
	if (f)
	  goto fini;
	break;
      }

  /* Classify and search the objects we've not yet processed.  */
  while ((ob = unseen_objects))
    {
      struct object **p;

      unseen_objects = ob->next;
      f = search_object (ob, pc);

      /* Insert the object into the classified list.  */
      for (p = &seen_objects; *p ; p = &(*p)->next)
	if ((*p)->pc_begin < ob->pc_begin)
	  break;
      ob->next = *p;
      *p = ob;

      if (f)
	goto fini;
    }

 fini:
  mutex_unlock(&object_mutex);

  if (f)
    {
      int encoding;
      _Unwind_Ptr func;

      bases->tbase = ob->tbase;
      bases->dbase = ob->dbase;

      encoding = ob->s.b.encoding;
      if (ob->s.b.mixed_encoding)
	encoding = get_fde_encoding (f);
      read_encoded_value_with_base (encoding, base_from_object (encoding, ob),
				    f->pc_begin, &func);
      bases->func = (void *) func;
    }

  return f;
}

