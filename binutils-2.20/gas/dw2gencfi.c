/* dw2gencfi.c - Support for generating Dwarf2 CFI information.
   Copyright 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
   Free Software Foundation, Inc.
   Contributed by Michal Ludvig <mludvig@suse.cz>

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#include "as.h"
#include "dw2gencfi.h"
#include "subsegs.h"
#include "dwarf2dbg.h"

#ifdef TARGET_USE_CFIPOP

/* By default, use difference expressions if DIFF_EXPR_OK is defined.  */
#ifndef CFI_DIFF_EXPR_OK
# ifdef DIFF_EXPR_OK
#  define CFI_DIFF_EXPR_OK 1
# else
#  define CFI_DIFF_EXPR_OK 0
# endif
#endif

#ifndef CFI_DIFF_LSDA_OK
# define CFI_DIFF_LSDA_OK CFI_DIFF_EXPR_OK
#endif

#if CFI_DIFF_EXPR_OK == 1 && CFI_DIFF_LSDA_OK == 0
# error "CFI_DIFF_EXPR_OK should imply CFI_DIFF_LSDA_OK"
#endif

/* We re-use DWARF2_LINE_MIN_INSN_LENGTH for the code alignment field
   of the CIE.  Default to 1 if not otherwise specified.  */
#ifndef  DWARF2_LINE_MIN_INSN_LENGTH
# define DWARF2_LINE_MIN_INSN_LENGTH 1
#endif

/* By default, use 32-bit relocations from .eh_frame into .text.  */
#ifndef DWARF2_FDE_RELOC_SIZE
# define DWARF2_FDE_RELOC_SIZE 4
#endif

/* By default, use a read-only .eh_frame section.  */
#ifndef DWARF2_EH_FRAME_READ_ONLY
# define DWARF2_EH_FRAME_READ_ONLY SEC_READONLY
#endif

#ifndef EH_FRAME_ALIGNMENT
# define EH_FRAME_ALIGNMENT (bfd_get_arch_size (stdoutput) == 64 ? 3 : 2)
#endif

#ifndef tc_cfi_frame_initial_instructions
# define tc_cfi_frame_initial_instructions() ((void)0)
#endif

#ifndef DWARF2_FORMAT
# define DWARF2_FORMAT(SEC) dwarf2_format_32bit
#endif

#ifndef DWARF2_ADDR_SIZE
# define DWARF2_ADDR_SIZE(bfd) (bfd_arch_bits_per_address (bfd) / 8)
#endif

struct cfi_escape_data {
  struct cfi_escape_data *next;
  expressionS exp;
};

struct cfi_insn_data
{
  struct cfi_insn_data *next;
  int insn;
  union {
    struct {
      unsigned reg;
      offsetT offset;
    } ri;

    struct {
      unsigned reg1;
      unsigned reg2;
    } rr;

    unsigned r;
    offsetT i;

    struct {
      symbolS *lab1;
      symbolS *lab2;
    } ll;

    struct cfi_escape_data *esc;

    struct {
      unsigned reg, encoding;
      expressionS exp;
    } ea;
  } u;
};

struct fde_entry
{
  struct fde_entry *next;
  symbolS *start_address;
  symbolS *end_address;
  struct cfi_insn_data *data;
  struct cfi_insn_data **last;
  unsigned char per_encoding;
  unsigned char lsda_encoding;
  expressionS personality;
  expressionS lsda;
  unsigned int return_column;
  unsigned int signal_frame;
};

struct cie_entry
{
  struct cie_entry *next;
  symbolS *start_address;
  unsigned int return_column;
  unsigned int signal_frame;
  unsigned char per_encoding;
  unsigned char lsda_encoding;
  expressionS personality;
  struct cfi_insn_data *first, *last;
};


/* List of FDE entries.  */
static struct fde_entry *all_fde_data;
static struct fde_entry **last_fde_data = &all_fde_data;

/* List of CIEs so that they could be reused.  */
static struct cie_entry *cie_root;

/* Stack of old CFI data, for save/restore.  */
struct cfa_save_data
{
  struct cfa_save_data *next;
  offsetT cfa_offset;
};

/* Current open FDE entry.  */
struct frch_cfi_data
{
  struct fde_entry *cur_fde_data;
  symbolS *last_address;
  offsetT cur_cfa_offset;
  struct cfa_save_data *cfa_save_stack;
};

/* Construct a new FDE structure and add it to the end of the fde list.  */

static struct fde_entry *
alloc_fde_entry (void)
{
  struct fde_entry *fde = (struct fde_entry *)
      xcalloc (1, sizeof (struct fde_entry));

  frchain_now->frch_cfi_data = (struct frch_cfi_data *)
      xcalloc (1, sizeof (struct frch_cfi_data));
  frchain_now->frch_cfi_data->cur_fde_data = fde;
  *last_fde_data = fde;
  last_fde_data = &fde->next;

  fde->last = &fde->data;
  fde->return_column = DWARF2_DEFAULT_RETURN_COLUMN;
  fde->per_encoding = DW_EH_PE_omit;
  fde->lsda_encoding = DW_EH_PE_omit;

  return fde;
}

/* The following functions are available for a backend to construct its
   own unwind information, usually from legacy unwind directives.  */

/* Construct a new INSN structure and add it to the end of the insn list
   for the currently active FDE.  */

static struct cfi_insn_data *
alloc_cfi_insn_data (void)
{
  struct cfi_insn_data *insn = (struct cfi_insn_data *)
      xcalloc (1, sizeof (struct cfi_insn_data));
  struct fde_entry *cur_fde_data = frchain_now->frch_cfi_data->cur_fde_data;

  *cur_fde_data->last = insn;
  cur_fde_data->last = &insn->next;

  return insn;
}

/* Construct a new FDE structure that begins at LABEL.  */

void 
cfi_new_fde (symbolS *label)
{
  struct fde_entry *fde = alloc_fde_entry ();
  fde->start_address = label;
  frchain_now->frch_cfi_data->last_address = label;
}

/* End the currently open FDE.  */

void 
cfi_end_fde (symbolS *label)
{
  frchain_now->frch_cfi_data->cur_fde_data->end_address = label;
  free (frchain_now->frch_cfi_data);
  frchain_now->frch_cfi_data = NULL;
}

/* Set the return column for the current FDE.  */

void
cfi_set_return_column (unsigned regno)
{
  frchain_now->frch_cfi_data->cur_fde_data->return_column = regno;
}

/* Universal functions to store new instructions.  */

static void
cfi_add_CFA_insn(int insn)
{
  struct cfi_insn_data *insn_ptr = alloc_cfi_insn_data ();

  insn_ptr->insn = insn;
}

static void
cfi_add_CFA_insn_reg (int insn, unsigned regno)
{
  struct cfi_insn_data *insn_ptr = alloc_cfi_insn_data ();

  insn_ptr->insn = insn;
  insn_ptr->u.r = regno;
}

static void
cfi_add_CFA_insn_offset (int insn, offsetT offset)
{
  struct cfi_insn_data *insn_ptr = alloc_cfi_insn_data ();

  insn_ptr->insn = insn;
  insn_ptr->u.i = offset;
}

static void
cfi_add_CFA_insn_reg_reg (int insn, unsigned reg1, unsigned reg2)
{
  struct cfi_insn_data *insn_ptr = alloc_cfi_insn_data ();

  insn_ptr->insn = insn;
  insn_ptr->u.rr.reg1 = reg1;
  insn_ptr->u.rr.reg2 = reg2;
}

static void
cfi_add_CFA_insn_reg_offset (int insn, unsigned regno, offsetT offset)
{
  struct cfi_insn_data *insn_ptr = alloc_cfi_insn_data ();

  insn_ptr->insn = insn;
  insn_ptr->u.ri.reg = regno;
  insn_ptr->u.ri.offset = offset;
}

/* Add a CFI insn to advance the PC from the last address to LABEL.  */

void
cfi_add_advance_loc (symbolS *label)
{
  struct cfi_insn_data *insn = alloc_cfi_insn_data ();

  insn->insn = DW_CFA_advance_loc;
  insn->u.ll.lab1 = frchain_now->frch_cfi_data->last_address;
  insn->u.ll.lab2 = label;

  frchain_now->frch_cfi_data->last_address = label;
}

/* Add a DW_CFA_offset record to the CFI data.  */

void
cfi_add_CFA_offset (unsigned regno, offsetT offset)
{
  unsigned int abs_data_align;

  gas_assert (DWARF2_CIE_DATA_ALIGNMENT != 0);
  cfi_add_CFA_insn_reg_offset (DW_CFA_offset, regno, offset);

  abs_data_align = (DWARF2_CIE_DATA_ALIGNMENT < 0
		    ? -DWARF2_CIE_DATA_ALIGNMENT : DWARF2_CIE_DATA_ALIGNMENT);
  if (offset % abs_data_align)
    as_bad (_("register save offset not a multiple of %u"), abs_data_align);
}

/* Add a DW_CFA_def_cfa record to the CFI data.  */

void
cfi_add_CFA_def_cfa (unsigned regno, offsetT offset)
{
  cfi_add_CFA_insn_reg_offset (DW_CFA_def_cfa, regno, offset);
  frchain_now->frch_cfi_data->cur_cfa_offset = offset;
}

/* Add a DW_CFA_register record to the CFI data.  */

void
cfi_add_CFA_register (unsigned reg1, unsigned reg2)
{
  cfi_add_CFA_insn_reg_reg (DW_CFA_register, reg1, reg2);
}

/* Add a DW_CFA_def_cfa_register record to the CFI data.  */

void
cfi_add_CFA_def_cfa_register (unsigned regno)
{
  cfi_add_CFA_insn_reg (DW_CFA_def_cfa_register, regno);
}

/* Add a DW_CFA_def_cfa_offset record to the CFI data.  */

void
cfi_add_CFA_def_cfa_offset (offsetT offset)
{
  cfi_add_CFA_insn_offset (DW_CFA_def_cfa_offset, offset);
  frchain_now->frch_cfi_data->cur_cfa_offset = offset;
}

void
cfi_add_CFA_restore (unsigned regno)
{
  cfi_add_CFA_insn_reg (DW_CFA_restore, regno);
}

void
cfi_add_CFA_undefined (unsigned regno)
{
  cfi_add_CFA_insn_reg (DW_CFA_undefined, regno);
}

void
cfi_add_CFA_same_value (unsigned regno)
{
  cfi_add_CFA_insn_reg (DW_CFA_same_value, regno);
}

void
cfi_add_CFA_remember_state (void)
{
  struct cfa_save_data *p;

  cfi_add_CFA_insn (DW_CFA_remember_state);

  p = (struct cfa_save_data *) xmalloc (sizeof (*p));
  p->cfa_offset = frchain_now->frch_cfi_data->cur_cfa_offset;
  p->next = frchain_now->frch_cfi_data->cfa_save_stack;
  frchain_now->frch_cfi_data->cfa_save_stack = p;
}

void
cfi_add_CFA_restore_state (void)
{
  struct cfa_save_data *p;

  cfi_add_CFA_insn (DW_CFA_restore_state);

  p = frchain_now->frch_cfi_data->cfa_save_stack;
  if (p)
    {
      frchain_now->frch_cfi_data->cur_cfa_offset = p->cfa_offset;
      frchain_now->frch_cfi_data->cfa_save_stack = p->next;
      free (p);
    }
  else
    as_bad (_("CFI state restore without previous remember"));
}


/* Parse CFI assembler directives.  */

static void dot_cfi (int);
static void dot_cfi_escape (int);
static void dot_cfi_sections (int);
static void dot_cfi_startproc (int);
static void dot_cfi_endproc (int);
static void dot_cfi_personality (int);
static void dot_cfi_lsda (int);
static void dot_cfi_val_encoded_addr (int);

/* Fake CFI type; outside the byte range of any real CFI insn.  */
#define CFI_adjust_cfa_offset	0x100
#define CFI_return_column	0x101
#define CFI_rel_offset		0x102
#define CFI_escape		0x103
#define CFI_signal_frame	0x104
#define CFI_val_encoded_addr	0x105

const pseudo_typeS cfi_pseudo_table[] =
  {
    { "cfi_sections", dot_cfi_sections, 0 },
    { "cfi_startproc", dot_cfi_startproc, 0 },
    { "cfi_endproc", dot_cfi_endproc, 0 },
    { "cfi_def_cfa", dot_cfi, DW_CFA_def_cfa },
    { "cfi_def_cfa_register", dot_cfi, DW_CFA_def_cfa_register },
    { "cfi_def_cfa_offset", dot_cfi, DW_CFA_def_cfa_offset },
    { "cfi_adjust_cfa_offset", dot_cfi, CFI_adjust_cfa_offset },
    { "cfi_offset", dot_cfi, DW_CFA_offset },
    { "cfi_rel_offset", dot_cfi, CFI_rel_offset },
    { "cfi_register", dot_cfi, DW_CFA_register },
    { "cfi_return_column", dot_cfi, CFI_return_column },
    { "cfi_restore", dot_cfi, DW_CFA_restore },
    { "cfi_undefined", dot_cfi, DW_CFA_undefined },
    { "cfi_same_value", dot_cfi, DW_CFA_same_value },
    { "cfi_remember_state", dot_cfi, DW_CFA_remember_state },
    { "cfi_restore_state", dot_cfi, DW_CFA_restore_state },
    { "cfi_window_save", dot_cfi, DW_CFA_GNU_window_save },
    { "cfi_escape", dot_cfi_escape, 0 },
    { "cfi_signal_frame", dot_cfi, CFI_signal_frame },
    { "cfi_personality", dot_cfi_personality, 0 },
    { "cfi_lsda", dot_cfi_lsda, 0 },
    { "cfi_val_encoded_addr", dot_cfi_val_encoded_addr, 0 },
    { NULL, NULL, 0 }
  };

static void
cfi_parse_separator (void)
{
  SKIP_WHITESPACE ();
  if (*input_line_pointer == ',')
    input_line_pointer++;
  else
    as_bad (_("missing separator"));
}

#ifndef tc_parse_to_dw2regnum
static void
tc_parse_to_dw2regnum(expressionS *exp)
{
# ifdef tc_regname_to_dw2regnum
  SKIP_WHITESPACE ();
  if (is_name_beginner (*input_line_pointer)
      || (*input_line_pointer == '%'
	  && is_name_beginner (*++input_line_pointer)))
    {
      char *name, c;

      name = input_line_pointer;
      c = get_symbol_end ();

      exp->X_op = O_constant;
      exp->X_add_number = tc_regname_to_dw2regnum (name);

      *input_line_pointer = c;
    }
  else
# endif
    expression_and_evaluate (exp);
}
#endif

static unsigned
cfi_parse_reg (void)
{
  int regno;
  expressionS exp;

  tc_parse_to_dw2regnum (&exp);
  switch (exp.X_op)
    {
    case O_register:
    case O_constant:
      regno = exp.X_add_number;
      break;

    default:
      regno = -1;
      break;
    }

  if (regno < 0)
    {
      as_bad (_("bad register expression"));
      regno = 0;
    }

  return regno;
}

static offsetT
cfi_parse_const (void)
{
  return get_absolute_expression ();
}

static void
dot_cfi (int arg)
{
  offsetT offset;
  unsigned reg1, reg2;

  if (frchain_now->frch_cfi_data == NULL)
    {
      as_bad (_("CFI instruction used without previous .cfi_startproc"));
      ignore_rest_of_line ();
      return;
    }

  /* If the last address was not at the current PC, advance to current.  */
  if (symbol_get_frag (frchain_now->frch_cfi_data->last_address) != frag_now
      || S_GET_VALUE (frchain_now->frch_cfi_data->last_address)
	 != frag_now_fix ())
    cfi_add_advance_loc (symbol_temp_new_now ());

  switch (arg)
    {
    case DW_CFA_offset:
      reg1 = cfi_parse_reg ();
      cfi_parse_separator ();
      offset = cfi_parse_const ();
      cfi_add_CFA_offset (reg1, offset);
      break;

    case CFI_rel_offset:
      reg1 = cfi_parse_reg ();
      cfi_parse_separator ();
      offset = cfi_parse_const ();
      cfi_add_CFA_offset (reg1,
			  offset - frchain_now->frch_cfi_data->cur_cfa_offset);
      break;

    case DW_CFA_def_cfa:
      reg1 = cfi_parse_reg ();
      cfi_parse_separator ();
      offset = cfi_parse_const ();
      cfi_add_CFA_def_cfa (reg1, offset);
      break;

    case DW_CFA_register:
      reg1 = cfi_parse_reg ();
      cfi_parse_separator ();
      reg2 = cfi_parse_reg ();
      cfi_add_CFA_register (reg1, reg2);
      break;

    case DW_CFA_def_cfa_register:
      reg1 = cfi_parse_reg ();
      cfi_add_CFA_def_cfa_register (reg1);
      break;

    case DW_CFA_def_cfa_offset:
      offset = cfi_parse_const ();
      cfi_add_CFA_def_cfa_offset (offset);
      break;

    case CFI_adjust_cfa_offset:
      offset = cfi_parse_const ();
      cfi_add_CFA_def_cfa_offset (frchain_now->frch_cfi_data->cur_cfa_offset
				  + offset);
      break;

    case DW_CFA_restore:
      for (;;)
	{
	  reg1 = cfi_parse_reg ();
	  cfi_add_CFA_restore (reg1);
	  SKIP_WHITESPACE ();
	  if (*input_line_pointer != ',')
	    break;
	  ++input_line_pointer;
	}
      break;

    case DW_CFA_undefined:
      for (;;)
	{
	  reg1 = cfi_parse_reg ();
	  cfi_add_CFA_undefined (reg1);
	  SKIP_WHITESPACE ();
	  if (*input_line_pointer != ',')
	    break;
	  ++input_line_pointer;
	}
      break;

    case DW_CFA_same_value:
      reg1 = cfi_parse_reg ();
      cfi_add_CFA_same_value (reg1);
      break;

    case CFI_return_column:
      reg1 = cfi_parse_reg ();
      cfi_set_return_column (reg1);
      break;

    case DW_CFA_remember_state:
      cfi_add_CFA_remember_state ();
      break;

    case DW_CFA_restore_state:
      cfi_add_CFA_restore_state ();
      break;

    case DW_CFA_GNU_window_save:
      cfi_add_CFA_insn (DW_CFA_GNU_window_save);
      break;

    case CFI_signal_frame:
      frchain_now->frch_cfi_data->cur_fde_data->signal_frame = 1;
      break;

    default:
      abort ();
    }

  demand_empty_rest_of_line ();
}

static void
dot_cfi_escape (int ignored ATTRIBUTE_UNUSED)
{
  struct cfi_escape_data *head, **tail, *e;
  struct cfi_insn_data *insn;

  if (frchain_now->frch_cfi_data == NULL)
    {
      as_bad (_("CFI instruction used without previous .cfi_startproc"));
      ignore_rest_of_line ();
      return;
    }

  /* If the last address was not at the current PC, advance to current.  */
  if (symbol_get_frag (frchain_now->frch_cfi_data->last_address) != frag_now
      || S_GET_VALUE (frchain_now->frch_cfi_data->last_address)
	 != frag_now_fix ())
    cfi_add_advance_loc (symbol_temp_new_now ());

  tail = &head;
  do
    {
      e = (struct cfi_escape_data *) xmalloc (sizeof (*e));
      do_parse_cons_expression (&e->exp, 1);
      *tail = e;
      tail = &e->next;
    }
  while (*input_line_pointer++ == ',');
  *tail = NULL;

  insn = alloc_cfi_insn_data ();
  insn->insn = CFI_escape;
  insn->u.esc = head;

  --input_line_pointer;
  demand_empty_rest_of_line ();
}

static void
dot_cfi_personality (int ignored ATTRIBUTE_UNUSED)
{
  struct fde_entry *fde;
  offsetT encoding;

  if (frchain_now->frch_cfi_data == NULL)
    {
      as_bad (_("CFI instruction used without previous .cfi_startproc"));
      ignore_rest_of_line ();
      return;
    }

  fde = frchain_now->frch_cfi_data->cur_fde_data;
  encoding = cfi_parse_const ();
  if (encoding == DW_EH_PE_omit)
    {
      demand_empty_rest_of_line ();
      fde->per_encoding = encoding;
      return;
    }

  if ((encoding & 0xff) != encoding
      || ((encoding & 0x70) != 0
#if CFI_DIFF_EXPR_OK || defined tc_cfi_emit_pcrel_expr
	  && (encoding & 0x70) != DW_EH_PE_pcrel
#endif
	  )
	 /* leb128 can be handled, but does something actually need it?  */
      || (encoding & 7) == DW_EH_PE_uleb128
      || (encoding & 7) > DW_EH_PE_udata8)
    {
      as_bad (_("invalid or unsupported encoding in .cfi_personality"));
      ignore_rest_of_line ();
      return;
    }

  if (*input_line_pointer++ != ',')
    {
      as_bad (_(".cfi_personality requires encoding and symbol arguments"));
      ignore_rest_of_line ();
      return;
    }

  expression_and_evaluate (&fde->personality);
  switch (fde->personality.X_op)
    {
    case O_symbol:
      break;
    case O_constant:
      if ((encoding & 0x70) == DW_EH_PE_pcrel)
	encoding = DW_EH_PE_omit;
      break;
    default:
      encoding = DW_EH_PE_omit;
      break;
    }

  fde->per_encoding = encoding;

  if (encoding == DW_EH_PE_omit)
    {
      as_bad (_("wrong second argument to .cfi_personality"));
      ignore_rest_of_line ();
      return;
    }

  demand_empty_rest_of_line ();
}

static void
dot_cfi_lsda (int ignored ATTRIBUTE_UNUSED)
{
  struct fde_entry *fde;
  offsetT encoding;

  if (frchain_now->frch_cfi_data == NULL)
    {
      as_bad (_("CFI instruction used without previous .cfi_startproc"));
      ignore_rest_of_line ();
      return;
    }

  fde = frchain_now->frch_cfi_data->cur_fde_data;
  encoding = cfi_parse_const ();
  if (encoding == DW_EH_PE_omit)
    {
      demand_empty_rest_of_line ();
      fde->lsda_encoding = encoding;
      return;
    }

  if ((encoding & 0xff) != encoding
      || ((encoding & 0x70) != 0
#if CFI_DIFF_LSDA_OK || defined tc_cfi_emit_pcrel_expr
	  && (encoding & 0x70) != DW_EH_PE_pcrel
#endif
	  )
	 /* leb128 can be handled, but does something actually need it?  */
      || (encoding & 7) == DW_EH_PE_uleb128
      || (encoding & 7) > DW_EH_PE_udata8)
    {
      as_bad (_("invalid or unsupported encoding in .cfi_lsda"));
      ignore_rest_of_line ();
      return;
    }

  if (*input_line_pointer++ != ',')
    {
      as_bad (_(".cfi_lsda requires encoding and symbol arguments"));
      ignore_rest_of_line ();
      return;
    }

  fde->lsda_encoding = encoding;

  expression_and_evaluate (&fde->lsda);
  switch (fde->lsda.X_op)
    {
    case O_symbol:
      break;
    case O_constant:
      if ((encoding & 0x70) == DW_EH_PE_pcrel)
	encoding = DW_EH_PE_omit;
      break;
    default:
      encoding = DW_EH_PE_omit;
      break;
    }

  fde->lsda_encoding = encoding;

  if (encoding == DW_EH_PE_omit)
    {
      as_bad (_("wrong second argument to .cfi_lsda"));
      ignore_rest_of_line ();
      return;
    }

  demand_empty_rest_of_line ();
}

static void
dot_cfi_val_encoded_addr (int ignored ATTRIBUTE_UNUSED)
{
  struct cfi_insn_data *insn_ptr;
  offsetT encoding;

  if (frchain_now->frch_cfi_data == NULL)
    {
      as_bad (_("CFI instruction used without previous .cfi_startproc"));
      ignore_rest_of_line ();
      return;
    }

  /* If the last address was not at the current PC, advance to current.  */
  if (symbol_get_frag (frchain_now->frch_cfi_data->last_address) != frag_now
      || S_GET_VALUE (frchain_now->frch_cfi_data->last_address)
	 != frag_now_fix ())
    cfi_add_advance_loc (symbol_temp_new_now ());

  insn_ptr = alloc_cfi_insn_data ();
  insn_ptr->insn = CFI_val_encoded_addr;
  
  insn_ptr->u.ea.reg = cfi_parse_reg ();

  cfi_parse_separator ();
  encoding = cfi_parse_const ();
  if ((encoding & 0xff) != encoding
      || ((encoding & 0x70) != 0
#if CFI_DIFF_EXPR_OK || defined tc_cfi_emit_pcrel_expr
	  && (encoding & 0x70) != DW_EH_PE_pcrel
#endif
	  )
	 /* leb128 can be handled, but does something actually need it?  */
      || (encoding & 7) == DW_EH_PE_uleb128
      || (encoding & 7) > DW_EH_PE_udata8)
    {
      as_bad (_("invalid or unsupported encoding in .cfi_lsda"));
      encoding = DW_EH_PE_omit;
    }

  cfi_parse_separator ();
  expression_and_evaluate (&insn_ptr->u.ea.exp);
  switch (insn_ptr->u.ea.exp.X_op)
    {
    case O_symbol:
      break;
    case O_constant:
      if ((encoding & 0x70) != DW_EH_PE_pcrel)
        break;
    default:
      encoding = DW_EH_PE_omit;
      break;
    }

  insn_ptr->u.ea.encoding = encoding;
  if (encoding == DW_EH_PE_omit)
    {
      as_bad (_("wrong third argument to .cfi_val_encoded_addr"));
      ignore_rest_of_line ();
      return;
    }

  demand_empty_rest_of_line ();
}

/* By default emit .eh_frame only, not .debug_frame.  */
#define CFI_EMIT_eh_frame	(1 << 0)
#define CFI_EMIT_debug_frame	(1 << 1)
static int cfi_sections = CFI_EMIT_eh_frame;

static void
dot_cfi_sections (int ignored ATTRIBUTE_UNUSED)
{
  int sections = 0;

  SKIP_WHITESPACE ();
  if (is_name_beginner (*input_line_pointer))
    while (1)
      {
	char *name, c;

	name = input_line_pointer;
	c = get_symbol_end ();

	if (strcmp (name, ".eh_frame") == 0)
	  sections |= CFI_EMIT_eh_frame;
	else if (strcmp (name, ".debug_frame") == 0)
	  sections |= CFI_EMIT_debug_frame;
	else
	  {
	    *input_line_pointer = c;
	    input_line_pointer = name;
	    break;
	  }

	*input_line_pointer = c;
	SKIP_WHITESPACE ();
	if (*input_line_pointer == ',')
	  {
	    name = input_line_pointer++;
	    SKIP_WHITESPACE ();
	    if (!is_name_beginner (*input_line_pointer))
	      {
		input_line_pointer = name;
		break;
	      }
	  }
	else if (is_name_beginner (*input_line_pointer))
	  break;
      }

  demand_empty_rest_of_line ();
  cfi_sections = sections;
}

static void
dot_cfi_startproc (int ignored ATTRIBUTE_UNUSED)
{
  int simple = 0;

  if (frchain_now->frch_cfi_data != NULL)
    {
      as_bad (_("previous CFI entry not closed (missing .cfi_endproc)"));
      ignore_rest_of_line ();
      return;
    }

  cfi_new_fde (symbol_temp_new_now ());

  SKIP_WHITESPACE ();
  if (is_name_beginner (*input_line_pointer))
    {
      char *name, c;

      name = input_line_pointer;
      c = get_symbol_end ();

      if (strcmp (name, "simple") == 0)
	{
	  simple = 1;
	  *input_line_pointer = c;
	}
      else
	input_line_pointer = name;
    }
  demand_empty_rest_of_line ();

  frchain_now->frch_cfi_data->cur_cfa_offset = 0;
  if (!simple)
    tc_cfi_frame_initial_instructions ();
}

static void
dot_cfi_endproc (int ignored ATTRIBUTE_UNUSED)
{
  if (frchain_now->frch_cfi_data == NULL)
    {
      as_bad (_(".cfi_endproc without corresponding .cfi_startproc"));
      ignore_rest_of_line ();
      return;
    }

  cfi_end_fde (symbol_temp_new_now ());

  demand_empty_rest_of_line ();
}


/* Emit a single byte into the current segment.  */

static inline void
out_one (int byte)
{
  FRAG_APPEND_1_CHAR (byte);
}

/* Emit a two-byte word into the current segment.  */

static inline void
out_two (int data)
{
  md_number_to_chars (frag_more (2), data, 2);
}

/* Emit a four byte word into the current segment.  */

static inline void
out_four (int data)
{
  md_number_to_chars (frag_more (4), data, 4);
}

/* Emit an unsigned "little-endian base 128" number.  */

static void
out_uleb128 (addressT value)
{
  output_leb128 (frag_more (sizeof_leb128 (value, 0)), value, 0);
}

/* Emit an unsigned "little-endian base 128" number.  */

static void
out_sleb128 (offsetT value)
{
  output_leb128 (frag_more (sizeof_leb128 (value, 1)), value, 1);
}

static void
output_cfi_insn (struct cfi_insn_data *insn)
{
  offsetT offset;
  unsigned int regno;

  switch (insn->insn)
    {
    case DW_CFA_advance_loc:
      {
	symbolS *from = insn->u.ll.lab1;
	symbolS *to = insn->u.ll.lab2;

	if (symbol_get_frag (to) == symbol_get_frag (from))
	  {
	    addressT delta = S_GET_VALUE (to) - S_GET_VALUE (from);
	    addressT scaled = delta / DWARF2_LINE_MIN_INSN_LENGTH;

	    if (scaled <= 0x3F)
	      out_one (DW_CFA_advance_loc + scaled);
	    else if (scaled <= 0xFF)
	      {
		out_one (DW_CFA_advance_loc1);
		out_one (scaled);
	      }
	    else if (scaled <= 0xFFFF)
	      {
		out_one (DW_CFA_advance_loc2);
		out_two (scaled);
	      }
	    else
	      {
		out_one (DW_CFA_advance_loc4);
		out_four (scaled);
	      }
	  }
	else
	  {
	    expressionS exp;

	    exp.X_op = O_subtract;
	    exp.X_add_symbol = to;
	    exp.X_op_symbol = from;
	    exp.X_add_number = 0;

	    /* The code in ehopt.c expects that one byte of the encoding
	       is already allocated to the frag.  This comes from the way
	       that it scans the .eh_frame section looking first for the
	       .byte DW_CFA_advance_loc4.  */
	    *frag_more (1) = DW_CFA_advance_loc4;

	    frag_var (rs_cfa, 4, 0, DWARF2_LINE_MIN_INSN_LENGTH << 3,
		      make_expr_symbol (&exp), frag_now_fix () - 1,
		      (char *) frag_now);
	  }
      }
      break;

    case DW_CFA_def_cfa:
      offset = insn->u.ri.offset;
      if (offset < 0)
	{
	  out_one (DW_CFA_def_cfa_sf);
	  out_uleb128 (insn->u.ri.reg);
	  out_sleb128 (offset / DWARF2_CIE_DATA_ALIGNMENT);
	}
      else
	{
	  out_one (DW_CFA_def_cfa);
	  out_uleb128 (insn->u.ri.reg);
	  out_uleb128 (offset);
	}
      break;

    case DW_CFA_def_cfa_register:
    case DW_CFA_undefined:
    case DW_CFA_same_value:
      out_one (insn->insn);
      out_uleb128 (insn->u.r);
      break;

    case DW_CFA_def_cfa_offset:
      offset = insn->u.i;
      if (offset < 0)
	{
	  out_one (DW_CFA_def_cfa_offset_sf);
	  out_sleb128 (offset / DWARF2_CIE_DATA_ALIGNMENT);
	}
      else
	{
	  out_one (DW_CFA_def_cfa_offset);
	  out_uleb128 (offset);
	}
      break;

    case DW_CFA_restore:
      regno = insn->u.r;
      if (regno <= 0x3F)
	{
	  out_one (DW_CFA_restore + regno);
	}
      else
	{
	  out_one (DW_CFA_restore_extended);
	  out_uleb128 (regno);
	}
      break;

    case DW_CFA_offset:
      regno = insn->u.ri.reg;
      offset = insn->u.ri.offset / DWARF2_CIE_DATA_ALIGNMENT;
      if (offset < 0)
	{
	  out_one (DW_CFA_offset_extended_sf);
	  out_uleb128 (regno);
	  out_sleb128 (offset);
	}
      else if (regno <= 0x3F)
	{
	  out_one (DW_CFA_offset + regno);
	  out_uleb128 (offset);
	}
      else
	{
	  out_one (DW_CFA_offset_extended);
	  out_uleb128 (regno);
	  out_uleb128 (offset);
	}
      break;

    case DW_CFA_register:
      out_one (DW_CFA_register);
      out_uleb128 (insn->u.rr.reg1);
      out_uleb128 (insn->u.rr.reg2);
      break;

    case DW_CFA_remember_state:
    case DW_CFA_restore_state:
      out_one (insn->insn);
      break;

    case DW_CFA_GNU_window_save:
      out_one (DW_CFA_GNU_window_save);
      break;

    case CFI_escape:
      {
	struct cfi_escape_data *e;
	for (e = insn->u.esc; e ; e = e->next)
	  emit_expr (&e->exp, 1);
	break;
      }

    case CFI_val_encoded_addr:
      {
        unsigned encoding = insn->u.ea.encoding;
        offsetT encoding_size;

	if (encoding == DW_EH_PE_omit)
	  break;
	out_one (DW_CFA_val_expression);
	out_uleb128 (insn->u.ea.reg);

        switch (encoding & 0x7)
	  {
	  case DW_EH_PE_absptr:
	    encoding_size = DWARF2_ADDR_SIZE (stdoutput);
	    break;
	  case DW_EH_PE_udata2:
	    encoding_size = 2;
	    break;
	  case DW_EH_PE_udata4:
	    encoding_size = 4;
	    break;
	  case DW_EH_PE_udata8:
	    encoding_size = 8;
	    break;
	  default:
	    abort ();
	  }

	/* If the user has requested absolute encoding,
	   then use the smaller DW_OP_addr encoding.  */
	if (insn->u.ea.encoding == DW_EH_PE_absptr)
	  {
	    out_uleb128 (1 + encoding_size);
	    out_one (DW_OP_addr);
	  }
	else
	  {
	    out_uleb128 (1 + 1 + encoding_size);
	    out_one (DW_OP_GNU_encoded_addr);
	    out_one (encoding);

	    if ((encoding & 0x70) == DW_EH_PE_pcrel)
	      {
#if CFI_DIFF_EXPR_OK
		insn->u.ea.exp.X_op = O_subtract;
		insn->u.ea.exp.X_op_symbol = symbol_temp_new_now ();
#elif defined (tc_cfi_emit_pcrel_expr)
		tc_cfi_emit_pcrel_expr (&insn->u.ea.exp, encoding_size);
		break;
#else
		abort ();
#endif
	      }
	  }
	emit_expr (&insn->u.ea.exp, encoding_size);
      }
      break;
      
    default:
      abort ();
    }
}

static offsetT
encoding_size (unsigned char encoding)
{
  if (encoding == DW_EH_PE_omit)
    return 0;
  switch (encoding & 0x7)
    {
    case 0:
      return bfd_get_arch_size (stdoutput) == 64 ? 8 : 4;
    case DW_EH_PE_udata2:
      return 2;
    case DW_EH_PE_udata4:
      return 4;
    case DW_EH_PE_udata8:
      return 8;
    default:
      abort ();
    }
}

static void
output_cie (struct cie_entry *cie, bfd_boolean eh_frame, int align)
{
  symbolS *after_size_address, *end_address;
  expressionS exp;
  struct cfi_insn_data *i;
  offsetT augmentation_size;
  int enc;
  enum dwarf2_format fmt = DWARF2_FORMAT (now_seg);

  cie->start_address = symbol_temp_new_now ();
  after_size_address = symbol_temp_make ();
  end_address = symbol_temp_make ();

  exp.X_op = O_subtract;
  exp.X_add_symbol = end_address;
  exp.X_op_symbol = after_size_address;
  exp.X_add_number = 0;

  if (eh_frame || fmt == dwarf2_format_32bit)
    emit_expr (&exp, 4);			/* Length.  */
  else
    {
      if (fmt == dwarf2_format_64bit)
	out_four (-1);
      emit_expr (&exp, 8);			/* Length.  */
    }
  symbol_set_value_now (after_size_address);
  if (eh_frame)
    out_four (0);				/* CIE id.  */
  else
    {
      out_four (-1);				/* CIE id.  */
      if (fmt != dwarf2_format_32bit)
	out_four (-1);
    }
  out_one (DW_CIE_VERSION);			/* Version.  */
  if (eh_frame)
    {
      out_one ('z');				/* Augmentation.  */
      if (cie->per_encoding != DW_EH_PE_omit)
	out_one ('P');
      if (cie->lsda_encoding != DW_EH_PE_omit)
	out_one ('L');
      out_one ('R');
    }
  if (cie->signal_frame)
    out_one ('S');
  out_one (0);
  out_uleb128 (DWARF2_LINE_MIN_INSN_LENGTH);	/* Code alignment.  */
  out_sleb128 (DWARF2_CIE_DATA_ALIGNMENT);	/* Data alignment.  */
  if (DW_CIE_VERSION == 1)			/* Return column.  */
    out_one (cie->return_column);
  else
    out_uleb128 (cie->return_column);
  if (eh_frame)
    {
      augmentation_size = 1 + (cie->lsda_encoding != DW_EH_PE_omit);
      if (cie->per_encoding != DW_EH_PE_omit)
	augmentation_size += 1 + encoding_size (cie->per_encoding);
      out_uleb128 (augmentation_size);		/* Augmentation size.  */

      if (cie->per_encoding != DW_EH_PE_omit)
	{
	  offsetT size = encoding_size (cie->per_encoding);
	  out_one (cie->per_encoding);
	  exp = cie->personality;
	  if ((cie->per_encoding & 0x70) == DW_EH_PE_pcrel)
	    {
#if CFI_DIFF_EXPR_OK
	      exp.X_op = O_subtract;
	      exp.X_op_symbol = symbol_temp_new_now ();
	      emit_expr (&exp, size);
#elif defined (tc_cfi_emit_pcrel_expr)
	      tc_cfi_emit_pcrel_expr (&exp, size);
#else
	      abort ();
#endif
	    }
	  else
	    emit_expr (&exp, size);
	}

      if (cie->lsda_encoding != DW_EH_PE_omit)
	out_one (cie->lsda_encoding);
    }

  switch (DWARF2_FDE_RELOC_SIZE)
    {
    case 2:
      enc = DW_EH_PE_sdata2;
      break;
    case 4:
      enc = DW_EH_PE_sdata4;
      break;
    case 8:
      enc = DW_EH_PE_sdata8;
      break;
    default:
      abort ();
    }
#if CFI_DIFF_EXPR_OK || defined tc_cfi_emit_pcrel_expr
  enc |= DW_EH_PE_pcrel;
#endif
  if (eh_frame)
    out_one (enc);

  if (cie->first)
    for (i = cie->first; i != cie->last; i = i->next)
      output_cfi_insn (i);

  frag_align (align, DW_CFA_nop, 0);
  symbol_set_value_now (end_address);
}

static void
output_fde (struct fde_entry *fde, struct cie_entry *cie,
	    bfd_boolean eh_frame, struct cfi_insn_data *first,
	    int align)
{
  symbolS *after_size_address, *end_address;
  expressionS exp;
  offsetT augmentation_size;
  enum dwarf2_format fmt = DWARF2_FORMAT (now_seg);
  int offset_size;
  int addr_size;

  after_size_address = symbol_temp_make ();
  end_address = symbol_temp_make ();

  exp.X_op = O_subtract;
  exp.X_add_symbol = end_address;
  exp.X_op_symbol = after_size_address;
  exp.X_add_number = 0;
  if (eh_frame || fmt == dwarf2_format_32bit)
    offset_size = 4;
  else
    {
      if (fmt == dwarf2_format_64bit)
	out_four (-1);
      offset_size = 8;
    }
  emit_expr (&exp, offset_size);		/* Length.  */
  symbol_set_value_now (after_size_address);

  if (eh_frame)
    {
      exp.X_add_symbol = after_size_address;
      exp.X_op_symbol = cie->start_address;
    }
  else
    {
      exp.X_op = O_symbol;
      exp.X_add_symbol = cie->start_address;
      exp.X_op_symbol = NULL;
    }
  emit_expr (&exp, offset_size);		/* CIE offset.  */

  if (eh_frame)
    {
#if CFI_DIFF_EXPR_OK
      exp.X_add_symbol = fde->start_address;
      exp.X_op_symbol = symbol_temp_new_now ();
      emit_expr (&exp, DWARF2_FDE_RELOC_SIZE);	/* Code offset.  */
#else
      exp.X_op = O_symbol;
      exp.X_add_symbol = fde->start_address;
      exp.X_op_symbol = NULL;
#ifdef tc_cfi_emit_pcrel_expr
      tc_cfi_emit_pcrel_expr (&exp, DWARF2_FDE_RELOC_SIZE);	 /* Code offset.  */
#else
      emit_expr (&exp, DWARF2_FDE_RELOC_SIZE);	/* Code offset.  */
#endif
#endif
      addr_size = DWARF2_FDE_RELOC_SIZE;
    }
  else
    {
      exp.X_add_symbol = fde->start_address;
      addr_size = DWARF2_ADDR_SIZE (stdoutput);
      emit_expr (&exp, addr_size);
    }

  exp.X_op = O_subtract;
  exp.X_add_symbol = fde->end_address;
  exp.X_op_symbol = fde->start_address;		/* Code length.  */
  emit_expr (&exp, addr_size);

  augmentation_size = encoding_size (fde->lsda_encoding);
  if (eh_frame)
    out_uleb128 (augmentation_size);		/* Augmentation size.  */

  if (fde->lsda_encoding != DW_EH_PE_omit)
    {
      exp = fde->lsda;
      if ((fde->lsda_encoding & 0x70) == DW_EH_PE_pcrel)
	{
#if CFI_DIFF_LSDA_OK
	  exp.X_op = O_subtract;
	  exp.X_op_symbol = symbol_temp_new_now ();
	  emit_expr (&exp, augmentation_size);
#elif defined (tc_cfi_emit_pcrel_expr)
	  tc_cfi_emit_pcrel_expr (&exp, augmentation_size);
#else
	  abort ();
#endif
	}
      else
	emit_expr (&exp, augmentation_size);
    }

  for (; first; first = first->next)
    output_cfi_insn (first);

  frag_align (align, DW_CFA_nop, 0);
  symbol_set_value_now (end_address);
}

static struct cie_entry *
select_cie_for_fde (struct fde_entry *fde, bfd_boolean eh_frame,
		    struct cfi_insn_data **pfirst, int align)
{
  struct cfi_insn_data *i, *j;
  struct cie_entry *cie;

  for (cie = cie_root; cie; cie = cie->next)
    {
      if (cie->return_column != fde->return_column
	  || cie->signal_frame != fde->signal_frame
	  || cie->per_encoding != fde->per_encoding
	  || cie->lsda_encoding != fde->lsda_encoding)
	continue;
      if (cie->per_encoding != DW_EH_PE_omit)
	{
	  if (cie->personality.X_op != fde->personality.X_op
	      || cie->personality.X_add_number
		 != fde->personality.X_add_number)
	    continue;
	  switch (cie->personality.X_op)
	    {
	    case O_constant:
	      if (cie->personality.X_unsigned != fde->personality.X_unsigned)
		continue;
	      break;
	    case O_symbol:
	      if (cie->personality.X_add_symbol
		  != fde->personality.X_add_symbol)
		continue;
	      break;
	    default:
	      abort ();
	    }
	}
      for (i = cie->first, j = fde->data;
	   i != cie->last && j != NULL;
	   i = i->next, j = j->next)
	{
	  if (i->insn != j->insn)
	    goto fail;
	  switch (i->insn)
	    {
	    case DW_CFA_advance_loc:
	    case DW_CFA_remember_state:
	      /* We reached the first advance/remember in the FDE,
		 but did not reach the end of the CIE list.  */
	      goto fail;

	    case DW_CFA_offset:
	    case DW_CFA_def_cfa:
	      if (i->u.ri.reg != j->u.ri.reg)
		goto fail;
	      if (i->u.ri.offset != j->u.ri.offset)
		goto fail;
	      break;

	    case DW_CFA_register:
	      if (i->u.rr.reg1 != j->u.rr.reg1)
		goto fail;
	      if (i->u.rr.reg2 != j->u.rr.reg2)
		goto fail;
	      break;

	    case DW_CFA_def_cfa_register:
	    case DW_CFA_restore:
	    case DW_CFA_undefined:
	    case DW_CFA_same_value:
	      if (i->u.r != j->u.r)
		goto fail;
	      break;

	    case DW_CFA_def_cfa_offset:
	      if (i->u.i != j->u.i)
		goto fail;
	      break;

	    case CFI_escape:
	    case CFI_val_encoded_addr:
	      /* Don't bother matching these for now.  */
	      goto fail;

	    default:
	      abort ();
	    }
	}

      /* Success if we reached the end of the CIE list, and we've either
	 run out of FDE entries or we've encountered an advance,
	 remember, or escape.  */
      if (i == cie->last
	  && (!j
	      || j->insn == DW_CFA_advance_loc
	      || j->insn == DW_CFA_remember_state
	      || j->insn == CFI_escape
	      || j->insn == CFI_val_encoded_addr))
	{
	  *pfirst = j;
	  return cie;
	}

    fail:;
    }

  cie = (struct cie_entry *) xmalloc (sizeof (struct cie_entry));
  cie->next = cie_root;
  cie_root = cie;
  cie->return_column = fde->return_column;
  cie->signal_frame = fde->signal_frame;
  cie->per_encoding = fde->per_encoding;
  cie->lsda_encoding = fde->lsda_encoding;
  cie->personality = fde->personality;
  cie->first = fde->data;

  for (i = cie->first; i ; i = i->next)
    if (i->insn == DW_CFA_advance_loc
	|| i->insn == DW_CFA_remember_state
	|| i->insn == CFI_escape
	|| i->insn == CFI_val_encoded_addr)
      break;

  cie->last = i;
  *pfirst = i;

  output_cie (cie, eh_frame, align);

  return cie;
}

#ifdef md_reg_eh_frame_to_debug_frame
static void
cfi_change_reg_numbers (struct cfi_insn_data *insn)
{
  for (; insn; insn = insn->next)
    switch (insn->insn)
      {
      case DW_CFA_advance_loc:
      case DW_CFA_def_cfa_offset:
      case DW_CFA_remember_state:
      case DW_CFA_restore_state:
      case DW_CFA_GNU_window_save:
      case CFI_escape:
	break;

      case DW_CFA_def_cfa:
      case DW_CFA_offset:
	insn->u.ri.reg = md_reg_eh_frame_to_debug_frame (insn->u.ri.reg);
	break;

      case DW_CFA_def_cfa_register:
      case DW_CFA_undefined:
      case DW_CFA_same_value:
      case DW_CFA_restore:
	insn->u.r = md_reg_eh_frame_to_debug_frame (insn->u.r);
	break;

      case DW_CFA_register:
	insn->u.rr.reg1 = md_reg_eh_frame_to_debug_frame (insn->u.rr.reg1);
	insn->u.rr.reg2 = md_reg_eh_frame_to_debug_frame (insn->u.rr.reg2);
	break;

      case CFI_val_encoded_addr:
	insn->u.ea.reg = md_reg_eh_frame_to_debug_frame (insn->u.ea.reg);
	break;

      default:
	abort ();
      }
}
#else
#define cfi_change_reg_numbers(insn) do { } while (0)
#endif

void
cfi_finish (void)
{
  segT cfi_seg;
  struct fde_entry *fde;
  int save_flag_traditional_format;

  if (all_fde_data == 0)
    return;

  if ((cfi_sections & CFI_EMIT_eh_frame) != 0)
    {
      /* Open .eh_frame section.  */
      cfi_seg = subseg_new (".eh_frame", 0);
      bfd_set_section_flags (stdoutput, cfi_seg,
			     SEC_ALLOC | SEC_LOAD | SEC_DATA
			     | DWARF2_EH_FRAME_READ_ONLY);
      subseg_set (cfi_seg, 0);
      record_alignment (cfi_seg, EH_FRAME_ALIGNMENT);

#ifdef md_fix_up_eh_frame
      md_fix_up_eh_frame (cfi_seg);
#endif

      /* Make sure check_eh_frame doesn't do anything with our output.  */
      save_flag_traditional_format = flag_traditional_format;
      flag_traditional_format = 1;

      for (fde = all_fde_data; fde ; fde = fde->next)
	{
	  struct cfi_insn_data *first;
	  struct cie_entry *cie;

	  if (fde->end_address == NULL)
	    {
	      as_bad (_("open CFI at the end of file; missing .cfi_endproc directive"));
	      fde->end_address = fde->start_address;
	    }

	  cie = select_cie_for_fde (fde, TRUE, &first, 2);
	  output_fde (fde, cie, TRUE, first,
		      fde->next == NULL ? EH_FRAME_ALIGNMENT : 2);
	}

      flag_traditional_format = save_flag_traditional_format;
    }

  if ((cfi_sections & CFI_EMIT_debug_frame) != 0)
    {
      struct cie_entry *cie, *cie_next;
      int alignment = ffs (DWARF2_ADDR_SIZE (stdoutput)) - 1;

      for (cie = cie_root; cie; cie = cie_next)
	{
	  cie_next = cie->next;
	  free ((void *) cie);
	}
      cie_root = NULL;

      /* Open .debug_frame section.  */
      cfi_seg = subseg_new (".debug_frame", 0);
      bfd_set_section_flags (stdoutput, cfi_seg,
			     SEC_READONLY | SEC_DEBUGGING);
      subseg_set (cfi_seg, 0);
      record_alignment (cfi_seg, alignment);

      for (fde = all_fde_data; fde ; fde = fde->next)
	{
	  struct cfi_insn_data *first;

	  if (fde->end_address == NULL)
	    {
	      as_bad (_("open CFI at the end of file; missing .cfi_endproc directive"));
	      fde->end_address = fde->start_address;
	    }

	  fde->per_encoding = DW_EH_PE_omit;
	  fde->lsda_encoding = DW_EH_PE_omit;
	  cfi_change_reg_numbers (fde->data);
	  cie = select_cie_for_fde (fde, FALSE, &first, alignment);
	  output_fde (fde, cie, FALSE, first, alignment);
	}
    }
}

#else /* TARGET_USE_CFIPOP */
void
cfi_finish (void)
{
}
#endif /* TARGET_USE_CFIPOP */
