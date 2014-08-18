/**********************************************************************************************
*      This file is part of X-Force, A Brute Force Execution Approach for Malware Analysis    *
*                                                                                             *
*      X-Force is owned and copyright (C) by Lab FRIENDS at Purdue University, 2009-2011.     *
*      All rights reserved.                                                                   *
*      Do not copy, disclose, or distribute without explicit written                          *
*      permission.                                                                            *
*                                                                                             *
*      Author: Zhiqiang Lin <zlin@cs.purdue.edu>                                              *
**********************************************************************************************/


#ifndef __TXT_TAINT_H
#define __TXT_TAINT_H

#define VGM_BYTE_INVALID   0xFF
#define TAINTED 1
#define UNTAINTED 0
#define FDTAINTED 2

#include <xed-interface.h>
#include <stdio.h>
/* Always 8 bits. */
typedef  unsigned char   UChar;
typedef    signed char   Char;
typedef           char   HChar; /* signfulness depends on host */
                                /* Only to be used for printf etc */

/* Always 16 bits. */
typedef  unsigned short  UShort;
typedef    signed short  Short;

/* Always 32 bits. */
typedef  unsigned int    UInt;
typedef  unsigned int    UINT;
typedef    signed int    Int;
typedef  unsigned int Addr;


#ifdef CPLUSPLUS
extern "C" {
#endif
void t_taintInit();
//void  init_shadow_memory(void);
void t_free_shadow_memory(void);
UInt t_get_mem_taint( Addr a );
void t_set_mem_taint( Addr a, UInt bytes);
void t_set_reg_taint(xed_reg_enum_t reg, UInt bytes);
UInt t_get_reg_taint(xed_reg_enum_t reg);
void t_set_mem_taint_bysize( Addr a, UInt bytes, UInt size);
void t_mem_taint_format();

//extern unsigned char taint;
//extern unsigned int taint_mem_addr;

#ifdef CPLUSPLUS
}
#endif


#endif
