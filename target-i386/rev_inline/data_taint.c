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



#include "rev_inline/config.h"
#include "data_taint.h"
#include <stdlib.h>
/*---------------------shadow memory----------------------*/
#define PAGE_BITS 16
#define PAGE_SIZE (1<<PAGE_BITS)
#define PAGE_NUM  (1<<16)

#define IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(map, addr)                              \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[addr >> 16])) {       \
         map[addr >> 16] = alloc_secondary_map; \
      }                                                           \
   } while(0)

#define ENSURE_MAPPABLE_BYTE_GRANUITY(map,addr)         \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[addr >> 16])) {    \
          map[addr >> 16] = alloc_secondary_map(); \
      }                                                           \
   } while(0)


#undef DEBUG

typedef struct {
   UInt byte[PAGE_SIZE];
} SecMap;

static SecMap distinguished_secondary_map;

static SecMap * ii_primary_map[PAGE_NUM];

static unsigned int shadow_bytes;

///////////////////////////////////////////////////////////////////

static void init_shadow_memory(void)
{
    Int i,j;

    for (i = 0; i< PAGE_SIZE; i++)
       distinguished_secondary_map.byte[i] = UNTAINTED; //0xff

      for (i = 0; i < PAGE_NUM; i++) {
        ii_primary_map[i] = &distinguished_secondary_map;
      }
}

void d_free_shadow_memory(void)
{
    Int i,j;

      for (i = 0; i < PAGE_NUM; i++) {
        if(ii_primary_map[i] != &distinguished_secondary_map)
        {
			free(ii_primary_map[i]);
        }
      }
}


static SecMap* alloc_secondary_map ()
{
   SecMap* map;
   UInt  i;

   /* Mark all bytes as invalid access and invalid value. */
   map = (SecMap *)malloc(sizeof(SecMap));
   //printf("create %x\n", map);
   shadow_bytes += sizeof(SecMap);
   for (i = 0; i < PAGE_SIZE; i++)
      map->byte[i] = UNTAINTED; /* Invalid Value */

   return map;
}

UInt  d_get_mem_taint( Addr a )
{
   
   SecMap* sm;
   sm= ii_primary_map[a>>16];

   UInt    sm_off = a & 0xFFFF;
   
#ifdef DEBUG
   printf("data get mem %x %x\n",a, sm->byte[sm_off]);
#endif
   return  sm->byte[sm_off];
}

void  d_set_mem_taint( Addr a, UInt pc)
{
#ifdef DEBUG
	printf("data set mem %x %x\n",a, pc); 
#endif
	SecMap* sm;
    UInt    sm_off;
    ENSURE_MAPPABLE_BYTE_GRANUITY(ii_primary_map, a);
    sm    = ii_primary_map[a >> 16];
    sm_off = a & 0xFFFF;
    sm->byte[sm_off] = pc;

}

void  d_set_mem_taint_bysize( Addr a, UInt pc, UInt size)
{
	UInt i;

	for(i=0; i<size;i++){
		d_set_mem_taint(a+i, pc);
#ifdef DEBUG		
		printf("data set mem %x %x\n",a+i, pc); 
#endif		
	}

}
/******************************************************************
* Shadow for register
******************************************************************/
static UInt regTaint[XED_REG_LAST];
static void regUntainted()
{
	int i;

	for( i=0; i< XED_REG_LAST;i++)
		regTaint[i]=UNTAINTED;

//	regTaint[XED_REG_ESP]=TAINTED;

}

UInt d_get_reg_taint(xed_reg_enum_t reg)
{
#ifdef DEBUG
	printf("data get reg taint%s %x\n",xed_reg_enum_t2str(reg),regTaint[reg]); 
#endif
	return regTaint[reg];
}
void d_set_reg_taint(xed_reg_enum_t reg, UInt bytes)
{

	if(reg==XED_REG_ESP)
		return;
	regTaint[reg]=bytes;

	//yang
#ifdef DEBUG	
	printf("data set reg taint%s %x \n",xed_reg_enum_t2str(reg), bytes); 
#endif
}

void print_all_reg_data(void)
{
	fprintf(stdout, "data::EAX:%x\nEBX:%x\nECX:%x\nEDX:%x\nESI:%x\nEDI:%x\n",
			d_get_reg_taint(XED_REG_EAX),
			d_get_reg_taint(XED_REG_EBX),
			d_get_reg_taint(XED_REG_ECX),
			d_get_reg_taint(XED_REG_EDX),
			d_get_reg_taint(XED_REG_ESI),
			d_get_reg_taint(XED_REG_EDI));
}



void d_taintInit()
{
	init_shadow_memory();
	regUntainted();
}


