#ifndef PATCH_INST_H
#define PATCH_INST_H

extern "C"{
#include <xed-interface.h>
}

#include<string.h>
#include<stdio.h>
#include "inline_inst.h"
#include "txt_rewrite.h"
extern xed_decoded_inst_t xedd_g;
extern unsigned int g_pc;
extern unsigned int g_dependence_base;

extern "C"{
int operand_is_mem4(const xed_operand_enum_t, uint32_t*, int);
}

INST *get_inst(unsigned int);

#endif
