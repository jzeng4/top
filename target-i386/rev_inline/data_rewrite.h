#ifndef DATA_REWRITE_H
#define DATA_REWRITE_H

extern "C"{
#include <xed-interface.h>
#include "qemu-pemu.h"
#include "data_taint.h"
}
#include <stdlib.h>
#include <stdio.h>
#include "txt_rewrite.h"

#include<map>
using namespace std;



typedef void (*DataFunc)(const xed_inst_t*);

extern unsigned int g_pc;
extern struct CPUX86State* cpu_single_env; 
extern xed_decoded_inst_t xedd_g;
extern xed_state_t dstate;

extern "C"{
	int operand_is_mem4(const xed_operand_enum_t, uint32_t*, int);
	int operand_is_reg(const xed_operand_enum_t, xed_reg_enum_t *);
	int operand_is_imm(const xed_operand_enum_t, uint32_t *);	
	void handle_data_rewrite(const xed_inst_t* xi);
	INST *get_inst(unsigned int);
}


#endif
