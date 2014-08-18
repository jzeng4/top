#ifndef PRINT_INST_H
#define PRINT_INST_H

extern "C"{
void print_program();
}

#include <stdlib.h>
#include <string>
#include <iostream>
#include <iomanip>
using namespace std;


extern "C"{
int operand_is_reg(const xed_operand_enum_t op_name, xed_reg_enum_t * reg_id);
}

extern "C"{
#include <xed-interface.h>
}


extern xed_decoded_inst_t xedd_g;
extern xed_state_t dstate;
extern char g_inst_str[128];

extern "C"{
int operand_is_relbr(const xed_operand_enum_t op_name, uint32_t * branch);
unsigned int get_dependence_base();
INST *get_inst(unsigned int);
}


void patch_operand(const xed_inst_t *xi);

extern char *replace(char *st, char *orig, char *repl);

#endif
