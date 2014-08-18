#ifndef TXT_REWRITE_H
#define TXT_REWRITE_H


extern "C"{
#include <xed-interface.h>
#include "txt_taint.h"
#include "helper_hook_inst.h"
}
#include "cpptoc.h"
#include <map>
using namespace std;

extern xed_decoded_inst_t xedd_g;
extern int xed_regmapping[][3];


typedef void (*TXTFunc)(const xed_inst_t*);
typedef void (*ControlFunc)(const xed_inst_t*);



extern unsigned int g_pc;
extern xed_decoded_inst_t xedd_g;
extern xed_state_t dstate;

extern uint32_t PEMU_img_start;
extern uint32_t PEMU_img_end;


extern "C"{

void insert_dependence_data(unsigned int addr, int size);
void insert_pc_imm(unsigned int pc, unsigned int imm);
unsigned int get_pc_imm(unsigned int pc);

int is_dependence_addr(unsigned int pc);

void print_dependence_data();
unsigned int dump_dependence_data(FILE *output);


//pc: inst pc
//val:	1 for imm
//		2 for displacement
//		3 for both 
void insert_pc_addr(unsigned int pc, unsigned int type);
int get_pc_addr(unsigned int pc);

void insert_d_written(unsigned int addr);
int is_d_written(unsigned int addr);

void handle_txt_rewrite(const xed_inst_t* xi);

int operand_is_mem4(const xed_operand_enum_t, uint32_t*, int);
int operand_is_relbr(const xed_operand_enum_t op_name, uint32_t * branch); 
int operand_is_reg(const xed_operand_enum_t, xed_reg_enum_t *);
int operand_is_imm(const xed_operand_enum_t op_name, uint32_t * value);
API_TYPE is_api_call(unsigned int, char**);
API_CALL *get_api_call(uint32_t addr);
INST *get_inst(unsigned int);
void hookCall(char*);
}


#endif
