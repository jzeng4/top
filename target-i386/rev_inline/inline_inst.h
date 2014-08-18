#ifndef INLINE_DICT_H
#define INLINE_DICT_H

#include "cpptoc.h"


#include <map>
#include <stack>
using namespace std;

typedef map<unsigned int, INST*> FUNCTION;
typedef map<unsigned int, FUNCTION*> PROGRAM;

extern FUNCTION *g_current_func;
extern PROGRAM *g_current_program;

extern "C"{
#include <xed-interface.h>
}


extern "C"{
	INST *create_inst();
	void insert_inst(unsigned int, unsigned char*, unsigned short);
	void insert_dependence_data(unsigned int, int);
	void print_operands(xed_decoded_inst_t*);
	void insert_pc_imm(unsigned int, unsigned int);
	unsigned int get_pc_imm(unsigned int);
	void print_dependence_data();
	void push_callstack(void *func, unsigned int ret);	
	unsigned int get_ret_pc();
	void pop_callstack();	
	INST* get_inst(unsigned int pc);
	void insert_jmp_dst(unsigned int dst);
	int get_jmp_dst(unsigned int dst);

	extern xed_decoded_inst_t xedd_g;
	extern xed_state_t dstate;
	extern char g_inst_str[128];

}




#endif
