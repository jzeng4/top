#ifndef INST_INTERFACE_H
#define INST_INTERFACE_H
//void xed2_init();
//int rev_init();
#include "rev_inline/config.h"

extern UInt is_in_range;

extern "C"{
int init();

void print_c_code();

void Instrument_PC1(UChar* buf);

void add_mem_into_rbt(UInt start_addr, UInt size, UInt flag);

heap_shadow_node_t* find_mem_from_rbt(UInt key);

void add_pc_into_rbt(UInt start_addr);

heap_shadow_node_t* find_pc_from_rbt(UInt key);

void add_reg_reg(struct Function* func, UInt pc, xed_reg_enum_t reg_id_0, 
		xed_reg_enum_t reg_id_1, UChar* op);

void add_reg_imm(struct Function* func, UInt pc, xed_reg_enum_t reg_id, 
		UInt value, UChar* op);

void add_reg_mem(struct Function* func, UInt pc, xed_reg_enum_t reg_id, 
		UInt mem_addr, UChar* op);

void add_mem_reg(struct Function* func, UInt pc, UInt mem_addr, xed_reg_enum_t reg_id, 
		UChar* op);

void add_mem_imm(struct Function* func, UInt pc, UInt mem_addr, UInt value,
		UChar* op);

void add_string_string(struct Function* func, UInt pc, const UChar* s1, const UChar* s2,
		const UChar* op);

void add_lib_call(struct Function* func, int pc, const char* call);

struct Frame* get_cpp_stack_top(struct Stack* st);

UInt is_cpp_empty(struct Stack* st);

void pop_cpp_stack(struct Stack* s);

inline void check_glibc_call(UInt pc);

inline void is_create_main_func();

inline void copy_string_from_mem(char* dest, UInt src);
}

VOID ImageLoad(IMG img, VOID *v);
#endif
