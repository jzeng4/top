#include <xed-interface.h>
#include "hook_inst.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cpu.h"
#include "rev_inline/config.h"

xed_decoded_inst_t xedd_g;


/* Variables to keep disassembler state */
xed_state_t dstate;
xed_decoded_inst_t xedd;
FILE* output;
FILE* output_inst;

uint32_t g_return_pc;
char file_name[100];
uint32_t g_is_printed;
uint32_t g_is_special_pc;
char g_inst_str[500];
FILE *inst_log;

extern uint32_t g_heap_num;
extern uint32_t g_rodata_size;
extern uint32_t g_global_data_size;
extern struct Stack* g_stack;
extern uint8_t c_inst[];
extern struct Function* g_cur_func;
extern struct Prog* g_prog;
extern uint32_t g_pc;
extern struct Hook_JMP* g_hook_jmp;
extern struct Prog* g_prog;
extern uint32_t g_main_start;
extern uint32_t g_main_pc;
extern uint32_t g_call_check;
extern uint32_t g_glibc_base;
extern uint32_t g_glibc_size;
extern uint32_t g_prev_pc;
extern uint32_t PEMU_txt_start;


/* XED2 initialization */
void xed2_init(){
	 xed_tables_init();
	 xed_state_zero(&dstate);

  	 xed_state_init(&dstate,
     XED_MACHINE_MODE_LEGACY_32,
     XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);

}

void log_init()
{
	inst_log = fopen("inst_log", "w");
	if(!inst_log) {
		perror("can't open inst_log\n");
		exit(0);
	}
}

int init_top(target_ulong mainEntry){
	xed_decoded_inst_set_mode(&xedd_g, XED_MACHINE_MODE_LEGACY_32,
			XED_ADDRESS_WIDTH_32b);
	
	xed2_init();
	setup_inst_hook();
	t_taintInit();
	d_taintInit();
	log_init();

	g_main_pc = mainEntry;
	return 0;
}


char g_inst_buffer[15];
void print_dependence_data();
//Hush.b
extern void update_mem_to_be_read();
//Hush.e
void Instrument_PC1(uint8_t* buf){

	if(g_main_pc == g_pc){
		g_main_start = 1;
		create_program(g_main_pc);//
	}
	
	if(g_main_start != 1)
		return;

	xed_decoded_inst_zero_set_mode(&xedd_g, &dstate);
    xed_error_enum_t xed_error = xed_decode(&xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  buf), 15);

	if (xed_error == XED_ERROR_NONE) 
	{
		xed_decoded_inst_dump_att_format(&xedd_g, g_inst_str, sizeof(g_inst_str), 0);
		const xed_inst_t *xi = xed_decoded_inst_inst(&xedd_g);

#ifdef DEBUG
		fprintf(stdout, "==============================pc:\t%x\t%s\t(eax=%x)=======================\n", g_pc, g_inst_str, PEMU_get_reg(XED_REG_EAX));
		PEMU_print_all_reg();
		print_all_reg_txt();
		print_all_reg_data();
		fprintf(inst_log, "%x\n", g_pc);
#endif		
		//Hush.b
		update_mem_to_be_read();
		//Hush.e	
		Instrument(xi);
		
	}

}



