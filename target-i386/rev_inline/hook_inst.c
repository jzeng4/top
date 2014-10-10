#include <xed-interface.h>
#include "cpu.h"
#include "hook_inst.h"
#include "rev_inline/config.h"
//#include "safety_guards.h"
/*
 * *****************************************************************
 * *****************************************************************
 * *****************************************************************
 */

/******************Global Data Section***************************/




uint32_t g_pc;
uint32_t g_main_start;
uint32_t g_main_pc;
uint32_t g_start_pc;

///////////////////////////////////////////////////////////////////////////
//
//
//
//
//
//
//////////////////////////////////////////////////////////////////////////

//#include "dependence_taint.h"
#include "cpptoc.h"

InstrumentFunction instrument_functions[XED_ICLASS_LAST];

static void Instrument_LEA(INS xi)
{
	INST *inst = get_inst(g_pc);
	unsigned int memlen =
			    xed_decoded_inst_operand_length(&xedd_g, 1);

	switch(memlen){
		case 1:
			inst->type = LEA_8;
			break;
		case 2:
			inst->type = LEA_16;
			break;
		case 4:
			inst->type = LEA_32;
			break;
		default:
			break;
	}

}


static void Instrument_Jcc(INS xi)
{
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	uint32_t dest = 0;

	if (operand_is_relbr(op_name, &dest)){
			
	}else{
		fprintf(stderr, "In Jcc: oprand is not relbr\n");
		exit(0);
	}

	INST* inst = get_inst(g_pc);
	inst->type = JCC;

	insert_jmp_dst(g_pc +  xed_decoded_inst_get_length(&xedd_g));
	insert_jmp_dst(g_pc +  xed_decoded_inst_get_length(&xedd_g) + dest);
}


static void Instrument_Loop(INS  xi)
{
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	uint32_t dest = 0;

	if (operand_is_relbr(op_name, &dest)){
			
	}else{
		fprintf(stderr, "In Loop: operand is not relbr\n");
		exit(0);
	}

	INST* inst = get_inst(g_pc);
	inst->type = LOOP;

	insert_jmp_dst(g_pc +  xed_decoded_inst_get_length(&xedd_g));
	insert_jmp_dst(g_pc +  xed_decoded_inst_get_length(&xedd_g) + dest);

}

static void Instrument_JMP(INS xi)
{
	uint32_t dest;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	xed_reg_enum_t reg_id;

	INST* inst = get_inst(g_pc);
#ifdef DEBUG
	fprintf(stdout, "in hook_inst:\tInstrument_JMP\n");	
#endif
	if (operand_is_relbr(op_name, &dest)){
		dest += g_pc + xed_decoded_inst_get_length(&xedd_g);
		if(is_plt(dest)){
			fprintf(stderr, "error in jmp\n");
			if(is_plt(dest)){
				api_copy(&inst->api_call, get_api_call(dest));
			}
#ifdef DEBUG
			fprintf(stdout, "dest\t%x\tfname:\t%s\n", dest, inst->api_call.fname);			
#endif
			inst->type = TAIL;
		}else{
			inst->type = JMP;
		}

		//Hush.b
		//If it jump to the begining of a function
        unsigned int esp = PEMU_get_reg(XED_REG_ESP);
        extern unsigned int g_current_esp;
        if(g_pc == 0x80535de)
            printf("TAIL %x %x\n", esp, g_current_esp); 
        if(esp == g_current_esp && dest < g_pc )
        {
	        void *func;
            target_ulong ret;
            PEMU_read_mem(esp , 4, &ret);
#ifdef DEBUG
			fprintf(stdout, "Tail call %x\n", dest);			
#endif
		    func = create_func1(dest);
            pop_callstack();
            push_callstack(func, ret, esp);
        }
		//Hush.e

	}else if(operand_is_mem4(op_name, &dest, 0)){
		inst->type = INJMP;
		PEMU_read_mem(dest, 4, &dest);
	}else if(operand_is_reg(op_name, &reg_id)){
		inst->type = INJMP;
		dest = PEMU_get_reg(reg_id);	
	}

	insert_jmp_dst(dest);
}

static void Instrument_JMP_FAR(INS xi){
//Hush.b
	
//Hush.e
}

static void Instrument_CALL(INS xi)
{
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_reg_enum_t reg_id;
	xed_operand_enum_t op_name = xed_operand_name(op);
	unsigned int dest, api_addr = 0;
	char *funName;
	unsigned int tmp;
	API_TYPE type;
	void *func;

	unsigned int return_pc = g_pc +  xed_decoded_inst_get_length(&xedd_g);
	INST* inst = get_inst(g_pc);
	
	if(operand_is_relbr(op_name, &dest)){
		inst->type = CALL;
		dest += (g_pc +  xed_decoded_inst_get_length(&xedd_g));				
	}else if(operand_is_reg(op_name, &reg_id)){
		inst->type = INCALL;
		dest = PEMU_get_reg(reg_id);	
	}else if(operand_is_mem4(op_name, &dest,0)){
		inst->type = INCALL;
		PEMU_read_mem(dest, 4, &tmp);
		dest = tmp;
	}
	
	if(type = is_api_call(dest, &funName)){
#ifdef DEBUG
		//fprintf(stdout, "hook_inst: plt call\t%x\t%s\n", dest, funName);
#endif
		api_copy(&inst->api_call, get_api_call(dest));
	}else{
		func = (void*)create_func1(dest);
		push_callstack(func, return_pc, PEMU_get_reg(XED_REG_ESP) -  sizeof(target_ulong));
	}
}

static void Instrument_RET(INS xi)
{
	if(!get_ret_pc()){
#ifndef WINDOWS_FORMAT
		//fprintf(stdout, "program exit\n");
		//finish_tracing();
		//exit(0);
#endif
		return;
	}
	unsigned int cur_esp=PEMU_get_reg(XED_REG_ESP);
	int buf=0;
	PEMU_read_mem(cur_esp, 4, &buf);
	if(get_ret_pc()==buf){
		pop_callstack();
	}
	else{
		fprintf(stderr, "RET DOESNT MATCH(%x)--(%x)\n",g_pc,buf);
		print_call_stack();
	}
}

//Hush.b
static  Instrument_SCASB(INS xi){
#ifdef DEBUG
#endif	
}
//Hush.e

static void UnimplementedInstruction(INS ins) {

	return;
}

void setup_inst_hook()
{
	int i;
	for (i = 0; i < XED_ICLASS_LAST; i++) {
		instrument_functions[i] = &UnimplementedInstruction;
	}
	instrument_functions[XED_ICLASS_JB] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JBE] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JL] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JLE] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JMP] = &Instrument_JMP;
	instrument_functions[XED_ICLASS_JMP_FAR] = &Instrument_JMP_FAR;
	instrument_functions[XED_ICLASS_JNB] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNBE] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNL] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNLE] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNO] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNP] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNS] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JNZ] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JO] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JP] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JRCXZ] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JS] = &Instrument_Jcc;
	instrument_functions[XED_ICLASS_JZ] = &Instrument_Jcc;

	instrument_functions[XED_ICLASS_LOOP] = &Instrument_Loop;
	
	instrument_functions[XED_ICLASS_CALL_NEAR] = &Instrument_CALL;
	instrument_functions[XED_ICLASS_RET_NEAR] = &Instrument_RET;

	instrument_functions[XED_ICLASS_LEA] = &Instrument_LEA;
//Hush.b
	instrument_functions[XED_ICLASS_SCASB] = &Instrument_SCASB;
//Hush.e
}



//#include "cpptoc.h"
extern char g_inst_buffer[15];
char g_inst_name[1024];
xed_iclass_enum_t g_opcode;

void Instrument(INS ins){
	xed_iclass_enum_t opcode = g_opcode = xed_decoded_inst_get_iclass(&xedd_g);
	strcpy(g_inst_name, xed_iclass_enum_t2str(opcode));

	if(g_pc == get_ret_pc()){
		pop_callstack();
#ifdef DEBUG
		fprintf(stdout, "pop function stack\n");
#endif
	}
	
	//handle data dependence
	handle_txt_rewrite(ins);
	//handle address rewrite for incall and injmp:
	handle_data_rewrite(ins);
	//general inst:
	insert_inst(g_pc, g_inst_buffer, xed_decoded_inst_get_length(&xedd_g));
	//special inst:	
	instrument_functions[opcode](ins);

#if 0
	if(g_pc == 0x80483ed){
		uint32_t val;
		PEMU_read_mem(0x804a014, 4, &val);
		fprintf(stderr, "%x\n", val);
	}
#endif


#if 0
	//hard code exit:
	if(g_pc == 0x31208256){
		print_dependence_data();
		print_program();
	}
#endif

}
