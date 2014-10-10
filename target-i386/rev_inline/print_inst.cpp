#include "inline_inst.h"
#include "print_inst.h"
#include "txt_rewrite.h"
#include <string.h>
#include "rev_inline/config.h"
#include <map>
//#define STATISTICS

static FILE *output;
extern unsigned int g_main_pc;
extern unsigned int g_pc;
//extern map<uint32_t, int> g_inst_count;
static char inst_buffer[500], safety_guard[500];
unsigned int g_dependence_base;

//statistics

#undef DEBUG

#ifdef STATISTICS
unsigned int g_check_nums = 0;
unsigned int g_symbol_nums = 0;
unsigned int g_imm_nums = 0;
unsigned int g_dis_nums = 0;
static uint32_t g_jcc_num;
static uint32_t g_jmp_num;
static uint32_t g_call_num;
static uint32_t g_dump_data;
static uint32_t g_inst_num;
#endif

static map<unsigned int, char> map_tmp;



//#define WINDOWS_FORMAT
//#define WINDOWS_NAKED

#define format_reg(str1, str2) \
	for(int i = 0,j = 0;i <= strlen(str2);i++){	\
		str1[j++] = str2[i];	\
		if(str2[i] == '%'){	\
			str1[j++] = '%';	\
		}	\
	}

//Hush.b
void format_scasbb(char* str){
	char * pch;
	pch = strstr (str,"scasbb");
	if(pch){
	strncpy (pch,"scasb ",6);
	puts (str);
	}
}

void format_cmpsbb(char* str){
	char * pch;
	pch = strstr (str,"cmpsbb");
	if(pch){
	strncpy (pch,"cmpsb ",6);
	puts (str);
	}
}
//Hush.e

static void format_normal(const xed_inst_t *xi)
{	
#ifdef WINDOWS_FORMAT
	strcpy(inst_buffer, g_inst_str);
#else

	format_reg(inst_buffer, g_inst_str);
	//Hush.b
	format_scasbb(inst_buffer);
	format_cmpsbb(inst_buffer);
	//Hush.e
#endif
}

static void format_jmp(const xed_inst_t *xi)
{
	uint32_t dest;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	xed_reg_enum_t reg_id;

#ifdef STATISTICS
	g_symbol_nums++;
	fprintf(stderr, "jmp at pc\t%x\n", g_pc);
	g_jmp_num++;
#endif

	INST* inst = get_inst(g_pc);

	if(inst->type == TAIL){//jmp to plt
#ifdef DEBUG
		fprintf(stdout, "TAIL:\t%p\n", inst);
#endif
		sprintf(inst_buffer, "%s %s", "jmp", inst->api_call.fname);
		return;
	}
	if(operand_is_relbr(op_name, &dest)){
		dest += g_pc + xed_decoded_inst_get_length(&xedd_g);
		sprintf(inst_buffer, "%s L_0x%x", "jmp", dest);
	}else{
		fprintf(stderr, "error in format_jmp\n");
	}
}

static int format_jcc(const xed_inst_t *xi)
{
	uint32_t dest, next;
	char opcode[20], jmp_dst[20];
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	
	xed_operand_enum_t op_name = xed_operand_name(op);
	xed_reg_enum_t reg_id;
	strcpy(opcode, xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&xedd_g)));

	INST* inst = get_inst(g_pc);

	if(operand_is_relbr(op_name, &dest)){
		next = g_pc + xed_decoded_inst_get_length(&xedd_g);
		dest += next;//TODO: handle two branch
#ifdef DEBUG
	fprintf(stdout, "format:%x\t%s\n", g_pc, g_inst_str);
#endif

#ifdef STATISTICS
		g_symbol_nums++;
		g_jcc_num++;
#endif
		if(get_inst(dest))
			sprintf(inst_buffer, "%s L_0x%x", opcode, dest);
		else{
			sprintf(inst_buffer, "%s L_ERROR_0x%x", opcode, g_current_func->begin()->first);
#ifdef STATISTICS
			g_check_nums += 1;
			fprintf(stderr, "check at pc\t%x\n", g_pc);
#endif
		}

		if(get_inst(next))
			memset(safety_guard, 0, sizeof(safety_guard));
		else{
			sprintf(safety_guard, "jmp L_ERROR_0x%x", g_current_func->begin()->first);
#ifdef STATISTICS
			fprintf(stderr, "check at pc\t%x\n", g_pc);
			g_check_nums += 1;
#endif
		}
	}else{
		fprintf(stderr, "error in format_jcc\n");
	}
}

static void format_direct_call(const xed_inst_t *xi)
{
	uint32_t dest;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	xed_reg_enum_t reg_id;

#ifdef STATISTICS
	fprintf(stderr, "call at pc\t%x\n", g_pc);
	g_symbol_nums++;
	g_call_num++;
#endif

	INST* inst = get_inst(g_pc);
	if(operand_is_relbr(op_name, &dest)){
		if(inst->api_call.fname){
			if(inst->api_call.type == API_IMP)
				sprintf(inst_buffer, "call %s", inst->api_call.fname);
			else 
				sprintf(inst_buffer, "call dword ptr %s", inst->api_call.fname);
			return;
		}
		dest += g_pc + xed_decoded_inst_get_length(&xedd_g);
		sprintf(inst_buffer, "call func_0x%x", dest);
	}else{
		fprintf(stderr, "error in format_jmp\n");
	}
}


static void format_lea(const xed_inst_t *xi)
{
	char r_str[50];
	INST *inst = get_inst(g_pc);
	switch(inst->type){
		case LEA_8:
			fprintf(stderr, "error in format_lea: lea_8\n");
			exit(0);
		case LEA_16:
			fprintf(stderr, "error in format_lea: lea_16\n");
			exit(0);
		case LEA_32:
			sprintf(r_str, "dword ptr");
			break;
	}
#ifdef WINDOWS_FORMAT
	strcpy(inst_buffer, replace(g_inst_str, "ptr", r_str));
#else
	format_reg(inst_buffer, g_inst_str);
#endif
}

typedef struct _TYPE{
	unsigned int val;
	int type;//1 for data addr; 2 for inst addr
	API_CALL api_call;
	//char *fname;
}TTYPE;
extern map<unsigned int, TTYPE*> g_map_mem_val; 

static unsigned int print_dependence_data_to_file(void)
{
	if(!g_dependence_base){
		g_dependence_base = get_dependence_base();
#ifdef DEBUG
		fprintf(stdout, "g_dependence_base:0x%x\n", g_dependence_base);
#endif
	}

	unsigned int size;
	size = dump_dependence_data(output);//dump dependence data
	//yang.begin
    //extern label
    map<unsigned int, unsigned int> label;
	for(map<unsigned int, TTYPE*>::iterator it = g_map_mem_val.begin();
			it != g_map_mem_val.end(); it++){
		unsigned int addr = it->first;
		unsigned int val = it->second->val;
        if(it->second->type == 2 && !it->second->api_call.fname)
            label[val] = val;
    }
    for(map<unsigned int, unsigned int > ::iterator it = label.begin();
            it != label.end(); it++)
        fprintf(output, "extern void * L_0x%x;\n", it->first);
    //yang.end
	fprintf(output, "void init_dependence_data(){\n");
	
	for(map<unsigned int, TTYPE*>::iterator it = g_map_mem_val.begin();
			it != g_map_mem_val.end(); it++){
		unsigned int addr = it->first;
		unsigned int val = it->second->val;
//		INST *inst = get_inst(g_pc);
		if(it->second->type == 0){
			continue;
		}else if(it->second->type == 1){
#ifdef STATISTICS
			fprintf(stderr, "rewrite global at\t%x\n", addr);
			g_symbol_nums++;
			g_dump_data++;
#endif
			fprintf(output, "*(unsigned int*)(global_data+0x%x) = global_data+0x%x;\n", 
					addr-g_dependence_base, val-g_dependence_base);
#ifdef DEBUG
			fprintf(stdout, "rewrite global: %x\t%x\t%x\t%x\n", addr, g_dependence_base, val, g_dependence_base);
#endif
		}else if(it->second->type == 2){

#ifdef STATISTICS
			fprintf(stderr, "rewrite global at\t%x\n", addr);
			g_symbol_nums++;
			g_dump_data++;
#endif
			if(it->second->api_call.fname){
				fprintf(output, "*(int*)(global_data+0x%x) = %s;\n", addr-g_dependence_base,
						it->second->api_call.fname);
			}
			else{
				//Hush.b
				fprintf(output, "*(int*)(global_data+0x%x) = &L_0x%x;\n", 
						addr-g_dependence_base, val);
				//Hush.e
			}
		} else if(it->second->type == 3) {
			fprintf(output, "*(int*)(global_data+0x%x) = func_0x%x;\n", 
					addr-g_dependence_base, val);
		}
	}
	fprintf(output, "\n}\n\n");
	
	return size;
}


static void print_debug(void)
{
	fprintf(stdout, "print pc:\t0x%x\n", g_pc);
	fprintf(output, "\/\/0x%x\n", g_pc);
	fprintf(output, "\"pushf\\n\\t\"\n");
	fprintf(output, "\"pushl %%%%eax\\n\\t\"\n");
	fprintf(output, "\"pushl %%%%edx\\n\\t\"\n");
	fprintf(output, "\"pushl %%%%ecx\\n\\t\"\n");
	fprintf(output, "\"pushl $0x%x\\n\\t\"\n", g_pc);
	fprintf(output, "\"call printpc\\n\\t\"\n");
	fprintf(output, "\"addl $0x4, %%%%esp\\n\\t\"\n");
	fprintf(output, "\"popl %%%%ecx\\n\\t\"\n");
	fprintf(output, "\"popl %%%%edx\\n\\t\"\n");
	fprintf(output, "\"popl %%%%eax\\n\\t\"\n");
	fprintf(output, "\"popf\\n\\t\"\n");
}

static void print_inst(INST *inst)
{
//#if 0
	xed_decoded_inst_zero_set_mode(&xedd_g, &dstate);
	xed_error_enum_t xed_error = xed_decode(&xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  inst->inst), 15);

#ifdef STATISTICS
			g_inst_num++;
#endif

//	fprintf(output, "\/\/0x%x\n", g_pc);

	if (xed_error == XED_ERROR_NONE) 
	{
#ifdef WINDOWS_FORMAT
		xed_decoded_inst_dump_intel_format(&xedd_g, g_inst_str, sizeof(g_inst_str), 0);
#else
		xed_decoded_inst_dump_att_format(&xedd_g, g_inst_str, sizeof(g_inst_str), 0);
		//xed_decoded_inst_dump_intel_format(&xedd_g, g_inst_str, sizeof(g_inst_str), 0);
#endif
		const xed_inst_t *xi = xed_decoded_inst_inst(&xedd_g);
	
		patch_operand(xi);
		
		switch(inst->type){
			case INCALL:
			case INJMP:
			case NORMAL:
				format_normal(xi);
				break;
			case JMP:
			case TAIL:
				format_jmp(xi);
				break;
			case CALL:
				format_direct_call(xi);
				break;
			case JCC:
			case LOOP:
				format_jcc(xi);
				break;
			case LEA_8:
			case LEA_16:
			case LEA_32:
				format_lea(xi);
			default:
				break;
		}
//		fprintf(stdout, "results:\"%s\\n\\t\"\n", inst_buffer);

		if(get_jmp_dst(g_pc))
#ifdef WINDOWS_FORMAT
			fprintf(output, "L_0x%x:\n", g_pc);
#else
			fprintf(output, "\"L_0x%x:\"\n", g_pc);
#endif

#ifdef DEBUG
		print_debug();
#endif

#ifdef WINDOWS_FORMAT
		fprintf(output, "%s\n", inst_buffer);
#else
		fprintf(output, "\"%s\\n\\t\"\n", inst_buffer);
#endif

		//patch safety guard
		switch(inst->type){
			case INJMP:
			case JCC:
				if(safety_guard[0]){
#ifdef WINDOWS_FORMAT
					fprintf(output, "%s\n", safety_guard);
#else
					fprintf(output, "\"%s\\n\\t\"\n", safety_guard);
#endif
				}
				break;
		}
	}
//#endif
}

static void print_prologue(unsigned int pc)
{
#ifdef WINDOWS_FORMAT
	fprintf(output, "call  L_Begin_0x%x\n", pc);
	fprintf(output, "jmp  L_End_0x%x\n", pc);
	fprintf(output, "L_Begin_0x%x:\n", pc);
#else
//	fprintf(output, "\"call  L_Begin_0x%x\\n\\t\"\n", pc);
//	fprintf(output, "\"jmp  L_End_0x%x\\n\\t\"\n", pc);
//	fprintf(output, "\"L_Begin_0x%x:\\n\\t\"\n", pc);
#endif
}

static void print_epilogue(unsigned int pc)
{
#ifdef WINDOWS_FORMAT
	fprintf(output, "L_End_0x%x:\n", pc);
#else
	fprintf(output, "\"L_End_0x%x:\\n\\t\"\n", pc);
#endif
}


static void print_func(FUNCTION *func)
{
	unsigned int start_pc = func->begin()->first;
#ifdef WINDOWS_FORMAT
	fprintf(output, "__asm{\n");
#else 
	fprintf(output, "__asm__ __volatile__(\n");
	fprintf(output, "\"leave\\n\\t\"\n");
#endif

#ifndef WINDOWS_NAKED
	print_prologue(start_pc);
#endif

	if(start_pc == g_main_pc){
#ifdef WINDOWS_FORMAT
		fprintf(output, "call  init_dependence_data\n");
#else
		fprintf(output, "\"call  init_dependence_data\\n\\t\"\n");
#endif
	}

	for(FUNCTION::iterator it = func->begin();
			it != func->end();it++){
		g_pc = it->first;
		fprintf(output, "//%x\n", g_pc);
		if(map_tmp.count(it->first) == 0 ){
			print_inst(it->second);
		}
		map_tmp[it->first] = 0;
	}
#ifndef WINDOWS_NAKED
	//print_epilogue(start_pc);
#endif

#ifdef WINDOWS_FORMAT
	fprintf(output, "L_ERROR_0x%x:\n", start_pc);
	fprintf(output, "}\n");
#else
	fprintf(output, "\"L_ERROR_0x%x:\\n\\t\"\n", start_pc);
	fprintf(output, "\"call safety_guard\\n\\t\"\n");
	fprintf(output, ":);\n");
#endif
}

static void print_header(void)
{
	fprintf(output, "#include<stdio.h>");
}

static void print_func_decaration(void)
{
	for(PROGRAM::iterator it = g_current_program->begin();//dump functions
			it != g_current_program->end();it++){
		fprintf(output, "int func_0x%x();\n", it->first);
	}

}

extern char PEMU_binary_name[100];

//Hush.b
typedef struct _Dst_item{
	char name[100];
}Dst_item;

extern map<unsigned int, Dst_item*> dst_map;
//Hush.e


void print_safety_guard(void)
{
	fprintf(output, "void safety_guard(void){printf(\"saftety guard triggered\\n\"); exit(-1);}\n\n");
}

void print_print_pc(void)
{
	fprintf(output, "FILE *output;\n");
	fprintf(output, "void printpc(unsigned int pc)\n");
	fprintf(output, "{\n");
	fprintf(output, "  fprintf(output, \"%%x\\n\", pc);\n");
	fprintf(output, "  fflush(output);\n");
	fprintf(output, "}\n");

}

void print_program()
{
#ifdef DEBUG
	fprintf(stdout, "starting print program...\n");
#endif

	output = fopen("output_a.out.c", "w");
	if(!output){
		fprintf(stderr, "error in print_program\n");
		exit(0);
	}

	print_header();	
	print_func_decaration();
	print_safety_guard();
	print_print_pc();
	
	//yang
	unsigned  instsize = 0;
	unsigned int globalsize = 0;
	globalsize = print_dependence_data_to_file();
	
////////	
	for(PROGRAM::iterator it = g_current_program->begin();//dump functions
			it != g_current_program->end();it++){
		
#ifdef WINDOWS_NAKED
	fprintf(output, "__declspec( naked ) ");
#endif
		if(g_main_pc == it->first){
			fprintf(output, "void main(){\n");
//Hush.b
//extern variables in dst
#ifdef DEBUG
			fprintf(stderr, "----dst_map size is %d\n", dst_map.size());	
#endif

#if 0
			if(!dst_map.empty()){
				for(map<unsigned int, Dst_item*>::iterator it= dst_map.begin();
					it!=dst_map.end();it++){
					fprintf(output, "extern %s;\n", it->second->name);	
				}	
			}
#endif
			fprintf(output, "output=fopen(\"log\", \"w\");\n");
//Hush.e
		}else{
			fprintf(output, "int func_0x%x(){\n", it->first);
		}
#ifdef DEBUG
		fprintf(stderr, "----function start pc:%x\t%x\n", it->first, it->second);
#endif
		g_current_func = it->second;
		print_func(it->second);
		fprintf(output, "}\n");

		instsize += it->second->size();
	}
	fclose(output);
#ifdef STATISTICS
	fprintf(stderr, "program:%s\n", PEMU_binary_name);
	fprintf(stderr, "number of executed inst:\t%d\n", g_inst_num);
	fprintf(stderr, "symbolized addresses %d\n", g_symbol_nums);
	fprintf(stderr, "direct jmp:\t%d\njcc:\t%d\ndirect call:\t%d\ndata:\t%d\ndis:\t%d\nimm:\t%d\n", 
			g_jmp_num, g_jcc_num, g_call_num, g_dump_data, g_dis_nums, g_imm_nums);
	fprintf(stderr, "checks num:%d\n", g_check_nums);
#endif
}

void print_operands(xed_decoded_inst_t* xedd) {
    unsigned int i, noperands;
    cout << "Operands" << endl;
    const xed_inst_t* xi = xed_decoded_inst_inst(xedd);
    noperands = xed_inst_noperands(xi);
    for( i=0; i < noperands ; i++) { 
        const xed_operand_t* op = xed_inst_operand(xi,i);
        xed_operand_enum_t op_name = xed_operand_name(op);
        cout << i << " " << xed_operand_enum_t2str(op_name) << " ";
        switch(op_name) {
          case XED_OPERAND_AGEN:
          case XED_OPERAND_MEM0:
          case XED_OPERAND_MEM1:
            // we print memops in a different function
            break;
          case XED_OPERAND_PTR:  // pointer (always in conjunction with a IMM0)
          case XED_OPERAND_RELBR: { // branch displacements
              xed_uint_t disp_bits = xed_decoded_inst_get_branch_displacement_width(xedd);
              if (disp_bits) {
                  //cout  << "BRANCH_DISPLACEMENT_BYTES= " << disp_bits << " ";
                  xed_int32_t disp = xed_decoded_inst_get_branch_displacement(xedd);
                  //cout << hex << setfill('0') << setw(8) << disp << setfill(' ') << dec;
              }
            }
            break;

          case XED_OPERAND_IMM0: { // immediates
              xed_uint_t width = xed_decoded_inst_get_immediate_width(xedd);
              if (xed_decoded_inst_get_immediate_is_signed(xedd)) {
                  xed_int32_t x =xed_decoded_inst_get_signed_immediate(xedd);
                  //cout << hex << setfill('0') << setw(8) << x << setfill(' ') << dec 
                  //     << '(' << width << ')';
              }
              else {
                  xed_uint64_t x = xed_decoded_inst_get_unsigned_immediate(xedd); 
                  //cout << hex << setfill('0') << setw(16) << x << setfill(' ') << dec 
                  //     << '(' << width << ')';
              }
              break;
          }
          case XED_OPERAND_IMM1: { // immediates
              xed_uint8_t x = xed_decoded_inst_get_second_immediate(xedd);
              //cout << hex << setfill('0') << setw(2) << (int)x << setfill(' ') << dec;
              break;
          }

          case XED_OPERAND_REG0:
          case XED_OPERAND_REG1:
          case XED_OPERAND_REG2:
          case XED_OPERAND_REG3:
          case XED_OPERAND_REG4:
          case XED_OPERAND_REG5:
          case XED_OPERAND_REG6:
          case XED_OPERAND_REG7:
          case XED_OPERAND_REG8:
          case XED_OPERAND_REG9:
          case XED_OPERAND_REG10:
          case XED_OPERAND_REG11:
          case XED_OPERAND_REG12:
          case XED_OPERAND_REG13:
          case XED_OPERAND_REG14:
          case XED_OPERAND_REG15: {
              xed_reg_enum_t r = xed_decoded_inst_get_reg(xedd, op_name);
              cout << xed_operand_enum_t2str(op_name) << "=" << xed_reg_enum_t2str(r);
              break;
          }
          default:
            //cout << "[Not currently printing value of field " << xed_operand_enum_t2str(op_name) << ']';
            break;

        }
        //cout << " " << xed_operand_visibility_enum_t2str(xed_operand_operand_visibility(op))
        //     << " / " << xed_operand_action_enum_t2str(xed_operand_rw(op))
        //     << " / " << xed_operand_width_enum_t2str(xed_operand_width(op));
        //cout << " bytes=" << xed_decoded_inst_operand_length(xedd,i);
        //cout << endl;
    }
}
