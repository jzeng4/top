//#include "inline_inst.h"

#include "rev_inline/config.h"
#include "patch_inst.h"


//#define WINDOWS_FORMAT

static int s_type = 0;
extern unsigned int g_pc;

extern uint32_t g_symbol_nums;
extern unsigned int g_imm_nums;
extern unsigned int g_dis_nums;

#undef DEBUG
#undef STATISTICS

//Hush.b
typedef struct _Dst_item{
	char name[100];
}Dst_item;

extern map<unsigned int, Dst_item*> dst_map;
//Hush.e

int operand_is_mem5(const xed_operand_enum_t op_name)
{
	switch (op_name) {
		/* Memory */
		case XED_OPERAND_AGEN:
		case XED_OPERAND_MEM0:
		case XED_OPERAND_MEM1:{
			return 1;
		}
	}
}


char *replace(char *st, char *orig, char *repl) {
	static char buffer[500];
	char *ch;
  	
	if (!(ch = strstr(st, orig)))
	   	return st;
	strncpy(buffer, st, ch-st);  
	buffer[ch-st] = 0;
	sprintf(buffer+(ch-st), "%s%s", repl, ch+strlen(orig));
	return buffer;
}


void patch_imm_operand(const xed_inst_t *xi)
{
    int noperands = xed_inst_noperands(xi);
	uint32_t value = 0;
	int i;
	const xed_operand_t *op;
	xed_operand_enum_t op_name;
	char org_imm_str[100], r_imm_str[100];

	noperands= noperands > 2 ? 2 : noperands;
	for( i=0; i < noperands ; i++){
		/* Immediate */
		op = xed_inst_operand(xi, i);
		op_name = xed_operand_name(op);
	
		if(operand_is_imm(op_name, &value)) {

#ifdef STATISTICS
		//statistics
		if(value > 0x8000000 ) {
			g_symbol_nums++;
			g_imm_nums++;
			fprintf(stderr, "imm num at pc\t%x\n", g_pc);
		}
#endif

//fprintf(stdout, "displacement_debug:%x\t%s\n", g_pc, g_inst_str);

#ifdef WINDOWS_FORMAT
			sprintf(org_imm_str, "0x%x", value);
#else
			sprintf(org_imm_str, "$0x%x", value);
#endif

			char *tmp;
			if(s_type == 1 || s_type == 4){
#ifdef WINDOWS_FORMAT
				sprintf(r_imm_str, "offset global_data+0x%x", value - g_dependence_base);
#else
				sprintf(r_imm_str, "$global_data+0x%x", value - g_dependence_base);
#ifdef DEBUG
				fprintf(stdout, "debug patch:\t%x\t%x\n", value, g_dependence_base);
#endif
#endif
			}else if(s_type == 2 || s_type == 5){
				INST *inst = get_inst(g_pc);
				if(inst->api_call.fname){
#ifdef WINDOWS_FORMAT
					if(inst->api_call.type == API_IMP)
						sprintf(r_imm_str, "offset %s", inst->api_call.fname);
					else
						sprintf(r_imm_str, "%s", inst->api_call.fname);
#else
					sprintf(r_imm_str, "$%s", inst->api_call.fname);
#endif
				}
				else{
#ifdef WINDOWS_FORMAT
					sprintf(r_imm_str, "offset func_0x%x", value);
#else
					sprintf(r_imm_str, "$func_0x%x", value);
#endif
				}
			}
			
			//If in Dynamic Symbolic Table, simply replace it with name
			if(0){
			}
			else{
				tmp = replace(g_inst_str, org_imm_str, r_imm_str);
				strcpy(g_inst_str, tmp);
			}
		}

	}
}

void patch_displacement(const xed_inst_t *xi)
{
	char org_imm_str[100], r_imm_str[100];
	uint32_t value = 0, mem_addr = 0;
	int noperands = xed_inst_noperands(xi);
	int i;

	noperands= noperands > 2 ? 2 : noperands;
	
	for( i=0; i < noperands; i++){
		const xed_operand_t *op = xed_inst_operand(xi,i);
		xed_operand_enum_t op_name = xed_operand_name(op);
		if(operand_is_mem4(op_name, &mem_addr, i)){
			int mem_idx = op_name == XED_OPERAND_MEM1 ? 1 : 0;
			unsigned int displacement =
				(unsigned int)
				xed_decoded_inst_get_memory_displacement(&xedd_g, mem_idx);
			xed_reg_enum_t base_regid =
				xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);

#ifdef STATISTICS
			//statistics
			if(base_regid == XED_REG_INVALID && displacement > 0x8000000 ){
				g_symbol_nums++;
				g_dis_nums++;
				fprintf(stderr, "displacement at pc\t%x\n", g_pc);
			}
#endif

			//Hush.b
#ifdef DEBUG	
			fprintf(stderr, "----displacement-debug: 0x%x\n", displacement);
#endif
			sprintf(org_imm_str, "0x%x", displacement);
			if(dst_map.count(displacement)>0){
				sprintf(r_imm_str, "%s", dst_map[displacement]->name);
			}
			else{
				sprintf(r_imm_str, "global_data+0x%x", displacement-g_dependence_base);
			}
			//Hush.e
			
			char *tmp = replace(g_inst_str, org_imm_str, r_imm_str);
			strcpy(g_inst_str, tmp);
#ifdef DEBUG
			fprintf(stderr, "----replacing org_imm_str(%s) with r_imm_str(%s)", org_imm_str,r_imm_str);
#endif
				//fprintf(stdout, "hererere:%s\t%s\t%s\t%s\n", g_inst_str, tmp, org_imm_str, r_imm_str);
	//		}
		}
	}

}

void patch_operand(const xed_inst_t *xi)
{
	
	switch(s_type = get_pc_addr(g_pc)){
		case 0:
			return;
		case 1:
		case 2:
			patch_imm_operand(xi);
			break;
		case 3:
			patch_displacement(xi);
			break;
		case 4:
		case 5:
			patch_imm_operand(xi);
			patch_displacement(xi);
			break;
		default:
			return;
	}
}
