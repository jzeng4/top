#include "helper_hook_inst.h"
#include "linux.h"
#include"cpu.h"
#include "rev_inline/config.h"
//#include "txt_rewrite.h"
//#include "dependence_taint.h"

extern uint32_t g_start_pc;

int operand_is_imm(const xed_operand_enum_t op_name, uint32_t * value) {
	switch (op_name) {
		/* Immediate */
	case XED_OPERAND_IMM0:{
			if (xed_decoded_inst_get_immediate_is_signed(&xedd_g)) {
				xed_int32_t signed_imm_val =
				    xed_decoded_inst_get_signed_immediate
				    (&xedd_g);
				*value = (uint32_t) signed_imm_val;
			} else {
				xed_uint64_t unsigned_imm_val =
				    xed_decoded_inst_get_unsigned_immediate
				    (&xedd_g);
				*value = (uint32_t) unsigned_imm_val;
			}
#ifdef DEBUG
			fprintf(stderr, "----operand_is_imm0:%x\n", *value);	
#endif

			return 1;
		}
		/* Special immediate only used in ENTER instruction */
	case XED_OPERAND_IMM1:{
			xed_uint8_t unsigned_imm_val =
			    xed_decoded_inst_get_second_immediate(&xedd_g);
			*value = (uint32_t) unsigned_imm_val;
#ifdef DEBUG
			fprintf(stderr, "----operand_is_imm1:%x\n", *value);	
#endif

			return 1;
		}

	default:
		return 0;
	}

}

target_ulong mem_taint;
int operand_is_mem4(const xed_operand_enum_t op_name, uint32_t* mem_addr, 
		   int operand_i)
{

	xed_reg_enum_t basereg;	
	mem_taint=0;

	switch (op_name) {
		/* Memory */
	case XED_OPERAND_AGEN:
	case XED_OPERAND_MEM0:
	case XED_OPERAND_MEM1:{
			unsigned long base = 0;
			unsigned long index = 0;
			unsigned long scale = 1;
			unsigned long segbase = 0;
			unsigned short segsel = 0;
			unsigned long displacement = 0;
//			size_t remaining = 0;

			/* Set memory index */
			int mem_idx = 0;
			if (op_name == XED_OPERAND_MEM1)
				mem_idx = 1;

			/* Initialization */
			base = 0;
			index = 0;
			scale = 0;
			segbase = 0;
			segsel = 0;
			displacement = 0;

			segbase = 0;
			// Get Base register
			xed_reg_enum_t base_regid =
			    xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
			
			if (base_regid != XED_REG_INVALID) {
				base = PEMU_get_reg(base_regid);
			}
			// Get Index register and Scale
			xed_reg_enum_t index_regid =
			    xed_decoded_inst_get_index_reg(&xedd_g, mem_idx);
			if (mem_idx == 0 && index_regid != XED_REG_INVALID) {
				index = PEMU_get_reg(index_regid);

				if (xed_decoded_inst_get_scale
				    (&xedd_g, operand_i) != 0) {
					scale =
					    (unsigned long)
					    xed_decoded_inst_get_scale(&xedd_g,
								       mem_idx);
				}
			}
			//Get displacement
			displacement =
			    (unsigned long)
			    xed_decoded_inst_get_memory_displacement(&xedd_g,
								     mem_idx);

			*mem_addr =
			    segbase + base + index * scale + displacement;
#ifdef DEBUG
			fprintf(stdout, "operand_is_mem4:\t%x\t%x\t%x\t%x\t%x\t%x\n", segbase, base, index, scale, displacement, *mem_addr);	
			int tempvalue;
			PEMU_read_mem(*mem_addr, 4, &tempvalue);
			fprintf(stderr, "----operand_is_mem4:\t%x\t%x\t%x\t%x\t%x\t%x(%x)\n", segbase, base, index, scale, displacement, *mem_addr, tempvalue);	
#endif
//			if((long) displacement > (long)base)
//				mem_taint=*mem_addr;
			target_ulong a,b;
			a = abs(*mem_addr-displacement);
			b = abs(*mem_addr-base);
			if(a <= b)
				mem_taint = *mem_addr;
#ifdef DEBUG
			fprintf(stdout, "displacement %lx %lx %x\n", displacement, base, mem_taint); 
#endif
			return 1;
		}

	default:
		return 0;
	}

}



int operand_is_relbr(const xed_operand_enum_t op_name, uint32_t * branch) {
	switch (op_name) {
		/* Jumps */
	case XED_OPERAND_PTR:	// pointer (always in conjunction with a IMM0)
	case XED_OPERAND_RELBR:{
				// branch displacements

			xed_uint_t disp =
			    xed_decoded_inst_get_branch_displacement(&xedd_g);
			*branch = disp;
			 return 1;
	} 
	default:return 0;
	}

}

int operand_is_reg(const xed_operand_enum_t op_name, xed_reg_enum_t * reg_id) {
	switch (op_name) {
		/* Register */
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
	case XED_OPERAND_REG15:{
			*reg_id = xed_decoded_inst_get_reg(&xedd_g, op_name);
			return 1;
		} default:return 0;
	}
}


inline int is_plt(unsigned int dest)
{
#ifdef DEBUG
	fprintf(stdout, "is_plt\t%x\t%x\n", dest, PEMU_txt_start);
#endif
	return dest < PEMU_txt_start ? 1 : 0;

#if 0
	char buf[15], tmp_str[4];
	unsigned int tmp = 0;

	PEMU_read_mem(dest, 15, buf);
	
	xed_decoded_inst_zero_set_mode(&xedd_g, &dstate);
    xed_error_enum_t xed_error = xed_decode(&xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  buf), 15);

	if (xed_error == XED_ERROR_NONE){
		xed_iclass_enum_t opcode = 	xed_decoded_inst_get_iclass(&xedd_g);
		const xed_inst_t *xi = xed_decoded_inst_inst(&xedd_g);
		const xed_operand_t *op = xed_inst_operand(xi, 0);
		xed_operand_enum_t op_name = xed_operand_name(op);

		if(opcode == XED_ICLASS_JMP && 
				operand_is_mem4(op_name, &tmp, 0)){
			PEMU_read_mem(tmp, 4, tmp_str);
			tmp = *(int*)tmp_str;
			xed_decode(&xedd_g,
					XED_STATIC_CAST(const xed_uint8_t *,  g_inst_buffer), 15);
		}
	}
   	xed_decode(&xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  g_inst_buffer), 15);

	return tmp;
#endif

}

#if 0
inline int is_new_func(unsigned dest)
{
	char buf[15];
	unsigned int tmp;
	xed_reg_enum_t reg_id;
	PEMU_read_mem(dest, 15, buf);

	xed_decoded_inst_zero_set_mode(&xedd_g, &dstate);
    xed_error_enum_t xed_error = xed_decode(&xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  buf), 15);

	if (xed_error == XED_ERROR_NONE){
		xed_iclass_enum_t opcode = 	xed_decoded_inst_get_iclass(&xedd_g);
		const xed_inst_t *xi = xed_decoded_inst_inst(&xedd_g);
		const xed_operand_t *op = xed_inst_operand(xi, 0);
		xed_operand_enum_t op_name = xed_operand_name(op);
		if(opcode == XED_ICLASS_PUSH){
			if(operand_is_reg(op_name, &reg_id)){
				if(reg_id == XED_REG_EBP){	
					return 1;
				}
			}
		}
		return 0;
	}

}
#endif




#ifndef WINDOWS_FORMAT
extern API_CALL *get_api_call(uint32_t addr);
inline int getFcnName(uint32_t addr, char **name)
{
	API_CALL *p = get_api_call(addr);
	if(p != 0){
		*name = p->fname;
		return p->type;
	}
}
#else

#endif


inline API_TYPE is_api_call(unsigned int dest, char **fname)
{
#ifndef WINDOWS_FORMAT
	
	int ret = 0;
	if(ret = (dest < PEMU_txt_start)){
		//getFcnName(dest, fname);
	}

	return ret;
#else
	unsigned int api_addr = 0;
	char tmp[50];
	API_TYPE res;
	if(api_addr = is_plt(dest)){
		if(getFcnName(api_addr, tmp) != -1){
			*fname = (char*)malloc(50);
			strcpy(*fname, tmp);
//			if(isApiImplememted(api_addr))
				res = API_IMP;
//			else res = API_REG;
		}
	}else if(getFcnName(dest, tmp) != -1){
		*fname = (char*)malloc(50);
		strcpy(*fname, tmp);
//		if(isApiImplememted(dest))
			res = API_IMP;
//		else res =API_REG;
	}else
		res=API_NONE;
	
	if(res!=API_NONE)
	{
		t_set_reg_taint(XED_REG_EAX,0);
		d_set_reg_taint(XED_REG_EAX,0);
	}
	return res;
#endif
}

//In this version of released code, we don't trace into libc functions, 
//thus we use this function.
//this function resolve libc API issues:
//type == 0: handle text;
//type == 1: handle global data;
inline void handle_api_issues(API_CALL *api, int type)
{
	uint32_t tmp, addr, taint, esp;
	uint32_t pos;//index for parameters

#ifdef DEBUG
	fprintf(stdout, "api->dptr\t%x\n", api->dptr);
#endif
	if((tmp = api->dptr) != 0){//api has pointer to data
		pos = 0;
		esp	= PEMU_get_reg(XED_REG_ESP);

		while(tmp){
			if(tmp & 1){
				esp += 4 * pos;
				PEMU_read_mem(esp, 4, &addr);				
				
				if(type == 0 && (taint = t_get_mem_taint(esp))){
					insert_pc_addr(taint, 1);
				}else if(type == 1 && (taint = d_get_mem_taint(addr))){
					update_mem_val_type(taint, 1, API_NONE, 0);
				}
				//TODO: the size of data
				insert_dependence_data(addr, 100);
			}
			tmp >>= 1;
			pos ++;
		}
	}
	if((tmp = api->tptr) != 0){//api has pointer to function
		pos = 0;
		esp	= PEMU_get_reg(XED_REG_ESP);

		while(tmp){
			if(tmp & 1){
				esp += 4 * pos;
				PEMU_read_mem(esp, 4, &addr);				
				
				if(type == 0 && (taint = t_get_mem_taint(esp))){
					insert_pc_addr(taint, 2);
				}else if(type == 1 && (taint = d_get_mem_taint(addr))){
					update_mem_val_type(taint, 2, API_NONE, 0);
				}
				//TODO: the size of data
				insert_dependence_data(addr, 100);
			}
			tmp >>= 1;
			pos ++;
		}

	}

}


inline void api_copy(API_CALL *to, API_CALL *from)
{
	to->type = from->type;
	to->fname = from->fname;
	to->dptr = from->dptr;
	to->tptr = from->tptr;
#ifdef DEBUG
	fprintf(stdout, "api_copy\t%s\n", to->fname);
#endif
}

