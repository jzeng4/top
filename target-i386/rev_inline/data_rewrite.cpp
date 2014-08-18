#include "rev_inline/config.h"
#include "data_rewrite.h"
#include <string.h>


typedef struct _TYPE{
	unsigned int val;
	int type;//1 for data addr; 2 for inst addr
	API_CALL api_call;
	//	char *fname;
}TTYPE;

map<unsigned int, TTYPE*> g_map_mem_val;

extern "C"{

void insert_mem_val(unsigned int addr, unsigned int val)
{
	if(g_map_mem_val.count(addr))
		return;

	TTYPE *tmp = (TTYPE*)malloc(sizeof(TTYPE));
	memset(tmp, 0, sizeof(TTYPE));
	tmp->val = val;
	tmp->type = 0;
	g_map_mem_val[addr] = tmp;
#ifdef DEBUG
	fprintf(stdout, "%x\tinsert_mem_val\t%x\t%x\n", g_pc, addr, val);
#endif
}


TTYPE *get_mem_val(unsigned int addr)
{
	unsigned int val;
	if(g_map_mem_val.count(addr) > 0)
		return g_map_mem_val[addr];
	return 0;
}

#ifdef STATISTICS
static uint32_t g_count = 0;
#endif
void update_mem_val_type(unsigned int addr, int type, API_TYPE api_call, char *fname)
{
	unsigned int val;
	if(g_map_mem_val.count(addr)){
#ifdef STATISTICS
		g_count++;
#endif
		val = g_map_mem_val[addr]->val;
		g_map_mem_val[addr]->type = type;
		g_map_mem_val[addr]->api_call.fname = fname;
		g_map_mem_val[addr]->api_call.type = api_call;
		
#ifdef DEBUG
		fprintf(stdout, "%x\tupdate_mem_val_type\t%x\t%x\t%x\n", g_pc,
				addr, val, type);
#endif
	}else{
		fprintf(stderr, "error in update_mem_val_type\n");
		exit(0);
	}
}

}



/****************start hook functions for data rewrite*****************/
static DataFunc data_func[XED_ICLASS_LAST];

static void NONE(const xed_inst_t* xi)
{
}

static void Instrument_PUSH(const xed_inst_t* xi)
{
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	xed_reg_enum_t reg_id;
	unsigned int taint = 0, mem_addr;

	if(operand_is_mem4(op_name, &mem_addr, 0)){
		taint = d_get_mem_taint(mem_addr);
	}else if(operand_is_reg(op_name, &reg_id)){
		taint = d_get_reg_taint(reg_id);
	}
	unsigned int esp = PEMU_get_reg(XED_REG_ESP) - 4;
	d_set_mem_taint_bysize(esp, taint, 4);
}

static void Instrument_POP(const xed_inst_t* xi)
{
	uint32_t mem_addr;
	xed_reg_enum_t reg_id;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	
	uint32_t esp = PEMU_get_reg(XED_REG_ESP);
	uint32_t taint = d_get_mem_taint(esp);

	if(operand_is_mem4(op_name, &mem_addr, 0)){
		d_set_mem_taint_bysize(mem_addr, taint, 4);
	}else if(operand_is_reg(op_name, &reg_id)){
		d_set_reg_taint(reg_id, taint);
	}
	d_set_mem_taint_bysize(esp, 0, 4);
}

static void Instrument_MOV(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id_0, reg_id_1;
	unsigned int mem_addr, imm;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);
	const xed_operand_t *op_1 = xed_inst_operand(xi, 1);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);
	xed_operand_enum_t op_name_1 = xed_operand_name(op_1);
	
	if(operand_is_mem4(op_name_0, &mem_addr, 0)){
		if (operand_is_reg(op_name_1, &reg_id_1)){
			d_set_mem_taint_bysize(mem_addr, d_get_reg_taint(reg_id_1),
					xed_decoded_inst_operand_length(&xedd_g, 0));
		}else if(operand_is_imm(op_name_1, &imm)){
			d_set_mem_taint_bysize(mem_addr, 
					xed_decoded_inst_operand_length(&xedd_g, 0), 0);
		}
	}else if(operand_is_reg(op_name_0, &reg_id_0)){
		if(operand_is_mem4(op_name_1, &mem_addr, 1)){
			d_set_reg_taint(reg_id_0, d_get_mem_taint(mem_addr));
		}else if(operand_is_reg(op_name_1, &reg_id_1)){
			d_set_reg_taint(reg_id_0, d_get_reg_taint(reg_id_1));
		}else if(operand_is_imm(op_name_1, &imm)){
			d_set_reg_taint(reg_id_0, 0);
		}
	}
}

static void Instrument_ADD(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id_0, reg_id_1;
	unsigned int imm = 0;
	unsigned int mem_addr, taint_s = 0, taint_d = 0;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);
	const xed_operand_t *op_1 = xed_inst_operand(xi, 1);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);
	xed_operand_enum_t op_name_1 = xed_operand_name(op_1);

	if(operand_is_mem4(op_name_0, &mem_addr, 0)){
		if(operand_is_imm(op_name_1, &imm))
			return;
		taint_d = d_get_mem_taint(mem_addr);
/*		if (operand_is_reg(op_name_1, &reg_id_1)){
			taint_s = d_get_reg_taint(reg_id_1);			
		}
		if((int)get_pc_imm(taint_s) < (int)get_pc_imm(taint_d))
			taint_s = taint_d;
		d_set_mem_taint_bysize(mem_addr, taint_s, 
				xed_decoded_inst_operand_length(&xedd_g, 0));
*/
		//yang
		int a, b;
		PEMU_read_mem(mem_addr, 4, &a);
		if (operand_is_reg(op_name_1, &reg_id_1)){
			taint_s = d_get_reg_taint(reg_id_1);			
			b = PEMU_get_reg(reg_id_1);
		}
//		if((int)get_pc_imm(taint_s) < (int)get_pc_imm(taint_d))

		if(b<a)
			taint_s = taint_d;
		d_set_mem_taint_bysize(mem_addr, taint_s, 
				xed_decoded_inst_operand_length(&xedd_g, 0));
	}else if(operand_is_reg(op_name_0, &reg_id_0)){
		if(operand_is_imm(op_name_1, &imm))
			return;
/*		taint_d = d_get_reg_taint(reg_id_0);
		if(operand_is_mem4(op_name_1, &mem_addr, 1)){
			taint_s = d_get_mem_taint(mem_addr);
		}else if(operand_is_reg(op_name_1, &reg_id_1)){
			taint_s = d_get_reg_taint(reg_id_1);
		}
		if((int)get_pc_imm(taint_s) < (int)get_pc_imm(taint_d))
			taint_s = taint_d;
		d_set_reg_taint(reg_id_0, taint_s);
		*/
		
		//yang
		int a, b;
		a = PEMU_get_reg(reg_id_0);

		taint_d = d_get_reg_taint(reg_id_0);
		if(operand_is_mem4(op_name_1, &mem_addr, 1)){
			taint_s = d_get_mem_taint(mem_addr);
			PEMU_read_mem(mem_addr, 4, &b);
		}else if(operand_is_reg(op_name_1, &reg_id_1)){
			taint_s = d_get_reg_taint(reg_id_1);
			b = PEMU_get_reg(reg_id_1);
		}

		//	if((int)get_pc_imm(taint_s) < (int)get_pc_imm(taint_d))
		if(b<a)
			taint_s = taint_d;
		d_set_reg_taint(reg_id_0, taint_s);
	}

}


static void Instrument_XOR(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id_0, reg_id_1;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);
	const xed_operand_t *op_1 = xed_inst_operand(xi, 1);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);
	xed_operand_enum_t op_name_1 = xed_operand_name(op_1);

	if (operand_is_reg(op_name_0, &reg_id_0)
				&& (operand_is_reg(op_name_1, &reg_id_1))){
			if(reg_id_0 == reg_id_1)
				d_set_reg_taint(reg_id_0, 0);
			return;
	}
	Instrument_ADD(xi);

}


static void Instrument_JMP(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id;
	char buf[4];
	unsigned int value = 0, dest = 0;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);

	unsigned int taint = 0;

#ifdef DEBUG
	fprintf(stdout, "in data_rewrite:\tInstrument_JMP\n");	
#endif
	if(operand_is_mem4(op_name, &dest, 0)){
		int mem_idx = op_name == XED_OPERAND_MEM1 ? 1 : 0;
		xed_reg_enum_t base_regid =
			xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
		if(base_regid!=XED_REG_INVALID){
			if(taint = d_get_reg_taint(base_regid)){	
				update_mem_val_type(taint, 2, API_NONE, 0);
			}
		}
		//Hush.b
		else{
			update_mem_val_type(dest, 2, API_NONE, 0);
#ifdef DEBUG
			fprintf(stderr, "----Updating dest %x\n", dest);
#endif
		}
		//Hush.e
	}else if(operand_is_reg(op_name, &reg_id)){
		if(taint = d_get_reg_taint(reg_id)){
			update_mem_val_type(taint, 2, API_NONE, 0);
		}
	}

}


static void Instrument_CALL(const xed_inst_t* xi)
{
#ifdef DEBUG
	fprintf(stdout, "data:instrument_call\n");
#endif
	xed_reg_enum_t reg_id;
	uint32_t buf;
	unsigned int value = 0, dest = 0;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	char *fname = 0;
	unsigned int taint = 0;
	API_TYPE type;	

//TODO: value may be plt call	
	if(operand_is_mem4(op_name, &dest, 0)){
		int mem_idx = op_name == XED_OPERAND_MEM1 ? 1 : 0;
		xed_reg_enum_t base_regid =
			xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
			
		PEMU_read_mem(dest, 4, &buf);
		dest = buf;

		if(taint = d_get_reg_taint(base_regid)){			
			if(type = is_api_call(dest, &fname)){
//				update_mem_val_type(taint, 2, type, fname);
				goto API_CALL;
			}else{
				update_mem_val_type(taint, 2, API_NONE, 0);
			}
		}else if(taint = d_get_mem_taint(dest)){
			if(type = is_api_call(dest, &fname)){
//				update_mem_val_type(taint, 2, type, fname);
				goto API_CALL;
			}else{
				update_mem_val_type(taint, 2, API_NONE, 0);
			}

		}
		/*
		else if(taint = t_get_reg_taint(base_regid))
		{
			uint32_t mem_addr=dest;
			PEMU_read_mem(dest, 4, buf);
			dest = *(unsigned int*)buf;
			insert_mem_val(mem_addr, dest);
			if(type = is_api_call(dest, &fname)){
				update_mem_val_type(mem_addr, 2, type, fname);
			}else{
				update_mem_val_type(mem_addr, 2, API_NONE, 0);
			}

		}else if(base_regid==XED_REG_INVALID)
		{
			uint32_t mem_addr=dest;
			PEMU_read_mem(dest, 4, buf);
			dest = *(unsigned int*)buf;
			insert_mem_val(mem_addr, dest);
			if(type = is_api_call(dest, &fname)){
				update_mem_val_type(mem_addr, 2, type, fname);
			}else{
				update_mem_val_type(mem_addr, 2, API_NONE, 0);
			}
		}*/
		return;
	}else if(operand_is_reg(op_name, &reg_id)){
		if(taint = d_get_reg_taint(reg_id)){
			dest = PEMU_get_reg(reg_id);
			if(type = is_api_call(dest, &fname)){
//				update_mem_val_type(taint, 2, type, fname);
				goto API_CALL;
			}else{
				update_mem_val_type(taint, 2, API_NONE, 0);
			}
		}
		return;
	}else if(operand_is_relbr(op_name, &dest)){
		dest += (g_pc +  xed_decoded_inst_get_length(&xedd_g));
		if(type = is_api_call(dest, &fname)){
#ifdef DEBUG
			fprintf(stdout, "is_api_call\t%x\t%x\n", dest, type);
#endif
			goto REST;
		}
		return;

	}

API_CALL:
	update_mem_val_type(taint, 2, type, fname);
	//api_copy(&inst->api_call, get_api_call(dest));
REST:
	handle_api_issues(get_api_call(dest), 1);
}

static void Instrument_LEA(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id;
	unsigned int mem_addr, imm;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);
	const xed_operand_t *op_1 = xed_inst_operand(xi, 1);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);
	xed_operand_enum_t op_name_1 = xed_operand_name(op_1);
	
	if(operand_is_mem4(op_name_1, &mem_addr, 1)){
		if (operand_is_reg(op_name_0, &reg_id)){
			int mem_idx = 0;
			if (op_name_1 == XED_OPERAND_MEM1)
				mem_idx = 1;
			xed_reg_enum_t base_regid =
				xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
			d_set_reg_taint(reg_id, d_get_reg_taint(base_regid));
		}else{
			fprintf(stderr, "error in Instrument_LEA\n");
			exit(0);
		}
	}else{
		fprintf(stderr, "error in Instrument_LEA\n");
		exit(0);
	}	
}


//yang.new
static void Instrument_XCHG(const xed_inst_t *xi)
{
	xed_reg_enum_t reg0, reg1;
	unsigned int mem_addr;
	unsigned int taint = 0;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);
	const xed_operand_t *op_1 = xed_inst_operand(xi, 1);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);
	xed_operand_enum_t op_name_1 = xed_operand_name(op_1);
	
	if(operand_is_mem4(op_name_0, &mem_addr, 0))
	{
		if(operand_is_reg(op_name_1, &reg1))
		{
			taint = d_get_reg_taint(reg1);
			d_set_reg_taint(reg1, d_get_mem_taint(mem_addr));
			d_set_mem_taint(mem_addr, taint);
		}
	}else if (operand_is_reg(op_name_0, &reg0))
	{
		if(operand_is_reg(op_name_1, &reg1))
		{	
			taint =  d_get_reg_taint(reg1);
			d_set_reg_taint(reg1, d_get_reg_taint(reg0));
			d_set_reg_taint(reg0, taint);
		}else if(operand_is_mem4(op_name_1, &mem_addr,1))
		{

			taint = d_get_reg_taint(reg0);
			d_set_reg_taint(reg0, d_get_mem_taint(mem_addr));
			d_set_mem_taint(mem_addr, taint);


		}
	}

}
//yang.new
static void Instrument_PUSHAD(const xed_inst_t *xi)
{

	xed_reg_enum_t regs[]={XED_REG_EAX, XED_REG_ECX, XED_REG_EDX,XED_REG_EBX,XED_REG_ESP,XED_REG_EBP, XED_REG_ESI, XED_REG_EDI};

	unsigned int mem_addr;
	mem_addr = PEMU_get_reg(XED_REG_ESP)-4;
	unsigned int i=0;
	
	for(i=0;i<8;i++,mem_addr=mem_addr-4){
		d_set_mem_taint(mem_addr, d_get_reg_taint(regs[i]));
	}
}

//yang.new
static void Instrument_POPAD(const xed_inst_t *xi)
{
	xed_reg_enum_t regs[]={XED_REG_EDI, XED_REG_ESI, XED_REG_EBP,XED_REG_ESP,XED_REG_EBX,XED_REG_EDX, XED_REG_ECX, XED_REG_EAX};
	unsigned int mem_addr;
	mem_addr = PEMU_get_reg(XED_REG_ESP);
	unsigned int i=0;

	for(i=0;i<8;i++,mem_addr=mem_addr+4){
		d_set_reg_taint(regs[i], d_get_mem_taint(mem_addr));
		d_set_mem_taint(mem_addr, 0);
	}
}







static void Instrument_LEAVE(const xed_inst_t* xi)
{
	uint32_t esp = PEMU_get_reg(XED_REG_ESP);
	uint32_t ebp = PEMU_get_reg(XED_REG_EBP);

	d_set_mem_taint_bysize(esp, 0, ebp - esp + 4); //clear stack memory tag
}
static void setup_data_taint()
{
	int i;
	for (i = 0; i < XED_ICLASS_LAST; i++) {
		data_func[i] = &NONE;
	}
	data_func[XED_ICLASS_PUSH] = Instrument_PUSH;
	data_func[XED_ICLASS_POP] = Instrument_POP;
	data_func[XED_ICLASS_MOV] = Instrument_MOV;
	data_func[XED_ICLASS_ADD] = Instrument_ADD;
	data_func[XED_ICLASS_SUB] = Instrument_ADD;
	data_func[XED_ICLASS_OR] = Instrument_ADD;
	data_func[XED_ICLASS_XOR] = Instrument_XOR;
	data_func[XED_ICLASS_JMP] = Instrument_JMP;
	data_func[XED_ICLASS_LEA] = Instrument_LEA;
	data_func[XED_ICLASS_CALL_NEAR] = Instrument_CALL;
	data_func[XED_ICLASS_LEAVE] = Instrument_LEAVE;

	data_func[XED_ICLASS_XCHG] = Instrument_XCHG;
	data_func[XED_ICLASS_PUSHAD] = Instrument_PUSHAD;
	data_func[XED_ICLASS_POPAD] = Instrument_POPAD;

}
/****************end hook functions for data rewrite*****************/




extern uint32_t mem_taint;

/*****************interface functions********************/
void handle_data_rewrite(const xed_inst_t* xi) {
	unsigned int value = 0, mem_addr = 0, begin = 0, end = 0;
	xed_reg_enum_t reg_id_0;

	if(data_func[0] == 0){
		setup_data_taint();
	}


	xed_iclass_enum_t opcode = xed_decoded_inst_get_iclass(&xedd_g);
	const xed_operand_t *op1 = xed_inst_operand(xi, 1);
	xed_operand_enum_t op_name1 = xed_operand_name(op1);
	const xed_operand_t *op0 = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name0 = xed_operand_name(op0);


	//dependence data store data addresses
	unsigned int taint = 0;
	int mem_idx;
	if(opcode != XED_ICLASS_LEA){
	if(operand_is_mem4(op_name0, &mem_addr, 0)){
		mem_idx = op_name0 == XED_OPERAND_MEM1 ? 1 : 0;
		xed_reg_enum_t base_regid =
			xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
		if((base_regid != XED_REG_INVALID)){
			if(taint = d_get_reg_taint(base_regid)){
				update_mem_val_type(taint, 1, API_NONE, 0);
				value = get_mem_val(taint)->val;
				insert_dependence_data(mem_addr,xed_decoded_inst_operand_length(&xedd_g, 0));
				/*
				if(value < mem_addr)//value is root
					insert_dependence_data(value, 
							mem_addr + xed_decoded_inst_operand_length(&xedd_g, 0) - value);
				else{ 
					insert_dependence_data(mem_addr,
							value > mem_addr + xed_decoded_inst_operand_length(&xedd_g, 0) ?
							value : mem_addr + xed_decoded_inst_operand_length(&xedd_g, 0) - mem_addr);
				}*/
			}
		}
		//Hush.b
		else{//For the scenario of no base_reg(just displacement + scale * index)
			fprintf(stderr, "----****g_pc: %x: %x--size(%d)\n", g_pc, mem_addr, xed_decoded_inst_operand_length(&xedd_g, 0));
			insert_dependence_data(mem_addr,  xed_decoded_inst_operand_length(&xedd_g, 0) );
		}
		//Hush.e
	}else if(operand_is_mem4(op_name1, &mem_addr, 1)){
		mem_idx = op_name1 == XED_OPERAND_MEM1 ? 1 : 0;
		xed_reg_enum_t base_regid =
			xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
		xed_reg_enum_t index_regid =
			xed_decoded_inst_get_index_reg(&xedd_g, mem_idx);
		if((base_regid != XED_REG_INVALID)){
			int a = 0,b = 0;
			a = PEMU_get_reg(base_regid);
			b = PEMU_get_reg(index_regid);	
			if(index_regid!=XED_REG_INVALID && b>a){
				if((taint = d_get_reg_taint(index_regid))&&mem_taint==0)
				{
					update_mem_val_type(taint, 1, API_NONE, 0);
					value = get_mem_val(taint)->val;
					insert_dependence_data(mem_addr,xed_decoded_inst_operand_length(&xedd_g, 0));
				}
			}else if((taint = d_get_reg_taint(base_regid))&&mem_taint==0){
					update_mem_val_type(taint, 1, API_NONE, 0);
					value = get_mem_val(taint)->val;
					insert_dependence_data(mem_addr,xed_decoded_inst_operand_length(&xedd_g, 0));
			}

		}
	}
	}

	//taint source:
	
	if(opcode == XED_ICLASS_PUSH ){
		if(operand_is_mem4(op_name0, &mem_addr, 0)){
			if(is_dependence_addr(mem_addr) && !is_d_written(mem_addr)){
				unsigned int esp = PEMU_get_reg(XED_REG_ESP) - 4;
#ifdef DEBUG
				fprintf(stdout, "taint source:\t%x\n", mem_addr);
#endif
				d_set_mem_taint_bysize(esp, mem_addr, 4);
				PEMU_read_mem(mem_addr, 4, &value);
				insert_mem_val(mem_addr, value);				
			}
		}
	}
	else if(opcode == XED_ICLASS_JMP || opcode == XED_ICLASS_CALL_NEAR) {
		
		if(operand_is_mem4(op_name0, &mem_addr, 0)){
			//Hush.b
			fprintf(stderr, "----++++pc %x: %x: %d, %d\n",g_pc, mem_addr, is_dependence_addr(mem_addr) , !is_d_written(mem_addr));
			//Hush.e
			if(is_dependence_addr(mem_addr) && !is_d_written(mem_addr)){
#ifdef DEBUG
				fprintf(stdout, "taint source:\t%x\n", mem_addr);
#endif
				d_set_mem_taint_bysize(mem_addr, mem_addr, 4);
				PEMU_read_mem(mem_addr, 4, &value);
				insert_mem_val(mem_addr, value);				
			}
		}

	
	}
	else{
		if(opcode != XED_ICLASS_LEA && operand_is_mem4(op_name1, &mem_addr, 1)){
			if(is_dependence_addr(mem_addr) && !is_d_written(mem_addr)){
				if(operand_is_reg(op_name0, &reg_id_0)){
#ifdef DEBUG
					fprintf(stdout, "taint source:\t%x\n", mem_addr);
#endif
					d_set_reg_taint(reg_id_0, mem_addr);
					PEMU_read_mem(mem_addr, 4, &value);
					insert_mem_val(mem_addr, value);
				}else{
					fprintf(stderr, "error in handle_data_rewrite\n");
					exit(0);
				}
				return;
			}
		}
	}

	//propagation
	data_func[opcode](xi);
}
