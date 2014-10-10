#include "txt_rewrite.h"
extern "C"{
#include "qemu-pemu.h"
}
#include <stdlib.h>
#include <stdio.h>
#include "rev_inline/config.h"

#undef DEBUG

extern uint32_t mem_taint;
static map<unsigned int, unsigned char> g_map_d_data;//store all global data
static map<unsigned int, unsigned int> g_map_pc_imm;//store all imm value
static map<unsigned int, short> g_map_pc_addr; //store value flags (1 for imm_data, 2 for imm_inst, 3 for displacement, 4 for 1 and 3, 5 for 2 and 3) for pc
static map<unsigned int, char> g_map_d_written; //store all accessed dependence
//Hush.b
//Because of lazy load, some mem is unreadable, mark it, then read it later.
//<uint memory_address, uint size_to_write>
static map<unsigned int, unsigned int> mem_to_be_read;
//Hush.e
extern "C"{

//Hush.b
void insert_mem_to_be_read(unsigned int memAddr, unsigned int size){
	mem_to_be_read[memAddr]=size;
}

void update_mem_to_be_read(){
	for(map<unsigned int, unsigned int>::iterator it=mem_to_be_read.begin();it!=mem_to_be_read.end();it++){
		for(int j=0;j<it->second;j++){
			if(g_map_d_data.count(it->first+j)==0){
				char fix;
				if(PEMU_read_mem(it->first+j,1,&fix)==0){
					g_map_d_data[it->first+j]=fix;
				}else{
					break;
				}	
			}
		}
	}
    mem_to_be_read.clear();
}
//Hush.e

void insert_dependence_data(unsigned int addr, int size)
{
	if(addr < PEMU_img_start || addr > PEMU_img_end)
		return;


	for(uint32_t i = 0; i < size; i++){
		if(g_map_d_data.count(addr+i) == 0){

			char byte;
			if(PEMU_read_mem(addr+i, 1, &byte)==0){
				g_map_d_data[addr+i] = byte;
#ifdef DEBUG
//			fprintf(stderr, "----global %x(size:%d): %x\n", addr+i,size, byte);
#endif
			}
			//Hush.b
			//Hush.TODO
			else {//Reading mem fail,  
				insert_mem_to_be_read(addr,size);
				//Temporarily set value as ZERO
				g_map_d_data[addr+i]=0;
				break;
			}
			//Hush.e
		}
	}
}

int is_dependence_addr(unsigned int addr)
{	
	return g_map_d_data.count(addr);
}

unsigned int get_dependence_base()
{
	return g_map_d_data.begin()->first;
}


unsigned int dump_dependence_data(FILE *output)
{
	unsigned int next_addr = 0;
    unsigned start;
	fprintf(output, "char global_data [] = {");
#ifdef WINDOWS_FORMAT
	uint32_t col=0;
#endif
	map<unsigned int, unsigned char>::iterator it;
	next_addr = g_map_d_data.begin()->first;
    start =  next_addr;
    fprintf(stderr, "##Global start %x\n", start);
	for( it = g_map_d_data.begin(); it != g_map_d_data.end(); it++){
		while(next_addr < it->first){
			fprintf(output, "0x%x, ", 0);
			next_addr++;
#ifdef WINDOWS_FORMAT
			col++;
			if(col%10==0)
				fprintf(output, "\\\n");
#endif
		}
		fprintf(output, "0x%x, ", it->second);
#ifdef DEBUG
        fprintf(stderr, "global data %x %x %x\n", next_addr, next_addr- start, it->second);
#endif
		next_addr++;

#ifdef WINDOWS_FORMAT
		col++;
		if(col%10==0)
			fprintf(output, "\\\n");
#endif		
	}
	fprintf(output, "};\n\n");

#ifdef DEBUG
	printf("global data start:%x end:%x\n", (--it)->first, g_map_d_data.begin()->first);
#endif

	return   (it->first-g_map_d_data.begin()->first);
}

void print_dependence_data()
{
	for(map<unsigned int, unsigned char >::iterator it = g_map_d_data.begin();
			it != g_map_d_data.end(); it++){
		fprintf(stdout, "global_data:\t%x %x\n", it->first,it->second);
	}
	for(map<unsigned int, unsigned int>::iterator it = g_map_pc_imm.begin();
			it != g_map_pc_imm.end(); it++){
		fprintf(stdout, "imm pc:\t%x\t%x\n", it->first, it->second);
	}
}

void insert_pc_imm(unsigned int pc, unsigned int imm)
{
	g_map_pc_imm[pc] = imm;
}

unsigned int get_pc_imm(unsigned int pc)
{
	if(g_map_pc_imm.count(pc) > 0)
		return g_map_pc_imm[pc];
	return 0;
}


//pc: inst pc
//val:	1 for imm_data
//		2 for imm_inst
//		3 for displacement
//		4 for 1 and 3
//		5 for 2 and 3 
void insert_pc_addr(unsigned int pc, unsigned int type)
{
	if(g_map_pc_addr.count(pc)){
		int tmp = g_map_pc_addr[pc];
		if(tmp == 4 || tmp == 5)
			return;
		if(tmp != type)
			g_map_pc_addr[pc] = tmp + type;
		return;
	}
#ifdef DEBUG
	fprintf(stdout, "0x%x 0x%x\n", pc, g_pc);
#endif
	g_map_pc_addr[pc] = type;
}

int get_pc_addr(unsigned int pc)
{
	if(g_map_pc_addr.count(pc)){
		return g_map_pc_addr[pc];
	}
	return 0;
}


void insert_d_written(unsigned int addr)
{
	g_map_d_written[addr] = 1;
}

int is_d_written(unsigned int addr)
{
	return g_map_d_written.count(addr) > 0;
}

}


/****************start hook functions for txt rewrite*****************/
static TXTFunc txt_func[XED_ICLASS_LAST];
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
		taint = t_get_mem_taint(mem_addr);
	}else if(operand_is_reg(op_name, &reg_id)){
		taint = t_get_reg_taint(reg_id);
	}
	unsigned int esp = PEMU_get_reg(XED_REG_ESP) - 4;
	t_set_mem_taint_bysize(esp, taint, 4);
}

static void Instrument_POP(const xed_inst_t* xi)
{
	uint32_t mem_addr;
	xed_reg_enum_t reg_id;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	
	uint32_t esp = PEMU_get_reg(XED_REG_ESP);
	uint32_t taint = t_get_mem_taint(esp);

	if(operand_is_mem4(op_name, &mem_addr, 0)){
		t_set_mem_taint_bysize(mem_addr, taint, 4);
	}else if(operand_is_reg(op_name, &reg_id)){
		t_set_reg_taint(reg_id, taint);
	}
	t_set_mem_taint_bysize(esp, 0, 4);
}

static void Instrument_MOV(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id_0, reg_id_1;
	unsigned int mem_addr;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);
	const xed_operand_t *op_1 = xed_inst_operand(xi, 1);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);
	xed_operand_enum_t op_name_1 = xed_operand_name(op_1);
	
	if(operand_is_mem4(op_name_0, &mem_addr, 0)){
		if (operand_is_reg(op_name_1, &reg_id_1)){
			t_set_mem_taint_bysize(mem_addr, t_get_reg_taint(reg_id_1),
					xed_decoded_inst_operand_length(&xedd_g, 0));
		}
	}else if(operand_is_reg(op_name_0, &reg_id_0)){
		if(operand_is_mem4(op_name_1, &mem_addr, 1)){
			t_set_reg_taint(reg_id_0, t_get_mem_taint(mem_addr));
		}else if(operand_is_reg(op_name_1, &reg_id_1)){
			t_set_reg_taint(reg_id_0, t_get_reg_taint(reg_id_1));
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
		taint_d = t_get_mem_taint(mem_addr);
		//yang
		int a, b;
		PEMU_read_mem(mem_addr, 4, &a);

		if (operand_is_reg(op_name_1, &reg_id_1)){
			taint_s = t_get_reg_taint(reg_id_1);			
			b = PEMU_get_reg(reg_id_1);
		}
		if(b<a)
//		if((int)get_pc_imm(taint_s) < (int)get_pc_imm(taint_d))
			taint_s = taint_d;
		t_set_mem_taint_bysize(mem_addr, taint_s, 
				xed_decoded_inst_operand_length(&xedd_g, 0));
	}else if(operand_is_reg(op_name_0, &reg_id_0)){
		if(operand_is_imm(op_name_1, &imm))
			return;
	
		//yang
		int a, b;
		a = PEMU_get_reg(reg_id_0);

		taint_d = t_get_reg_taint(reg_id_0);
		if(operand_is_mem4(op_name_1, &mem_addr, 1)){
			taint_s = t_get_mem_taint(mem_addr);
			PEMU_read_mem(mem_addr, 4, &b);
		}else if(operand_is_reg(op_name_1, &reg_id_1)){
			taint_s = t_get_reg_taint(reg_id_1);
			b = PEMU_get_reg(reg_id_1);
		}

		//	if((int)get_pc_imm(taint_s) < (int)get_pc_imm(taint_d))
		if(b<a)
			taint_s = taint_d;
		t_set_reg_taint(reg_id_0, taint_s);
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
				t_set_reg_taint(reg_id_0, 0);
			return;
	}
	Instrument_ADD(xi);

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
			xed_reg_enum_t index_regid =
			    xed_decoded_inst_get_index_reg(&xedd_g, mem_idx);
            //if(index_regid == XED_REG_INVALID && mem_taint == 0)
            //   t_set_reg_taint(reg_id, t_get_reg_taint(base_regid));
			if(index_regid == XED_REG_INVALID) {
				if(find_min_dist(mem_addr, g_base, g_index, g_disp) != 3) {
					t_set_reg_taint(reg_id, t_get_reg_taint(base_regid));
				}
			}
            else {
                unsigned int a=0, b=0;
                if(base_regid != XED_REG_INVALID)
                    a = PEMU_get_reg(base_regid);
                b = PEMU_get_reg(index_regid);
                if( a < b)
                    t_set_reg_taint(reg_id, t_get_reg_taint(index_regid));
                else
                    t_set_reg_taint(reg_id, t_get_reg_taint(base_regid));
            }
		}else{
			fprintf(stderr, "error in Instrument_LEA\n");
			exit(0);
		}
	}else{
		fprintf(stderr, "error in Instrument_LEA\n");
		exit(0);
	}	
}
/*
static void Instrument_LEA(const xed_inst_t* xi)
{
	xed_reg_enum_t reg_id_0;

	const xed_operand_t *op_0 = xed_inst_operand(xi, 0);

	xed_operand_enum_t op_name_0 = xed_operand_name(op_0);

	if (operand_is_reg(op_name_0, &reg_id_0)){
		t_set_reg_taint(reg_id_0, 0);
	}else{
		fprintf(stderr, "error in txt_rewrite_LEA\n");
		exit(0);
	}

}
*/

static void Instrument_JMP(const xed_inst_t* xi)
{
	//TODO
}

static void Instrument_CALL(const xed_inst_t* xi)
{
#ifdef DEBUG
	fprintf(stdout, "txt:instrument_call\n");
#endif
	xed_reg_enum_t reg_id;
	unsigned int dest = 0, taint = 0;
	uint32_t buf;
	char *fname;
	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	API_TYPE type;
	INST *inst;

	if(operand_is_mem4(op_name, &dest, 0)){
		int mem_idx = op_name == XED_OPERAND_MEM1 ? 1 : 0;
		xed_reg_enum_t base_regid =
			xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
		
		PEMU_read_mem(dest, 4, &buf);
		dest = buf;
		
		if(taint = t_get_reg_taint(base_regid)){
#ifdef DEBUG
			fprintf(stdout, "txt: indirect call1\n");
#endif
			if(type = is_api_call(dest, &fname)){
				goto API_CALL;				
			}else{
				insert_pc_addr(taint, 2);
			}
		}else if(taint = t_get_mem_taint(dest)){
#ifdef DEBUG
fprintf(stdout, "txt: indirect call2\n");
#endif
	if(type = is_api_call(dest, &fname)){
				goto API_CALL;				
			}else{
				insert_pc_addr(taint, 2);
			}
		}
		return;
	}else if(operand_is_reg(op_name, &reg_id)){
#ifdef DEBUG
fprintf(stdout, "txt: indirect call3\n");
#endif
		if(taint = t_get_reg_taint(reg_id)){
			insert_pc_addr(taint, 2);
			dest = PEMU_get_reg(reg_id);
			
			if(type = is_api_call(dest, &fname)){
				goto API_CALL;
			}else{
				insert_pc_addr(taint, 2);
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
	inst = get_inst(taint);
//	api_copy(&inst->api_call, get_api_call(dest));
REST:
#ifdef DEBUG
fprintf(stdout, "taint:\t%x\t%x\n", taint, dest);
#endif
	t_set_reg_taint(XED_REG_EAX, 0);
	handle_api_issues(get_api_call(dest), 0);
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
			taint = t_get_reg_taint(reg1);
			t_set_reg_taint(reg1, t_get_mem_taint(mem_addr));
			t_set_mem_taint(mem_addr, taint);
		}
	}else if (operand_is_reg(op_name_0, &reg0))
	{
		if(operand_is_reg(op_name_1, &reg1))
		{	
			taint =  t_get_reg_taint(reg1);
			t_set_reg_taint(reg1, t_get_reg_taint(reg0));
			t_set_reg_taint(reg0, taint);
		}else if(operand_is_mem4(op_name_1, &mem_addr,1))
		{

			taint = t_get_reg_taint(reg0);
			t_set_reg_taint(reg0, t_get_mem_taint(mem_addr));
			t_set_mem_taint(mem_addr, taint);


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
		t_set_mem_taint(mem_addr, t_get_reg_taint(regs[i]));
	}
}

//yang.new
static void Instrument_POPAD(const xed_inst_t *xi)
{
	xed_reg_enum_t regs[]={XED_REG_EDI, XED_REG_ESI, XED_REG_EBP,XED_REG_ESP,XED_REG_EBX,XED_REG_EDX, XED_REG_ECX, XED_REG_EAX};
	unsigned int  mem_addr;
	mem_addr = PEMU_get_reg(XED_REG_ESP);
	unsigned int i=0;

	for(i=0;i<8;i++,mem_addr=mem_addr+4){
		t_set_reg_taint(regs[i], t_get_mem_taint(mem_addr));
		t_set_mem_taint(mem_addr, 0);
	}
}




static void Instrument_LEAVE(const xed_inst_t* xi)
{
	uint32_t esp = PEMU_get_reg(XED_REG_ESP);
	uint32_t ebp = PEMU_get_reg(XED_REG_EBP);

	t_set_mem_taint_bysize(esp, 0, ebp - esp + 4); //clear stack memory tag
}
static void setup_txt_taint()
{
	int i;
	for (i = 0; i < XED_ICLASS_LAST; i++) {
		txt_func[i] = &NONE;
	}
	txt_func[XED_ICLASS_PUSH] = Instrument_PUSH;
	txt_func[XED_ICLASS_POP] = Instrument_POP;
	txt_func[XED_ICLASS_MOV] = Instrument_MOV;
	txt_func[XED_ICLASS_ADD] = Instrument_ADD;
	txt_func[XED_ICLASS_SUB] = Instrument_ADD;
	txt_func[XED_ICLASS_OR] = Instrument_ADD;
	txt_func[XED_ICLASS_XOR] = Instrument_XOR;
	txt_func[XED_ICLASS_LEA] = Instrument_LEA;
	txt_func[XED_ICLASS_JMP] = Instrument_JMP;
	txt_func[XED_ICLASS_CALL_NEAR] = Instrument_CALL;
	txt_func[XED_ICLASS_LEAVE] = Instrument_LEAVE;

	txt_func[XED_ICLASS_XCHG] = Instrument_XCHG;
	txt_func[XED_ICLASS_PUSHAD] = Instrument_PUSHAD;
	txt_func[XED_ICLASS_POPAD] = Instrument_POPAD;

}
/****************end hook functions for txt rewrite*****************/






/*****************interface functions********************/
void handle_txt_rewrite(const xed_inst_t* xi) {
	uint32_t value = 0, taint = 0;
	int i = 0;
	const xed_operand_t *op;
	xed_operand_enum_t op_name;
	unsigned int mem_addr;

	if(txt_func[0] == 0){
		setup_txt_taint();
	}



    int noperands = xed_inst_noperands(xi);
	xed_iclass_enum_t opcode = xed_decoded_inst_get_iclass(&xedd_g);

	
	noperands = noperands > 2 ? 2 : noperands;
	for( i = 0; i < noperands ; i++){
		/* Immediate */
		op = xed_inst_operand(xi, i);
		op_name = xed_operand_name(op);
	
		if(opcode == XED_ICLASS_LEA)//hardcode
			continue;

		if(operand_is_imm(op_name, &value))
			insert_pc_imm(g_pc, value);

		if(operand_is_mem4(op_name, &mem_addr, i)){
			unsigned int taint; 
			unsigned int displacement = 0;	
			int mem_idx = op_name == XED_OPERAND_MEM1 ? 1 : 0;

			if(xed_operand_written(op))
				insert_d_written(mem_addr);

			xed_reg_enum_t base_regid =
				xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
			xed_reg_enum_t index_regid =
			    xed_decoded_inst_get_index_reg(&xedd_g, mem_idx);
			displacement =
				(unsigned int)
			    xed_decoded_inst_get_memory_displacement(&xedd_g,
								     mem_idx);

#if 0				
			if((base_regid != XED_REG_INVALID)) {//indirect mem access
				if((taint = t_get_reg_taint(base_regid)) && (mem_taint == 0)) {//base reg
					unsigned int imm = get_pc_imm(taint);
					//yang
					insert_pc_addr(taint, 1);
					insert_dependence_data(mem_addr, xed_decoded_inst_operand_length(&xedd_g, i));
					
				} else if(mem_taint != 0) { //displacement
					insert_pc_addr(g_pc, 3);
					insert_dependence_data(mem_addr, xed_decoded_inst_operand_length(&xedd_g, i));
				}
			} else if(index_regid != XED_REG_INVALID) {
                if((taint = t_get_reg_taint(index_regid)) && (mem_taint ==0)) {
					insert_pc_addr(taint, 1);
					insert_dependence_data(mem_addr, xed_decoded_inst_operand_length(&xedd_g, i));
                } else if(mem_taint != 0) {
					insert_pc_addr(g_pc, 3);
					insert_dependence_data(mem_addr, xed_decoded_inst_operand_length(&xedd_g, i));

                }
            } else if(displacement > 0) {//displacement
				insert_dependence_data(displacement, 
						mem_addr + xed_decoded_inst_operand_length(&xedd_g, i) - displacement);
				insert_pc_addr(g_pc, 3);
			}
#endif
			switch(find_min_dist(mem_addr, g_base, g_index, g_disp)) {
				case 1:
					if(taint = t_get_reg_taint(base_regid)) {
						insert_pc_addr(taint, 1);
						insert_dependence_data(mem_addr, xed_decoded_inst_operand_length(&xedd_g, i));
					}
					break;
				case 2:
					if(taint = t_get_reg_taint(index_regid)) {
						insert_pc_addr(taint, 1);
						insert_dependence_data(mem_addr, xed_decoded_inst_operand_length(&xedd_g, i));
					}
					break;
				case 3:
					insert_dependence_data(displacement, 
						mem_addr + xed_decoded_inst_operand_length(&xedd_g, i) - displacement);
					insert_pc_addr(g_pc, 3);
					break;
				default:
					break;
			}
		}
	}
	
	unsigned int esp;
	xed_reg_enum_t dest_r;
	op_name = xed_operand_name(xed_inst_operand(xi, 0));

	if(value != 0){//taint source
		switch(opcode){
			case XED_ICLASS_PUSH:
				esp = PEMU_get_reg(XED_REG_ESP) - 4;
				t_set_mem_taint_bysize(esp, g_pc, 4);
			break;
			case XED_ICLASS_MOV:	
				if(operand_is_mem4(op_name, &mem_addr, 0)){
					t_set_mem_taint_bysize(mem_addr, g_pc,
							xed_decoded_inst_operand_length(&xedd_g, 0));
				}else if(operand_is_reg(op_name, &dest_r)){
					t_set_reg_taint(dest_r, g_pc);
				}
			break;
			defalut:
			break;
		}
		return;
	}

	//propagation
	txt_func[opcode](xi);
}
