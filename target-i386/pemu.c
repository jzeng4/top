#include "pemu.h"
#include "xed2.h"
#include "pemu_helper.h"
#include "bb_heap.h"
#include "int_heap.h"
#include <stdio.h>

//PEMU_instrument *PEMU_instance;
//PEMU_interface *PEMU_interface_instance;
char PEMU_binary_name[100];
char PEMU_so_name[100];
uint32_t PEMU_start = 0;
uint32_t PEMU_cr3 = 0;
uint32_t PEMU_task_addr = 0;
uint32_t PEMU_libc_start = 0;
uint32_t PEMU_libc_end = 0;
uint32_t PEMU_g_pc = 0;
Module_info *PEMU_module;

int PEMU_find_mmap(uint32_t nextaddr)
{
   	uint32_t  mmap;
	char comm[512];

	mmap = get_first_mmap(nextaddr);
	while (0 != mmap) {
  		get_mod_name(mmap, comm, 512);
		int base = get_vmstart(mmap); 
		int size = get_vmend(mmap) - get_vmstart(mmap);
		mmap = get_next_mmap(mmap);
	//	if(get_vmflags(mmap) & 0x00000004)
		if(!strcmp("libc-2.13.so", comm)){
			PEMU_libc_start = base;
			PEMU_libc_end = base + size;
			break;
		}else if(!strcmp("ld-2.13.so", comm)){
		}
	}
	return 1;
}

int PEMU_find_process(void *opaque)
{
	int pid;
	//uint32_t pgd, mmap;
	uint32_t nextaddr = 0;
	char comm[512];

	nextaddr = taskaddr;
	do{
	  	get_name(nextaddr, 16, comm);
		if(!strcmp(comm, PEMU_binary_name))
			break;
		nextaddr = next_task_struct(nextaddr);
	}while(nextaddr != taskaddr);

	pid = get_pid(nextaddr);
	PEMU_cr3 = get_pgd(nextaddr) - 0xc0000000;
	PEMU_task_addr = nextaddr;
	fprintf(stderr, "%s\t0x%x\t0x%x\n", comm, pid, PEMU_cr3);
	return 1;
}



int PEMU_handle_bb(uint32_t pc)
{
	uint32_t dest;
	uint32_t next_pc;
	
	xed_operand_enum_t op_name = PEMU_op_name;
	xed_iclass_enum_t opcode = PEMU_opcode;
	
		switch(opcode)
	{
		case XED_ICLASS_JO:
		case XED_ICLASS_JNO:
		case XED_ICLASS_JB:
		case XED_ICLASS_JNB:
		case XED_ICLASS_JZ:
		case XED_ICLASS_JNZ:
		case XED_ICLASS_JBE:
		case XED_ICLASS_JNBE:
		case XED_ICLASS_JS:
		case XED_ICLASS_JNS:
		case XED_ICLASS_JP:
		case XED_ICLASS_JNP:
		case XED_ICLASS_JL:
		case XED_ICLASS_JNL:
		case XED_ICLASS_JLE:
		case XED_ICLASS_JNLE:
		case XED_ICLASS_JRCXZ:
			if(operand_is_relbr(op_name, &dest))
			{
				next_pc = pc +  xed_decoded_inst_get_length(&PEMU_xedd_g);
				dest += next_pc;
				if(!bb_find2(dest))
				{
					add_bb_into_rbt(dest, create_bb(dest));
					add_bb_into_rbt(next_pc, create_bb(next_pc));
				}
			}else{
				fprintf(stderr, "error in PEMU_handle_bb, JCC\n");
			}
			break;
		case XED_ICLASS_JMP:
			if(operand_is_relbr(op_name, &dest))
			{
				dest += (pc +  xed_decoded_inst_get_length(&PEMU_xedd_g));
				if(!bb_find2(dest))
					add_bb_into_rbt(dest, create_bb(dest));
			}else{
				fprintf(stderr, "error in PEMU_handle_bb, JMP\n");
			}
			break;
		case XED_ICLASS_CALL_NEAR:
			dest = get_call_dest(pc);
			next_pc = pc +  xed_decoded_inst_get_length(&PEMU_xedd_g);
			if(!bb_find2(dest))
				add_bb_into_rbt(dest, create_bb(dest));
			if(!bb_find2(next_pc))
				add_bb_into_rbt(next_pc, create_bb(next_pc));
			break;
		case XED_ICLASS_RET_NEAR:
			break;
		default:
			return 0;

	}
		return 1;
}

int PEMU_find_module(void *opaque)
{
//	if(pc == 0xc1088907)//hook sys_init_module
	{
		PEMU_module = (Module_info*) malloc(sizeof(Module_info));
		memset(PEMU_module, 0, sizeof(Module_info));

		uint32_t mod = PEMU_get_reg(XED_REG_EAX);
		PEMU_read_mem(mod + 0xc, sizeof(PEMU_module->name), PEMU_module->name);
		PEMU_read_mem(mod + 0xd4, sizeof(PEMU_module->init_func), &PEMU_module->init_func);
		PEMU_read_mem(mod + 0xd8, sizeof(PEMU_module->module_init), &PEMU_module->module_init);
		PEMU_read_mem(mod + 0xdc, sizeof(PEMU_module->module_core), &PEMU_module->module_core);
		PEMU_read_mem(mod + 0xe0, sizeof(PEMU_module->init_size), &PEMU_module->init_size);
		PEMU_read_mem(mod + 0xe4, sizeof(PEMU_module->core_size), &PEMU_module->core_size);
		PEMU_read_mem(mod + 0xe8, sizeof(PEMU_module->init_text_size), &PEMU_module->init_text_size);
		PEMU_read_mem(mod + 0xec, sizeof(PEMU_module->core_text_size), &PEMU_module->core_text_size);
		
		fprintf(stderr, "new module insert:\t%s\tinit_func:%x\tmodule_init:%x\tmodule_core:%x\tinit_size:%x\tcore_size:%x \
				init_text_size:%x\tcore_text_size:%x\n", PEMU_module->name, PEMU_module->init_func, PEMU_module->module_init, 
				PEMU_module->module_core, PEMU_module->init_size, PEMU_module->core_size, PEMU_module->init_text_size, 
				PEMU_module->core_text_size);
	}
	return 1;
}


int PEMU_load_idt(void *opaque)
{
	char idt[256*8];
	uint32_t idtr = PEMU_get_idtr_base(opaque);
	fprintf(stderr, "PEMU_load_idt\n");
	PEMU_read_mem_monitor(opaque, idtr, 256*8, idt);
	Interrupt_Gate *pidt = (Interrupt_Gate *)idt;
	int i = 0;
	for(;i < 256;i++)
	{
		uint32_t addr = 0;
		addr = pidt->offset2;
		addr = addr << 16;
		addr += pidt->offset1;
		add_int_into_rbt(addr, 0);
		pidt++;
	}
	return 1;
}



int PEMU_exit(void)
{
	PEMU_start = 0;
	return 1;
}
