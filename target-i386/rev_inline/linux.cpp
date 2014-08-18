#include "linux.h"
#include "rev_inline/config.h"
/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

//#include "config.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "cpptoc.h"

extern "C"
{
#include "qemu-pemu.h"
//#include <xed-interface.h>
}
#include "../read_linux.h"

#include <map>
using namespace std;

uint32_t hookingpoint = 0;
uint32_t hookingpoint2 = 0;
uint32_t taskaddr = 0;
int tasksize = 0;
int listoffset = 0;
int pidoffset = 0;
int mmoffset = 0;
int pgdoffset = 0;
int commoffset = 0;
int commsize = 0;
int vmstartoffset = 0;
int vmendoffset = 0;
int vmnextoffset = 0;
int vmfileoffset = 0;
int vmflagsoffset = 0;	
int dentryoffset = 0;
int dnameoffset = 0;
int dinameoffset = 0;


char PEMU_binary_name[100];
char PEMU_so_name[100];
uint32_t PEMU_start = 0;
uint32_t PEMU_cr3 = 0;
uint32_t PEMU_task_addr = 0;
uint32_t PEMU_libc_start = 0;
uint32_t PEMU_libc_end = 0;
uint32_t PEMU_g_pc = 0;
uint32_t PEMU_main_start = 0;
uint32_t PEMU_img_start = 0;
uint32_t PEMU_img_end = 0;
uint32_t PEMU_txt_start = 0;
uint32_t PEMU_txt_end = 0;

static map<unsigned int, Libc_item*> libc_map;

static map<uint32_t, API_CALL*> g_map_plt;

//Hush.b
// This map is used to store dynamic symbolic table info,
// such as stdin, stdout, stderr, optind
map<unsigned int, Dst_item*> dst_map;
//Hush.e

//Hush.b
//This map is used to store all elf sections
//map<unsigned int, >
//Hush.e

/* need to check next_task_struct with the corresponding 
   kernel source code for compatibality 
   in 2.4.20 the next pointer points directly to the next
   tast_struct, while in 2.6.15, it is done through list_head */
static struct koffset kernel_table[] = {
	{
	"2.6.38-8-generic",               /* entry name */
   	0xC1060460, 0x00000000,      /* hooking address: flush_signal_handlers */
	0xC1731F60, /* task struct root */
	3228, /* size of task_struct */
	432, /* offset of task_struct list */
	508, /* offset of pid */
	460, /* offset of mm */
	40, /* offset of pgd in mm */
	732, /* offset of comm */
	16, /* size of comm */
	4, /* offset of vm_start in vma */
	8, /* offset of vm_end in vma */
	12, /* offset of vm_next in vma */
	76, /* offset of vm_file in vma */
	24, /*offset of vm_flags in vma*/
	12, /* offset of dentry in file */
	20, /* offset of d_name in dentry */
	36 /* offset of d_iname in dentry */
	},
  {"", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};



extern "C"{
int init_kernel_offsets(void)
{
  int retval = -1;
  int i = 0;
 // char buf[128];

    hookingpoint = kernel_table[i].hookingpoint;
    hookingpoint2 = kernel_table[i].hookingpoint2;
    taskaddr = kernel_table[i].taskaddr;
    tasksize = kernel_table[i].tasksize;
    listoffset = kernel_table[i].listoffset;
    pidoffset = kernel_table[i].pidoffset;
    mmoffset = kernel_table[i].mmoffset;
    pgdoffset = kernel_table[i].pgdoffset;
    commoffset = kernel_table[i].commoffset;
    commsize = kernel_table[i].commsize;
    vmstartoffset = kernel_table[i].vmstartoffset;
    vmendoffset = kernel_table[i].vmendoffset;
    vmnextoffset = kernel_table[i].vmnextoffset;
    vmfileoffset = kernel_table[i].vmfileoffset;
	vmflagsoffset = kernel_table[i].vmflagsoffset;
    dentryoffset = kernel_table[i].dentryoffset;
    dnameoffset = kernel_table[i].dnameoffset;
    dinameoffset = kernel_table[i].dinameoffset;

  	retval = 0;
	//fprintf(stderr, "read_linux\t%x\n", hookingpoint);
	return retval;
}


///////////////////////////
static void get_name(uint32_t addr, int size, char *buf)
{
   PEMU_read_mem(addr + commoffset, 16, buf);
}

static uint32_t next_task_struct(uint32_t addr)
{
	uint32_t retval;
	uint32_t next;

    PEMU_read_mem(addr + listoffset + sizeof(uint32_t), 
			sizeof(uint32_t), &next);
    retval = next - listoffset;

  	return retval;
}

static uint32_t get_pid(uint32_t addr)
{
  	uint32_t pid;

  	PEMU_read_mem(addr + pidoffset, sizeof(pid), &pid);
	return pid;
}

static uint32_t get_pgd(uint32_t addr)
{
	uint32_t mmaddr, pgd;
	PEMU_read_mem(addr + mmoffset, sizeof(mmaddr), &mmaddr);
	
	if (0 == mmaddr)
		PEMU_read_mem(addr + mmoffset + sizeof(mmaddr), 
  				sizeof(mmaddr), &mmaddr);

	if (0 != mmaddr)
	   	PEMU_read_mem(mmaddr + pgdoffset, sizeof(pgd), &pgd);
	else
	   	memset(&pgd, 0, sizeof(pgd));

	return pgd;
}

static uint32_t get_first_mmap(uint32_t addr)
{
	uint32_t mmaddr, mmap;
	PEMU_read_mem(addr + mmoffset, sizeof(mmaddr), &mmaddr);

	if (0 == mmaddr)
		PEMU_read_mem(addr + mmoffset + sizeof(mmaddr), 
                   sizeof(mmaddr), &mmaddr);

  	if (0 != mmaddr)
	 	PEMU_read_mem(mmaddr, sizeof(mmap), &mmap);
	else
		memset(&mmap, 0, sizeof(mmap));
	
	return mmap;
}

static void get_mod_name(uint32_t addr, char *name, int size)
{
	uint32_t vmfile, dentry;

	if(PEMU_read_mem(addr + vmfileoffset, sizeof(vmfile), &vmfile) != 0
			|| PEMU_read_mem(vmfile + dentryoffset, sizeof(dentry), &dentry) != 0
			|| PEMU_read_mem(dentry + dinameoffset, size < 36 ? size : 36, name) != 0)
		name[0] = 0;
}

static uint32_t get_vmstart(uint32_t addr)
{
	uint32_t vmstart;
	PEMU_read_mem(addr + vmstartoffset, sizeof(vmstart), &vmstart);
  	return vmstart;
}

static uint32_t get_next_mmap(uint32_t addr)
{
  	uint32_t mmap;
	PEMU_read_mem(addr + vmnextoffset, sizeof(mmap), &mmap);
	return mmap;
}

static uint32_t get_vmend(uint32_t addr)
{
   	uint32_t vmend;
	PEMU_read_mem(addr + vmendoffset, sizeof(vmend), &vmend);
	return vmend;
}

static uint32_t get_vmflags(uint32_t addr)
{
	uint32_t vmflags;
	PEMU_read_mem(addr + vmflagsoffset, sizeof(vmflags), &vmflags);
	return vmflags;
}
/////////////////////////////

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
	//fprintf(stderr, "%s\t0x%x\t0x%x\n", comm, pid, PEMU_cr3);
	return 1;
}


int PEMU_find_mmap(uint32_t nextaddr)
{
   	uint32_t  mmap;
	char comm[512];

	if(PEMU_libc_start != 0 || PEMU_task_addr == 0)
		return 0;

	mmap = get_first_mmap(nextaddr);
	while (0 != mmap) {
  		get_mod_name(mmap, comm, 512);
		int base = get_vmstart(mmap); 
		int size = get_vmend(mmap) - get_vmstart(mmap);
		mmap = get_next_mmap(mmap);
		
		if(!strcmp(PEMU_binary_name, comm)){	
			if(PEMU_img_start != 0)
				PEMU_img_start = (uint32_t)base < (uint32_t)PEMU_img_start ? base : PEMU_img_start;
			else PEMU_img_start = base;
			
			PEMU_img_end = (uint32_t)(base + size) > (uint32_t)PEMU_img_end ? 
				base + size : PEMU_img_end;

			PEMU_txt_start = PEMU_img_start;
			PEMU_txt_end = PEMU_img_end;
#ifdef DEBUG
			fprintf(stdout, "img:%x\t%x\t%s\n", PEMU_img_start, PEMU_img_end, comm);
#endif
		}
		
		if(!strcmp("libc-2.13.so", comm)){
			//PEMU_libc_start = base;
			//PEMU_libc_end = base + size;

			if(PEMU_libc_start != 0)
				PEMU_libc_start = (uint32_t)base < (uint32_t)PEMU_libc_start ? base : PEMU_libc_start;
			else PEMU_libc_start = base;
			
			PEMU_libc_end = (uint32_t)(base + size) > (uint32_t)PEMU_libc_end ? 
				base + size : PEMU_libc_end;
#ifdef DEBUG
			fprintf(stdout, "libc_start:%x\tlibc_end:%x\t%s\n", PEMU_libc_start, PEMU_libc_end, comm);
#endif
		}else if(!strcmp("ld-2.13.so", comm)){
		}
	}
	return 1;
}

// Init libc_map
void libc_init(void)
{
	char name[100];
	int offset = 0;
	
	FILE *file = fopen("libc.so", "r");
	if(!file){
		fprintf(stderr, "can't find libc.so\n");
		//return;
		exit(0);
	}

	while(fscanf (file, "%s\t%x\n", name, &offset) != EOF){
		Libc_item *item = (Libc_item *)malloc(sizeof(Libc_item));
		memset(item, 0, sizeof(Libc_item));
		strcpy(item->name, name);
		libc_map[offset] = item;
		
		//fprintf(stdout, "%x\t%s\n", offset, name);	
		//fflush(stdout);
	}
	fclose(file);
}



Libc_item* hook_libc(unsigned int pc)
{
	char buf[5];
	Libc_item *item;
	uint32_t return_pc;
	uint32_t addr = pc - PEMU_libc_start;

//	fprintf(stdout, "libc call\t%x\t%x\n", pc, PEMU_libc_start);

	Libc_item *tmp;
	if(tmp = libc_map[addr]){
#ifdef DEBUG
		fprintf(stdout, "libc call\t%s\n", tmp->name);
#endif
		return tmp;
	}
	return 0;
}

void find_main_function(unsigned int pc)
{
	if(PEMU_main_start != 0)
		return;
	
	Libc_item* tmp = hook_libc(pc);
	if(tmp != 0){
		if(strcmp(tmp->name, "__libc_start_main") == 0){
			uint32_t esp = PEMU_get_reg(XED_REG_ESP);
			char *tt[4];
			PEMU_read_mem(esp+4, 4, tt);
			PEMU_main_start = *(uint32_t*)tt;
#ifdef DEBUG
			fprintf(stderr, "----main pc:\t%x\n", PEMU_main_start);
#endif
		}
	}
}


void load_plt_info(void)
{
	char name[300];
	char line[500];
	unsigned int addr, num;
	char fname[50];
	char tmp[200], subtmp[200];
	char type[10];
	unsigned int po;

	sprintf(name, "plt/%s.plt", PEMU_binary_name);
	FILE *f = fopen(name, "r");

	if(!f){
		fprintf(stderr, "can't open %s\n", name);
		exit(0);
	}

#ifdef DEBUG
	fprintf(stdout, "Now loading plt info\n");
#endif

	while(fgets(line, 500, f)){	
		char *token = strtok(line, "\t");
		sscanf(token, "%x", &addr);

		if(g_map_plt.count(addr) != 0)
			continue;

		token = strtok(NULL, "\t");
		strcpy(fname, token);
		//fprintf(stderr, "%s\n", token);
		token = strtok(NULL, "\t");//num
		//fprintf(stderr, "%s\n", token);
		token = strtok(NULL, "\t");
		//fprintf(stderr, "%s\n", token);
		
		API_CALL *api = (API_CALL*)malloc(sizeof(API_CALL));
		memset(api, 0, sizeof(API_CALL));

		api->fname = (char*)malloc(50);			
		strcpy(api->fname, fname);
		
		api->type = API_IMP;
		
		while(strcmp(token, "NONE\n")){
			sscanf(token, "%d:%s", &po, type);
			if(!strcmp(type, "dptr")){
				api->dptr |= 1 << (po-1);
			}else if(!strcmp(type, "tplt")){
				api->tptr != 1 << (po-1);
			}
			token = strtok(NULL, "\t");
		}

		g_map_plt[addr] = api;
#ifdef DEBUG
		fprintf(stdout, "%x\t%s\t%x\t%x\n", addr, fname, api->dptr, api->tptr);
#endif
	}
	fclose(f);

}

//Hush.b
void load_dst(void){
	char exe_name[300];
	unsigned int addr;
	char sym[300];	

	sprintf(exe_name, "dst/%s.dst", PEMU_binary_name);
	FILE *f = fopen(exe_name, "r");
	if(!f){
		fprintf(stderr, "load_dst can't open %s\n", exe_name);
		exit(0);
	}

	fprintf(stdout, "\nLoading Dynamic Symbolic Table:\n");
	fflush(stdout);

	while(fscanf (f, "%x %s\n", &addr, sym) != EOF){
		Dst_item *item = (Dst_item *)malloc(sizeof(Dst_item));
		memset(item, 0, sizeof(Dst_item));
		strcpy(item->name, sym);
		dst_map[addr] = item;
	}
	fclose(f);

#ifdef DEBUG
	for(map<unsigned int, Dst_item*>::iterator it= dst_map.begin();it!=dst_map.end();it++){
		fprintf(stdout, "%x %s\n", it->first, it->second->name);	
		fflush(stdout);
	}
#endif
}

//Hush.e

void load_start_addr(void)
{
	char name[300];
	unsigned int addr;

	FILE *f = fopen("start_addrs", "r");

	if(!f){
		fprintf(stderr, "load_start_addr can't open start_addrs\n");
		exit(0);
	}

#ifdef DEBUG
	fprintf(stdout, "loading start_addrs\n");
#endif

	while(fscanf(f, "%s\t%x\n", name, &addr) != EOF){
		if(!strcmp(PEMU_binary_name, name)){
			PEMU_txt_start = addr;
#ifdef DEBUG
			fprintf(stdout, "prgram %x\tstarting address\t%x\n", PEMU_txt_start, addr);
#endif
			return;
		}
	}
	
	fprintf(stderr, "can't find the starting addresses\n");
	exit(0);

}

//Hush.b
void load_sections()
{	
	char exe_name[300];
	unsigned int addr;
	char sym[300];	

	sprintf(exe_name, "dst/%s.sec", PEMU_binary_name);
	FILE *f = fopen(exe_name, "r");
	if(!f){
		fprintf(stderr, "load_sections can't open %s\n", exe_name);
		exit(0);
	}

	fprintf(stdout, "\nLoading ELF Sections:\n");
	fflush(stdout);

	while(fscanf (f, "%x %s\n", &addr, sym) != EOF){
		Dst_item *item = (Dst_item *)malloc(sizeof(Dst_item));
		memset(item, 0, sizeof(Dst_item));
		strcpy(item->name, sym);
		dst_map[addr] = item;
	}
	fclose(f);

#ifdef DEBUG
	for(map<unsigned int, Dst_item*>::iterator it= dst_map.begin();it!=dst_map.end();it++){
		fprintf(stdout, "%x %s\n", it->first, it->second->name);	
		fflush(stdout);
	}
#endif
}
//Hush.e


API_CALL *get_api_call(uint32_t addr)
{
	return g_map_plt[addr];
}


}
