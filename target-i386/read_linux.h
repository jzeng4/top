/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef __READ_LINUX_H__
#define __READ_LINUX_H__


#define uint32_t unsigned int
#define uint16_t unsigned short

struct koffset {
    char version[128]; 
    uint32_t hookingpoint;
    uint32_t hookingpoint2; 
    uint32_t taskaddr; 
    int tasksize; 
    int listoffset; 
    int pidoffset; 
    int mmoffset; 
    int pgdoffset; 
    int commoffset; 
    int commsize; 
    int vmstartoffset; 
    int vmendoffset;
    int vmnextoffset; 
    int vmfileoffset;
    int vmflagsoffset;	
    int dentryoffset; 
    int dnameoffset; 
    int dinameoffset; 
}; 

typedef struct T_module_info
{
	char name[64];
	uint32_t init_func;
	uint32_t module_init;
	uint32_t module_core;
	uint32_t init_size, core_size;
	uint32_t init_text_size, core_text_size;

}Module_info;


typedef struct T_ird
{
	uint16_t offset1;
	uint16_t b1;
	uint16_t b2;
	uint16_t offset2;
}Interrupt_Gate;

extern uint32_t kernel_mem_start; 
extern uint32_t hookingpoint;
extern uint32_t hookingpoint2;
extern uint32_t taskaddr; 
extern int tasksize; 
extern int listoffset; 
extern int pidoffset; 
extern int mmoffset; 
extern int pgdoffset; 
extern int commoffset; 
extern int commsize; 
extern int vmstartoffset; 
extern int vmendoffset; 
extern int vmnextoffset; 
extern int vmfileoffset; 
extern int vmflagsoffset;	
extern int dentryoffset; 
extern int dnameoffset; 
extern int dinameoffset; 


/* offset for fc5 image 
static const long hookingpoint = 0xC01A26FC; // selinux_...
static const long taskaddr = 0xC033C300; 
static const int tasksize = 1360; 
static const int listoffset = 96; 
static const int pidoffset = 156; 
static const int mmoffset = 120; 
static const int pgdoffset = 40; 
static const int commoffset = 432; 
static const int commsize = 16; 

static const int vmfileoffset = 76; 
static const int dentryoffset = 8; 
static const int dnameoffset = 40; 
static const int dinameoffset = 112; */

/* offset for redhat 7.3 */
/* static const long hookingpoint = 0xC0117140; 
static const long taskaddr = 0xC031E000; 
static const int tasksize = 1424; 
static const int listoffset = 72; 
static const int pidoffset = 108; 
static const int mmoffset = 44; 
static const int pgdoffset = 12; 
static const int commoffset = 558; 
static const int commsize = 16; 

static const int vmfileoffset = 56; 
static const int dentryoffset = 8; 
static const int dnameoffset = 60; 
static const int dinameoffset = 96;  */

#if 0
int get_data(uint32_t addr, void *target, int size); 
uint32_t next_task_struct(uint32_t addr); 
uint32_t get_pid(uint32_t addr); 
uint32_t get_pgd(uint32_t addr);
void get_name(uint32_t addr, char *buf, int size);
uint32_t get_first_mmap(uint32_t addr);
uint32_t get_next_mmap(uint32_t addr);
uint32_t get_vmstart(uint32_t addr);
uint32_t get_vmend(uint32_t addr);
void get_mod_name(uint32_t addr, char *name, int size);
int init_kernel_offsets();
void for_all_hookpoints(hook_proc_t func, int action);
#endif


//int init_kernel_offsets(void);
#endif
