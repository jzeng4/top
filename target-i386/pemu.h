#ifndef PEMU_H
#define PEMU_H

//#include "pin.h"
#include "qemu-pemu.h"
//#include "libc_heap.h"
#include "read_linux.h"

//extern PEMU_instrument *pemu_instance;
extern char PEMU_binary_name[];
extern char PEMU_so_name[];
extern uint32_t PEMU_start;
extern uint32_t PEMU_cr3;
extern uint32_t PEMU_task_addr;
extern uint32_t PEMU_g_pc;
#if 0
#define target_ulong uint32_t

extern target_ulong hookingpoint;
extern target_ulong hookingpoint2;
extern target_ulong taskaddr;
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
#endif
extern uint32_t PEMU_libc_start;
extern uint32_t PEMU_libc_end;

extern Module_info *PEMU_module;
//extern PEMU_interface *PEMU_interface_instance;

int PEMU_find_process(void *opaque);
int PEMU_handle_bb(uint32_t pc);
int PEMU_find_module(void *opaque);
int PEMU_load_idt(void *opaque);
int PEMU_find_mmap(uint32_t nextaddr);
int PEMU_exit(void);
#endif
