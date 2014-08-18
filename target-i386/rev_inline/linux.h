#ifndef __LINUX_H__
#define __LINUX_H__


typedef struct _Libc_item{
	char name[100];
}Libc_item;

//Dynamic symbolic table
typedef struct _Dst_item{
	char name[100];
}Dst_item;

typedef unsigned int uint32_t;
extern uint32_t PEMU_start;
extern uint32_t PEMU_task_addr;
extern uint32_t PEMU_main_start;
extern uint32_t PEMU_img_start;
extern uint32_t PEMU_img_end;
extern uint32_t PEMU_txt_start;
extern uint32_t PEMU_txt_end;
extern uint32_t PEMU_cr3;
extern uint32_t hookingpoint;

extern uint32_t g_pc;
extern uint32_t g_start_pc;
extern uint32_t g_main_start;
extern char g_inst_buffer[15];

//extern 
#endif
