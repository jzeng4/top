
#ifndef HOOK_INST_H
#define HOOK_INST_H

#include <xed-interface.h>

#include <stdio.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
//#include <xed-interface.h>
//#include "hook_inst.h"
//#include "qemu-common.h"
#include "cpu.h"
#include "cpptoc.h"
//#include "qemu-log.h"

extern xed_decoded_inst_t xedd_g;
extern xed_state_t dstate;

typedef const xed_inst_t * INS;
typedef void (*InstrumentFunction)(INS ins);
INST* get_inst(unsigned int pc);
void *create_func1(unsigned int pc);
INST *get_inst(unsigned int);
int is_api_call(unsigned int dest, char **fname);
API_CALL *get_api_call(uint32_t addr);


#endif
