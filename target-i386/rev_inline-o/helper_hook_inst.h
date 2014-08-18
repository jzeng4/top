#ifndef HELPER_HOOK_INST_H
#define HELPER_HOOK_INST_H
#include <xed-interface.h>

#include "cpptoc.h"

extern xed_decoded_inst_t xedd_g;
extern int xed_regmapping[][3];



//typedef void (*DepFunc)(const xed_inst_t*);
//typedef void (*Func)(const xed_inst_t*);

void handle_data_dependence(const xed_inst_t* xi);
void handle_addr_rewrite(const xed_inst_t* xi);

extern unsigned int g_pc;
extern xed_decoded_inst_t xedd_g;
extern xed_state_t dstate;

inline void handle_api_issues(API_CALL *api, int type);
inline void api_copy(API_CALL *to, API_CALL *from);


#endif
