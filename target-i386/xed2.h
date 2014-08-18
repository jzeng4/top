#ifndef XED22_H
#define XED22_H
#include <xed-interface.h>

#define PEMU_dstate dstate
#define PEMU_xedd xedd
#define PEMU_xedd_g xedd_g

extern xed_state_t PEMU_dstate;
extern xed_decoded_inst_t PEMU_xedd;
extern xed_decoded_inst_t PEMU_xedd_g;
extern char PEMU_inst_buf[];
extern char PEMU_inst_str[];
extern const xed_inst_t *PEMU_g_xi;
extern const xed_operand_t *PEMU_op;
extern xed_operand_enum_t PEMU_op_name; 
extern xed_iclass_enum_t PEMU_opcode;

void xed2_init(void);
void update_xed(char *buf);

#endif
