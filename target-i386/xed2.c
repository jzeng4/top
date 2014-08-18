#include "xed2.h"

xed_state_t PEMU_dstate;
xed_decoded_inst_t PEMU_xedd;
xed_decoded_inst_t PEMU_xedd_g;
const xed_inst_t *PEMU_g_xi;
const xed_operand_t *PEMU_op;
xed_operand_enum_t PEMU_op_name;
xed_iclass_enum_t PEMU_opcode;
char PEMU_inst_buf[15];
char PEMU_inst_str[128];

void xed2_init(void)
{
	 xed_tables_init();
	 xed_state_zero(&PEMU_dstate);

  	 xed_state_init(&PEMU_dstate,
			 XED_MACHINE_MODE_LEGACY_32,
			 XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b);

}

inline void update_xed(char *buf)
{
	xed_decoded_inst_zero_set_mode(&PEMU_xedd_g, &PEMU_dstate);
	xed_error_enum_t xed_error = xed_decode(&PEMU_xedd_g,
			XED_STATIC_CAST(const xed_uint8_t *,  buf), 15);
	if (xed_error == XED_ERROR_NONE) 
	{
	   xed_decoded_inst_dump_intel_format(&PEMU_xedd_g, PEMU_inst_str, sizeof(PEMU_inst_str), 0);	
	   PEMU_g_xi = xed_decoded_inst_inst(&PEMU_xedd_g);
   	   PEMU_op = xed_inst_operand(PEMU_g_xi, 0);
   	   PEMU_op_name = xed_operand_name(PEMU_op);
	   PEMU_opcode = xed_decoded_inst_get_iclass(&PEMU_xedd_g);
	}
}
