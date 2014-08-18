#include "qemu-pemu.h"
#include "cpu.h"

static int xed_regmapping[][3] = {
/* XED_REG_INVALID, */ {-1,-1,-1},
/* XED_REG_CR0, */ {-1,-1,-1},
/* XED_REG_CR1, */ {-1,-1,-1},
/* XED_REG_CR2, */ {-1,-1,-1},
/* XED_REG_CR3, */ {-1,-1,-1},
/* XED_REG_CR4, */ {-1,-1,-1},
/* XED_REG_CR5, */ {-1,-1,-1},
/* XED_REG_CR6, */ {-1,-1,-1},
/* XED_REG_CR7, */ {-1,-1,-1},
/* XED_REG_CR8, */ {-1,-1,-1},
/* XED_REG_CR9, */ {-1,-1,-1},
/* XED_REG_CR10, */ {-1,-1,-1},
/* XED_REG_CR11, */ {-1,-1,-1},
/* XED_REG_CR12, */ {-1,-1,-1},
/* XED_REG_CR13, */ {-1,-1,-1},
/* XED_REG_CR14, */ {-1,-1,-1},
/* XED_REG_CR15, */ {-1,-1,-1},
/* XED_REG_DR0, */ {-1,-1,-1},
/* XED_REG_DR1, */ {-1,-1,-1},
/* XED_REG_DR2, */ {-1,-1,-1},
/* XED_REG_DR3, */ {-1,-1,-1},
/* XED_REG_DR4, */ {-1,-1,-1},
/* XED_REG_DR5, */ {-1,-1,-1},
/* XED_REG_DR6, */ {-1,-1,-1},
/* XED_REG_DR7, */ {-1,-1,-1},
/* XED_REG_DR8, */ {-1,-1,-1},
/* XED_REG_DR9, */ {-1,-1,-1},
/* XED_REG_DR10, */ {-1,-1,-1},
/* XED_REG_DR11, */ {-1,-1,-1},
/* XED_REG_DR12, */ {-1,-1,-1},
/* XED_REG_DR13, */ {-1,-1,-1},
/* XED_REG_DR14, */ {-1,-1,-1},
/* XED_REG_DR15, */ {-1,-1,-1},
/* XED_REG_FLAGS, */ {-1,-1,-1},
/* XED_REG_EFLAGS, */ {-1,-1,-1},
/* XED_REG_RFLAGS, */ {-1,-1,-1},
/* XED_REG_AX, */ {R_EAX,-1,-1},
/* XED_REG_CX, */ {R_ECX,-1,-1},
/* XED_REG_DX, */ {R_EDX,-1,-1},
/* XED_REG_BX, */ {R_EBX,-1,-1},
/* XED_REG_SP, */ {R_ESP,-1,-1},
/* XED_REG_BP, */ {R_EBP,-1,-1},
/* XED_REG_SI, */ {R_ESI,-1,-1},
/* XED_REG_DI, */ {R_EDI,-1,-1},
/* XED_REG_R8W, */ {-1,-1,-1},
/* XED_REG_R9W, */ {-1,-1,-1},
/* XED_REG_R10W, */ {-1,-1,-1},
/* XED_REG_R11W, */ {-1,-1,-1},
/* XED_REG_R12W, */ {-1,-1,-1},
/* XED_REG_R13W, */ {-1,-1,-1},
/* XED_REG_R14W, */ {-1,-1,-1},
/* XED_REG_R15W, */ {-1,-1,-1},
/* XED_REG_EAX, */ {R_EAX,-1,-1},
/* XED_REG_ECX, */ {R_ECX,-1,-1},
/* XED_REG_EDX, */ {R_EDX,-1,-1},
/* XED_REG_EBX, */ {R_EBX,-1,-1},
/* XED_REG_ESP, */ {R_ESP,-1,-1},
/* XED_REG_EBP, */ {R_EBP,-1,-1},
/* XED_REG_ESI, */ {R_ESI,-1,-1},
/* XED_REG_EDI, */ {R_EDI,-1,-1},
/* XED_REG_R8D, */ {-1,-1,-1},
/* XED_REG_R9D, */ {-1,-1,-1},
/* XED_REG_R10D, */ {-1,-1,-1},
/* XED_REG_R11D, */ {-1,-1,-1},
/* XED_REG_R12D, */ {-1,-1,-1},
/* XED_REG_R13D, */ {-1,-1,-1},
/* XED_REG_R14D, */ {-1,-1,-1},
/* XED_REG_R15D, */ {-1,-1,-1},
/* XED_REG_RAX, */ {-1,-1,-1},
/* XED_REG_RCX, */ {-1,-1,-1},
/* XED_REG_RDX, */ {-1,-1,-1},
/* XED_REG_RBX, */ {-1,-1,-1},
/* XED_REG_RSP, */ {-1,-1,-1},
/* XED_REG_RBP, */ {-1,-1,-1},
/* XED_REG_RSI, */ {-1,-1,-1},
/* XED_REG_RDI, */ {-1,-1,-1},
/* XED_REG_R8, */ {-1,-1,-1},
/* XED_REG_R9, */ {-1,-1,-1},
/* XED_REG_R10, */ {-1,-1,-1},
/* XED_REG_R11, */ {-1,-1,-1},
/* XED_REG_R12, */ {-1,-1,-1},
/* XED_REG_R13, */ {-1,-1,-1},
/* XED_REG_R14, */ {-1,-1,-1},
/* XED_REG_R15, */ {-1,-1,-1},
/* XED_REG_AL, */ {R_EAX,-1,-1},
/* XED_REG_CL, */ {R_ECX,-1,-1},
/* XED_REG_DL, */ {R_EDX,-1,-1},
/* XED_REG_BL, */ {R_EBX,-1,-1},
/* XED_REG_SPL, */ {-1,-1,-1},
/* XED_REG_BPL, */ {-1,-1,-1},
/* XED_REG_SIL, */ {-1,-1,-1},
/* XED_REG_DIL, */ {-1,-1,-1},
/* XED_REG_R8B, */ {-1,-1,-1},
/* XED_REG_R9B, */ {-1,-1,-1},
/* XED_REG_R10B, */ {-1,-1,-1},
/* XED_REG_R11B, */ {-1,-1,-1},
/* XED_REG_R12B, */ {-1,-1,-1},
/* XED_REG_R13B, */ {-1,-1,-1},
/* XED_REG_R14B, */ {-1,-1,-1},
/* XED_REG_R15B, */ {-1,-1,-1},
/* XED_REG_AH, */ {R_EAX,-1,-1},
/* XED_REG_CH, */ {R_ECX,-1,-1},
/* XED_REG_DH, */ {R_EDX,-1,-1},
/* XED_REG_BH, */ {R_EBX,-1,-1},
/* XED_REG_ERROR, */ {-1,-1,-1},
/* XED_REG_RIP, */ {-1,-1,-1},
/* XED_REG_EIP, */ {-1,-1,-1},
/* XED_REG_IP, */ {-1,-1,-1},
/* XED_REG_MMX0, */ {-1,-1,-1},
/* XED_REG_MMX1, */ {-1,-1,-1},
/* XED_REG_MMX2, */ {-1,-1,-1},
/* XED_REG_MMX3, */ {-1,-1,-1},
/* XED_REG_MMX4, */ {-1,-1,-1},
/* XED_REG_MMX5, */ {-1,-1,-1},
/* XED_REG_MMX6, */ {-1,-1,-1},
/* XED_REG_MMX7, */ {-1,-1,-1},
/* XED_REG_MXCSR, */ {-1,-1,-1},
/* XED_REG_STACKPUSH, */ {-1,-1,-1},
/* XED_REG_STACKPOP, */ {-1,-1,-1},
/* XED_REG_GDTR, */ {-1,-1,-1},
/* XED_REG_LDTR, */ {-1,-1,-1},
/* XED_REG_IDTR, */ {-1,-1,-1},
/* XED_REG_TR, */ {-1,-1,-1},
/* XED_REG_TSC, */ {-1,-1,-1},
/* XED_REG_TSCAUX, */ {-1,-1,-1},
/* XED_REG_MSRS, */ {-1,-1,-1},
/* XED_REG_X87CONTROL, */ {-1,-1,-1},
/* XED_REG_X87STATUS, */ {-1,-1,-1},
/* XED_REG_X87TOP, */ {-1,-1,-1},
/* XED_REG_X87TAG, */ {-1,-1,-1},
/* XED_REG_X87PUSH, */ {-1,-1,-1},
/* XED_REG_X87POP, */ {-1,-1,-1},
/* XED_REG_X87POP2, */ {-1,-1,-1},
/* XED_REG_CS, */ {R_CS,-1,-1},
/* XED_REG_DS, */ {R_DS,-1,-1},
/* XED_REG_ES, */ {R_ES,-1,-1},
/* XED_REG_SS, */ {R_SS,-1,-1},
/* XED_REG_FS, */ {R_FS,-1,-1},
/* XED_REG_GS, */ {R_GS,-1,-1},
/* XED_REG_TMP0, */ {-1,-1,-1},
/* XED_REG_TMP1, */ {-1,-1,-1},
/* XED_REG_TMP2, */ {-1,-1,-1},
/* XED_REG_TMP3, */ {-1,-1,-1},
/* XED_REG_TMP4, */ {-1,-1,-1},
/* XED_REG_TMP5, */ {-1,-1,-1},
/* XED_REG_TMP6, */ {-1,-1,-1},
/* XED_REG_TMP7, */ {-1,-1,-1},
/* XED_REG_TMP8, */ {-1,-1,-1},
/* XED_REG_TMP9, */ {-1,-1,-1},
/* XED_REG_TMP10, */ {-1,-1,-1},
/* XED_REG_TMP11, */ {-1,-1,-1},
/* XED_REG_TMP12, */ {-1,-1,-1},
/* XED_REG_TMP13, */ {-1,-1,-1},
/* XED_REG_TMP14, */ {-1,-1,-1},
/* XED_REG_TMP15, */ {-1,-1,-1},
/* XED_REG_ST0, */ {-1,-1,-1},
/* XED_REG_ST1, */ {-1,-1,-1},
/* XED_REG_ST2, */ {-1,-1,-1},
/* XED_REG_ST3, */ {-1,-1,-1},
/* XED_REG_ST4, */ {-1,-1,-1},
/* XED_REG_ST5, */ {-1,-1,-1},
/* XED_REG_ST6, */ {-1,-1,-1},
/* XED_REG_ST7, */ {-1,-1,-1},
/* XED_REG_XMM0, */ {-1,-1,-1},
/* XED_REG_XMM1, */ {-1,-1,-1},
/* XED_REG_XMM2, */ {-1,-1,-1},
/* XED_REG_XMM3, */ {-1,-1,-1},
/* XED_REG_XMM4, */ {-1,-1,-1},
/* XED_REG_XMM5, */ {-1,-1,-1},
/* XED_REG_XMM6, */ {-1,-1,-1},
/* XED_REG_XMM7, */ {-1,-1,-1},
/* XED_REG_XMM8, */ {-1,-1,-1},
/* XED_REG_XMM9, */ {-1,-1,-1},
/* XED_REG_XMM10, */ {-1,-1,-1},
/* XED_REG_XMM11, */ {-1,-1,-1},
/* XED_REG_XMM12, */ {-1,-1,-1},
/* XED_REG_XMM13, */ {-1,-1,-1},
/* XED_REG_XMM14, */ {-1,-1,-1},
/* XED_REG_XMM15, */ {-1,-1,-1},
/* XED_REG_YMM0, */ {-1,-1,-1},
/* XED_REG_YMM1, */ {-1,-1,-1},
/* XED_REG_YMM2, */ {-1,-1,-1},
/* XED_REG_YMM3, */ {-1,-1,-1},
/* XED_REG_YMM4, */ {-1,-1,-1},
/* XED_REG_YMM5, */ {-1,-1,-1},
/* XED_REG_YMM6, */ {-1,-1,-1},
/* XED_REG_YMM7, */ {-1,-1,-1},
/* XED_REG_YMM8, */ {-1,-1,-1},
/* XED_REG_YMM9, */ {-1,-1,-1},
/* XED_REG_YMM10, */ {-1,-1,-1},
/* XED_REG_YMM11, */ {-1,-1,-1},
/* XED_REG_YMM12, */ {-1,-1,-1},
/* XED_REG_YMM13, */ {-1,-1,-1},
/* XED_REG_YMM14, */ {-1,-1,-1},
/* XED_REG_YMM15, */ {-1,-1,-1},
/* XED_REG_LAST, */ {-1,-1,-1},
/* XED_REG_CR_FIRST=XED_REG_CR0, */ {-1,-1,-1},
/* XED_REG_CR_LAST=XED_REG_CR15, */ {-1,-1,-1},
/* XED_REG_DR_FIRST=XED_REG_DR0, */ {-1,-1,-1},
/* XED_REG_DR_LAST=XED_REG_DR15, */ {-1,-1,-1},
/* XED_REG_FLAGS_FIRST=XED_REG_FLAGS, */ {-1,-1,-1},
/* XED_REG_FLAGS_LAST=XED_REG_RFLAGS, */ {-1,-1,-1},
/* XED_REG_GPR16_FIRST=XED_REG_AX, */ {-1,-1,-1},
/* XED_REG_GPR16_LAST=XED_REG_R15W, */ {-1,-1,-1},
/* XED_REG_GPR32_FIRST=XED_REG_EAX, */ {-1,-1,-1},
/* XED_REG_GPR32_LAST=XED_REG_R15D, */ {-1,-1,-1},
/* XED_REG_GPR64_FIRST=XED_REG_RAX, */ {-1,-1,-1},
/* XED_REG_GPR64_LAST=XED_REG_R15, */ {-1,-1,-1},
/* XED_REG_GPR8_FIRST=XED_REG_AL, */ {-1,-1,-1},
/* XED_REG_GPR8_LAST=XED_REG_R15B, */ {-1,-1,-1},
/* XED_REG_GPR8H_FIRST=XED_REG_AH, */ {-1,-1,-1},
/* XED_REG_GPR8H_LAST=XED_REG_BH, */ {-1,-1,-1},
/* XED_REG_INVALID_FIRST=XED_REG_INVALID, */ {-1,-1,-1},
/* XED_REG_INVALID_LAST=XED_REG_ERROR, */ {-1,-1,-1},
/* XED_REG_IP_FIRST=XED_REG_RIP, */ {-1,-1,-1},
/* XED_REG_IP_LAST=XED_REG_IP, */ {-1,-1,-1},
/* XED_REG_MMX_FIRST=XED_REG_MMX0, */ {-1,-1,-1},
/* XED_REG_MMX_LAST=XED_REG_MMX7, */ {-1,-1,-1},
/* XED_REG_MXCSR_FIRST=XED_REG_MXCSR, */ {-1,-1,-1},
/* XED_REG_MXCSR_LAST=XED_REG_MXCSR, */ {-1,-1,-1},
/* XED_REG_PSEUDO_FIRST=XED_REG_STACKPUSH, */ {-1,-1,-1},
/* XED_REG_PSEUDO_LAST=XED_REG_X87POP2, */ {-1,-1,-1},
/* XED_REG_SR_FIRST=XED_REG_CS, */ {-1,-1,-1},
/* XED_REG_SR_LAST=XED_REG_GS, */ {-1,-1,-1},
/* XED_REG_TMP_FIRST=XED_REG_TMP0, */ {-1,-1,-1},
/* XED_REG_TMP_LAST=XED_REG_TMP15, */ {-1,-1,-1},
/* XED_REG_X87_FIRST=XED_REG_ST0, */ {-1,-1,-1},
/* XED_REG_X87_LAST=XED_REG_ST7, */ {-1,-1,-1},
/* XED_REG_XMM_FIRST=XED_REG_XMM0, */ {-1,-1,-1},
/* XED_REG_XMM_LAST=XED_REG_XMM15, */ {-1,-1,-1},
/* XED_REG_YMM_FIRST=XED_REG_YMM0, */ {-1,-1,-1},
/* XED_REG_YMM_LAST=XED_REG_YMM15 */ {-1,-1,-1},
};

//uint32_t PEMU_get_reg(int reg)

uint32_t PEMU_get_reg(xed_reg_enum_t reg_id)
{
	if(reg_id == XED_REG_INVALID)
		return 0;
	uint32_t reg = xed_regmapping[reg_id][0];
	//return cpu_single_env->regs[reg];
	struct CPUX86State* env=(struct CPUX86State*)(first_cpu->env_ptr);
	return env->regs[reg];
}

uint32_t PEMU_get_cr3()
{
	struct CPUX86State* env=(struct CPUX86State*)(first_cpu->env_ptr);
	return env->cr[3];
}


int PEMU_read_mem(uint32_t vaddr, int len, void *buf)
{
//	PIN_SafeCopy(buf, (VOID*)vaddr, 15);
//	memcpy(buf, (void*)vaddr, len);
//	return 0;
	
	//struct CPUX86State* env=(struct CPUX86State*)(first_cpu->env_ptr);
	return cpu_memory_rw_debug(first_cpu, vaddr, buf, len, 0);
}

