#ifndef CPPTOC_H
#define CPPTOC_H



typedef enum _INST_TYPE{
	NORMAL = 0,
	JMP,
	INJMP,
	CALL,
	INCALL,
	CHGAPICALL,
	JCC,
	TAIL,
	JPLT,
	CPLT,
	LEA_8,
	LEA_16,
	LEA_32,
	LOOP
}INST_TYPE;

typedef enum _API_TPYE{
	API_NONE = 0,
	API_IMP = 1,
	API_REG = 2
}API_TYPE;

typedef struct _API_CALL{
	API_TYPE type;
	char *fname;
	unsigned int dptr;		//data pointer
	unsigned int tptr;		//txt pointer
}API_CALL;


typedef struct _INST{
	unsigned char inst[15];
	unsigned short len;
	INST_TYPE type;
	API_CALL api_call;	
}INST;

typedef struct {
	unsigned int next;
	unsigned int dst;
}JCC_DEST;


#include <stdio.h>

#endif
