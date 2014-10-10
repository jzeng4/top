#include "inline_inst.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
using namespace std;

FUNCTION *g_current_func;
PROGRAM *g_current_program;
unsigned int g_current_esp;
map<unsigned int, char> g_map_jmp;
extern int g_atexit;

typedef struct{
	FUNCTION* func;
	unsigned int ret_pc;
    unsigned int esp;
}ELEM;

vector<ELEM*> g_callstack;

extern "C"{
INST *create_inst()
{
	INST* tmp = (INST*)malloc(sizeof(INST));
	
	if(tmp == 0){
		fprintf(stderr, "error in create_inst\n");
		exit(0);
	}
	
	memset(tmp, 0, sizeof(INST));
#ifdef DEBUG
	fprintf(stdout, "new inst\t%p\n", tmp);
#endif
	return tmp;
}


void insert_inst(unsigned int pc, unsigned char *inst, unsigned short len)
{
	if(g_current_func->count(pc))
		return;
	else if(g_atexit == pc) {
		inst[0] = 0x90;
	}

	INST *tmp = create_inst();
	memcpy(tmp->inst, inst, 15);
	tmp->len = len;
	(*g_current_func)[pc] = tmp;
#ifdef DEBUG
	fprintf(stdout, "insert pc %x\t%p\n", pc, g_current_func);
#endif
}

void *get_current_func()
{
	return g_current_func;
}

unsigned int get_current_esp()
{
    return g_current_esp;
}


INST* get_inst(unsigned int pc)
{
//fprintf(stdout, "get_inst current_func:\t%x\n", g_current_func);
//	if((*g_current_func).count(pc) == 0)
//		return 0;
//	return (*g_current_func)[pc];

	if((*g_current_func).count(pc) == 0)
	{
		 //yang.new

		for(PROGRAM::iterator it = g_current_program->begin();
				it != g_current_program->end();it++){
			FUNCTION *f =it->second;
		  	if((*f).count(pc)!=0)
				return (*f)[pc];
		}
		return 0;
	}else
		return (*g_current_func)[pc];
}

FUNCTION *create_func1(unsigned int pc)
{
	if(g_current_program->count(pc))
		return (*g_current_program)[pc];

	FUNCTION* tmp = new FUNCTION;
		
	if(tmp == 0){
		fprintf(stderr, "error in create_func1\n");
		exit(0);
	}

#ifdef DEBUG
	fprintf(stderr, "----created a new function %x\t%x\n", pc, tmp);
#endif

//	memset(tmp, 0, sizeof(FUNCTION));
	(*g_current_program)[pc] = tmp;
	return tmp;

}

void insert_func(unsigned int pc)
{
#if 0
	if(g_current_program->count(pc))
		return;

	FUNCTION *tmp = create_func1();
	(*g_current_program)[pc] = tmp;
#endif
}

void print_call_stack(){

	for(vector<ELEM*>::iterator it=g_callstack.begin();it!=g_callstack.end();it++){
		fprintf(stderr, "----call_stack: %x\n", (*it)->ret_pc);
	}
}

void push_callstack(void *func, unsigned int ret, unsigned int esp)
{
	ELEM *t = new ELEM;
	t->func = (FUNCTION*)func;
	t->ret_pc = ret;
    t->esp  = esp;
	//g_callstack.push(t);
	g_callstack.push_back(t);
	g_current_func = (FUNCTION*) func;
    g_current_esp = t->esp;
#ifdef DEBUG
	print_call_stack();
#endif
}


void pop_callstack()
{
	//g_callstack.pop();
	g_callstack.pop_back();
	//ELEM *p = g_callstack.top();
	ELEM *p = g_callstack.back();
	g_current_func = p->func;
    g_current_esp = p->esp;
#ifdef DEBUG
	print_call_stack();	
#endif
}

unsigned int get_ret_pc()
{
	//return g_callstack.top()->ret_pc;
	return g_callstack.back()->ret_pc;
}


void create_program(unsigned int pc)
{
	g_current_program = new PROGRAM;	
	FUNCTION *tmp = create_func1(pc);
	(*g_current_program)[pc] = tmp;
	g_current_func = tmp;
	push_callstack(tmp, 0, 0);
}

void insert_jmp_dst(unsigned int dst)
{
//	g_map_jmp[next] = 1;
	g_map_jmp[dst] = 1;
#ifdef DEBUG
	fprintf(stdout, "Insert jmp target %x \n", dst);
#endif
}

int get_jmp_dst(unsigned int dst)
{
	if(g_map_jmp.count(dst))
		return g_map_jmp[dst];
	return 0;
}

}
