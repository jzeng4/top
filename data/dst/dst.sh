#!/bin/bash
elf=$1
objdump -T $elf|grep bss |cut -d' ' -f1,12 >$elf.dst
