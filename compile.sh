#!/bin/bash

gcc -g -o target target.c
gcc -g -W -o injector injector.c
nasm -f elf64 payload.asm
ld -o payload payload.o


