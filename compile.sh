#!/bin/bash

gcc -g -o target target.c
gcc -g -W -o injector injector.c
nasm -f elf64 payload2.s
ld -o payload2 payload2.o


