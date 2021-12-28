@echo off

gcc -o t3x_stage0.exe -DDEBUG -DPLATFORM_WIN src/t3x_stage0.c

vasmm68k_mot -Fbin -L vsm.lst -o vsm.bin src/vsm.s