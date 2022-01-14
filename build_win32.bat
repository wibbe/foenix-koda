@echo off

if not exist bin mkdir bin

gcc -o t3x_m68k.exe -DPLATFORM_WIN -Isrc src/t3x.c src/standalone.c

vasmm68k_mot -m68000 -quiet -Fbin -L bin\vsm.lst -o bin\vsm.bin src/vsm.s