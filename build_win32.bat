@echo off

if not exist bin mkdir bin

..\bin2h\bin2h.exe foenix_stdlib stdlib\stdlib.k bin\foenix_stdlib.h

gcc -o koda.exe -DPLATFORM_WIN -Isrc -Ibin src/koda.c src/standalone.c

vasmm68k_mot -m68000 -quiet -Fbin -L bin\vsm.lst -o bin\vsm.bin src/vsm.s