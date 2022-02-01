@echo off

if not exist bin mkdir bin

gcc -o bin\process_asm.exe -Isrc\tools src\tools\process_asm.c