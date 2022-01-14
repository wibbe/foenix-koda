@echo off

set VBCC=%cd%\vbcc
set CFG_FILE=%VBCC%\config\a2560u_ram
set DEFINES=-DPLATFORM_FOENIX
set CFLAGS=-cpu=68000 -Isrc -Ibin +%CFG_FILE%
set ASFLAGS=-m68000 -quiet -Fvobj -nowarn=62

if not exist bin mkdir bin

..\bin2h\bin2h.exe foenix_stdlib stdlib\stdlib.k bin\foenix_stdlib.h

call :asm bin\startup.o src\foenix\startup.s
call :asm bin\vsm.bin src\vsm.s -Fbin -L bin\vsm.lst

call :cc bin\editor.o src\editor.c
call :cc bin\koda.o src\koda.c
call :cc bin\console.o src\console.c
call :cc bin\heap.o src\foenix\heap.c
call :cc bin\syscall.o src\foenix\syscall.c

echo linking koda.bin
vc %CFLAGS% %DEFINES% -o koda.bin bin\editor.o bin\console.o bin\koda.o bin\heap.o bin\syscall.o

exit /b 0


:cc
echo compiling %2
vc %CFLAGS% %DEFINES% -c -o %1 %2

if %ERRORLEVEL% EQU 1 (
	exit /b 0
)
exit /b 0

:asm
echo assembling %2
vasmm68k_mot %ASFLAGS% %3 %4 %5 %6 %7 %8 %9 -o %1 %2

if %ERRORLEVEL% EQU 1 (
	exit /b 0
)
exit /b 0