@echo off

if not exist bin mkdir bin
pushd bin
	if not exist src mkdir src
popd

vasmm68k_mot -m68000 -quiet -Fbin -L bin\stdlib.lst -o bin\stdlib.bin src\library\stdlib.s
..\bin2h\bin2h.exe foenix_stdlib bin\stdlib.bin bin\src\foenix_stdlib.h
if %ERRORLEVEL% EQU 1 (
	exit /b 0
)

vasmm68k_mot -m68000 -quiet -Fbin -L bin\vsm.lst -o bin\vsm.bin src/vsm.s
vasmm68k_mot -m68000 -quiet -Fbin -L bin\gfx.lst -o bin\gfx.lib src\library\gfx.s

call :opcode init
call :opcode enter
call :opcode dealloc
call :opcode local_vec
call :opcode global_vec
call :opcode exit

echo compiling koda...
gcc -o koda.exe -DPLATFORM_WIN -Isrc -Ibin\src src\koda.c src\standalone.c
if %ERRORLEVEL% EQU 1 (
	exit /b 0
)

exit /b 0



:opcode
echo assembling opcode %1
rem vasmm68k_mot -m68000 -quiet -Fbin -L bin\opcode_%1.lst -Isrc\opcodes -o bin\opcode_%1.bin src\opcodes\opcode_%1.s
vasmm68k_mot -m68000 -quiet -Fbin -Isrc\opcodes -o bin\opcode_%1.bin src\opcodes\opcode_%1.s

if %ERRORLEVEL% EQU 1 (
	echo error compiling src\opcodes\%s.s
	exit /b 0
)

bin\process_asm.exe bin\opcode_%1.bin bin\src\opcode_%1.h %1
del bin\opcode_%1.bin

exit /b 0