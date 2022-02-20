@echo off

if not exist bin mkdir bin
pushd bin
	if not exist src mkdir src
popd

..\bin2h\bin2h.exe foenix_stdlib stdlib\stdlib.k bin\src\foenix_stdlib.h
if %ERRORLEVEL% EQU 1 (
	exit /b 0
)

vasmm68k_mot -m68000 -quiet -Fbin -L bin\vsm.lst -o bin\vsm.bin src/vsm.s
vasmm68k_mot -m68000 -quiet -Fbin -L bin\gfx.lst -o bin\gfx.lib src/gfx.s

call :opcode syscall0
call :opcode syscall1
call :opcode syscall2
call :opcode syscall3
call :opcode memscan
call :opcode memcopy
call :opcode memset
call :opcode min
call :opcode max
call :opcode mul32
call :opcode div32
call :opcode init
call :opcode enter
call :opcode dealloc
call :opcode local_vec
call :opcode global_vec
call :opcode exit

rem call :opcode load_value
rem call :opcode load_global_addr
rem call :opcode load_local_addr
rem call :opcode load_global
rem call :opcode load_local
rem call :opcode store_global
rem call :opcode store_local
rem call :opcode store_indirect_word
rem call :opcode store_indirect_byte
rem call :opcode halt
rem call :opcode index_word
rem call :opcode index_byte
rem call :opcode deref_word
rem call :opcode deref_byte
rem call :opcode call
rem call :opcode call_indirect
rem call :opcode neg
rem call :opcode inv
rem call :opcode lognot
rem call :opcode add
rem call :opcode sub
rem call :opcode mul
rem call :opcode div
rem call :opcode mod
rem call :opcode and
rem call :opcode or
rem call :opcode xor
rem call :opcode shift_left
rem call :opcode shift_right
rem call :opcode eq
rem call :opcode not_eq
rem call :opcode less
rem call :opcode less_eq
rem call :opcode greater
rem call :opcode greater_eq
rem call :opcode jump_fwd
rem call :opcode jump_back
rem call :opcode jump_true
rem call :opcode jump_false
rem call :opcode inc
rem call :opcode dec
rem call :opcode clear
rem call :opcode drop

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