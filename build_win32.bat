@echo off

if not exist bin mkdir bin
pushd bin
	if not exist src mkdir src
popd

..\bin2h\bin2h.exe foenix_stdlib stdlib\stdlib.k bin\src\foenix_stdlib.h
if %ERRORLEVEL% EQU 1 (
	exit /b 0
)

rem vasmm68k_mot -m68000 -quiet -Fbin -L bin\vsm.lst -o bin\vsm.bin src/vsm.s

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
call :opcode load_value
call :opcode load_global_addr
call :opcode load_local_addr
call :opcode load_global
call :opcode load_local
call :opcode store_global
call :opcode store_local
call :opcode store_indirect_word
call :opcode store_indirect_byte
call :opcode alloc
call :opcode dealloc
call :opcode local_vec
call :opcode global_vec
call :opcode halt
call :opcode index_word
call :opcode index_byte
call :opcode deref_word
call :opcode deref_byte
call :opcode call
call :opcode call_indirect
call :opcode enter
call :opcode exit
call :opcode neg
call :opcode inv
call :opcode lognot
call :opcode add
call :opcode sub
call :opcode mul
call :opcode div
call :opcode mod
call :opcode and
call :opcode or
call :opcode xor
call :opcode shift_left
call :opcode shift_right
call :opcode eq
call :opcode not_eq
call :opcode less
call :opcode less_eq
call :opcode greater
call :opcode greater_eq
call :opcode jump_fwd
call :opcode jump_back
call :opcode jump_true
call :opcode jump_false
call :opcode inc
call :opcode dec
call :opcode clear
call :opcode drop
call :opcode peek8
call :opcode peek16
call :opcode peek32
call :opcode poke8
call :opcode poke16
call :opcode poke32

echo compiling koda...
gcc -o koda.exe -DPLATFORM_WIN -Isrc -Ibin\src src\koda.c src\standalone.c
if %ERRORLEVEL% EQU 1 (
	exit /b 0
)

exit /b 0



:opcode
echo assembling opcode %1
vasmm68k_mot -m68000 -quiet -Fbin -L bin\opcode_%1.lst -Isrc\opcodes -o bin\opcode_%1.bin src\opcodes\opcode_%1.s

if %ERRORLEVEL% EQU 1 (
	echo error compiling src\opcodes\%s.s
	exit /b 0
)

bin\process_asm.exe bin\opcode_%1.bin bin\src\opcode_%1.h %1
del bin\opcode_%1.bin

exit /b 0