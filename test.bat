@echo off

if not exist bin mkdir bin

echo compiling...
gcc -o bin\koda_test.exe -DPLATFORM_WIN -Isrc -Ibin\src src\koda.c src\test.c
if %ERRORLEVEL% EQU 1 (
	exit /b 0
)

bin\koda_test.exe
