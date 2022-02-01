
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "koda.h"
#include "opcodes.h"


#define VAR_A 	0
#define VAR_B 	1

void print_bytecode(int *bytecode, int len)
{
	int it = 0;
	while (it < len)
	{
		int opcode = bytecode[it];
		if (koda_opcode_arg_count(opcode) == 1)
		{
			printf("  %03d: %s %d\n", it, koda_opcode_name(opcode), bytecode[it + 1]);
			it += 2;
		}
		else
		{
			printf("  %03d: %s\n", it, koda_opcode_name(opcode));
			it++;
		}
	}
}

int find_main(int *bytecode, int len)
{
	int it = 0;

	while (it < len)
	{
		int opcode = bytecode[it++];
		switch (opcode)
		{
			case OP_INIT:
				it++;
				break;

			case OP_JUMP_FWD:
				it += bytecode[it];
				break;

			case OP_CALL:
				it = bytecode[it];
				break;

			case OP_ENTER:
				return it;
		}
	}

	return -1;
}

void test(char *name, char *str, ...)
{
	char code_buffer[2048];
	snprintf(code_buffer, 2048, "var a, b\nfunc main() {\n%s\n}\n", str);

	va_list args;
	va_start(args, str);

	char test_buffer[50];
	int test_buffer_len = snprintf(test_buffer, 50, "running test %s...", name);
	printf(test_buffer);
	while (test_buffer_len < 50)
	{
		printf(" ");
		test_buffer_len++;
	}

	koda_compiler_options_t options = {
		.text_start_address = 0,
		.data_start_address = 0,
		.text_size = 1024,
		.data_size = 1024,
	};

	int *bytecode;
	int bytecode_len;

	if (koda_compile_to_bytecode(&options, name, code_buffer, &bytecode, &bytecode_len) == 0)
	{
		printf("failed\n");
		return;
	}

	int bytecode_it = find_main(bytecode, bytecode_len);
	if (bytecode_it == -1)
	{
		printf("failed - could not locate main function\n");
		goto end;
	}

	bool test_finished = false;

	while (bytecode_it < bytecode_len)
	{
		int opcode = va_arg(args, int);
		if (opcode == 0)
		{
			test_finished = true;
			break;
		}

		int bytecode_opcode = bytecode[bytecode_it++];

		if (bytecode_opcode != opcode)
		{
			printf("FAILED - expected opcode %s but found %s\n", koda_opcode_name(opcode), koda_opcode_name(bytecode_opcode));
			print_bytecode(bytecode, bytecode_len);
			goto end;
		}


		if (koda_opcode_arg_count(opcode) == 1)
		{
			int opcode_arg = va_arg(args, int);

			// A negative value indicates we are not interested in testing the argument
			if (opcode_arg != -1)
			{
				if (bytecode[bytecode_it] != opcode_arg)
				{
					printf("FAILED - expected %s %d but found %s %d\n", koda_opcode_name(opcode), opcode_arg, koda_opcode_name(bytecode_opcode), bytecode[bytecode_it]);
					print_bytecode(bytecode, bytecode_len);
					goto end;
				}
			}

			bytecode_it++;
		}
	}

	// Check to see if the test succeeded of failed
	if (!test_finished || bytecode_it >= bytecode_len || bytecode[bytecode_it] != OP_CLEAR)
	{
		printf("FAILED\n");
		print_bytecode(bytecode, bytecode_len);
		goto end;
	}

	printf("success\n");

end:
	free(bytecode);
	va_end(args);
}

void test_var_assignment(void)
{
	test("var-const-assignment", "a = 1", OP_LOAD_VALUE, 1, OP_STORE_GLOBAL, VAR_A, 0);
	test("var-var-assignment", "a = 1\nb = a", OP_LOAD_VALUE, 1, OP_STORE_GLOBAL, VAR_A, OP_LOAD_GLOBAL, VAR_A, OP_STORE_GLOBAL, VAR_B, 0);
}


void test_local_vars(void)
{
	test("local-var", "var c\n", OP_ALLOC, 4, OP_DEALLOC, 4, 0);
	test("local-var-multiple", "var c\nvar d\n", OP_ALLOC, 8, OP_DEALLOC, 8, 0);
	test("local-var-assign", "var c\nc = 4", OP_ALLOC, 4, OP_LOAD_VALUE, 4, OP_STORE_LOCAL, -4, OP_DEALLOC, 4, 0);
}

void test_constant_folding(void)
{
	test("constant-folding-add", "a = 1 + 2", OP_LOAD_VALUE, 3, OP_STORE_GLOBAL, VAR_A, 0);
	test("constant-folding-mul", "a = 2 * 4", OP_LOAD_VALUE, 8, OP_STORE_GLOBAL, VAR_A, 0);
	test("constant-folding-div", "a = 10 / 2", OP_LOAD_VALUE, 5, OP_STORE_GLOBAL, VAR_A, 0);
	test("constant-folding-mod", "a = 5 % 4", OP_LOAD_VALUE, 1, OP_STORE_GLOBAL, VAR_A, 0);
	test("constant-folding-add-multiple", "a = 1 + 2 + 3 + 4 + 5", OP_LOAD_VALUE, 15, OP_STORE_GLOBAL, VAR_A, 0);
}



int main(int argc, char *argv[])
{
	test_var_assignment();
	test_local_vars();
	test_constant_folding();
}