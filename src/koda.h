
#ifndef KODA_H
#define KODA_H

enum {
	KODA_OUTPUT_TYPE_PGZ    	= 0,
    KODA_OUTPUT_TYPE_SREC   	= 1,
    KODA_OUTPUT_TYPE_BIN		= 2,
};

typedef struct koda_embed_t {
	char *name;
	char *source_file;
} koda_embed_t;

typedef struct koda_compiler_options_t {
	char *input_files[32];
	int input_files_count;

	int output_type;
	char *output_filename;

	int generate_labels;
	char *labels_filename;

	koda_embed_t embed_files[32];
	int embed_files_count;

	int no_optimize;
	int debug;

	int text_start_address;
	int data_start_address;
	int text_size;
	int data_size;
} koda_compiler_options_t;


int koda_compile(koda_compiler_options_t *options);

#if PLATFORM_WIN
	int koda_opcode_arg_count(int opcode);
	const char *koda_opcode_name(int opcode);
	int koda_compile_to_bytecode(koda_compiler_options_t *options, const char *name, const char *code_string, int **bytecode_output, int *bytecode_len);
#endif

#endif