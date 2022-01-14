
#ifndef KODA_H
#define KODA_H

enum {
	KODA_OUTPUT_TYPE_PGZ    = 0,
    KODA_OUTPUT_TYPE_SREC   = 1,
};

typedef struct t3x_compiler_options_t {
	char *input_files[32];
	int input_files_count;

	int output_type;
	char *output_filename;

	int generate_labels;
	char *labels_filename;

	int print_usage_statistics;
} koda_compiler_options_t;


int koda_compile(koda_compiler_options_t *options);


#endif