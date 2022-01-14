
#ifndef T3X_H
#define T3X_H

enum {
	T3X_OUTPUT_TYPE_PGZ    = 0,
    T3X_OUTPUT_TYPE_SREC   = 1,
};

typedef struct t3x_compiler_options_t {
	char *input_files[32];
	int input_files_count;

	int output_type;
	char *output_filename;

	int generate_labels;
	char *labels_filename;
} t3x_compiler_options_t;


int t3x_compile(t3x_compiler_options_t *options);


#endif