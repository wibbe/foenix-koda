#ifndef PLATFORM_WIN
	#error "Standalone mode not supported on the platform"
#endif	


#include <stdio.h>
#include <string.h>

#include "koda.h"


void print_usage(char *name)
{
    printf("usage: %s [-o <output>] [--pgz/-p] [--srec/-s] [--labels/-l <labels-file>] <input-file...>\n", name);
}

int main(int argc, char *argv[])
{
	koda_compiler_options_t options = {0};

    if (argc == 1)
    {
        print_usage(argv[0]);
        return 1;
    }

    // Parse arguments
    int arg = 1;
    while (arg < argc)
    {     
        if (strcmp(argv[arg], "--pgz") == 0 || strcmp(argv[arg], "-p") == 0)
        {
            options.output_type = KODA_OUTPUT_TYPE_PGZ;
            arg++;
            continue;
        }
        if (strcmp(argv[arg], "--srec") == 0 || strcmp(argv[arg], "-s") == 0)
        {
            options.output_type = KODA_OUTPUT_TYPE_SREC;
            arg++;
            continue;
        }       

        if (strcmp(argv[arg], "--usage") == 0 || strcmp(argv[arg], "-u") == 0)
        {
            options.print_usage_statistics = 1;
            arg++;
            continue;
        }

        if (strcmp(argv[arg], "--nostdlib") == 0)
        {
            options.no_stdlib = 1;
            arg++;
            continue;
        }

        if (strcmp(argv[arg], "-o") == 0)
        {
            if (arg >= argc - 1)
            {
                printf("error: missing output filename\n");
                print_usage(argv[0]);
                return 1;
            }
            options.output_filename = argv[arg + 1];
            arg += 2;
            continue;
        }

        if (strcmp(argv[arg], "--labels") == 0 || strcmp(argv[arg], "-l") == 0)
        {
            if (arg >= argc - 1)
            {
                printf("error: missing label filename\n");
                print_usage(argv[0]);
                return 1;
            }
            options.generate_labels = 1;
            options.labels_filename = argv[arg + 1];
            arg += 2;
            continue;
        }

        // Must be input file
        options.input_files[options.input_files_count++] = argv[arg];
        arg++;
    }

    // Check arguments

    if (options.output_filename == NULL)
    {
        printf("Error: missing output file\n");
        print_usage(argv[0]);
        return 1;
    }

    if (options.input_files_count == 0)
    {
        printf("error: no input files to compile\n");
        print_usage(argv[0]);
        return 1;
    }

    koda_compile(&options);
    return 0;
}