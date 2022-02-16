#ifndef PLATFORM_WIN
	#error "Standalone mode not supported on the platform"
#endif	


#include <stdio.h>
#include <string.h>

#include "koda.h"


void print_usage(char *name)
{
    printf("Usage: %s [options] [input files] ...\n", name);
    printf("Options:\n");
    printf("  -o FILE                 Specify the output file.\n");
    printf("  -p, --pgz               Generated file will be in PGZ binary format.\n");
    printf("  -s, --srec              Generated file will be in Motorola S68 text format.\n");
    printf("  -b, --bin               Generated plain binary file, will only contain the text segment.\n");
    printf("  -O0                     Turn off optimizations.\n");
    printf("  -l FILE, --labels FILE  Generate a labels file.\n");
    printf("  -d, --debug             Print debug information about the generated code.\n");
    printf("  --embed NAME FILE       Embed the specified file into the generated executable.\n");
    printf("                          This will also create a global variable with the specified\n");
    printf("                          name that points to the embedded data.\n");
}

int main(int argc, char *argv[])
{
	koda_compiler_options_t options = {
        .text_size = 0x10000,               // 64K of memory for the text segment
        .data_size = 0x20000,               // 128K of memory for the data segment
        .text_start_address = 0x00020000,
        .data_start_address = 0x00040000,
    };

    if (argc == 1)
    {
        print_usage(argv[0]);
        return 1;
    }

    // TODO: Add a build argument, that will read and parse a custom build.k file that specifies all the
    //       various build options.

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
        if (strcmp(argv[arg], "--bin") == 0 || strcmp(argv[arg], "-b") == 0)
        {
            options.output_type = KODA_OUTPUT_TYPE_BIN;
            arg++;
            continue;            
        }

        if (strcmp(argv[arg], "--debug") == 0 || strcmp(argv[arg], "-d") == 0)
        {
            options.debug = 1;
            arg++;
            continue;
        }

        if (strcmp(argv[arg], "-O0") == 0)
        {
            options.no_optimize = 1;
            arg++;
            continue;
        }

        if (strcmp(argv[arg], "-o") == 0)
        {
            if (arg >= argc - 1)
            {
                printf("Error: missing output filename\n");
                print_usage(argv[0]);
                return 1;
            }
            options.output_filename = argv[arg + 1];
            arg += 2;
            continue;
        }

        if (strcmp(argv[arg], "--embed") == 0)
        {
            if (arg >= argc - 2)
            {
                printf("Error: missing embed file parameters");
                print_usage(argv[0]);
                return 1;
            }

            options.embed_files[options.embed_files_count].name = argv[arg + 1];
            options.embed_files[options.embed_files_count++].source_file = argv[arg + 2];
            arg += 3;
            continue;
        }

        if (strcmp(argv[arg], "--labels") == 0 || strcmp(argv[arg], "-l") == 0)
        {
            if (arg >= argc - 1)
            {
                printf("Error: missing label filename\n");
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
        printf("Error: no input files to compile\n");
        print_usage(argv[0]);
        return 1;
    }

    koda_compile(&options);
    return 0;
}