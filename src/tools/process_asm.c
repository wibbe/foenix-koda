
#include <stdio.h>
#include <string.h>
#include <ctype.h>

enum {
	IN_SIZE	= 2048,
};

unsigned char LONG_VALUE[] = { 0xBE, 0xEF, 0xFE, 0xED };
unsigned char WORD_VALUE[] = { 0x1B, 0xEF };
unsigned char ADDRESS[] = { 0x12, 0x34, 0x56, 0x78 };
unsigned char JUMP_FWD[] = { 0x2B, 0xED };
unsigned char JUMP_BACK[] = { 0x3B, 0xED };

void write_byte(FILE *out, int data)
{
    unsigned char output[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    fputc(output[(data >> 4) & 0x0F], out);
    fputc(output[data & 0x0F], out);
}

void write_buffer(FILE *out, unsigned char *buffer, int len)
{
	for (int i = 0; i < len; ++i)
		write_byte(out, buffer[i]);
}

int main(int argc, char *argv[])
{
	unsigned char in_data[IN_SIZE];

	FILE *in = fopen(argv[1], "r");
	if (in == NULL)
	{
		fprintf(stderr, "Error: Could not open %s\n", argv[1]);
		return 1;
	}

	int in_len = fread(in_data, 1, IN_SIZE, in);
	fclose(in);

	FILE *out = fopen(argv[2], "w");

	fprintf(out, "#define INST_");
	char *ptr = argv[3];
	while (*ptr != '\0')
	{
		fputc(toupper(*ptr), out);
		ptr++;
	}

	fprintf(out, " \"");

	int it = 0;
	while (it < in_len)
	{
		int len = in_len - it;
		if (len >= 4 && memcmp(&in_data[it], LONG_VALUE, 4) == 0)
		{
			fputc(',', out);
			fputc('l', out);
			it += 4;
		}
		else if (len >= 4 && memcmp(&in_data[it], ADDRESS, 4) == 0)
		{
			fputc(',', out);
			fputc('a', out);
			it += 4;			
		}
		else if (len >= 2 && memcmp(&in_data[it], WORD_VALUE, 2) == 0)
		{
			fputc(',', out);
			fputc('w', out);
			it += 2;
		}
		else if (len >= 2 && memcmp(&in_data[it], JUMP_FWD, 2) == 0)
		{
			fputc(',', out);
			fputc('>', out);
			it += 2;
		}
		else if (len >= 2 && memcmp(&in_data[it], JUMP_BACK, 2) == 0)
		{
			fputc(',', out);
			fputc('<', out);
			it += 2;
		}
		else
		{
			write_byte(out, in_data[it]);
			it += 1;
		}
	}

	fprintf(out, "\"\n");
	fclose(in);
	fclose(out);

	return 0;
}