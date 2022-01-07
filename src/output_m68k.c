
/**
 * VSM Machine
 *
 * Description:
 * - S will denote the stack
 * - I will denote the instruction pointer
 * - P will denote the stack pointer
 * - F will denote the frame pointer
 * - S0 will denote the element on top of the stack
 * - S1 will denote the second element on the stack
 * - decrementing P will add an element to the stack
 * - incrementing P will remove an element from the stack
 * - w, v will indicate machine words
 * - a will indicate an address (which has to be relocated)
 * - [x] will indicate the value at address x
 * - b[x] will indicate the unsigned char at address x
 *
 * Note 680000
 * - Word and long-word operands must be aligned on word boundaries (even addresses)
 */

#define CG_INIT         ""
#define CG_PUSH         "2F00"                  // P: = P − 1; S0: = A
#define CG_LDVAL        /*"2f00*/"203C,w"           // P: = P − 1; S0: = A; A: = w
#define CG_LDADDR       /*"2f00*/"203C,a"           // P: = P − 1; S0: = A; A: = a
#define CG_LDLOCALREF   /*"2f00*/"200ED0BC,w"       // P: = P − 1; S0: = A; A: = F + w
#define CG_LDGLOBAL     /*"2f00*/"2039,a"           // P: = P − 1; S0: = A; A: = [a]
#define CG_LDLOCAL      /*"2f00*/"202E,l"           // P: = P − 1; S0: = A; A: = [F + w]
#define CG_CLEAR        "7000"                  // A: = 0
#define CG_STGLOB       "23C0,a201F"            // [a]: = A; A: = S0; P: = P + 1
#define CG_STLOCL       "2F40,l201F"            // [F + w]: = A; A: = S0; P: = P + 1
#define CG_STINDR       "2A5F2A80"              // [S0]: = A; P: = P + 1
#define CG_STINDB       "2A5F1A80"              // b[S0]: = A; P: = P + 1
#define CG_ALLOC        "9FFC,w"                // P: = P − w
#define CG_DEALLOC      "DFFC,w"                // P: = P + w
#define CG_LOCLVEC      "2A4f2F0D"              // w: = P; P: = P − 1; S0: = w
#define CG_GLOBVEC      "23CD,a"                // [a]: = P
#define CG_HALT         "223C,w70004E4F"
#define CG_INDEX        "221FE588D081"          // A: = 4 ⋅ A + S0; P: = P + 1
#define CG_DEREF        "2A402015"              // A: = [A]
#define CG_INDXB        "221FD081"              // A: = A + S0; P: = P + 1
#define CG_DREFB        "2A4070001015"
#define CG_CALL         "4EB9,w"
#define CG_MARK         ",m"
#define CG_JUMPFWD      "6000,>"
#define CG_JUMPBACK     "6000,<"
#define CG_ENTER        "2F0E2C4F"
#define CG_EXIT         "2C5F4E75"
#define CG_RESOLV       ",r"
#define CG_NEG          "4480"
#define CG_INV          "4680"
#define CG_LOGNOT       "220070004A81660270FF"
#define CG_ADD          "221FD081221FC1419081"
#define CG_SUB          "221FC1419081"
#define CG_MUL          "221F23C100B0302023C000B03024203900B03028"
#define CG_DIV          "221F23C100B0306023C000B03064203900B03068"
#define CG_MOD          "221F23C100B0306023C000B03064203900B0306C"
#define CG_AND          "221FC081"
#define CG_OR           "221F8081"
#define CG_XOR          "221FB380"
#define CG_SHL          ""
#define CG_SHR          ""
#define CG_EQ           "221F24007000B481660270FF"
#define CG_NEQ          "221F24007000B481670270FF"
#define CG_LT           ""
#define CG_GT           ""
#define CG_LE           ""
#define CG_GE           ""
#define CG_JMPFALSE     "4A806700,>"
#define CG_JMPTRUE      "4A806600,>"
#define CG_FOR          "221FB0816C00,>"
#define CG_INCGLOB      "52B9,a"
#define CG_INCLOCL      "52AE,l"

#define CG_P_SYSCALL0   "2F002F0E202F000C4E4F2C5F201F4E75"
#define CG_P_SYSCALL1   "2F002F0E222F000C202F00104E4F2C5F201F4E75"
#define CG_P_SYSCALL2   "2F002F0E242F000C222F0010202F00144E4F2C5F201F4E75"
#define CG_P_SYSCALL3   "2F002F0E262F000C242F0010222F0014202F00184E4F2C5F201F4E75"



void write_output_word(int x);
void write_output_byte(unsigned char ch);


void write_pgz_header(void)
{
    write_output_byte('z');

    // write initial start segment
    write_output_word(TEXT_VADDR);      // start address
    write_output_word(0);               // size
}

void write_pgz_segment(int load_address, unsigned char *start, int size)
{
    write_output_word(load_address);
    write_output_word(size);

#ifdef PLATFORM_WIN
    fwrite(start, size, 1, _output_target);
#else
    #error "Platform not supported"
#endif
}

void write_srec_byte(unsigned char data)
{
    unsigned char output[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#ifdef PLATFORM_WIN
    write_output_byte(output[(data >> 4) & 0x0F]);
    write_output_byte(output[data & 0x0F]);
#endif
}

void write_srec_word(int data)
{
    write_srec_byte((data >> 24) & 0xFF);
    write_srec_byte((data >> 16) & 0xFF);
    write_srec_byte((data >> 8) & 0xFF);
    write_srec_byte(data & 0xFF);
}

void write_srec_header(void)
{
#ifdef PLATFORM_WIN
    fprintf(_output_target, "S00B00007365673130303030C4\n");
#endif  
}

void write_srec_record(unsigned char *data, int address, int byte_count)
{
#ifdef PLATFORM_WIN
    fprintf(_output_target, "S3");
#endif

    int data_count = byte_count + 5;
    int checksum = data_count & 0xFF;
    checksum += (address >> 24) & 0xFF;
    checksum += (address >> 16) & 0xFF;
    checksum += (address >> 8) & 0xFF;
    checksum += address & 0xFF;

    write_srec_byte(data_count);
    write_srec_word(address);

    for (int i = 0; i < byte_count; ++i)
    {
        unsigned char byte = data[i];
        write_srec_byte(byte);
        checksum += byte;
    }

    write_srec_byte((checksum & 0xFF) ^ 0xFF);
    write_output_byte('\n');
}

void write_srec_segment(int load_address, unsigned char *start, int size)
{
    int pos = 0;
    int address = load_address;

    while (pos < size)
    {
        int len = size - pos < 32 ? size - pos : 32;
        write_srec_record(start, address, len);

        pos += len;
        start += len;
        address += len;
    }
}
