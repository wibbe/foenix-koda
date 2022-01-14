
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

#define CG_INIT         "202F0004222F00082E7C,w2F002F01"
#define CG_PUSH         "2F00"                  // P: = P − 1; S0: = A
#define CG_LDVAL        "203C,w"                // P: = P − 1; S0: = A; A: = w
#define CG_LDADDR       "203C,a"                // P: = P − 1; S0: = A; A: = a
#define CG_LDLOCALREF   "200ED0BC,w"            // P: = P − 1; S0: = A; A: = F + w
#define CG_LDGLOBAL     "2039,a"                // P: = P − 1; S0: = A; A: = [a]
#define CG_LDLOCAL      "202E,l"                // P: = P − 1; S0: = A; A: = [F + w]
#define CG_CLEAR        "7000"                  // A: = 0
#define CG_STGLOB       "23C0,a"                // [a]: = A; A: = S0; P: = P + 1
#define CG_STLOCL       "2D40,l"                // [F + w]: = A; A: = S0; P: = P + 1
#define CG_STINDR       "2A5F2A80"              // [S0]: = A; P: = P + 1
#define CG_STINDB       "2A5F1A80"              // b[S0]: = A; P: = P + 1
#define CG_ALLOC        "9FFC,w"                // P: = P − w
#define CG_DEALLOC      "DFFC,w"                // P: = P + w
#define CG_LOCLVEC      "2A4f2F0D"              // w: = P; P: = P − 1; S0: = w
#define CG_GLOBVEC      "23CF,a"                // [a]: = P
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
#define CG_ADD          "221FD081"
#define CG_SUB          "221FC1419081"
#define CG_MUL          "221F4EB9,w"
#define CG_DIV          "2200201F4EB9,w"
#define CG_MOD          "2200201F4EB9,w2001"
#define CG_AND          "221FC081"
#define CG_OR           "221F8081"
#define CG_XOR          "221FB380"
#define CG_SHL          "221FE1A92001"
#define CG_SHR          "221FE0A92001"
#define CG_EQ           "221F24007000B481660270FF"
#define CG_NEQ          "221F24007000B481670270FF"
#define CG_LT           "221F24007000B4816F0270FF"
#define CG_LE           "221F24007000B4816D0270FF"
#define CG_GT           "221F24007000B4816C0270FF"
#define CG_GE           "221F24007000B4816E0270FF"
#define CG_JMPFALSE     "4A806700,>"
#define CG_JMPTRUE      "4A806600,>"
#define CG_FOR          "221FB2806C00,>"
#define CG_INCGLOB      "52B9,a"
#define CG_INCLOCL      "52AE,l"
#define CG_INC          "2A405295"

#define CG_FUNC_SYSCALL0    "2F002F0E202F000C4E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL1    "2F002F0E222F000C202F00104E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL2    "2F002F0E242F000C222F0010202F00144E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL3    "2F002F0E262F000C242F0010222F0014202F00184E4F2C5F201F4E75"
#define CG_FUNC_MEMSCAN     "222F0004242F0008206F000C22482448D5C1B5C9671276001619B483670260F22009908853804E7570FF4E75"
#define CG_FUNC_MEMCOPY     "206F000C226F0008222F000410D951C9FFFC4E75"

#define CG_MUL32            "2801B1844A806A0244804A816A024481B2BC0000FFFF630CC141B2BC0000FFFF620000203400C4C14840C0C148404A4066000010D0826B00000A4A846A0244804E75700060FA"
#define CG_DIV32            "24012801B1844A806A0244804A816A024481761F22007000D281D1806708B0826B045281908251CBFFF0C1414A846A04448044814E75"

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
    sys_chan_write(_output_channel, start, size);
#endif
}

void write_srec_byte(unsigned char data)
{
    unsigned char output[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    write_output_byte(output[(data >> 4) & 0x0F]);
    write_output_byte(output[data & 0x0F]);
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
    const char *header = "S00B00007365673130303030C4\n";
#ifdef PLATFORM_WIN
    fprintf(_output_target, header);
#else
    sys_chan_write(_output_channel, (char *)header, strlen(header));
#endif  
}

void write_srec_record(unsigned char *data, int address, int byte_count)
{
#ifdef PLATFORM_WIN
    fprintf(_output_target, "S3");
#else
    sys_chan_write(_output_channel, "S3", 2);    
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
