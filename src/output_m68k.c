
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

#define CG_INIT             "202F0004222F00082E7C,w2F002F01"
#define CG_PUSH             "2F00"                  // P: = P − 1; S0: = A
#define CG_LDVAL            "203C,w"                // P: = P − 1; S0: = A; A: = w
#define CG_LDVAL_SHORT      "70,b"
#define CG_LDVAL_SP         "2F3C,w"
#define CG_LDADDR           "203C,a"                // P: = P − 1; S0: = A; A: = a
#define CG_LDADDR_SP        "2F3C,a"
#define CG_LDLOCALREF       "200ED0BC,w"            // P: = P − 1; S0: = A; A: = F + w
#define CG_LDGLOBAL         "2039,a"                // P: = P − 1; S0: = A; A: = [a]
#define CG_LDGLOBAL_SP      "2F39,a"
#define CG_LDLOCAL          "202E,l"                // P: = P − 1; S0: = A; A: = [F + w]
#define CG_LDLOCAL_SP       "2F2E,l"
#define CG_CLEAR            "7000"                  // A: = 0
#define CG_STGLOB           "23C0,a"                // [a]: = A; A: = S0; P: = P + 1
#define CG_STLOCL           "2D40,l"                // [F + w]: = A; A: = S0; P: = P + 1
#define CG_STINDR           "2A5F2A80"              // [S0]: = A; P: = P + 1
#define CG_STINDB           "2A5F1A80"              // b[S0]: = A; P: = P + 1
#define CG_ALLOC            "9FFC,w"                // P: = P − w
#define CG_DEALLOC          "DFFC,w"                // P: = P + w
#define CG_LOCLVEC          "2A4f2F0D"              // w: = P; P: = P − 1; S0: = w
#define CG_GLOBVEC          "23CF,a"                // [a]: = P
#define CG_HALT             "223C,w70004E4F"
#define CG_INDEX            "221FE588D081"          // A: = 4 ⋅ A + S0; P: = P + 1
#define CG_INDEX_CONSTANT   "E588D0BC,w"
#define CG_DEREF            "2A402015"              // A: = [A]
#define CG_INDXB            "221FD081"              // A: = A + S0; P: = P + 1
#define CG_DREFB            "2A4070001015"
#define CG_CALL             "4EB9,w"
#define CG_MARK             ",m"
#define CG_JUMPFWD          "6000,>"
#define CG_JUMPBACK         "6000,<"
#define CG_ENTER            "2F0E2C4F"
#define CG_EXIT             "2C5F4E75"
#define CG_RESOLV           ",r"
#define CG_NEG              "4480"
#define CG_INV              "4680"
#define CG_LOGNOT           "220070004A81660270FF"
#define CG_ADD              "D09F"
#define CG_SUB              "221FC1419081"
#define CG_MUL              "221F4EB9,w"
#define CG_DIV              "2200201F4EB9,w"
#define CG_MOD              "2200201F4EB9,w2001"
#define CG_AND              "C09F"
#define CG_OR               "809F"
#define CG_XOR              "221FB380"
#define CG_SHL              "221FE1A92001"
#define CG_SHR              "221FE0A92001"
#define CG_EQ               "221F24007000B481660270FF"
#define CG_NEQ              "221F24007000B481670270FF"
#define CG_LT               "221F24007000B4816F0270FF"
#define CG_LE               "221F24007000B4816D0270FF"
#define CG_GT               "221F24007000B4816C0270FF"
#define CG_GE               "221F24007000B4816E0270FF"
#define CG_JMPFALSE         "4A806700,>"
#define CG_JMPTRUE          "4A806600,>"
#define CG_FOR              "221FB2806C00,>"
#define CG_INCGLOB          "52B9,a"
#define CG_INCLOCL          "52AE,l"
#define CG_INC              "2A405295"

#define CG_FUNC_SYSCALL0    "2F002F0E202F000C4E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL1    "2F002F0E222F000C202F00104E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL2    "2F002F0E242F000C222F0010202F00144E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL3    "2F002F0E262F000C242F0010222F0014202F00184E4F2C5F201F4E75"
#define CG_FUNC_MEMSCAN     "222F0004242F0008206F000C22482448D5C1B5C9671276001619B483670260F22009908853804E7570FF4E75"
#define CG_FUNC_MEMCOPY     "206F000C226F0008222F000410D951C9FFFC4E75"

#define CG_MUL32            "2801B1844A806A0244804A816A024481B2BC0000FFFF630CC141B2BC0000FFFF620000203400C4C14840C0C148404A4066000010D0826B00000A4A846A0244804E75700060FA"
#define CG_DIV32            "24012801B1844A806A0244804A816A024481761F22007000D281D1806708B0826B045281908251CBFFF0C1414A846A04448044814E75"


char *_instructions[OP_COUNT] = {
    [OP_INIT] = CG_INIT,
    [OP_PUSH] = CG_PUSH,
    [OP_LDVAL] = CG_LDVAL,
    [OP_LDADDR] = CG_LDADDR,
    [OP_LDLOCALREF] = CG_LDLOCALREF,
    [OP_LDGLOBAL] = CG_LDGLOBAL,
    [OP_LDLOCAL] = CG_LDLOCAL,
    [OP_CLEAR] = CG_CLEAR,
    [OP_STGLOB] = CG_STGLOB,
    [OP_STLOCL] = CG_STLOCL,
    [OP_STINDR] = CG_STINDR,
    [OP_STINDB] = CG_STINDB,
    [OP_ALLOC] = CG_ALLOC,
    [OP_DEALLOC] = CG_DEALLOC,
    [OP_LOCLVEC] = CG_LOCLVEC,
    [OP_GLOBVEC] = CG_GLOBVEC,
    [OP_HALT] = CG_HALT,
    [OP_INDEX] = CG_INDEX,
    [OP_DEREF] = CG_DEREF,
    [OP_INDXB] = CG_INDXB,
    [OP_DREFB] = CG_DREFB,
    [OP_CALL] = CG_CALL,
    [OP_MARK] = CG_MARK,
    [OP_JUMPFWD] = CG_JUMPFWD,
    [OP_JUMPBACK] = CG_JUMPBACK,
    [OP_ENTER] = CG_ENTER,
    [OP_EXIT] = CG_EXIT,
    [OP_RESOLV] = CG_RESOLV,
    [OP_NEG] = CG_NEG,
    [OP_INV] = CG_INV,
    [OP_LOGNOT] = CG_LOGNOT,
    [OP_ADD] = CG_ADD,
    [OP_SUB] = CG_SUB,
    [OP_MUL] = CG_MUL,
    [OP_DIV] = CG_DIV,
    [OP_MOD] = CG_MOD,
    [OP_AND] = CG_AND,
    [OP_OR] = CG_OR,
    [OP_XOR] = CG_XOR,
    [OP_SHL] = CG_SHL,
    [OP_SHR] = CG_SHR,
    [OP_EQ] = CG_EQ,
    [OP_NEQ] = CG_NEQ,
    [OP_LT] = CG_LT,
    [OP_LE] = CG_LE,
    [OP_GT] = CG_GT,
    [OP_GE] = CG_GE,
    [OP_JMPFALSE] = CG_JMPFALSE,
    [OP_JMPTRUE] = CG_JMPTRUE,
    [OP_FOR] = CG_FOR,
    [OP_INCGLOB] = CG_INCGLOB,
    [OP_INCLOCL] = CG_INCLOCL,
    [OP_INC] = CG_INC,    
};


int _last_opcode = -1;
int _last_value = 0;

int _opcode_queue[2];
int _value_queue[2];
int _queue_len = 0;


void emit_byte(int value);
void emit_short(int value);
void emit_word(int value);

void write_output_word(int x);
void write_output_byte(unsigned char ch);
void emit_code(char *code, int value);
void internal_error(char *message, char *extra);


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

void op_load_value(int value)
{
    if (value < SCHAR_MIN || value > SCHAR_MAX)
        emit_code(CG_LDVAL, value);
    else
        emit_code(CG_LDVAL_SHORT, value);
}

void emit_addq(int value)
{
    emit_short(0x5080 | ((value & 0x07) << 9));
}

void emit_opcode(int opcode, int value)
{
    _last_opcode = -1;
    _last_value = 0;

    switch (opcode)
    {
        case OP_LDVAL:
            op_load_value(value);
            break;

        default:
            emit_code(_instructions[opcode], value);
            break;
    }    
}

void clear_queue(void)
{

}

void push_opcode(int opcode, int value)
{

}



void generate_m68k(int opcode, int value)
{
    // Certain opcodes we must handle right away
    if (opcode == OP_JUMPFWD || opcode == OP_JUMPBACK || opcode == OP_JMPTRUE ||
        opcode == OP_RESOLV || opcode == OP_MARK || opcode == OP_JMPFALSE)
    {
        // Make sure to emit the previous opcode first if we have one
        if (_last_opcode != -1)
            emit_opcode(_last_opcode, _last_value);

        emit_opcode(opcode, value);
        return;
    }

    if (_last_opcode == -1)
    {
        // We did not have a stored opcode
        _last_opcode = opcode;
        _last_value = value;
    }
    else
    {
        // TODO: Could we have a larger buffer of opcodes, and maybe optimize out
        //       constant expressions like '1 + 4'?
        // - We might be able to optimize expressions like 'a + 1' if we replace the OP_LDVAL + OP_PUSH
        //   with a new OP_LDVAL_SP opcode, instead of emitting CG_LDVAL_SP directly.

        if (_last_opcode == OP_LDVAL && opcode == OP_PUSH)          // pushing im value onto stack?
        {
            emit_code(CG_LDVAL_SP, _last_value);
            _last_opcode = -1;
        }
        else if (_last_opcode == OP_LDLOCAL && opcode == OP_PUSH)   // pushing local val onto stack?
        {
            emit_code(CG_LDLOCAL_SP, _last_value);
            _last_opcode = -1;
        }
        else if (_last_opcode == OP_LDADDR && opcode == OP_PUSH)
        {
            emit_code(CG_LDADDR_SP, _last_value);
            _last_opcode = -1;
        }
        else if (_last_opcode == OP_LDGLOBAL && opcode == OP_PUSH)
        {
            emit_code(CG_LDGLOBAL_SP, _last_value);
            _last_opcode = -1;
        }
        else if (_last_opcode == OP_LDVAL && opcode == OP_ADD)
        {
            if (_last_value >= 0 && _last_value < 8)
            {
                emit_addq(_last_value);
            }
            else
            {
                emit_opcode(_last_opcode, _last_value);
                emit_opcode(opcode, value);
            }

            _last_opcode = -1;
        }
        else
        {
            // We could not optimize the expression any more so first emit the old opcode
            // and then store the new one
            emit_opcode(_last_opcode, _last_value);

            _last_opcode = opcode;
            _last_value = value;
        }
    }
}

void clear_opcode_generation(void)
{
    if (_last_opcode != -1)
        emit_opcode(_last_opcode, _last_value);
}




