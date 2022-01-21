
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#if PLATFORM_FOENIX
    #include "foenix/syscall.h"
    #include "foenix/heap.h"
#endif

#include "foenix_stdlib.h"
#include "koda.h"


#define CG_INIT             "202F0004222F00082E7C,l2F002F01"
#define CG_PUSH             "2F00"                  // P: = P − 1; S0: = A
#define CG_LDVAL            "203C,l"                // P: = P − 1; S0: = A; A: = w
#define CG_LDVAL_SHORT      "70,b"
#define CG_LDVAL_SP         "2F3C,l"
#define CG_LDADDR           "203C,a"                // P: = P − 1; S0: = A; A: = a
#define CG_LDADDR_SP        "2F3C,a"
#define CG_LDLOCALREF       "200ED0BC,l"            // P: = P − 1; S0: = A; A: = F + w
#define CG_LDGLOBAL         "2039,a"                // P: = P − 1; S0: = A; A: = [a]
#define CG_LDGLOBAL_SP      "2F39,a"
#define CG_LDLOCAL          "202E,w"                // P: = P − 1; S0: = A; A: = [F + w]
#define CG_LDLOCAL_SP       "2F2E,w"
#define CG_CLEAR            "7000"                  // A: = 0
#define CG_STGLOB           "23C0,a"                // [a]: = A; A: = S0; P: = P + 1
#define CG_STLOCL           "2D40,w"                // [F + w]: = A; A: = S0; P: = P + 1
#define CG_STINDR           "2A5F2A80"              // [S0]: = A; P: = P + 1
#define CG_STINDB           "2A5F1A80"              // b[S0]: = A; P: = P + 1
#define CG_ALLOC            "9FFC,l"                // P: = P − w
#define CG_DEALLOC          "DFFC,l"                // P: = P + w
#define CG_LOCLVEC          "2A4f2F0D"              // w: = P; P: = P − 1; S0: = w
#define CG_GLOBVEC          "23CF,a"                // [a]: = P
#define CG_HALT             "223C,l70004E4F"
#define CG_INDEX            "221FE588D081"          // A: = 4 ⋅ A + S0; P: = P + 1
#define CG_INDEX_CONSTANT   "D0BC,l"
#define CG_DEREF            "2A402015"              // A: = [A]
#define CG_INDXB            "221FD081"              // A: = A + S0; P: = P + 1
#define CG_DREFB            "2A4070001015"
#define CG_CALL             "4EB9,a"
#define CG_JUMPFWD          "6000,>"
#define CG_JUMPBACK         "6000,<"
#define CG_JUMP_TARGET      ",r"
#define CG_ENTER            "2F0E2C4F"
#define CG_EXIT             "2C5F4E75"
#define CG_NEG              "4480"
#define CG_INV              "4680"
#define CG_LOGNOT           "220070004A81660270FF"
#define CG_ADD              "D09F"
#define CG_ADD_CONSTANT     "D0BC,l"
#define CG_SUB              "221FC1419081"
#define CG_MUL              "221F4EB9,a"
#define CG_DIV              "2200201F4EB9,a"
#define CG_MOD              "2200201F4EB9,a2001"
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
#define CG_INCGLOB          "52B9,a"
#define CG_INCLOCL          "52AE,w"
#define CG_INC              "2A405295"

#define CG_FUNC_SYSCALL0    "2F002F0E202F000C4E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL1    "2F002F0E222F000C202F00104E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL2    "2F002F0E242F000C222F0010202F00144E4F2C5F201F4E75"
#define CG_FUNC_SYSCALL3    "2F002F0E262F000C242F0010222F0014202F00184E4F2C5F201F4E75"
#define CG_FUNC_MEMSCAN     "222F0004242F0008206F000C22482448D5C1B5C9671276001619B483670260F22009908853804E7570FF4E75"
#define CG_FUNC_MEMCOPY     "206F000C226F0008222F000410D951C9FFFC4E75"

#define CG_MUL32            "2801B1844A806A0244804A816A024481B2BC0000FFFF630CC141B2BC0000FFFF620000203400C4C14840C0C148404A4066000010D0826B00000A4A846A0244804E75700060FA"
#define CG_DIV32            "24012801B1844A806A0244804A816A024481761F22007000D281D1806708B0826B045281908251CBFFF0C1414A846A04448044814E75"


enum {
    BPW                     = 4,
    PROGRAM_SIZE            = 0xF000,

    TEXT_VADDR              = 0x00020000,
    DATA_VADDR              = 0x00040000,

    TEXT_SIZE               = 0x10000,
    DATA_SIZE               = 0x10000,
    RELOCATION_SIZE         = 10000,
    STACK_SIZE              = 100,
    SYMBOL_TABLE_SIZE       = 2048,
    STRING_TABLE_SIZE       = 8192,

    SYM_GLOBF               = 0x01,
    SYM_CONST               = 0x02,
    SYM_VECTOR              = 0x04,
    SYM_DECLARATION         = 0x08,
    SYM_FUNCTION            = 0x10,
    SYM_MEMORY              = 0x20,

    MAXTBL                  = 1024,
    MAXLOOP                 = 100,

    TOKEN_LEN               = 128,

    HEAP_START              = 0x00060000,
    HEAP_END                = 0x00100000,
    INITIAL_STACK_SIZE      = 0x40000,          // Reserve space for a 256k stack
};

enum {
    ENDFILE = -1,
    SYMBOL = 100, 
    INTEGER, 
    STRING,
    ADDROF = 200, 
    ASSIGN, 
    BINOP, 
    BYTEOP, 
    COLON, 
    COMMA, 
    COND,
    CONJ, 
    DISJ,
    LBRACK, 
    LPAREN, 
    RBRACK, 
    RPAREN, 
    UNOP,
    BLOCK_START, 
    BLOCK_END,
    KCONST, 
    KDECL, 
    KELSE, 
    KFUNC,
    KHALT, 
    KIF,
    KMAIN,
    KLEAVE, 
    KLOOP, 
    KRETURN, 
    KSTRUCT, 
    KVAR,
    KWHILE
};

enum {
    OP_NONE,
    OP_INIT,
    OP_PUSH,
    OP_LDVAL,
    OP_LDADDR,
    OP_LDLOCALREF,
    OP_LDGLOBAL,
    OP_LDLOCAL,
    OP_CLEAR,
    OP_STGLOB,
    OP_STLOCL,
    OP_STINDR,
    OP_STINDB,
    OP_ALLOC,
    OP_DEALLOC,
    OP_LOCLVEC,
    OP_GLOBVEC,
    OP_HALT,
    OP_INDEX,
    OP_DEREF,
    OP_INDXB,
    OP_DREFB,
    OP_CALL,
    OP_JUMPFWD,
    OP_JUMPBACK,
    OP_ENTER,
    OP_EXIT,
    OP_NEG,
    OP_INV,
    OP_LOGNOT,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_SHL,
    OP_SHR,
    OP_EQ,
    OP_NEQ,
    OP_LT,
    OP_LE,
    OP_GT,
    OP_GE,
    OP_JMPFALSE,
    OP_JMPTRUE,
    OP_INCGLOB,
    OP_INCLOCL,
    OP_INC,

    // Special opcodes used internally for optimization
    OP_ASM,                 // We have a blob of assembly code
    OP_JUMP_TARGET,
    OP_ALLOC_MEM,
    OP_WRITE_32,

    OP_LDVAL_SHORT,
    OP_LDVAL_STACK,
    OP_LDADDR_STACK,
    OP_LDGLOBAL_STACK,
    OP_LDLOCAL_STACK,

    OP_ADD_CONSTANT,
    OP_INDEX_CONSTANT,

    OP_COUNT,
};

char *_opcode_names[OP_COUNT] = {
    [OP_INIT] = "OP_INIT",
    [OP_PUSH] = "OP_PUSH",
    [OP_LDVAL] = "OP_LDVAL",
    [OP_LDADDR] = "OP_LDADDR",
    [OP_LDLOCALREF] = "OP_LDLOCALREF",
    [OP_LDGLOBAL] = "OP_LDGLOBAL",
    [OP_LDLOCAL] = "OP_LDLOCAL",
    [OP_CLEAR] = "OP_CLEAR",
    [OP_STGLOB] = "OP_STGLOB",
    [OP_STLOCL] = "OP_STLOCL",
    [OP_STINDR] = "OP_STINDR",
    [OP_STINDB] = "OP_STINDB",
    [OP_ALLOC] = "OP_ALLOC",
    [OP_DEALLOC] = "OP_DEALLOC",
    [OP_LOCLVEC] = "OP_LOCLVEC",
    [OP_GLOBVEC] = "OP_GLOBVEC",
    [OP_HALT] = "OP_HALT",
    [OP_INDEX] = "OP_INDEX",
    [OP_DEREF] = "OP_DEREF",
    [OP_INDXB] = "OP_INDXB",
    [OP_DREFB] = "OP_DREFB",
    [OP_CALL] = "OP_CALL",
    [OP_JUMPFWD] = "OP_JUMPFWD",
    [OP_JUMPBACK] = "OP_JUMPBACK",
    [OP_ENTER] = "OP_ENTER",
    [OP_EXIT] = "OP_EXIT",
    [OP_NEG] = "OP_NEG",
    [OP_INV] = "OP_INV",
    [OP_LOGNOT] = "OP_LOGNOT",
    [OP_ADD] = "OP_ADD",
    [OP_SUB] = "OP_SUB",
    [OP_MUL] = "OP_MUL",
    [OP_DIV] = "OP_DIV",
    [OP_MOD] = "OP_MOD",
    [OP_AND] = "OP_AND",
    [OP_OR] = "OP_OR",
    [OP_XOR] = "OP_XOR",
    [OP_SHL] = "OP_SHL",
    [OP_SHR] = "OP_SHR",
    [OP_EQ] = "OP_EQ",
    [OP_NEQ] = "OP_NEQ",
    [OP_LT] = "OP_LT",
    [OP_LE] = "OP_LE",
    [OP_GT] = "OP_GT",
    [OP_GE] = "OP_GE",
    [OP_JMPFALSE] = "OP_JMPFALSE",
    [OP_JMPTRUE] = "OP_JMPTRUE",
    [OP_INCGLOB] = "OP_INCGLOB",
    [OP_INCLOCL] = "OP_INCLOCL",
    [OP_INC] = "OP_INC",
    [OP_ASM] = "OP_ASM",
    [OP_JUMP_TARGET] = "OP_JUMP_TARGET",
    [OP_ALLOC_MEM] = "OP_ALLOC_MEM",
    [OP_WRITE_32] = "OP_WRITE_32",
    [OP_LDVAL_SHORT] = "OP_LDVAL_SHORT",
    [OP_LDVAL_STACK] = "OP_LDVAL_STACK",
    [OP_LDADDR_STACK] = "OP_LDADDR_STACK",
    [OP_LDGLOBAL_STACK] = "OP_LDGLOBAL_STACK",
    [OP_LDLOCAL_STACK] = "OP_LDLOCAL_STACK",
    [OP_ADD_CONSTANT] = "OP_ADD_CONSTANT",
    [OP_INDEX_CONSTANT] = "OP_INDEX_CONSTANT",
};

char *_opcode_to_machine_code[OP_COUNT] = {
    [OP_INIT] = CG_INIT,
    [OP_PUSH] = CG_PUSH,
    [OP_LDVAL] = CG_LDVAL,
    [OP_LDVAL_STACK] = CG_LDVAL_SP,
    [OP_LDADDR] = CG_LDADDR,
    [OP_LDADDR_STACK] = CG_LDADDR_SP,
    [OP_LDLOCALREF] = CG_LDLOCALREF,
    [OP_LDGLOBAL] = CG_LDGLOBAL,
    [OP_LDGLOBAL_STACK] = CG_LDGLOBAL_SP,
    [OP_LDLOCAL] = CG_LDLOCAL,
    [OP_LDLOCAL_STACK] = CG_LDLOCAL_SP,
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
    [OP_INDEX_CONSTANT] = CG_INDEX_CONSTANT,
    [OP_DEREF] = CG_DEREF,
    [OP_INDXB] = CG_INDXB,
    [OP_DREFB] = CG_DREFB,
    [OP_CALL] = CG_CALL,
    [OP_JUMPFWD] = CG_JUMPFWD,
    [OP_JUMPBACK] = CG_JUMPBACK,
    [OP_JUMP_TARGET] = CG_JUMP_TARGET,
    [OP_ENTER] = CG_ENTER,
    [OP_EXIT] = CG_EXIT,
    [OP_NEG] = CG_NEG,
    [OP_INV] = CG_INV,
    [OP_LOGNOT] = CG_LOGNOT,
    [OP_ADD] = CG_ADD,
    [OP_ADD_CONSTANT] = CG_ADD_CONSTANT,
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
    [OP_INCGLOB] = CG_INCGLOB,
    [OP_INCLOCL] = CG_INCLOCL,
    [OP_INC] = CG_INC,    
};



typedef struct symbol_t symbol_t;
typedef struct code_t code_t;

typedef unsigned char bool;
#define true 1
#define false 0

struct code_t {
    code_t *next;
    code_t *prev;

    bool used;
    int position;
    unsigned char opcode;


    int value;
    symbol_t *symbol;
    code_t *code;
    char *assembly;
};

struct symbol_t {
    char *name;
    int flags;
    int value;
    bool used;
    code_t *code;
};

typedef struct relocation_t {
    int addr;
    int seg;
} relocation_t;



char *_program_source_file;
int _current_line = 1;
bool _has_main_body = false;

#ifdef PLATFORM_WIN
    static FILE * _output_target = NULL;
#else
    static int _output_channel = 0;
#endif

relocation_t *_relocation_table;

unsigned char *_text_buffer;
unsigned char *_data_buffer;

int _relocation_ptr = 0;
int _text_buffer_ptr = 0;
int _data_buffer_ptr = 0;
int _local_frame_ptr = 0;

int _start_location = 0;

int _accumulator_loaded = 0;

char *_string_table;
int _string_table_ptr = 0;

symbol_t *_symbol_table;
int _symbol_table_ptr = 0;

bool _parsing_function = false;

code_t *_code_start = NULL;
code_t *_current_code = NULL;

code_t *_mul32_code = NULL;
code_t *_div32_code = NULL;

code_t *_loop0 = NULL;
code_t *_leaves[MAXLOOP];
int _leaves_ptr = 0;
code_t *_loops[MAXLOOP];
int _loops_ptr = 0;

koda_compiler_options_t *_options = NULL;


int _div32_routine_address;
int _mul32_routine_address;


void compiler_error(char *message, char *extra)
{
#if PLATFORM_WIN    
    fprintf(stderr, "error: %s(%d): %s", _program_source_file, _current_line + 1, message);
    if (extra != NULL)
        fprintf(stderr, ": %s", extra);
    fputc('\n', stderr);
    exit(1);
#else
    char buff[64];
    snprintf(buff, 64, "error: %s(%d): %s", _program_source_file, _current_line + 1, message);
    sys_chan_write(0, buff, strlen(buff));

    if (extra != NULL)
    {
        sys_chan_write(0, ": ", 2);
        sys_chan_write(0, extra, strlen(extra));
        sys_chan_write_b(0, '\n');
    }
#endif  
}

void internal_error(char *message, char *extra)
{
#if PLATFORM_WIN    
    fprintf(stderr, "internal error\n");
#else
    sys_chan_write(0, "internal error\n", 15);
#endif  
    compiler_error(message, extra);
}


/**
 * Code
 */

code_t *alloc_code(void)
{
#if PLATFORM_WIN
    code_t *code = malloc(sizeof(code_t));
#else
    code_t *code = heap_alloc(sizeof(code_t));
#endif
    memset(code, 0, sizeof(code_t));
    //code->used = true;
    return code;
}

code_t *code_opcode(int opcode)
{
    code_t *code = alloc_code();
    code->opcode = opcode;

    code->prev = _current_code;
    _current_code->next = code;
    _current_code = code;
    return code;     
}

code_t *code_opcode_value(int opcode, int value)
{
    code_t *code = alloc_code();
    code->opcode = opcode;
    code->value = value;

    code->prev = _current_code;
    _current_code->next = code;
    _current_code = code;
    return code;
}

code_t *code_symbol(int opcode, symbol_t *sym)
{
    code_t *code = alloc_code();
    code->opcode = opcode;
    code->symbol = sym;

    code->prev = _current_code;
    _current_code->next = code;
    _current_code = code;
    return code;       
}

code_t *code_symbol_value(int opcode, symbol_t *sym, int value)
{
    code_t *code = alloc_code();
    code->opcode = opcode;
    code->symbol = sym;
    code->value = value;

    code->prev = _current_code;
    _current_code->next = code;
    _current_code = code;
    return code;       
}

code_t *code_asm(symbol_t *func, char *asm_code)
{
    code_t *code = alloc_code();
    code->opcode = OP_ASM;
    code->assembly = asm_code;
    code->symbol = func;
    func->code = code;

    code->prev = _current_code;
    _current_code->next = code;
    _current_code = code;
    return code;       
}

void resolve_jump(code_t *source, code_t *target)
{
    if (target->opcode != OP_JUMP_TARGET)
        internal_error("trying to resolve jump but target is not a jump target", NULL);
    target->code = source;
    source->code = target;
}

void print_code(code_t *code)
{
#if PLATFORM_WIN
    char buffer[64];
    int len = snprintf(buffer, 64, "%c %06X  %s", code->used ? ' ' : '-', code->position, _opcode_names[code->opcode]);

    while (len < 32)
        buffer[len++] = ' ';
    buffer[len] = 0;

    switch (code->opcode)
    {
        case OP_JUMPFWD:
        case OP_JUMPBACK:
        case OP_JMPTRUE:
        case OP_JMPFALSE:
            printf("%s%06X\n", buffer, code->code->position);
            break;

        case OP_CALL:
            printf("%s%s(%d)\n", buffer, code->symbol->name, code->symbol->flags >> 8);
            break;

        case OP_JUMP_TARGET:
            printf("%s%06X\n", buffer, code->code->position);
            break;

        case OP_ASM:
            printf("%s:\n", code->symbol->name);
            printf("%s'%s'\n", buffer, code->assembly);
            break;

        case OP_WRITE_32:
        case OP_ALLOC_MEM:
        case OP_ENTER:
            printf("%s:\n", code->symbol->name);
            printf("%s%d\n", buffer, code->value);
            break;

        case OP_LDADDR:
        case OP_LDADDR_STACK:
            if (code->symbol != NULL)
                printf("%s%s\n", buffer, code->symbol->name);
            else
                printf("%s%06X\n", buffer, code->value);
            break;

        case OP_LDLOCALREF:
        case OP_LDGLOBAL:
        case OP_LDGLOBAL_STACK:
        case OP_LDLOCAL:
        case OP_LDLOCAL_STACK:
        case OP_STGLOB:
        case OP_STLOCL:
        case OP_GLOBVEC:
            if (code->symbol != NULL)
                printf("%s%s\n", buffer, code->symbol->name);
            else
                printf("%s%d\n", buffer, code->value);
            break;

        default:
            printf("%s%d\n", buffer, code->value);
            break;
    }
#endif    
}

bool has_next(code_t *code)
{
    return code->next != NULL;
}

bool has_prev(code_t *code)
{
    return code->prev != NULL;
}

void remove_next(code_t *code)
{
    if (code->next == NULL)
        return;

    code_t *prev = code;
    code_t *next = code->next->next;

    prev->next = next;
    if (next != NULL)
        next->prev = prev;
}


void optimize_remove_dead_code(void)
{
    // Mark all code as unused
    for (code_t *it = _code_start; it != NULL; it = it->next)
        it->used = false;

    // Special pass to handle mul32 and div32 asm code
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (it->opcode == OP_MUL)
            _mul32_code->used = true;
        else if (it->opcode == OP_DIV || it->opcode == OP_MOD)
            _div32_code->used = true;
    }

    code_t *call_stack[64];
    int call_stack_ptr = 0;
    code_t *pc = _code_start;
    int conditional_jump_count[64] = {0};


    // Step through all instructions, marking the ones that will actually be used.
    while (pc != NULL)
    {
        pc->used = true;

        switch (pc->opcode)
        {
            case OP_JUMPFWD:
                if (conditional_jump_count[call_stack_ptr] == 0)
                    pc = pc->code;
                else
                    pc = pc->next;
                break;

            case OP_JMPFALSE:
            case OP_JMPTRUE:
                conditional_jump_count[call_stack_ptr]++;
                pc = pc->next;
                break;

            case OP_JUMP_TARGET:
                if (pc->code->opcode == OP_JMPTRUE || pc->code->opcode == OP_JMPFALSE)
                    if (conditional_jump_count[call_stack_ptr] > 0)
                        conditional_jump_count[call_stack_ptr]--;
                pc = pc->next;
                break;

            case OP_EXIT:
                if (conditional_jump_count[call_stack_ptr] == 0)
                {
                    pc = call_stack[--call_stack_ptr];
                }
                else
                {
                    pc = pc->next;
                }
                break;

            case OP_STGLOB:
            case OP_GLOBVEC:
            case OP_LDADDR:
            case OP_LDADDR_STACK:            
            case OP_LDGLOBAL:
            case OP_LDGLOBAL_STACK:
                if (pc->symbol != NULL)
                {   
                    if (pc->symbol->code != NULL)
                        pc->symbol->code->used = true;
                }
                pc = pc->next;
                break;

            case OP_CALL:
                {
                    if (pc->symbol->code == NULL)
                        internal_error("No code associated with symbol", pc->symbol->name);

                    if (pc->symbol->code->opcode == OP_ASM)
                    {
                        pc->symbol->code->used = true;
                        pc = pc->next;
                    }
                    else
                    {
                        call_stack[call_stack_ptr++] = pc->next;
                        conditional_jump_count[call_stack_ptr] = 0;
                        pc = pc->symbol->code;
                    }
                }
                break;

            default:
                pc = pc->next;
                break;
        }
    }

    // Finally we remove all the unused instructions
    code_t *it = _code_start;
    while (it != NULL)
    {        
        while (has_next(it) && !it->next->used)
        {
            remove_next(it);
        }
        it = it->next;
    }
}

// Transform LOAD + PUSH to LOAD_STACK instructions
void optimize_load_push(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_LDVAL && it->next->opcode == OP_PUSH)
        {
            it->opcode = OP_LDVAL_STACK;
            remove_next(it);
        }
        else if (it->opcode == OP_LDGLOBAL && it->next->opcode == OP_PUSH)
        {
            it->opcode = OP_LDGLOBAL_STACK;
            remove_next(it);
        }
        else if (it->opcode == OP_LDLOCAL && it->next->opcode == OP_PUSH)
        {
            it->opcode = OP_LDLOCAL_STACK;
            remove_next(it);
        }
        else if (it->opcode == OP_LDADDR && it->next->opcode == OP_PUSH)
        {
            it->opcode = OP_LDADDR_STACK;
            remove_next(it);
        }
    }
}

// Transform LOAD_VALUE + ADD to ADD_CONSTANT
void optimize_load_value_add(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_LDVAL && it->next->opcode == OP_ADD)
        {
            it->opcode = OP_ADD_CONSTANT;
            remove_next(it);
        }
    }
}

// Merge multiple ADD_CONSTANT + PUSH + ADD_CONSTANT instructions
void optimize_merge_add_constant(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it) || !has_next(it->next))
            continue;

        if (it->opcode == OP_ADD_CONSTANT && it->next->opcode == OP_PUSH && it->next->next->opcode == OP_ADD_CONSTANT)
        {
            it->value += it->next->next->value;
            remove_next(it);    // remove OP_PUSH
            remove_next(it);    // remove OP_ADD_CONSTANT

            // Do the optimization again
            it = it->prev;
        }
    }
}

void optimize_remove_constant_addition(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_LDVAL_STACK && it->next->opcode == OP_ADD_CONSTANT)
        {
            it->value += it->next->value;
            remove_next(it);

            // Move to the previous instruction so we can merge multiple adds together
            it = it->prev;
        }
    }
}

// Merge continous jumps
void optimize_jumps(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_JUMP_TARGET && it->next->opcode == OP_JUMPFWD)
        {
            code_t *jump_source = it->code;
            code_t *next_jump_target = it->next->code;

            if (next_jump_target->opcode != OP_JUMP_TARGET)
                internal_error("invalid jump target", NULL);

            // Update jump source code
            jump_source->code = next_jump_target;

            // Update next jump target
            next_jump_target->code = jump_source;

            // Remove it and it->next instructions, they are no longer needed
            code_t *prev = it->prev;
            code_t *next = it->next->next;

            prev->next = next;
            if (next != NULL)
                next->prev = prev;

            // Update it pointer
            it = prev;
        }
        else if (it->opcode == OP_JUMPFWD && it->next->opcode == OP_JUMP_TARGET)
        {   
            // Do we have a jump to the next instruction?
            if (it->code == it->next)
            {
                it = it->prev;
                remove_next(it);
                remove_next(it);
            }
        }
    }
}

// Merge continous calls to OP_ALLOC
void optimize_merge_alloc(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_prev(it))
            continue;

        if (it->prev->opcode == OP_ALLOC && it->opcode == OP_ALLOC)
        {
            // Add the two allocations together
            it->prev->value += it->value;

            // Step back to the last instruction and remove the current one
            it = it->prev;
            remove_next(it);
        }
    }
}

// Transform LOAD_VALUE + INDEX to INDEX_CONSTANT
void optimize_load_value_index(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_LDVAL && it->next->opcode == OP_INDEX)
        {
            it->opcode = OP_INDEX_CONSTANT;
            // Update index value so it's correct
            it->value = it->value * 4;
            remove_next(it);
        }
    }
}

// Remove OP_INDEX_CONSTANT 0 instructions, they do nothing for us
void optimize_index_constant(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (it->opcode == OP_INDEX_CONSTANT && it->value == 0)
        {
            it = it->prev;
            remove_next(it);

            if (it->opcode == OP_LDGLOBAL_STACK || it->opcode == OP_LDLOCAL_STACK)
            {
                if (has_next(it) && it->next->opcode == OP_PUSH)
                    remove_next(it);
            }
        }
    }
}

void optimize_fix_load_value_xxx_constant(void)
{
    // We have been to agressive in transforming OP_LDGLOBL/OP_LDLOCL + OP_PUSH to OP_LDxxx_STACK instructions, so we fix that here.

    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_LDGLOBAL_STACK && it->next->opcode == OP_ADD_CONSTANT)
        {
            it->opcode = OP_LDGLOBAL;
        }
        else if (it->opcode == OP_LDLOCAL_STACK && it->next->opcode == OP_ADD_CONSTANT)
        {
            it->opcode = OP_LDLOCAL;
        }
        else if (it->opcode == OP_LDGLOBAL_STACK && it->next->opcode == OP_INDEX_CONSTANT)
        {
            it->opcode = OP_LDGLOBAL;
        }
        else if (it->opcode == OP_LDLOCAL_STACK && it->next->opcode == OP_INDEX_CONSTANT)
        {
            it->opcode = OP_LDLOCAL;
        }
         else if (it->opcode == OP_LDGLOBAL_STACK && it->next->opcode == OP_DEREF)
        {
            it->opcode = OP_LDGLOBAL;
        }
        else if (it->opcode == OP_LDLOCAL_STACK && it->next->opcode == OP_DEREF)
        {
            it->opcode = OP_LDLOCAL;
        }
    }    
}

void optimize_code(void)
{
    // TODO: Add optimization for OP_STLOCL + OP_LDLOCL combinations
    //       Add new opcode for OP_LDVAL + OP_STLOCL pair

    // The order of these optimization passes are really important, we can not move them around without
    // changing the generated machine code.
    optimize_remove_dead_code();
    optimize_jumps();
    optimize_load_push();
    optimize_load_value_add();
    optimize_merge_add_constant();
    optimize_remove_constant_addition();
    optimize_load_value_index();
    optimize_index_constant();
    optimize_merge_alloc();
    optimize_fix_load_value_xxx_constant();
}

void mark_used_symbols(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        switch (it->opcode)
        {
            case OP_STGLOB:
            case OP_GLOBVEC:
            case OP_LDADDR:
            case OP_LDADDR_STACK:
            case OP_LDGLOBAL:
            case OP_LDGLOBAL_STACK:
                if (it->symbol != NULL)
                    it->symbol->used = true;
                break;

            case OP_CALL:
                if (it->symbol->code == NULL)
                    internal_error("No code associated with symbol", it->symbol->name);
                it->symbol->used = true;
                break;

            case OP_MUL:
                _mul32_code->symbol->used = true;
                it->symbol = _mul32_code->symbol;
                break;

            case OP_DIV:
            case OP_MOD:
                _div32_code->symbol->used = true;
                it->symbol = _div32_code->symbol;
                break;
        }
    }


}



/**
 * String table
 */

char *intern_string(char *str)
{
    int len = strlen(str);
    if (_string_table_ptr + len + 1 > STRING_TABLE_SIZE)
        internal_error("string table full", NULL);

    char *result = &_string_table[_string_table_ptr];
    memcpy(result, str, len + 1);
    _string_table_ptr += len + 1;

    return result;
}


/*
 * Symbol table
 */

symbol_t *find(char *symbol_name)
{
    int i;

    for (i = _symbol_table_ptr - 1; i >= 0; i--)
    {
        if (!strcmp(_symbol_table[i].name, symbol_name))
            return &_symbol_table[i];
    }
    return NULL;
}

symbol_t *lookup(char *symbol_name, int flags)
{
    symbol_t *y;

    y = find(symbol_name);
    if (NULL == y)
        compiler_error("undefined", symbol_name);
    if ((y->flags & flags) != flags)
        compiler_error("unexpected type", symbol_name);

    return y;
}

symbol_t *add(char *symbol_name, int flags, int value)
{
    symbol_t *y;

    y = find(symbol_name);
    if (y != NULL && (y->flags & SYM_GLOBF) == (flags & SYM_GLOBF))
    {
        if (y->flags & SYM_DECLARATION && flags & SYM_FUNCTION)
            return y;
        else
            compiler_error("redefined", symbol_name);
    }

    if (_symbol_table_ptr >= SYMBOL_TABLE_SIZE)
        compiler_error("too many symbols", NULL);

    _symbol_table[_symbol_table_ptr].name = intern_string(symbol_name);
    _symbol_table[_symbol_table_ptr].flags = flags;
    _symbol_table[_symbol_table_ptr].value = value;
    _symbol_table[_symbol_table_ptr].used = false;
    _symbol_table[_symbol_table_ptr].code = NULL;
    
    return &_symbol_table[_symbol_table_ptr++];
}


/*
 * Emitter
 */

void generate(int opcode, int value);

void spill(void)
{
    if (_accumulator_loaded)
        //generate(OP_PUSH, 0);
        code_opcode_value(OP_PUSH, 0);
    else
        _accumulator_loaded = 1;
}

int loaded(void)
{
    return _accumulator_loaded;
}

void clear(void)
{
    _accumulator_loaded = 0;
}

int hex(int ch)
{
    if (isdigit(ch))
        return ch - '0';
    else
        return tolower(ch) - 'a' + 10;
}

void emit_byte(int value)
{
    _text_buffer[_text_buffer_ptr++] = value;
}

void emit_short(int value)
{
    emit_byte((value >> 8) & 0xFF);
    emit_byte(value & 0xFF);
}

void emit_word(int value)
{
    emit_byte((value >> 24) & 0xFF);
    emit_byte((value >> 16) & 0xFF);
    emit_byte((value >> 8) & 0xFF);
    emit_byte(value & 0xFF);
}

void emit_allocate(int size)
{
    for (int i = 0; i < size; ++i)
        emit_byte(0);
}

void text_patch_short(int address, int value)
{
    _text_buffer[address + 0] = (value >> 8) & 0xFF;
    _text_buffer[address + 1] = value & 0xFF;
}

void text_patch_word(int address, int value)
{
    _text_buffer[address + 0] = (value >> 24) & 0xFF;
    _text_buffer[address + 1] = (value >> 16) & 0xFF;
    _text_buffer[address + 2] = (value >> 8) & 0xFF;
    _text_buffer[address + 3] = value & 0xFF;
}

int text_fetch(int a)
{
    return _text_buffer[a + 3] | (_text_buffer[a + 2] << 8) | (_text_buffer[a + 1] << 16) | (_text_buffer[a + 0] << 24);
}

int text_fetch_short(int a)
{
    return _text_buffer[a + 1] | (_text_buffer[a + 0] << 8);
}

void data_byte(unsigned char value)
{
    _data_buffer[_data_buffer_ptr++] = value;
}

void data_word(int value)
{
    data_byte((value >> 24) & 255);
    data_byte((value >> 16) & 255);
    data_byte((value >> 8) & 255);
    data_byte(value);
}

void data_patch(int address, int value)
{
    _data_buffer[address + 0] = (value >> 24) & 0xFF;
    _data_buffer[address + 1] = (value >> 16) & 0xFF;
    _data_buffer[address + 2] = (value >> 8) & 0xFF;
    _data_buffer[address + 3] = value & 0xFF;
}

int data_fetch(int address)
{
    return _data_buffer[address + 3] | (_data_buffer[address + 2]<<8) | (_data_buffer[address + 1]<<16) | (_data_buffer[address + 0]<<24);
}

void tag(int seg)
{
    if (_relocation_ptr >= RELOCATION_SIZE)
        internal_error("relocation buffer overflow", NULL);

    _relocation_table[_relocation_ptr].seg = seg;
    _relocation_table[_relocation_ptr].addr = seg == 't' ? _text_buffer_ptr - BPW : _data_buffer_ptr - BPW;
    _relocation_ptr++;
}

void resolve(void)
{
    int dist = DATA_VADDR;

    for (int i = 0; i < _relocation_ptr; ++i)
    {
        if (_relocation_table[i].seg == 't')
        {
            int address = text_fetch(_relocation_table[i].addr);
            address += dist;
            text_patch_word(_relocation_table[i].addr, address);
        }
        else
        {
            int address = data_fetch(_relocation_table[i].addr);
            address += dist;
            data_patch(_relocation_table[i].addr, address);
        }
    }   
}

void allocate_global_variables(void)
{
    for (int i = 0; i < _symbol_table_ptr; ++i)
    {
        symbol_t *sym = &_symbol_table[i];
        if (!sym->used)
            continue;

        // Only allocate data space for global variables
        if ((sym->flags == SYM_GLOBF) || (sym->flags == (SYM_GLOBF | SYM_VECTOR)))
        {
            sym->value = _data_buffer_ptr + DATA_VADDR;
            data_word(0);
        }
    }
}

void emit_code(code_t *code, char *machine_code)
{
    if (machine_code == NULL)
        internal_error("missing machine code for opcode", _opcode_names[code->opcode]);

    code->position = _text_buffer_ptr + TEXT_VADDR;

    while (*machine_code)
    {
        if (*machine_code == ',')
        {
            if (machine_code[1] == 'b')
            {
                emit_byte(code->value);
            }
            else if (machine_code[1] == 'l')
            {
                emit_word(code->value);
            }
            else if (machine_code[1] == 'w')
            {
                emit_short(code->value);
            }
            else if (machine_code[1] == 'a')
            {
                if (code->symbol != NULL)
                    emit_word(code->symbol->value);
                else
                    emit_word(code->value);
            }
            else if (machine_code[1] == '>')
            {
                code->position = _text_buffer_ptr;
                emit_short(0);
            }
            else if (machine_code[1] == '<')
            {
                int addr = code->code->position;
                emit_short(addr - _text_buffer_ptr);
            }
            else if (machine_code[1] == 'r')
            {
                if (code->code->opcode == OP_JUMPFWD || code->code->opcode == OP_JMPTRUE || code->code->opcode == OP_JMPFALSE)
                {
                    int addr = code->code->position;
                    text_patch_short(addr, _text_buffer_ptr - addr);
                }
            }
            else
            {
                internal_error("bad code", NULL);
            }
        }
        else
        {
            emit_byte(16 * hex(machine_code[0]) + hex(machine_code[1]));
        }

        machine_code += 2;
    }
}

void emit_load_value(code_t *code)
{
    if (code->value < SCHAR_MIN || code->value > SCHAR_MAX)
        emit_code(code, CG_LDVAL);
    else
        emit_code(code, CG_LDVAL_SHORT);
}

void emit_addq(int value)
{
    emit_short(0x5080 | ((value & 0x07) << 9));
}

void emit_m68k_machine_code(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        it->position = _text_buffer_ptr;
        switch (it->opcode)
        {
            case OP_WRITE_32:
                it->symbol->value = _text_buffer_ptr + TEXT_VADDR;
                emit_word(it->value);
                break;

            case OP_ALLOC_MEM:
                it->symbol->value = _text_buffer_ptr + TEXT_VADDR;
                emit_allocate(it->value);
                break;

            case OP_ENTER:
                it->symbol->value = _text_buffer_ptr + TEXT_VADDR;
                emit_code(it, CG_ENTER);
                break;

            case OP_ADD_CONSTANT:
                if (it->value >= 0 && it->value < 8)
                    emit_addq(it->value);
                else
                    emit_code(it, CG_ADD_CONSTANT);
                break;

            case OP_ASM:
                if (it->symbol != NULL)
                    it->symbol->value = _text_buffer_ptr + TEXT_VADDR;
                emit_code(it, it->assembly);
                break;

            case OP_LDVAL:
                emit_load_value(it);
                break;

            default:
                emit_code(it, _opcode_to_machine_code[it->opcode]);
                break;
        }
    }    
}

void generate_m68k_machine_code(void)
{
    // First pass, calculate the correct positions for all symbols and code instructions
    _text_buffer_ptr = 0;
    emit_m68k_machine_code();

    // Next pass we output the correct final code
    _text_buffer_ptr = 0;
    emit_m68k_machine_code();
}

void builtin(char *name, int arity, char *code)
{
    /*
    generate(OP_JUMPFWD, 0);
    symbol_t *func = add(name, SYM_GLOBF | SYM_FUNCTION | (arity << 8), _text_buffer_ptr);
    emit_code(code, 0);
    generate(OP_RESOLV, 0);
    */

    code_t *jmp = code_opcode(OP_JUMPFWD);
    symbol_t *func = add(name, SYM_GLOBF | SYM_FUNCTION | (arity << 8), 0);
    code_asm(func, code);
    resolve_jump(jmp, code_opcode(OP_JUMP_TARGET));
}

int align(int x, int a)
{
    return (x + a) & ~(a - 1);
}


/**
 * File output
 */

void write_output_word(int x)
{
#ifdef PLATFORM_WIN
    fputc(x>>24 & 0xff, _output_target);
    fputc(x>>16 & 0xff, _output_target);
    fputc(x>>8 & 0xff, _output_target);
    fputc(x & 0xff, _output_target);
#else
    sys_chan_write_b(_output_channel, x>>24 & 0xff);
    sys_chan_write_b(_output_channel, x>>16 & 0xff);
    sys_chan_write_b(_output_channel, x>>8 & 0xff);
    sys_chan_write_b(_output_channel, x & 0xff);
#endif
}

void write_output_byte(unsigned char ch)
{
#ifdef PLATFORM_WIN
    fputc(ch, _output_target);
#else
    sys_chan_write_b(_output_channel, ch);
#endif
}

void save_labels(void)
{
#if PLATFORM_WIN
    _output_target = fopen(_options->labels_filename, "w");
    if (_output_target == NULL)
        compiler_error("could not write to output labels file", _options->labels_filename);

    for (int i = 0; i < _symbol_table_ptr; ++i)
    {
        symbol_t *sym = &_symbol_table[i];

        if (!sym->used)
            continue;

        int value = sym->value;
/*
        if (sym->flags & SYM_FUNCTION)
            value += TEXT_VADDR;
        else if (!(sym->flags & SYM_CONST))
            value += DATA_VADDR;
*/
        fprintf(_output_target, "%08X\t%s\n", value, sym->name);
    }

    //fprintf(_output_target, "%08X\tmul32\n", _mul32_routine_address);
    //fprintf(_output_target, "%08X\tdiv32\n", _div32_routine_address);
    //fprintf(_output_target, "%08X\t_start\n", _start_location);

    fclose(_output_target);
    _output_target = NULL;
#endif 
}

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

void save_output(char *output_filename)
{
#if PLATFORM_WIN
    _output_target = fopen(output_filename, _options->output_type == KODA_OUTPUT_TYPE_PGZ ? "wb" : "w");
    if (_output_target == NULL)
        compiler_error("could not write to output file", output_filename);
#else
    _output_channel = sys_fsys_open(output_filename, FILE_MODE_CREATE_ALWAYS | FILE_MODE_WRITE); 
#endif  

    if (_options->output_type == KODA_OUTPUT_TYPE_PGZ)
    {
        write_pgz_header();
        write_pgz_segment(TEXT_VADDR, _text_buffer, _text_buffer_ptr);
        write_pgz_segment(DATA_VADDR, _data_buffer, _data_buffer_ptr);
    }
    else
    {
        write_srec_header();
        write_srec_segment(TEXT_VADDR, _text_buffer, _text_buffer_ptr);
        write_srec_segment(DATA_VADDR, _data_buffer, _data_buffer_ptr);
    }

#if PLATFORM_WIN
    fclose(_output_target);
    _output_target = NULL;
#else
    sys_fsys_close(_output_channel);
    _output_channel = -1;
#endif  

    if (_options->generate_labels)
        save_labels();
}


/**
 * Scanner
 */

char _program_source[PROGRAM_SIZE];

int _program_source_ptr = 0;
int _program_source_len;

void read_input_source(char *source_file)
{
    _program_source_file = source_file;
    _current_line = 0;
    _program_source_ptr = 0;

#ifdef PLATFORM_WIN
    FILE *input = fopen(source_file, "r");
    if (input == NULL)
        compiler_error("could not read source file", source_file);

    _program_source_len = fread(_program_source, 1, PROGRAM_SIZE, input);
    if (_program_source_len >= PROGRAM_SIZE)
        compiler_error("program too big", NULL);

    fclose(input);

#else
    int input_channel = sys_fsys_open(source_file, FILE_MODE_READ);
    if (input_channel == -1)
        compiler_error("could not read source file", source_file);

    _program_source_len = sys_chan_read(input_channel, _program_source, PROGRAM_SIZE);
    sys_fsys_close(input_channel);
#endif
}

void read_stdlib_source(void)
{
    static char * name = "stdlib.k";

    if (foenix_stdlib_len >= PROGRAM_SIZE)
        internal_error("stdlib.k too large", NULL);

    memcpy(_program_source, foenix_stdlib_data, foenix_stdlib_len);
    _program_source_len = foenix_stdlib_len;
    _program_source_ptr = 0;
    _program_source_file = name;
}

int read_char(void)
{
    return _program_source_ptr >= _program_source_len? EOF: _program_source[_program_source_ptr++];
}

int read_lower_char(void)
{
    return _program_source_ptr >= _program_source_len? EOF: tolower(_program_source[_program_source_ptr++]);
}

#define META        256

int read_encoded_char(void)
{
    int ch = read_char();
    if (ch != '\\')
        return ch;
    ch = read_lower_char();
    if (ch == 'a') return '\a';
    if (ch == 'b') return '\b';
    if (ch == 'e') return '\033';
    if (ch == 'f') return '\f';
    if (ch == 'n') return '\n';
    if (ch == 'q') return '"' | META;
    if (ch == 'r') return '\r';
    if (ch == 's') return ' ';
    if (ch == 't') return '\t';
    if (ch == 'v') return '\v';
    return ch;
}

void reject(void)
{
    _program_source_ptr--;
}


int _token;
char _token_str[TOKEN_LEN];
int _token_value;
int _token_op_id;

int _equal_op;
int _minus_op;
int _mul_op;
int _div_op;
int _mod_op;
int _add_op;

typedef struct operator_t {
    int prec;
    int len;
    char *name;
    int tok;
    int code;
} operator_t;


operator_t _operators[] = {
    { 7, 1, "%",    BINOP,  OP_MOD      },
    { 6, 1, "+",    BINOP,  OP_ADD      },
    { 7, 1, "*",    BINOP,  OP_MUL      },
    { 0, 1, ",",    COMMA,  0           },
    { 0, 1, "(",    LPAREN, 0           },
    { 0, 1, ")",    RPAREN, 0           },
    { 0, 1, "[",    LBRACK, 0           },
    { 0, 1, "]",    RBRACK, 0           },
    { 5, 1, "&",    BINOP,  OP_AND      },
    { 1, 2, "&&",   DISJ,   0           },
    { 6, 1, "-",    BINOP,  OP_SUB      },
    { 5, 1, "^",    BINOP,  OP_XOR      },
    { 0, 1, "@",    ADDROF, 0           },
    { 5, 1, "|",    BINOP,  OP_OR       },
    { 2, 2, "||",   CONJ,   0           },
    { 0, 1, "!",    UNOP,   OP_LOGNOT   },
    { 0, 1, "?",    COND,   0           },
    { 7, 1, "/",    BINOP,  OP_DIV      },
    { 0, 1, "~",    UNOP,   OP_INV      },
    { 0, 1, ":",    COLON,  0           },
    { 0, 2, "::",   BYTEOP, 0           },
    { 3, 2, "!=",   BINOP,  OP_NEQ      },
    { 4, 1, "<",    BINOP,  OP_LT       },
    { 4, 2, "<=",   BINOP,  OP_LE       },
    { 5, 2, "<<",   BINOP,  OP_SHL      },
    { 4, 1, ">",    BINOP,  OP_GT       },
    { 4, 2, ">=",   BINOP,  OP_GE       },
    { 5, 2, ">>",   BINOP,  OP_SHR      },
    { 0, 1, "=",    ASSIGN, 0           },
    { 3, 2, "==",   BINOP,  OP_EQ       },
    { 0, 0, NULL,   0,      0           }
};

const char * _operator_symbols = "%+*;,()[]=&|^@~:\\/!<>-?";

int skip_whitespace_and_comment(void)
{
    int ch = read_char();

    while (true)
    {
        while (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
        {
            if (ch == '\n')
                _current_line++;
            ch = read_char();
        }

        if (ch != '/')
            return ch;

        ch = read_char();
        if (ch != '/')
        {
            reject();
            return '/';
        }

        while (ch != '\n' && ch != EOF)
            ch = read_char();
    }
}

int find_keyword(char *str)
{
    switch (str[0])
    {
        case 'c':
            if (!strcmp(str, "const")) return KCONST;
            return 0;
        case 'd':
            if (!strcmp(str, "decl")) return KDECL;
            return 0;
        case 'e':
            if (!strcmp(str, "else")) return KELSE;
            return 0;
        case 'f':
            if (!strcmp(str, "func")) return KFUNC;
            return 0;
        case 'h':
            if (!strcmp(str, "halt")) return KHALT;
            return 0;
        case 'i':
            if (!strcmp(str, "if")) return KIF;
            return 0;
        case 'l':
            if (!strcmp(str, "leave")) return KLEAVE;
            if (!strcmp(str, "loop")) return KLOOP;
            return 0;
        case 'm':
            if (!strcmp(str, "main")) return KMAIN;
            return 0;
        case 'r':
            if (!strcmp(str, "return")) return KRETURN;
            return 0;
        case 's':
            if (!strcmp(str, "struct")) return KSTRUCT;
            return 0;
        case 'v':
            if (!strcmp(str, "var")) return KVAR;
            return 0;
        case 'w':
            if (!strcmp(str, "while")) return KWHILE;
            return 0;
    }

    return 0;
}

int scan_operator(int ch)
{
    int op_idx = 0;
    int name_idx = 0;

    _token_op_id = -1;

    while (_operators[op_idx].len > 0)
    {
        if (_operators[op_idx].len >= name_idx)
        {
            if (_operators[op_idx].name[name_idx] == ch)
            {
                _token_op_id = op_idx;
                _token_str[name_idx] = ch;
                ch = read_char();
                name_idx++;

                // Make sure we check the same operator one more time.
                op_idx--;
            }
        }
        else
        {
            break;
        }

        op_idx++;
    }
    
    if (_token_op_id == -1)
    {
        _token_str[name_idx++] = ch;
        _token_str[name_idx] = 0;
        compiler_error("unknown operator", _token_str);
    }

    _token_str[name_idx] = 0;
    reject();

    return _operators[_token_op_id].tok;
}

void find_operator(char *name)
{
    int i;

    i = 0;
    while (_operators[i].len > 0)
    {
        if (!strcmp(name, _operators[i].name))
        {
            _token_op_id = i;
            return;
        }
        i++;
    }

    internal_error("operator not found", name);
}

int scan_next_token(void)
{
    int ch = skip_whitespace_and_comment();
    if (ch == EOF)
    {
        strcpy(_token_str, "end of file");
        return ENDFILE;
    }

    if (ch == '{')
        return BLOCK_START;
    if (ch == '}')
        return BLOCK_END;

    if (isalpha(ch) || ch == '_')
    {
        int i = 0;
        while (isalpha(ch) || ch == '_' || ch == '.' || isdigit(ch))
        {
            if (i >= TOKEN_LEN - 1)
            {
                _token_str[i] = 0;
                compiler_error("symbol too long", _token_str);
            }

            _token_str[i++] = ch;
            ch = read_char();
        }

        _token_str[i] = 0;
        reject();

        int keyword = find_keyword(_token_str);

        if (keyword != 0)
            return keyword;

        return SYMBOL;
    }

    if (isdigit(ch) || ch == '-')
    {
        int sign = 1;
        int i = 0;
        int base = 10;

        if (ch == '-')
        {
            sign = -1;
            ch = read_lower_char();
            _token_str[i++] = ch;

            if (!isdigit(ch))
            {
                reject();
                return scan_operator('-');
            }
        }
        else if (ch == '0')
        {
            _token_str[i++] = ch;
            ch = read_lower_char();

            if (ch == 'x')
            {
                base = 16;
                _token_str[i++] = ch;

                ch = read_lower_char();

                if (!isdigit(ch) && (ch < 'a' || ch > 'f'))
                {
                    _token_str[i++] = ch;
                    _token_str[i] = 0;
                    compiler_error("invalid number", _token_str);
                }
            }
        }

        _token_value = 0;

        while (isdigit(ch) || (base == 16 && ch >= 'a' && ch <= 'f'))
        {
            if (i >= TOKEN_LEN-1)
            {
                _token_str[i] = 0;
                compiler_error("integer too long", _token_str);
            }

            _token_str[i++] = ch;
            _token_value = _token_value * base + (base == 16 ? hex(ch) : ch - '0');
            ch = read_lower_char();
        }


        if (base == 16 && ch > 'f' && ch <= 'z')
        {
            _token_str[i++] = ch;
            _token_str[i] = 0;
            compiler_error("invalid number", _token_str);
        }

        _token_str[i] = 0;

        reject();
        _token_value = _token_value * sign;
        return INTEGER;
    }

    if ('\'' == ch)
    {
        _token_value = read_encoded_char();
        if (read_char() != '\'')
            compiler_error("missing ''' in character", NULL);
        return INTEGER;
    }

    if ('"' == ch)
    {
        int i = 0;
        ch = read_encoded_char();
        while (ch != '"' && ch != EOF)
        {
            if (i >= TOKEN_LEN - 1)
            {
                _token_str[i] = 0;
                compiler_error("string too long", _token_str);
            }
            _token_str[i++] = ch & (META-1);
            ch = read_encoded_char();
        }
        _token_str[i] = 0;
        return STRING;
    }

    return scan_operator(ch);
}

void scan(void)
{
    _token = scan_next_token();
}


/**
 *
 * Parser
 *
 */


void expect(int token, char *msg)
{
    char    b[100];

    if (token == _token)
        return;
    sprintf(b, "%s expected", msg);
    compiler_error(b, _token_str);
}

void expect_equal_sign(void)
{
    if (_token != ASSIGN || _token_op_id != _equal_op)
        expect(0, "'='");
    scan();
}

void expect_left_paren(void)
{
    expect(LPAREN, "'('");
    scan();
}

void expect_right_paren(void)
{
    expect(RPAREN, "')'");
    scan();
}

int const_factor(void)
{

    int value;
    symbol_t *sym;

    if (INTEGER == _token)
    {
        value = _token_value;
        scan();
        return value;
    }
    if (SYMBOL == _token)
    {
        sym = lookup(_token_str, SYM_CONST);
        scan();
        return sym->value;
    }
    compiler_error("constant value expected", _token_str);
    return 0;
}

int const_value(void)
{
    int value;

    value = const_factor();
    if (BINOP == _token && _mul_op == _token_op_id)
    {
        scan();
        value *= const_factor();
    }
    else if (BINOP == _token && _add_op == _token_op_id)
    {
        scan();
        value += const_factor();
    }
    return value;
}

void expression(int clr);
void store(symbol_t *sym);

void var_declaration(int glob)
{
    symbol_t *var;
    int size;

    scan();
    while (1)
    {
        expect(SYMBOL, "symbol");
        size = 1;
        if (glob & SYM_GLOBF)
            var = add(_token_str, glob, _data_buffer_ptr);
        else
            var = add(_token_str, 0, _local_frame_ptr);

        scan();
        if (LBRACK == _token)
        {
            scan();
            size = const_value();
            if (size < 1)
                compiler_error("invalid size", NULL);
            var->flags |= SYM_VECTOR;
            expect(RBRACK, "']'");
            scan();
        }
        else if (BYTEOP == _token)
        {
            scan();
            size = const_value();
            if (size < 1)
                compiler_error("invalid size", NULL);
            size = (size + BPW - 1) / BPW;
            var->flags |= SYM_VECTOR;
        }

        if (glob & SYM_GLOBF)
        {
            if (var->flags & SYM_VECTOR)
            {
                code_opcode_value(OP_ALLOC, size * BPW);
                code_symbol(OP_GLOBVEC, var);
            }
            
            // We will allocate space for the variables at a later state in the compilation
            //data_word(0);
        }
        else
        {
            code_opcode_value(OP_ALLOC, size * BPW);
            
            _local_frame_ptr -= size * BPW;
            if (var->flags & SYM_VECTOR)
            {
                code_opcode_value(OP_LOCLVEC, 0);
                _local_frame_ptr -= BPW;
            }
            var->value = _local_frame_ptr;
        }

        if (_token == ASSIGN)
            compiler_error("not allowed to assign values to variables on declaration", var->name);

        if (_token != COMMA)
            break;

        scan();
    }
}

void const_declaration(int glob)
{
    symbol_t    *y;

    scan();
    while (1)
    {
        expect(SYMBOL, "symbol");
        y = add(_token_str, glob | SYM_CONST, 0);

        scan();
        expect_equal_sign();
        y->value = const_value();

        if (_token != COMMA)
            break;

        scan();
    }
}

void struct_declaration(int glob)
{
    scan();
    expect(SYMBOL, "symbol");
    symbol_t *struct_sym = add(_token_str, glob | SYM_CONST, 0);
    scan();
    int i = 0;

    expect(BLOCK_START, "{");
    scan();

    while (_token != BLOCK_END)
    {
        expect(SYMBOL, "symbol");

        char member[TOKEN_LEN];
        snprintf(member, TOKEN_LEN, "%s.%s", struct_sym->name, _token_str);

        add(member, glob | SYM_CONST, i++);
        scan();
    }

    struct_sym->value = i;
    scan();
}

void forward_declaration(void)
{
    symbol_t *sym;
    int n;

    scan();
    while (1)
    {
        expect(SYMBOL, "symbol");
        sym = add(_token_str, SYM_GLOBF|SYM_DECLARATION, 0);
        scan();
        expect_left_paren();
        n = const_value();
        sym->flags |= n << 8;
        expect_right_paren();

        if (n < 0)
            compiler_error("invalid arity", NULL);

        if (_token != COMMA)
            break;

        scan();
    }
}

void resolve_forward(int loc, int fn)
{
    int nloc;

    while (loc != 0)
    {
        nloc = text_fetch(loc);
        text_patch_word(loc, fn - loc - BPW);
        loc = nloc;
    }
}

void block_statement(void);
void statement(void);


void function_declaration(void)
{
    int local_addr = 2 * BPW;
    int number_arguments = 0;

    code_t *jump = code_opcode(OP_JUMPFWD);

    scan();
    symbol_t *func_sym = add(_token_str, SYM_GLOBF | SYM_FUNCTION, _text_buffer_ptr);

    scan();
    expect_left_paren();

    int old_symbol_table_ptr = _symbol_table_ptr;
    int old_string_table_ptr = _string_table_ptr;
    int local_base = _symbol_table_ptr;

    while (SYMBOL == _token)
    {
        add(_token_str, 0, local_addr);
        local_addr += BPW;
        number_arguments++;
        scan();
        if (_token != COMMA)
            break;
        scan();
    }

    for (int i = local_base; i < _symbol_table_ptr; i++)
    {
        _symbol_table[i].value = 12+number_arguments*BPW - _symbol_table[i].value;
    }

    if (func_sym->flags & SYM_DECLARATION)
    {
        resolve_forward(func_sym->value, _text_buffer_ptr);
        if (number_arguments != func_sym->flags >> 8)
            compiler_error("redefinition with different type", func_sym->name);

        func_sym->flags &= ~SYM_DECLARATION;
        func_sym->flags |= SYM_FUNCTION;
        func_sym->value = _text_buffer_ptr;
    }

    expect_right_paren();

    func_sym->flags |= number_arguments << 8;
    func_sym->code = code_symbol(OP_ENTER, func_sym);

    _parsing_function = true;
    
    block_statement();

    _parsing_function = false;
    code_opcode_value(OP_CLEAR, 0);
    code_opcode_value(OP_EXIT, 0);
    
    resolve_jump(jump, code_opcode(OP_JUMP_TARGET));

    _symbol_table_ptr = old_symbol_table_ptr;
    _string_table_ptr = old_string_table_ptr;
    _local_frame_ptr = 0;
}

void declaration(int glob)
{
    switch (_token)
    {
        case KVAR:
            var_declaration(glob);
            break;
        case KCONST:
            const_declaration(glob);
            break;
        case KSTRUCT:
            struct_declaration(glob);
            break;
        case KDECL:
            forward_declaration();
            break;
        default:
            function_declaration();
            break;
    }
}

void function_call(symbol_t *fn)
{
    int argument_count = 0;

    scan();
    if (NULL == fn)
        compiler_error("call of non-function", NULL);

    while (_token != RPAREN)
    {
        expression(0);
        argument_count++;

        if (COMMA != _token)
            break;
        scan();
        
        if (RPAREN == _token)
            compiler_error("syntax error", _token_str);
    }

    if (argument_count != (fn->flags >> 8))
        compiler_error("wrong number of arguments", fn->name);

    expect(RPAREN, "')'");
    scan();

    if (loaded())
        spill();

    if (fn->flags & SYM_DECLARATION)
    {
        code_symbol(OP_CALL, fn);
        fn->value = _text_buffer_ptr - BPW;
    }
    else
    {
        code_symbol(OP_CALL, fn);
    }

    if (argument_count != 0)
    {
        code_opcode_value(OP_DEALLOC, argument_count * BPW);
    }

    _accumulator_loaded = 1;
}

int make_string(char *str)
{
    int address = _data_buffer_ptr;
    int len = strlen(str);

    for (int i = 0; i <= len; i++)
        data_byte(str[i]);

    while (_data_buffer_ptr % 4 != 0)
        data_byte(0);

    return address;
}

int make_table(void)
{
    int n, i;
    int loc;
    int table_value[MAXTBL];
    code_t *table_code[MAXTBL] = {0};
    int dynamic = 0;

    scan();
    n = 0;

    while (_token != RBRACK)
    {
        if (n >= MAXTBL)
            compiler_error("table too big", NULL);

        if (LPAREN == _token)
        {
            scan();
            dynamic = 1;
            continue;
        }
        else if (dynamic)
        {
            expression(1);
            table_value[n] = 0;
            table_code[n++] = code_opcode_value(OP_STGLOB, 0);
            
            if (RPAREN == _token)
            {
                scan();
                dynamic = 0;
            }
        }
        else if (_token == INTEGER || _token == SYMBOL)
        {
            table_value[n++] = const_value();
            //table_code[n++] = 0;
        }
        else if (_token == STRING)
        {
            table_value[n++] = make_string(_token_str) + DATA_VADDR;
            //table_code[n++] = 1;
            scan();
        }
        else if (_token == LBRACK)
        {
            table_value[n++] = make_table() + DATA_VADDR;
            //table_code[n++] = 1;
        }
        else
        {
            compiler_error("invalid table element", _token_str);
        }

        if (_token != COMMA)
            break;

        scan();
    }

    expect(RBRACK, "']'");
    scan();
    loc = _data_buffer_ptr;

    for (i = 0; i < n; i++)
    {
        data_word(table_value[i]);

        if (table_code[i] != NULL)
        {
            table_code[i]->value = _data_buffer_ptr - 4 + DATA_VADDR;
            //tag('d');
        }
//        else if (table_code[i] > 1)
//        {
//            //text_patch_word(table_code[i], _data_buffer_ptr-4);
//
//        }
    }

    return loc;
}

void load(symbol_t *sym)
{
    if (sym->flags & SYM_GLOBF)
        code_symbol(OP_LDGLOBAL, sym);
    else
        code_opcode_value(OP_LDLOCAL, sym->value);
}

void store(symbol_t *sym)
{
    if (sym->flags & SYM_GLOBF)
        code_symbol(OP_STGLOB, sym);
    else
        code_opcode_value(OP_STLOCL, sym->value);
}

void factor(void);

symbol_t *address(int level, int *byte_ptr)
{
    symbol_t *sym = lookup(_token_str, 0);
    scan();

    if (sym->flags & SYM_CONST)
    {
        if (level > 0 && !(sym->flags & SYM_MEMORY))
            compiler_error("invalid address", sym->name);

        spill();
        code_opcode_value(OP_LDVAL, sym->value);
        
    }
    else if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION))
    {
        if (level == 2)
            compiler_error("invalid address", sym->name);
    }
    else if (level == 0 || _token == LBRACK || _token == BYTEOP)
    {
        spill();
        load(sym);
    }

    if (_token == LBRACK || _token == BYTEOP)
    {
        if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION | SYM_CONST) && !(sym->flags & SYM_MEMORY))
            compiler_error("bad subscript", sym->name);
    }

    while (LBRACK == _token)
    {
        *byte_ptr = 0;
        scan();
        expression(0);
        expect(RBRACK, "']'");
        scan();

        // Handle the special mem variable
        if (sym && sym->flags & SYM_MEMORY)
            code_opcode_value(OP_INDXB, 0);
        else
            code_opcode_value(OP_INDEX, 0);

        sym = NULL;

        if (_token == LBRACK || _token == BYTEOP || level == 0)
            code_opcode_value(OP_DEREF, 0);
    }

    if (_token == BYTEOP)
    {
        *byte_ptr = 1;
        scan();
        factor();
        sym = NULL;
        code_opcode_value(OP_INDXB, 0);

        if (level == 0)
            code_opcode_value(OP_DREFB, 0);
    }
    return sym;
}

void factor(void)
{
    symbol_t    *y;
    int op;
    int b;

    if (_token == INTEGER)
    {
        spill();
        code_opcode_value(OP_LDVAL, _token_value);
        scan();
    }
    else if (_token == SYMBOL)
    {
        y = address(0, &b);

        if (LPAREN == _token)
            function_call(y);
    }
    else if (_token == STRING)
    {
        spill();
        code_opcode_value(OP_LDADDR, make_string(_token_str) + DATA_VADDR);
        scan();
    }
    else if (_token == LBRACK)
    {
        spill();
        code_opcode_value(OP_LDADDR, make_table() + DATA_VADDR);
    }
    else if (_token == ADDROF)
    {
        scan();
        y = address(2, &b);
        if (y == NULL)
        {
            ;
        }
        else if (y->flags & SYM_GLOBF)
        {
            spill();
            code_symbol(OP_LDADDR, y);
        }
        else
        {
            spill();
            code_opcode_value(OP_LDLOCALREF, y->value);
        }
    }
    else if (_token == BINOP)
    {
        op = _token_op_id;
        if (_token_op_id != _minus_op)
            compiler_error("syntax error", _token_str);
        scan();
        factor();
        code_opcode(OP_NEG);
    }
    else if (_token == UNOP)
    {
        op = _token_op_id;
        scan();
        factor();
        code_opcode(_operators[op].code);
    }
    else if (_token == LPAREN)
    {
        scan();
        expression(0);
        expect_right_paren();
    }
    else
    {
        compiler_error("syntax error", _token_str);
    }
}

int emitop(int *operator_stack, int stack_ptr)
{
    int op = operator_stack[stack_ptr - 1];

    // TODO: Need to reenable this
    //if (op == _div_op || op == _mul_op || op == _mod_op)
    //    generate(_operators[op].code, op == _mul_op ? _mul32_routine_address : _div32_routine_address);
    //else
    //    generate(_operators[op].code, 0);
    code_opcode(_operators[op].code);


    return stack_ptr - 1;
}

void arithmetic(void)
{
    int operator_stack[10];
    int stack_ptr = 0;

    factor();
    while (BINOP == _token)
    {
        while (stack_ptr && _operators[_token_op_id].prec <= _operators[operator_stack[stack_ptr - 1]].prec)
            stack_ptr = emitop(operator_stack, stack_ptr);

        operator_stack[stack_ptr++] = _token_op_id;
        scan();
        factor();
    }

    while (stack_ptr > 0)
        stack_ptr = emitop(operator_stack, stack_ptr);
}

void conjn(void)
{
    code_t *jump_stack[32];
    int n = 0;

    arithmetic();

    while (CONJ == _token)
    {
        scan();
        jump_stack[n] = code_opcode(OP_JMPFALSE);
        clear();
        arithmetic();
        n++;
    }

    while (n > 0)
    {
        resolve_jump(jump_stack[n - 1], code_opcode(OP_JUMP_TARGET));
        n--;
    }
}

void disjn(void)
{
    code_t *jump_stack[32];
    int n = 0;

    conjn();

    while (DISJ == _token)
    {
        scan();
        jump_stack[n] = code_opcode(OP_JMPTRUE);
        clear();
        conjn();
        n++;
    }

    while (n > 0)
    {
        resolve_jump(jump_stack[n - 1], code_opcode(OP_JUMP_TARGET));
        n--;
    }
}

void expression(int clr)
{
    if (clr)
    {
        clear();
    }

    disjn();

    if (_token == COND)
    {
        scan();
        code_t *false_jump = code_opcode(OP_JMPFALSE);
        expression(1);
        expect(COLON, "':'");
        scan();
        code_t *fwd_jump = code_opcode(OP_JUMPFWD);

        resolve_jump(false_jump, code_opcode(OP_JUMP_TARGET));
        expression(1);
        resolve_jump(fwd_jump, code_opcode(OP_JUMP_TARGET));
    }
}

void halt_statement(void)
{
    scan();
    code_opcode_value(OP_HALT, const_value());
}

void return_statement(void)
{
    scan();

    if (!_parsing_function)
        compiler_error("can't return from main", 0);

    expression(1);

    if (_local_frame_ptr != 0)
    {
        code_opcode_value(OP_DEALLOC, -_local_frame_ptr);
    }

    code_opcode_value(OP_EXIT, 0);
}

void if_statement()
{
    scan();
    expect_left_paren();
    expression(1);
    
    code_t *jump = code_opcode(OP_JMPFALSE);
    
    expect_right_paren();

    block_statement();

    if (_token == KELSE)
    {
        code_t *else_jump = code_opcode(OP_JUMPFWD);
        resolve_jump(jump, code_opcode(OP_JUMP_TARGET));
        jump = else_jump;

        scan();
        block_statement();
    }

    resolve_jump(jump, code_opcode(OP_JUMP_TARGET));
}

void while_statement(void)
{
    code_t *old_loop0 = _loop0;
    int old_leaves_ptr = _leaves_ptr;

    scan();
    expect_left_paren();

    code_t *while_test = code_opcode(OP_JUMP_TARGET);
    _loop0 = while_test;
    
    expression(1);
    expect_right_paren();

    code_t *jump_false = code_opcode(OP_JMPFALSE);
   

    block_statement();
    
    resolve_jump(code_opcode(OP_JUMPBACK), while_test);
    resolve_jump(jump_false, code_opcode(OP_JUMP_TARGET));

    while (_leaves_ptr > old_leaves_ptr)
    {
        resolve_jump(_leaves[_leaves_ptr - 1], code_opcode(OP_JUMP_TARGET));
        _leaves_ptr--;
    }

    _loop0 = old_loop0;
}

void leave_statement(void)
{
    if (_loop0 == NULL)
        compiler_error("LEAVE not in loop context", 0);

    scan();

    if (_leaves_ptr >= MAXLOOP)
        compiler_error("too many LEAVEs", NULL);

    _leaves[_leaves_ptr++] = code_opcode(OP_JUMPFWD);
}

void loop_statement(void)
{
    if (_loop0 == NULL)
        compiler_error("LOOP not in loop context", 0);

    scan();

    code_t *jump_target = alloc_code();
    jump_target->opcode = OP_JUMP_TARGET;

    jump_target->next = _loop0->next;
    jump_target->prev = _loop0;

    _loop0->next = jump_target;
    if (jump_target->next != NULL)
        jump_target->next->prev = jump_target;

    resolve_jump(code_opcode(OP_JUMPBACK), jump_target);
}

void assignment_or_call(void)
{
    int byte_addr;

    clear();
    symbol_t *sym = address(1, &byte_addr);

    if (_token == LPAREN)
    {
        function_call(sym);
    }
    else if (_token == ASSIGN)
    {
        scan();
        expression(0);
        if (sym == NULL)
        {
            if (byte_addr)
                code_opcode(OP_STINDB);
            else
                code_opcode(OP_STINDR);
        }
        else if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION | SYM_CONST | SYM_VECTOR))
        {
            compiler_error("bad location", sym->name);
        }
        else
        {
            store(sym);
        }
    }
    else
    {
        compiler_error("syntax error", _token_str);
    }
}

void statement(void)
{
    switch (_token)
    {
        case KHALT:
            halt_statement();
            break;
        case KIF:
            if_statement();
            break;
        case KLEAVE:
            leave_statement();
            break;
        case KLOOP:
            loop_statement();
            break;
        case KRETURN:
            return_statement();
            break;
        case KWHILE:
            while_statement();
            break;
        case BLOCK_START:
            block_statement();
            break;
        case SYMBOL:
            assignment_or_call();
            break;
        default:
            expect(0, "statement");
            break;
    }
}

void block_statement(void)
{
    expect(BLOCK_START, "{");
    scan();

    int old_symbol_table_ptr = _symbol_table_ptr;
    int old_local_frame_ptr = _local_frame_ptr;

    while (KVAR == _token || KCONST == _token || KSTRUCT == _token)
        declaration(0);

    while (_token != BLOCK_END)
        statement();

    scan();

    if (old_local_frame_ptr - _local_frame_ptr != 0)
    {
        code_opcode_value(OP_DEALLOC, old_local_frame_ptr-_local_frame_ptr);
    }

    _symbol_table_ptr = old_symbol_table_ptr;
    _local_frame_ptr = old_local_frame_ptr;
}

void program(void)
{
    // Reset important pointers
    _relocation_ptr = 0;

    int i;

    scan();
    while (_token == KVAR || _token == KCONST || _token == KFUNC || _token == KDECL || _token == KSTRUCT)
        declaration(SYM_GLOBF);

    for (i = 0; i < _symbol_table_ptr; i++)
    {
        if (_symbol_table[i].flags & SYM_DECLARATION && _symbol_table[i].value)
            compiler_error("undefined function", _symbol_table[i].name);
    }
}

void resolve_main(void)
{
    symbol_t *main = lookup("main", SYM_FUNCTION);
    if (main == NULL)
        compiler_error("missing main entry point", NULL);

    _start_location = _text_buffer_ptr + TEXT_VADDR;
    code_symbol(OP_CALL, main);
    code_opcode_value(OP_HALT, 0);
}

/**
 * Main
 */

void init(void)
{
    _text_buffer_ptr = 0;
    _data_buffer_ptr = 0;
    _symbol_table_ptr = 0;


    _code_start = alloc_code();
    _current_code = _code_start;
    _current_code->opcode = OP_INIT;
    _current_code->value = HEAP_END;
    code_t *jmp = code_opcode(OP_JUMPFWD);
    
    // Special variables used by the standard library
    if (_options->no_stdlib == 0)
    {
        // Heap allocation ptr
        symbol_t *sym = add("__heap_ptr", SYM_GLOBF, 0);
        sym->code = code_symbol_value(OP_WRITE_32, sym, HEAP_START);

        // 32 byte buffer
        sym = add("__buffer", SYM_GLOBF, 0);
        sym->code = code_symbol_value(OP_ALLOC_MEM, sym, 32);
    }

    // Add special math routines
    //_mul32_routine_address = _text_buffer_ptr + TEXT_VADDR;
    //emit_code(CG_MUL32, 0);
    {
        symbol_t *mul32 = add("__mul32", SYM_GLOBF, 0);
        _mul32_code = code_asm(mul32, CG_MUL32);

        symbol_t *div32 = add("__div32", SYM_GLOBF, 0);
        _div32_code = code_asm(div32, CG_DIV32);
    }



    //_div32_routine_address = _text_buffer_ptr + TEXT_VADDR;
    //emit_code(CG_DIV32, 0);

    //generate(OP_RESOLV, 0);
    resolve_jump(jmp, code_opcode(OP_JUMP_TARGET));


    find_operator("="); _equal_op = _token_op_id;
    find_operator("-"); _minus_op = _token_op_id;
    find_operator("*"); _mul_op = _token_op_id;
    find_operator("+"); _add_op = _token_op_id;
    find_operator("/"); _div_op = _token_op_id;
    find_operator("%"); _mod_op = _token_op_id;

    builtin("syscall0", 1, CG_FUNC_SYSCALL0);
    builtin("syscall1", 2, CG_FUNC_SYSCALL1);
    builtin("syscall2", 3, CG_FUNC_SYSCALL2);
    builtin("syscall3", 4, CG_FUNC_SYSCALL3);
    builtin("memscan", 3, CG_FUNC_MEMSCAN);
    builtin("memcopy", 3, CG_FUNC_MEMCOPY);

    add("mem", SYM_CONST | SYM_MEMORY, 0);     // special memory access, set to -DATA_VADDR to compensate for LDGLOBAL that adds DATA_VADDR
    add("HEAP_START", SYM_CONST, HEAP_START);
    add("HEAP_END", SYM_CONST, HEAP_END - INITIAL_STACK_SIZE);
    add("BYTE", SYM_CONST, 1);
    add("WORD", SYM_CONST, 4);
}


int koda_compile(koda_compiler_options_t *options)
{
    _options = options;

#if PLATFORM_WIN
    _text_buffer = malloc(TEXT_SIZE);
    _data_buffer = malloc(DATA_SIZE);
    _string_table = malloc(STRING_TABLE_SIZE);
    _symbol_table = malloc(sizeof(symbol_t) * SYMBOL_TABLE_SIZE);
    _relocation_table = malloc(sizeof(relocation_t) * RELOCATION_SIZE);
#else
    void *current_heap_pos = heap_position();

    _text_buffer = heap_alloc(TEXT_SIZE);
    _data_buffer = heap_alloc(DATA_SIZE);
    _string_table = heap_alloc(STRING_TABLE_SIZE);
    _symbol_table = heap_alloc(sizeof(symbol_t) * SYMBOL_TABLE_SIZE);
    _relocation_table = heap_alloc(sizeof(relocation_t) * RELOCATION_SIZE);
#endif   

    init();

    if (_options->no_stdlib == 0)
    {
        // Compile stdlib
        read_stdlib_source();
        program();
        resolve();
    }

    // Compile all input files
    for (int i = 0; i < options->input_files_count; ++i)
    {
        read_input_source(options->input_files[i]);
        program();
        resolve();
    }

    resolve_main();

    int start_instruction_count = 0;
    if (options->debug)
    {
        for (code_t *it = _code_start; it != NULL; it = it->next)
            it->position = start_instruction_count++;
    }

    if (options->no_optimize == 0)
        optimize_code();

    mark_used_symbols();

    allocate_global_variables();
    generate_m68k_machine_code();

    if (options->debug)
    {
        printf("\nCODE:\n");
        int optimized_instruction_count = 0;

        for (code_t *it = _code_start; it != NULL; it = it->next)
            it->position = optimized_instruction_count++;

        for (code_t *it = _code_start; it != NULL; it = it->next)
            print_code(it);

        printf("\nSYMBOLS:\n");
        for (int i = 0; i < _symbol_table_ptr; ++i)
        {
            symbol_t *sym = &_symbol_table[i];
            if (sym->used)
            {
                printf("  %06X  %s (%02X)\n", sym->value, sym->name, sym->flags);
            }
        }

#if PLATFORM_WIN
        printf("\nSTATISTICS:\n");
        printf("          Code usage: %d / %dkb\n", _text_buffer_ptr / 1024, TEXT_SIZE / 1024);
        printf("          Data usage: %d / %dkb\n", _data_buffer_ptr / 1024, DATA_SIZE / 1024);
        printf("  Symbol table usage: %d / %d\n", _symbol_table_ptr, SYMBOL_TABLE_SIZE);
        printf("  String table usage: %d / %d\n", _string_table_ptr, STRING_TABLE_SIZE);
        printf("       Optimizations: %d -> %d\n", start_instruction_count, optimized_instruction_count);
#endif        
    }

    save_output(options->output_filename);

    _options = NULL;

#if PLATFORM_WIN
    free(_text_buffer);
    free(_data_buffer);
    free(_string_table);
    free(_symbol_table);
    free(_relocation_table);
#else    
    heap_rewind(current_heap_pos);
#endif    

    return 1;
}

