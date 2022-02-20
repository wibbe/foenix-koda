
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#if PLATFORM_FOENIX
    #include "foenix/syscall.h"
    #include "foenix/heap.h"
#endif

#include "foenix_stdlib.h"
#include "opcodes.h"
#include "opcodes_68k.h"
#include "koda.h"

#define INST_JUMP_TARGET      ",r"


enum {
    BPW                     = 4,
    PROGRAM_SIZE            = 0xF000,

    RELOCATION_SIZE         = 10000,
    STACK_SIZE              = 100,
    SYMBOL_TABLE_SIZE       = 2048,
    STRING_TABLE_SIZE       = 8192,
    INPUT_STACK_SIZE        = 4,

    SYM_GLOBF               = 0x01,
    SYM_CONST               = 0x02,
    SYM_VECTOR              = 0x04,
    SYM_DECLARATION         = 0x08,
    SYM_FUNCTION            = 0x10,

    MAXTBL                  = 1024,
    MAXLOOP                 = 100,

    TOKEN_LEN               = 128,

    SCRATCH_REG             = 7,
    RETURN_REG              = 6,
    NUMBER_OF_REGS          = 4,
    REGISTER_SAVE_STACK     = 32,

    HEAP_START              = 0x00060000,
    HEAP_END                = 0x00100000,
    INITIAL_STACK_SIZE      = 0x40000,          // Reserve space for a 256k stack
};

enum {
    TOKEN_ENDFILE = -1,
    TOKEN_SYMBOL = 100, 
    TOKEN_INTEGER, 
    TOKEN_STRING,
    TOKEN_ADDROF = 200, 
    TOKEN_ASSIGN, 
    TOKEN_BINOP, 
    TOKEN_BYTEOP, 
    TOKEN_COLON, 
    TOKEN_COMMA, 
    TOKEN_COND,
    TOKEN_CONJ, 
    TOKEN_DISJ,
    TOKEN_LEFT_BRACKET, 
    TOKEN_LEFT_PAREN, 
    TOKEN_RIGHT_BRACKET, 
    TOKEN_RIGHT_PAREN, 
    TOKEN_UNOP,
    TOKEN_BLOCK_START, 
    TOKEN_BLOCK_END,
    TOKEN_KEYWORD_CONST,
    TOKEN_KEYWORD_DEC, 
    TOKEN_KEYWORD_DECL, 
    TOKEN_KEYWORD_ELSE,
    TOKEN_KEYWORD_FUNC,
    TOKEN_KEYWORD_HALT, 
    TOKEN_KEYWORD_INC,
    TOKEN_KEYWORD_IMPORT,
    TOKEN_KEYWORD_IF,
    TOKEN_KEYWORD_PEEK8,
    TOKEN_KEYWORD_PEEK16,
    TOKEN_KEYWORD_PEEK32,
    TOKEN_KEYWORD_POKE8,
    TOKEN_KEYWORD_POKE16,
    TOKEN_KEYWORD_POKE32,
    TOKEN_KEYWORD_LEAVE, 
    TOKEN_KEYWORD_LOOP, 
    TOKEN_KEYWORD_RETURN, 
    TOKEN_KEYWORD_STRUCT, 
    TOKEN_KEYWORD_VAR,
    TOKEN_KEYWORD_WHILE
};


enum {
    OP_ARG_NONE,
    OP_ARG_VALUE_WORD,
    OP_ARG_VALUE_LONG,
    OP_ARG_ADDRESS,
    OP_ARG_FORWARD_REF,
    OP_ARG_BACKWARD_REF,
    OP_ARG_TARGET_REF,
};

enum {
    M68_BRANCH_TRUE             = 0x0000,
    M68_BRANCH_FALSE            = 0x0100,
    M68_BRANCH_NOT_EQUAL        = 0x0600,
    M68_BRANCH_EQUAL            = 0x0700,
    M68_BRANCH_GREATER_EQUAL    = 0x0C00,
    M68_BRANCH_LESS             = 0x0D00,
    M68_BRANCH_GREATER          = 0x0E00,
    M68_BRANCH_LESS_EQUAL       = 0x0F00,
};


char *_opcode_names[OP_COUNT] = {
    [OP_INIT] = "OP_INIT",
    [OP_LOAD_VALUE] = "OP_LOAD_VALUE",
    [OP_LOAD_GLOBAL_ADDR] = "OP_LOAD_GLOBAL_ADDR",
    [OP_LOAD_LOCAL_ADDR] = "OP_LOAD_LOCAL_ADDR",
    [OP_LOAD_GLOBAL] = "OP_LOAD_GLOBAL",
    [OP_LOAD_LOCAL] = "OP_LOAD_LOCAL",
    [OP_CLEAR] = "OP_CLEAR",
    [OP_TO_RET] = "OP_TO_RET",
    [OP_FROM_RET] = "OP_FROM_RET",
    [OP_STORE_GLOBAL] = "OP_STORE_GLOBAL",
    [OP_STORE_GLOBAL_NP] = "OP_STORE_GLOBAL_NP",
    [OP_STORE_LOCAL] = "OP_STORE_LOCAL",
    [OP_STORE_LOCAL_NP] = "OP_STORE_LOCAL_NP",
    [OP_STORE_INDIRECT_WORD] = "OP_STORE_INDIRECT_WORD",
    [OP_STORE_INDIRECT_BYTE] = "OP_STORE_INDIRECT_BYTE",
    [OP_ALLOC] = "OP_ALLOC",
    [OP_DEALLOC] = "OP_DEALLOC",
    [OP_LOCAL_VEC] = "OP_LOCAL_VEC",
    [OP_GLOBAL_VEC] = "OP_GLOBAL_VEC",
    [OP_HALT] = "OP_HALT",
    [OP_INDEX_WORD] = "OP_INDEX_WORD",
    [OP_DEREF_WORD] = "OP_DEREF_WORD",
    [OP_INDEX_BYTE] = "OP_INDEX_BYTE",
    [OP_DEREF_BYTE] = "OP_DEREF_BYTE",
    [OP_CALL_SETUP] = "OP_CALL_SETUP",
    [OP_FUNC_START] = "OP_FUNC_START",
    [OP_FUNC_END] = "OP_FUNC_END",
    [OP_CALL] = "OP_CALL",
    [OP_CALL_INDIRECT] = "OP_CALL_INDIRECT",
    [OP_CALL_CLEANUP] = "OP_CALL_CLEANUP",
    [OP_JUMP_FWD] = "OP_JUMP_FWD",
    [OP_JUMP_BACK] = "OP_JUMP_BACK",
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
    [OP_SHIFT_LEFT] = "OP_SHIFT_LEFT",
    [OP_SHIFT_RIGHT] = "OP_SHIFT_RIGHT",
    [OP_EQ] = "OP_EQ",
    [OP_NOT_EQ] = "OP_NOT_EQ",
    [OP_LESS] = "OP_LESS",
    [OP_LESS_EQ] = "OP_LESS_EQ",
    [OP_GREATER] = "OP_GREATER",
    [OP_GREATER_EQ] = "OP_GREATER_EQ",
    [OP_JUMP_FALSE] = "OP_JUMP_FALSE",
    [OP_JUMP_TRUE] = "OP_JUMP_TRUE",
    [OP_INC] = "OP_INC",
    [OP_DEC] = "OP_DEC",
    [OP_PEEK8] = "OP_PEEK8",
    [OP_PEEK16] = "OP_PEEK16",
    [OP_PEEK32] = "OP_PEEK32",
    [OP_POKE8] = "OP_POKE8",
    [OP_POKE16] = "OP_POKE16",
    [OP_POKE32] = "OP_POKE32",
    [OP_ASM] = "OP_ASM",
    [OP_JUMP_TARGET] = "OP_JUMP_TARGET",
    [OP_ALLOC_MEM] = "OP_ALLOC_MEM",
    [OP_WRITE_32] = "OP_WRITE_32",
};

int _opcode_arguments[OP_COUNT] = {
    [OP_INIT] = OP_ARG_VALUE_LONG,
    [OP_LOAD_VALUE] = OP_ARG_VALUE_LONG,
    [OP_LOAD_GLOBAL] = OP_ARG_ADDRESS,
    [OP_LOAD_GLOBAL_ADDR] = OP_ARG_ADDRESS,
    [OP_LOAD_LOCAL] = OP_ARG_VALUE_LONG,
    [OP_LOAD_LOCAL_ADDR] = OP_ARG_VALUE_WORD,
    [OP_CLEAR] = OP_ARG_NONE,
    [OP_TO_RET] = OP_ARG_NONE,
    [OP_FROM_RET] = OP_ARG_NONE,
    [OP_STORE_GLOBAL] = OP_ARG_ADDRESS,
    [OP_STORE_GLOBAL_NP] = OP_ARG_ADDRESS,
    [OP_STORE_LOCAL] = OP_ARG_VALUE_WORD,
    [OP_STORE_LOCAL_NP] = OP_ARG_VALUE_WORD,
    [OP_STORE_INDIRECT_WORD] = OP_ARG_NONE,
    [OP_STORE_INDIRECT_BYTE] = OP_ARG_NONE,
    [OP_FUNC_START] = OP_ARG_VALUE_LONG,
    [OP_FUNC_END] = OP_ARG_NONE,
    [OP_ALLOC] = OP_ARG_VALUE_LONG,
    [OP_DEALLOC] = OP_ARG_VALUE_LONG,
    [OP_LOCAL_VEC] = OP_ARG_NONE,
    [OP_GLOBAL_VEC] = OP_ARG_NONE,
    [OP_HALT] = OP_ARG_VALUE_LONG,
    [OP_INDEX_WORD] = OP_ARG_NONE,
    [OP_INDEX_BYTE] = OP_ARG_NONE,
    [OP_DEREF_WORD] = OP_ARG_NONE,
    [OP_DEREF_BYTE] = OP_ARG_NONE,
    [OP_CALL_SETUP] = OP_ARG_NONE,
    [OP_CALL] = OP_ARG_ADDRESS,
    [OP_CALL_INDIRECT] = OP_ARG_NONE,
    [OP_CALL_CLEANUP] = OP_ARG_NONE,
    [OP_JUMP_FWD] = OP_ARG_FORWARD_REF,
    [OP_JUMP_BACK] = OP_ARG_BACKWARD_REF,
    [OP_JUMP_FALSE] = OP_ARG_FORWARD_REF,
    [OP_JUMP_TRUE] = OP_ARG_FORWARD_REF,
    [OP_JUMP_TARGET] = OP_ARG_TARGET_REF,
    [OP_EXIT] = OP_ARG_NONE,
    [OP_NEG] = OP_ARG_NONE,
    [OP_INV] = OP_ARG_NONE,
    [OP_LOGNOT] = OP_ARG_NONE,
    [OP_ADD] = OP_ARG_NONE,
    [OP_SUB] = OP_ARG_NONE,
    [OP_MUL] = OP_ARG_NONE,
    [OP_DIV] = OP_ARG_NONE,
    [OP_MOD] = OP_ARG_NONE,
    [OP_AND] = OP_ARG_NONE,
    [OP_OR] = OP_ARG_NONE,
    [OP_XOR] = OP_ARG_NONE,
    [OP_SHIFT_LEFT] = OP_ARG_NONE,
    [OP_SHIFT_RIGHT] = OP_ARG_NONE,
    [OP_EQ] = OP_ARG_NONE,
    [OP_NOT_EQ] = OP_ARG_NONE,
    [OP_LESS] = OP_ARG_NONE,
    [OP_LESS_EQ] = OP_ARG_NONE,
    [OP_GREATER] = OP_ARG_NONE,
    [OP_GREATER_EQ] = OP_ARG_NONE,
    [OP_INC] = OP_ARG_NONE,
    [OP_DEC] = OP_ARG_NONE,
    [OP_PEEK8] = OP_ARG_NONE,
    [OP_PEEK16] = OP_ARG_NONE,
    [OP_PEEK32] = OP_ARG_NONE,
    [OP_POKE8] = OP_ARG_NONE,
    [OP_POKE16] = OP_ARG_NONE,
    [OP_POKE32] = OP_ARG_NONE,
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


char _program_source_file[128];
int _current_line = 1;
bool _has_main_body = false;

#ifdef PLATFORM_WIN
    static FILE * _output_target = NULL;
#else
    static int _output_channel = 0;
#endif

unsigned char *_text_buffer;
unsigned char *_text_lib_buffer;
unsigned char *_data_buffer;

int _text_buffer_ptr = 0;
int _text_lib_buffer_ptr = 0;
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


int _primary_reg = -1;
int _secondary_reg = -1;
int _register_stack_depth = 0;

int _save_primary_reg[REGISTER_SAVE_STACK];
int _save_register_stack_depth[REGISTER_SAVE_STACK];
int _save_reg_ptr = 0;


koda_compiler_options_t *_options = NULL;


int _div32_routine_address;
int _mul32_routine_address;


#define compiler_error(message, extra) \
    print_compiler_error(__FILE__, __LINE__, (message), (extra))

#define internal_error(message, extra) \
    print_internal_error(__FILE__, __LINE__, (message), (extra))

void print_compiler_error(char *file, int line, char *message, char *extra)
{
#if PLATFORM_WIN    
    fprintf(stderr, "%s(%d) error: %s(%d): %s", file, line, _program_source_file, _current_line + 1, message);
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

void print_internal_error(char *file, int line, char *message, char *extra)
{
#if PLATFORM_WIN    
    fprintf(stderr, "internal error\n");
#else
    sys_chan_write(0, "internal error\n", 15);
#endif  
    print_compiler_error(file, line, message, extra);
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
        case OP_JUMP_FWD:
        case OP_JUMP_BACK:
        case OP_JUMP_TRUE:
        case OP_JUMP_FALSE:
            printf("%s%06X\n", buffer, code->code->position);
            break;

        case OP_CALL:
            printf("%s%s(%d)\n", buffer, code->symbol->name, code->symbol->flags >> 8);
            break;

        case OP_CALL_INDIRECT:
            printf("%s%s\n", buffer, code->symbol->name);
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
        case OP_FUNC_START:
            printf("%s:\n", code->symbol->name);
            printf("%s%d\n", buffer, code->value);
            break;

        case OP_LOAD_GLOBAL_ADDR:
        //case OP_LDADDR_STACK:
            if (code->symbol != NULL)
                printf("%s%s\n", buffer, code->symbol->name);
            else
                printf("%s%06X\n", buffer, code->value);
            break;

        case OP_LOAD_LOCAL_ADDR:
        case OP_LOAD_GLOBAL:
        //case OP_LDGLOBAL_STACK:
        case OP_LOAD_LOCAL:
        //case OP_LDLOCAL_STACK:
        case OP_STORE_GLOBAL:
        case OP_STORE_LOCAL:
        case OP_GLOBAL_VEC:
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

    code_t *to_remove = code->next;

    code_t *prev = code;
    code_t *next = code->next->next;

    prev->next = next;
    if (next != NULL)
        next->prev = prev;

#if PLATFORM_WIN
    free(to_remove);
#endif    
}


void optimize_remove_dead_code(void)
{
    // Mark all code as unused, except for OP_FUNC_END opcodes
    for (code_t *it = _code_start; it != NULL; it = it->next)
        it->used = false;

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
            case OP_JUMP_FWD:
                if (conditional_jump_count[call_stack_ptr] == 0)
                    pc = pc->code;
                else
                    pc = pc->next;
                break;

            case OP_JUMP_FALSE:
            case OP_JUMP_TRUE:
                conditional_jump_count[call_stack_ptr]++;
                pc = pc->next;
                break;

            case OP_JUMP_TARGET:
                if (pc->code->opcode == OP_JUMP_TRUE || pc->code->opcode == OP_JUMP_FALSE)
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

            case OP_STORE_GLOBAL:
            case OP_GLOBAL_VEC:
            case OP_LOAD_GLOBAL_ADDR:
            case OP_LOAD_GLOBAL:
                if (pc->symbol != NULL)
                {   
                    if (pc->symbol->code != NULL)
                    {
                        pc->symbol->code->used = true;

                        // This monstrosity makes sure we mark functions if we take the address of a function
                        if (pc->symbol->flags & SYM_FUNCTION)
                        {
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
                        else
                        {
                            pc = pc->next;
                        }
                    }
                    else
                    {
                        pc = pc->next;
                    }
                }
                else
                {
                    pc = pc->next;
                }
                break;

            case OP_CALL:
                {
                    if (pc->symbol->code == NULL)
                    {
                        // This could be a call to a function pointer
                        pc = pc->next;
                    }
                    else
                    {
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
                }
                break;

            default:
                pc = pc->next;
                break;
        }
    }

    // Special pass to handle mul32 and div32 asm code
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (it->used)
        {
            if (it->opcode == OP_MUL)
                _mul32_code->used = true;
            else if (it->opcode == OP_DIV || it->opcode == OP_MOD)
                _div32_code->used = true;
        }
    }

    // Special pass to handle OP_FUNC_END in used functions
    bool func_in_use = false;
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (it->opcode == OP_FUNC_START && it->used)
        {
            func_in_use = true;
        }
        else if (it->opcode == OP_FUNC_END && func_in_use)
        {
            it->used = true;
            func_in_use = false;
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

// Merge continous jumps
void optimize_jumps(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (!has_next(it))
            continue;

        if (it->opcode == OP_JUMP_TARGET && it->next->opcode == OP_JUMP_FWD)
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
        else if (it->opcode == OP_JUMP_FWD && it->next->opcode == OP_JUMP_TARGET)
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

void optimize_fold_constant_expressions(void)
{
    // We do four passes of constant expression folding, so we can be sure we got them all
    for (int pass = 0; pass < 4; ++pass)
    {
        for (code_t *it = _code_start; it != NULL; it = it->next)
        {
            if (has_next(it) && has_next(it->next))
            {
                if (it->opcode == OP_LOAD_VALUE && it->next->opcode == OP_LOAD_VALUE)
                {
                    switch (it->next->next->opcode)
                    {
                        case OP_ADD:
                            it->value += it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;

                        case OP_SUB:
                            it->value -= it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;

                        case OP_MUL:
                            it->value *= it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;

                        case OP_DIV:
                            it->value /= it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;

                        case OP_MOD:
                            it->value %= it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;

                        case OP_SHIFT_LEFT:
                            it->value = it->value << it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;

                        case OP_SHIFT_RIGHT:
                            it->value = it->value >> it->next->value;
                            remove_next(it);
                            remove_next(it);
                            break;                            
                    }
                }
            }
        }
    }
}

void optimize_store_load(void)
{
    // This pass does not work with the kind of register allocation we do
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        if (has_next(it))
        {   
            // Are we first writing a value to memory, and then directly fetching it again?
            if (it->opcode == OP_STORE_GLOBAL && it->next->opcode == OP_LOAD_GLOBAL && it->symbol == it->next->symbol)
            {
                it->opcode = OP_STORE_GLOBAL_NP;
                remove_next(it);
            }
            else if (it->opcode == OP_STORE_LOCAL && it->next->opcode == OP_LOAD_LOCAL && it->value == it->next->value)
            {
                it->opcode = OP_STORE_LOCAL_NP;
                remove_next(it);
            }
        }
    }
}

void optimize_code(void)
{
    // TODO: Add a pass for OP_STORE_GLOBAL a, OP_LOAD_GLOBAL a

    optimize_jumps();
    optimize_merge_alloc();
    optimize_store_load();
    optimize_fold_constant_expressions();
    optimize_remove_dead_code();
}

void mark_used_symbols(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        switch (it->opcode)
        {
            case OP_STORE_GLOBAL:
            case OP_STORE_GLOBAL_NP:
            case OP_GLOBAL_VEC:
            case OP_LOAD_GLOBAL_ADDR:
            case OP_LOAD_GLOBAL:
                if (it->symbol != NULL)
                    it->symbol->used = true;
                break;

            case OP_CALL:
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

void spill(void)
{
    /*
    if (_accumulator_loaded)
        code_opcode_value(OP_PUSH, 0);
    else
        _accumulator_loaded = 1;
    */
}

int loaded(void)
{
    return 1; //_accumulator_loaded;
}

void clear(void)
{
    //_accumulator_loaded = 0;
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
            if (sym->value == 0)
            {
                sym->value = _data_buffer_ptr + _options->data_start_address;
                data_word(0);
            }
        }
    }
}


/**
 * Code Generation
 */

void m68_push_reg(int reg);
void m68_pop_reg(int reg);

void allocate_reg(void)
{
    if (_primary_reg > NUMBER_OF_REGS)
    {
        _primary_reg = 0;
        m68_push_reg(_primary_reg);
        _register_stack_depth++;
    }
    else if (_register_stack_depth > 0)
    {
        _primary_reg++;
        m68_push_reg(_primary_reg);
        _register_stack_depth++;
    }
    else
    {
        _primary_reg++;
    }

    _secondary_reg = _primary_reg < 1 ? NUMBER_OF_REGS - 1 : _primary_reg - 1;
}

void free_reg(bool pop_reg)
{
    if (_register_stack_depth > 0)
    {
        if (pop_reg)
            m68_pop_reg(_primary_reg);

        _register_stack_depth--;
        _primary_reg--;
        if (_primary_reg < 0)
            _primary_reg = NUMBER_OF_REGS - 1;
    }
    else
    {
        _primary_reg--;
    }

    _secondary_reg = _primary_reg < 1 ? NUMBER_OF_REGS - 1 : _primary_reg - 1;
}

void free_all_regs(void)
{
    while (_register_stack_depth > 0)
    {
        m68_pop_reg(SCRATCH_REG);        // pop into our scratch register, we don't care about the value
        _register_stack_depth--;
    }
    _primary_reg = -1;
    _secondary_reg = -1;
}


void emit_assembly(code_t *code, char *machine_code)
{
    if (machine_code == NULL)
        internal_error("missing machine code for opcode", _opcode_names[code->opcode]);

    // code->position = _text_buffer_ptr + _options->text_start_address;

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
                if (code->code->opcode == OP_JUMP_FWD || code->code->opcode == OP_JUMP_TRUE || code->code->opcode == OP_JUMP_FALSE)
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

void m68_push_reg(int reg)
{
    // move.l d0,-(sp) -> 2F 00 -> 0010 1111 0000 0000
    int opcode = 0x2F00 | reg;
    emit_short(opcode);
}

void m68_pop_reg(int reg)
{
    // move.l (sp)+,d0 -> 20 1F -> 0010 0000 0001 1111
    int opcode = 0x201F | (reg << 9);
    emit_short(opcode);
}

void m68_push_multiple_regs(int start, int end)
{
    // movem d0-d3,-(sp) -> 48 E7 F0 00 -> 0100 1000 1110 0111 , 1111 0000 0000 0000
    int opcode = 0x48E7;
    int regs = 0x0000;

    for (int reg = start; reg <= end; ++reg)
        regs |= (1 << (16 - reg));

    emit_short(opcode);
    emit_short(regs);
}

void m68_pop_multiple_regs(int start, int end)
{
    // movem.l (sp)+,d0-d3  -> 4C DF 00 0F
    int opcode = 0x4CDF;
    int regs = 0x0000;

    for (int reg = start; reg <= end; ++reg)
        regs |= 1 << reg;

    emit_short(opcode);
    emit_short(regs);
}

void m68_move_im_to_reg(int value, int reg)
{
    // move.l #$XXXXXXXX,d0 -> 20 3C -> 0010 0000 0011 1100
    int opcode = 0x203C | (reg << 9);        // move.l #$XXXX,dY
    emit_short(opcode);
    emit_word(value);
}

void m68_moveq_to_reg(char value, int reg)
{
    // moveq #$XX,dY -> 70 00
    int opcode = 0x7000 | (reg << 9) | (unsigned char)value;
    emit_short(opcode);    
}

// If offset == 0 then we move a6 -> dY otherwise it's an offset(a6) -> dY move
void m68_move_fp_to_reg(int offset, int reg)
{
    // move.l a6,d0 -> 20 0E
    // move.l $1BEF(a6),d0 -> 20 2E
    int opcode = 0x200E | (reg << 9) | (offset == 0 ? 0x0000 : 0x0020);
    emit_short(opcode);

    if (offset != 0)
        emit_short(offset);
}

void m68_move_reg_to_fp_offset(int reg, int offset)
{
    // move.l dY,$XXXX(a6) -> 2D 40
    int opcode = 0x2D40 | reg;
    emit_short(opcode);
    emit_short(offset);
}

void m68_move_sp_reg(int reg)
{
    // move.l sp,dY -> 20 0F
    int opcode = 0x200F | (reg << 9);
    emit_short(opcode);
}

void m68_move_sp_mem(int addr)
{
    // move.l sp,$BEEFFEED  -> 23 CF
    emit_short(0x23CF);
    emit_word(addr);
}

void m68_move_reg_to_reg(int source, int dest)
{
    // move.l d0,d1 -> 22 00 -> 0010 0010 0000 0000
    // move.l d7,d2 -> 24 07 -> 0010 0100 0000 0111
    // move.l d6,d3 -> 26 06 -> 0010 0110 0000 0110
    int opcode = 0x2000 | (dest << 9) | source;
    emit_short(opcode);
}

void m68_move_mem_to_reg(int addr, int reg)
{
    // move.l $XXXXXXXX,d0 -> 20 39
    int opcode = 0x2039 | (reg << 9);
    emit_short(opcode);
    emit_word(addr);
}

void m68_move_reg_to_mem(int reg, int addr)
{
    // move.l d0,$XXXXXXXX -> 23 C0
    int opcode = 0x23C0 | reg;
    emit_short(opcode);
    emit_word(addr);
}

void m68_move_reg_to_a5(int reg)
{
    // move.l dY,a5 -> 2A 40
    int opcode = 0x2A40 | reg;
    emit_short(opcode);
}


void m68_move_reg_to_a5_indirect_byte(int reg)
{
    // move.b dY,(a5) -> 1A 80
    int opcode = 0x1A80 | reg;
    emit_short(opcode);
}

void m68_move_reg_to_a5_indirect_word(int reg)
{
    // move.w dY,(a5) -> 3A 80
    int opcode = 0x3A80 | reg;
    emit_short(opcode);
}

void m68_move_reg_to_a5_indirect_long(int reg)
{
    // move.l dY,(a5) -> 2A 80
    int opcode = 0x2A80 | reg;
    emit_short(opcode);
}

void m68_move_a5_indirect_byte_to_reg(int reg)
{
    // move.b (a5),dY -> 10 15
    int opcode = 0x1015 | (reg << 9);
    emit_short(opcode);
}

void m68_move_a5_indirect_word_to_reg(int reg)
{
    // move.w (a5),dY -> 30 15
    int opcode = 0x3015 | (reg << 9);
    emit_short(opcode);
}

void m68_move_a5_indirect_long_to_reg(int reg)
{
    // move.l (a5),dY -> 20 15
    int opcode = 0x2015 | (reg << 9);
    emit_short(opcode);
}

void m68_exg(int source, int dest)
{
    // exg d0,d1 -> C1 41
    // exg d1,d0 -> C3 40
    int opcode = 0xC140 | (dest << 9) | source;
    emit_short(opcode);
}

void m68_add_im_to_reg(int value, int reg)
{
    // add.l #$BEEFFEED,d0 -> D0 BC -> 1101 0000 1011 1100
    // add.l #$BEEFFEED,d1 -> D2 BC -> 1101 0010 1011 1100
    int opcode = 0xD0BC | (reg << 9);
    emit_short(opcode);
    emit_word(value);
}

void m68_add_reg_to_reg(int source, int dest)
{
    // add.l d0,d1 -> D2 80
    // add.l d0,d2 -> D4 80
    // add.l d1,d0 -> D0 81
    int opcode = 0xD080 | (dest << 9) | source;
    emit_short(opcode);
}

void m68_sub_reg_to_reg(int source, int dest)
{
    // sub.l d0,d1 -> 92 80
    int opcode = 0x9080 | (dest << 9) | source;
    emit_short(opcode);
}

void m68_sub_im_to_reg(int value, int dest)
{
    // sub.l #1234,d0 -> 90 BC
    int opcode = 0x90BC | (dest << 9);
    emit_short(opcode);
    emit_word(value);
}

void m68_sub_im_to_stack(int value)
{
    // suba.l #XXXXXX,a7 -> 9F FC
    int opcode = 0x9FFC;
    emit_short(opcode);
    emit_word(value);
}

void m68_and_reg_to_reg(int source, int dest)
{
    // and.l d0,d1 -> C2 80
    int opcode = 0xC080 | (dest << 9) | source;
    emit_short(opcode);
}

void m68_or_reg_to_reg(int source, int dest)
{
    // or.l d0,d1 -> 82 80
    int opcode = 0x8080 | (dest << 9) | source;
    emit_short(opcode);
}

void m68_logic_shift_left(int amount, int reg)
{
    // lsl.l #1,d0 -> E3 88 -> 1110 0011 1000 1000
    if (amount < 1)
        internal_error("invalid shift amount", NULL);

    int opcode = 0xE188 | (amount << 9) | reg;
    emit_short(opcode);
}

void m68_trap(int number)
{
    assert(number >= 0 && number <= 15);

    int opcode = 0x4E40 | number;
    emit_short(opcode);
}

void m68_jsr(int addr)
{
    // jsr -> 4E B9
    int opcode = 0x4EB9;
    emit_short(opcode);
    emit_word(addr);
}

void m68_jsr_indirect(void)
{
    // jsr (a5) -> 4E 95
    int opcode = 0x4E95;
    emit_short(opcode);
}

void m68_neg(int reg)
{
    int opcode = 0x4480 | reg;
    emit_short(opcode);
}

void m68_not(int reg)
{
    int opcode = 0x4680 | reg;
    emit_short(opcode);
}

void m68_cmp_im_to_reg(int value, int reg)
{
    if (value == 0)
    {
       // cmp.l #0,d0 -> 4A 80
        int opcode = 0x4A80 | reg;
        emit_short(opcode);
    }
    else
    {
        // cmp.l $XX,d0 -> B0 BC
        int opcode = 0xB0BC | (reg << 9);
        emit_short(opcode);
        emit_word(value);
    }
}

void m68_cmp_reg_to_reg(int source, int dest)
{
    // cmp.l d0,d0 -> B0 80
    // cmp.l d0,d1 -> B2 80
    // cmp.l d1,d0 -> B0 81
    int opcode = 0xB080 | (dest << 9) | source;
    emit_short(opcode);
}

int m68_branch(int type, int offset)
{
    if (offset < SCHAR_MIN || offset > SCHAR_MAX)
    {
        int opcode = 0x6000 | type;
        emit_short(opcode);
        emit_short(offset);

        return _text_buffer_ptr - 2;
    }
    else
    {
        int opcode = 0x6000 | type | offset;
        emit_short(opcode);

        return -1;
    }
}

void emit_write32(code_t *code)
{
    code->symbol->value = _text_buffer_ptr + _options->text_start_address;
    emit_word(code->value);
}

void emit_alloc_mem(code_t *code)
{
    code->symbol->value = _text_buffer_ptr + _options->text_start_address;
    emit_allocate(code->value);
}

void emit_asm(code_t *code)
{
    if (code->symbol != NULL)
        code->symbol->value = _text_buffer_ptr + _options->text_start_address;
    emit_assembly(code, code->assembly);
}

void emit_alloc(code_t *code)
{
    m68_sub_im_to_stack(code->value);
}

void emit_load_value(code_t *code)
{
    allocate_reg();

    if (code->value < SCHAR_MIN || code->value > SCHAR_MAX)
        m68_move_im_to_reg(code->value, _primary_reg);
    else
        m68_moveq_to_reg(code->value, _primary_reg);
}

void emit_load_global_addr(code_t *code)
{
    int value = code->symbol != NULL ? code->symbol->value : code->value;
    allocate_reg();
    m68_move_im_to_reg(value, _primary_reg);
}

void emit_load_local_addr(code_t *code)
{
    // move.l a6,dY
    // add.l #LONG_VALUE,dY
    allocate_reg();
    m68_move_fp_to_reg(0, _primary_reg);
    m68_add_im_to_reg(code->value, _primary_reg);
}

void emit_load_global(code_t *code)
{
    // move.l $XXXXXXXX,dY
    int addr = code->symbol != NULL ? code->symbol->value : code->value;
    allocate_reg();
    m68_move_mem_to_reg(addr, _primary_reg);
}

void emit_load_local(code_t *code)
{
    // move.l $XXX(a6),dY   
    allocate_reg();
    m68_move_fp_to_reg(code->value, _primary_reg);
}

void emit_clear(code_t *code)
{
    // move.q #$00,dX
    m68_moveq_to_reg(0, RETURN_REG);
}

void emit_to_ret(code_t *code)
{
    m68_move_reg_to_reg(_primary_reg, RETURN_REG);
    free_reg(true);
}

void emit_from_ret(code_t *code)
{
    allocate_reg();
    m68_move_reg_to_reg(RETURN_REG, _primary_reg);
}

void emit_halt(code_t *code)
{
    if (code->value < SCHAR_MIN || code->value > SCHAR_MAX)
        m68_move_im_to_reg(code->value, 1);
    else
        m68_moveq_to_reg(code->value, 1);

    m68_moveq_to_reg(0, 0);
    m68_trap(15);
}

void emit_store_global(code_t *code)
{
    // move.l dY,$XXXXXXXX
    int addr = code->symbol != NULL ? code->symbol->value : code->value;
    m68_move_reg_to_mem(_primary_reg, addr);

    if (code->opcode == OP_STORE_GLOBAL)
        free_reg(true);
}

void emit_store_local(code_t *code)
{
    // move.l dY,$XXX(a6)
    m68_move_reg_to_fp_offset(_primary_reg, code->value);

    if (code->opcode == OP_STORE_LOCAL)
        free_reg(true);
}

void emit_store_indirect_word(code_t *code)
{
    // [S0] := A; P := P + 1
    // move.l (sp)+,d0
    // move.l (sp)+,a5
    // move.l d0,(a5)  
    m68_move_reg_to_a5(_secondary_reg);
    m68_move_reg_to_a5_indirect_long(_primary_reg);
    free_reg(true);
    free_reg(true);
}

void emit_store_indirect_byte(code_t *code)
{
    // b[S0] := A; P := P + 1
    // move.l (sp)+,d0
    // move.l (sp)+,a5
    // move.b d0,(a5)
    m68_move_reg_to_a5(_secondary_reg);
    m68_move_reg_to_a5_indirect_byte(_primary_reg);
    free_reg(true);
    free_reg(true);
}

void emit_index_word(code_t *code)
{
    // A := 4 * A + S0; P := P + 1
    // move.l (sp)+,d0
    // move.l (sp)+,d1
    // lsl.l #2,d0
    // add.l d1,d0
    // move.l d0,-(sp)
    m68_logic_shift_left(2, _primary_reg);
    m68_add_reg_to_reg(_primary_reg, _secondary_reg);
    free_reg(true);
}

void emit_index_byte(code_t *code)
{
    // A := A + S0; P := P + 1
    m68_add_reg_to_reg(_primary_reg, _secondary_reg);
    free_reg(true);
}

void emit_deref_word(code_t *code)
{
    // A := [A]
    // move.l dY,a5
    // move.l (a5),dY
    m68_move_reg_to_a5(_primary_reg);
    m68_move_a5_indirect_long_to_reg(_primary_reg);
}

void emit_deref_byte(code_t *code)
{
    // A := b[A]
    // move.l dY,a5
    // moveq #0,dY
    // move.b (a5),dY
    m68_move_reg_to_a5(_primary_reg);
    m68_moveq_to_reg(0, _primary_reg);
    m68_move_a5_indirect_long_to_reg(_primary_reg);
}

void emit_call_setup(code_t *code)
{
    if (_register_stack_depth > 0)
    {
        for (int i = _primary_reg + 1; i < NUMBER_OF_REGS; ++i)
            m68_push_reg(i);
    }

    if (_primary_reg >= 0)
    {
        for (int i = 0; i <= _primary_reg; ++i)
            m68_push_reg(i);
    }
}

void emit_call_cleanup(code_t *code)
{
    int arg_count = code->value;
    while (arg_count > 0)
    {
        free_reg(false);
        arg_count--;
    }

    if (_primary_reg - 1 >= 0)
    {
        for (int i = _primary_reg; i >= 0; --i)
            m68_pop_reg(i);
    }

    if (_register_stack_depth > 0)
    {
        for (int i = NUMBER_OF_REGS - 1; i > _primary_reg; --i)
            m68_push_reg(i);
    }    
}

void emit_func_start(code_t *code)
{
    code->symbol->value = _text_buffer_ptr + _options->text_start_address;
    emit_assembly(code, INST_ENTER);

    // Save the values of the old registers
    _save_primary_reg[_save_reg_ptr] = _primary_reg;
    _save_register_stack_depth[_save_reg_ptr] = _register_stack_depth;
    _save_reg_ptr++;

    _primary_reg = -1;
    _secondary_reg = -1;
    _register_stack_depth = 0;
}

void emit_func_end(code_t *code)
{
    if (_save_reg_ptr == 0)
        internal_error("register save stack empty, this could not happen", NULL);

    _save_reg_ptr--;

    _primary_reg = _save_primary_reg[_save_reg_ptr];
    _register_stack_depth = _save_register_stack_depth[_save_reg_ptr];
    _secondary_reg = _primary_reg < 1 ? NUMBER_OF_REGS - 1 : _primary_reg - 1;
}

void emit_call(code_t *code)
{
    m68_jsr(code->symbol->value);
}

void emit_call_indirect(code_t *code)
{
    if (code->symbol->flags & SYM_GLOBF)
        emit_load_global_addr(code);
    else
        emit_load_local_addr(code);

    m68_move_reg_to_a5(_primary_reg);
    free_reg(false);

    m68_jsr_indirect();
}

void emit_neg(code_t *code)
{
    assert(_primary_reg >= 0);
    m68_neg(_primary_reg);
}

void emit_inv(code_t *code)
{
    assert(_primary_reg >= 0);
    m68_not(_primary_reg);
}

void emit_lognot(code_t *code)
{
    assert(_primary_reg >= 0);

    //     move.l (sp)+,d1
    //     moveq #0,d0
    //     cmp.l #0,d1
    //     bne done
    //     move.l #$ffffffff,d0
    // done:
    //     move.l d0,-(sp)
    m68_move_reg_to_reg(_primary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _primary_reg);
    m68_cmp_im_to_reg(0, SCRATCH_REG);
    m68_branch(M68_BRANCH_NOT_EQUAL, 6);
    //m68_move_im_to_reg(-1, _primary_reg);
    m68_moveq_to_reg(0xFF, _primary_reg);
}

void emit_add(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_add_reg_to_reg(_primary_reg, _secondary_reg);
    free_reg(true);
}

void emit_sub(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_exg(_primary_reg, _secondary_reg);
    m68_sub_reg_to_reg(_primary_reg, _secondary_reg);
    free_reg(true);
}

void emit_mul(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_push_multiple_regs(0, NUMBER_OF_REGS - 1);
    m68_jsr(_mul32_code->position);
    m68_move_reg_to_reg(0, SCRATCH_REG);
    m68_pop_multiple_regs(0, NUMBER_OF_REGS - 1);
    m68_move_reg_to_reg(SCRATCH_REG, _secondary_reg);
    free_reg(true);
}

void emit_div(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_push_multiple_regs(0, NUMBER_OF_REGS - 1);
    m68_jsr(_div32_code->position);
    m68_move_reg_to_reg(0, SCRATCH_REG);
    m68_pop_multiple_regs(0, NUMBER_OF_REGS - 1);
    m68_move_reg_to_reg(SCRATCH_REG, _secondary_reg);
    free_reg(true); 
}

void emit_mod(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_push_multiple_regs(0, NUMBER_OF_REGS - 1);
    m68_jsr(_div32_code->position);
    m68_move_reg_to_reg(1, SCRATCH_REG);
    m68_pop_multiple_regs(0, NUMBER_OF_REGS - 1);
    m68_move_reg_to_reg(SCRATCH_REG, _secondary_reg);
    free_reg(true); 
}

void emit_and(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);
    m68_and_reg_to_reg(_primary_reg, _secondary_reg);
    free_reg(true);
}

void emit_or(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);
    m68_or_reg_to_reg(_primary_reg, _secondary_reg);
    free_reg(true);
}

void emit_jump_fwd(code_t *code)
{
    // Use a dummy address for the jump. It will be patched by the jump target opcode later on.
    code->position = m68_branch(M68_BRANCH_TRUE, 0x1234);
}

void emit_jump_back(code_t *code)
{
    int addr = code->code->position;
    m68_branch(M68_BRANCH_TRUE, addr - _text_buffer_ptr);
}

void emit_jump_true(code_t *code)
{
    // move.l (sp)+,d0
    // cmp.l #0,d0
    // bne JUMP_FWD

    m68_move_reg_to_reg(_primary_reg, SCRATCH_REG);
    free_reg(true);
    m68_cmp_im_to_reg(0, SCRATCH_REG);
    code->position = m68_branch(M68_BRANCH_NOT_EQUAL, 0x1234);
}

void emit_jump_false(code_t *code)
{
    // move.l (sp)+,d0
    // cmp.l #0,d0
    // beq JUMP_FWD

    m68_move_reg_to_reg(_primary_reg, SCRATCH_REG);
    free_reg(true);
    m68_cmp_im_to_reg(0, SCRATCH_REG);
    code->position = m68_branch(M68_BRANCH_EQUAL, 0x1234);
}

void emit_jump_target(code_t *code)
{
    if (code->code->opcode == OP_JUMP_FWD || code->code->opcode == OP_JUMP_TRUE || code->code->opcode == OP_JUMP_FALSE)
    {
        int addr = code->code->position;
        text_patch_short(addr, _text_buffer_ptr - addr);
    }
}

void emit_eq(code_t *code)
{
    //     moveq #0,d0
    //     cmp.l d1,d2
    //     beq .done
    //     move.l #$FFFFFFFF,d0
    // .done:

    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_reg(_secondary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _secondary_reg);
    m68_cmp_reg_to_reg(_primary_reg, SCRATCH_REG);
    m68_branch(M68_BRANCH_NOT_EQUAL, 2);
    m68_moveq_to_reg(0xFF, _secondary_reg);

    free_reg(true);
}

void emit_not_eq(code_t *code)
{
    m68_move_reg_to_reg(_secondary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _secondary_reg);
    m68_cmp_reg_to_reg(_primary_reg, SCRATCH_REG);
    m68_branch(M68_BRANCH_EQUAL, 2);
    m68_moveq_to_reg(0xFF, _secondary_reg);

    free_reg(true);
}

void emit_less(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_reg(_secondary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _secondary_reg);
    m68_cmp_reg_to_reg(SCRATCH_REG, _primary_reg);
    m68_branch(M68_BRANCH_GREATER_EQUAL, 2);
    m68_moveq_to_reg(0xFF, _secondary_reg);

    free_reg(true);    
}

void emit_less_equal(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_reg(_secondary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _secondary_reg);
    m68_cmp_reg_to_reg(SCRATCH_REG, _primary_reg);
    m68_branch(M68_BRANCH_GREATER, 2);
    m68_moveq_to_reg(0xFF, _secondary_reg);

    free_reg(true);    
}

void emit_greater(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_reg(_secondary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _secondary_reg);
    m68_cmp_reg_to_reg(SCRATCH_REG, _primary_reg);
    m68_branch(M68_BRANCH_LESS_EQUAL, 2);
    m68_moveq_to_reg(0xFF, _secondary_reg);

    free_reg(true);    
}

void emit_greater_equal(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_reg(_secondary_reg, SCRATCH_REG);
    m68_moveq_to_reg(0, _secondary_reg);
    m68_cmp_reg_to_reg(SCRATCH_REG, _primary_reg);
    m68_branch(M68_BRANCH_LESS, 2);
    m68_moveq_to_reg(0xFF, _secondary_reg);

    free_reg(true);    
}


void emit_inc(code_t *code)
{
    // move.l (sp)+,a5
    // addq.l #1,(a5)
    m68_move_reg_to_a5(_primary_reg);
    m68_move_a5_indirect_long_to_reg(SCRATCH_REG);
    m68_add_im_to_reg(1, SCRATCH_REG);
    m68_move_reg_to_a5_indirect_long(SCRATCH_REG);

    free_reg(true);    
}

void emit_dec(code_t *code)
{
    // move.l (sp)+,a5
    // addq.l #1,(a5)
    m68_move_reg_to_a5(_primary_reg);
    m68_move_a5_indirect_long_to_reg(SCRATCH_REG);
    m68_sub_im_to_reg(1, SCRATCH_REG);
    m68_move_reg_to_a5_indirect_long(SCRATCH_REG);

    free_reg(true);    
}

void emit_peek8(code_t *code)
{
    assert(_primary_reg >= 0);
    m68_move_reg_to_a5(_primary_reg);
    m68_moveq_to_reg(0, RETURN_REG);
    m68_move_a5_indirect_byte_to_reg(RETURN_REG);
    free_reg(true);
}

void emit_peek16(code_t *code)
{
    assert(_primary_reg >= 0);
    m68_move_reg_to_a5(_primary_reg);
    m68_moveq_to_reg(0, RETURN_REG);
    m68_move_a5_indirect_word_to_reg(RETURN_REG);
    free_reg(true);
}

void emit_peek32(code_t *code)
{
    assert(_primary_reg >= 0);
    m68_move_reg_to_a5(_primary_reg);
    m68_move_a5_indirect_long_to_reg(RETURN_REG);
    free_reg(true);
}

void emit_poke8(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);
    m68_move_reg_to_a5(_secondary_reg);
    m68_move_reg_to_a5_indirect_byte(_primary_reg);

    free_reg(true);
    free_reg(true);
}

void emit_poke16(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_a5(_secondary_reg);
    m68_move_reg_to_a5_indirect_word(_primary_reg);

    free_reg(true);
    free_reg(true);    
}

void emit_poke32(code_t *code)
{
    assert(_primary_reg >= 0 && _secondary_reg >= 0);

    m68_move_reg_to_a5(_secondary_reg);
    m68_move_reg_to_a5_indirect_long(_primary_reg);

    free_reg(true);
    free_reg(true);
}

void emit_m68k_machine_code(void)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        it->position = _text_buffer_ptr + _options->text_start_address;

        switch (it->opcode)
        {
            case OP_WRITE_32:
                emit_write32(it);
                break;
            case OP_ALLOC_MEM:
                emit_alloc_mem(it);
                break;
            case OP_ASM:
                emit_asm(it);
                break;
            case OP_ALLOC:
                emit_alloc(it);
                break;
            case OP_LOAD_VALUE:
                emit_load_value(it);
                break;
            case OP_LOAD_GLOBAL_ADDR:
                emit_load_global_addr(it);
                break;
            case OP_LOAD_LOCAL_ADDR:
                emit_load_local_addr(it);
                break;
            case OP_LOAD_GLOBAL:
                emit_load_global(it);
                break;
            case OP_LOAD_LOCAL:
                emit_load_local(it);
                break;
            case OP_CLEAR:
                emit_clear(it);
                break;
            case OP_TO_RET:
                emit_to_ret(it);
                break;
            case OP_FROM_RET:
                emit_from_ret(it);
                break;
            case OP_HALT:
                emit_halt(it);
                break;
            case OP_STORE_GLOBAL:
            case OP_STORE_GLOBAL_NP:
                emit_store_global(it);
                break;
            case OP_STORE_LOCAL:
            case OP_STORE_LOCAL_NP:
                emit_store_local(it);
                break;
            case OP_STORE_INDIRECT_WORD:
                emit_store_indirect_word(it);
                break;
            case OP_STORE_INDIRECT_BYTE:
                emit_store_indirect_byte(it);
                break;
            case OP_DEALLOC:
                emit_assembly(it, INST_DEALLOC);
                break;
            case OP_LOCAL_VEC:
                emit_assembly(it, INST_LOCAL_VEC);
                break;
            case OP_GLOBAL_VEC:
                emit_assembly(it, INST_GLOBAL_VEC);
                break;
            case OP_INDEX_WORD:
                emit_index_word(it);
                break;
            case OP_INDEX_BYTE:
                emit_index_byte(it);
                break;
            case OP_DEREF_WORD:
                emit_deref_word(it);
                break;
            case OP_DEREF_BYTE:
                emit_deref_byte(it);
                break;
            case OP_CALL_SETUP:
                emit_call_setup(it);
                break;
            case OP_CALL:
                emit_call(it);
                break;
            case OP_CALL_INDIRECT:
                emit_call_indirect(it);
                break;
            case OP_CALL_CLEANUP:
                emit_call_cleanup(it);
                break;
            case OP_FUNC_START:
                emit_func_start(it);
                break;
            case OP_FUNC_END:
                emit_func_end(it);
                break;    
            case OP_EXIT:
                emit_assembly(it, INST_EXIT);
                break;   
            case OP_NEG:
                emit_neg(it);
                break;
            case OP_INV:
                emit_inv(it);
                break;
            case OP_LOGNOT:
                emit_lognot(it);
                break;
            case OP_ADD:
                emit_add(it);
                break;
            case OP_SUB:
                emit_sub(it);
                break;
            case OP_MUL:
                emit_mul(it);
                break;
            case OP_DIV:
                emit_div(it);
                break;
            case OP_MOD:
                emit_mod(it);
                break;
            case OP_AND:
                emit_and(it);
                break;
            case OP_OR:
                emit_or(it);
                break;
            // case OP_XOR:
            //     break;
            // case OP_SHIFT_LEFT:
            //     break;
            // case OP_SHIFT_RIGHT:
            //     break;
            case OP_EQ:
                emit_eq(it);
                break;
            case OP_NOT_EQ:
                emit_not_eq(it);
                break;
            case OP_LESS:
                emit_less(it);
                break;
            case OP_LESS_EQ:
                emit_less_equal(it);
                break;
            case OP_GREATER:
                emit_greater(it);
                break;
            case OP_GREATER_EQ:
                emit_greater_equal(it);
                break;
            case OP_JUMP_FWD:
                emit_jump_fwd(it);
                break;
            case OP_JUMP_BACK:
                emit_jump_back(it);
                break;
            case OP_JUMP_FALSE:
                emit_jump_true(it);
                break;
            case OP_JUMP_TRUE:
                emit_jump_false(it);
                break;
            case OP_JUMP_TARGET:
                emit_jump_target(it);
                break;
            case OP_INC:
                emit_inc(it);
                break;
            case OP_DEC:
                emit_dec(it);
                break;
            case OP_INIT:
                emit_assembly(it, INST_INIT);
                break;
            case OP_PEEK8:
                emit_peek8(it);
                break;
            case OP_PEEK16:
                emit_peek16(it);
                break;
            case OP_PEEK32:
                emit_peek32(it);
                break;
            case OP_POKE8:
                emit_poke8(it);
                break;
            case OP_POKE16:
                emit_poke16(it);
                break;
            case OP_POKE32:
                emit_poke32(it);
                break;

            default:
                {
                    char buffer[32];
                    snprintf(buffer, 32, "%d (%s)", it->opcode, _opcode_names[it->opcode]);
                    internal_error("missing opcode", buffer);
                }
                
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

#if PLATFORM_WIN

void emit_opcode(int *bytecode, int opcode)
{
    if (bytecode != NULL)
        bytecode[_text_buffer_ptr++] = opcode;
    else
        _text_buffer_ptr++;
}

void emit_opcode_value(int *bytecode, int opcode, int value)
{
    if (bytecode != NULL)
    {
        bytecode[_text_buffer_ptr++] = opcode;
        bytecode[_text_buffer_ptr++] = value;
    }
    else
        _text_buffer_ptr += 2;
}

void emit_bytecode(int *bytecode)
{
    for (code_t *it = _code_start; it != NULL; it = it->next)
    {
        it->position = _text_buffer_ptr;

        switch (it->opcode)
        {
            case OP_WRITE_32:
                it->symbol->value = _text_buffer_ptr + _options->text_start_address;
                _text_buffer_ptr += 1;
                break;

            case OP_ALLOC_MEM:
                it->symbol->value = _text_buffer_ptr + _options->text_start_address;
                _text_buffer_ptr += ((it->value / 4) + 1) * 4;
                break;

            case OP_FUNC_START:
                it->symbol->value = _text_buffer_ptr + _options->text_start_address;
                emit_opcode(bytecode, OP_FUNC_START);
                break;

            case OP_ASM:
                if (it->symbol != NULL)
                    it->symbol->value = _text_buffer_ptr + _options->text_start_address;
                //emit_assembly(it, it->assembly);
                emit_opcode(bytecode, OP_ASM);
                break;

            default:
                {
                    int arg_type = _opcode_arguments[it->opcode];

                    switch (arg_type)
                    {
                        case OP_ARG_NONE:
                            emit_opcode(bytecode, it->opcode);
                            break;

                        case OP_ARG_VALUE_WORD:
                        case OP_ARG_VALUE_LONG:
                            emit_opcode_value(bytecode, it->opcode, it->value);
                            break;

                        case OP_ARG_ADDRESS:
                            emit_opcode_value(bytecode, it->opcode, it->symbol != NULL ? it->symbol->value : it->value);
                            break;

                        case OP_ARG_FORWARD_REF:
                            emit_opcode(bytecode, it->opcode);
                            it->position = _text_buffer_ptr;
                            if (bytecode != NULL)
                                bytecode[_text_buffer_ptr] = 0;
                            _text_buffer_ptr += 1;                        
                            break;

                        case OP_ARG_BACKWARD_REF:
                            emit_opcode(bytecode, it->opcode);
                            if (bytecode != NULL)
                            {
                                int addr = it->code->position;
                                bytecode[_text_buffer_ptr] = addr - _text_buffer_ptr;
                            }
                            _text_buffer_ptr += 1;                        
                            break;

                        case OP_ARG_TARGET_REF:
                            if (it->code->opcode == OP_JUMP_FWD || it->code->opcode == OP_JUMP_TRUE || it->code->opcode == OP_JUMP_FALSE)
                            {
                                if (bytecode != NULL)
                                {
                                    int addr = it->code->position;
                                    bytecode[addr] = _text_buffer_ptr - addr;
                                }
                            }                           
                            break;
                    }                    
                }
                //emit_opcode(bytecode, it->opcode);
                break;
        }
    }  
}

void generate_bytecode(int **bytecode, int *bytecode_len)
{
    _text_buffer_ptr = 0;
    emit_bytecode(NULL);

    *bytecode_len = _text_buffer_ptr;
    *bytecode = malloc(sizeof(int) * *bytecode_len);

    _text_buffer_ptr = 0;
    emit_bytecode(*bytecode);
}

#endif

void builtin(char *name, int arity, char *code)
{
    code_t *jmp = code_opcode(OP_JUMP_FWD);
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
            value += _options->text_start_address;
        else if (!(sym->flags & SYM_CONST))
            value += _options->data_start_address;
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
    write_output_word(_options->text_start_address);      // start address
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
        write_pgz_segment(_options->text_start_address, _text_buffer, _text_buffer_ptr);
        
        if (_text_lib_buffer_ptr > 0)
            write_pgz_segment(_options->text_lib_start_address, _text_lib_buffer, _text_lib_buffer_ptr);
        
        write_pgz_segment(_options->data_start_address, _data_buffer, _data_buffer_ptr);

        // TODO: Add binary files as custom segments here
    }
    else if (_options->output_type == KODA_OUTPUT_TYPE_SREC)
    {
        write_srec_header();
        write_srec_segment(_options->text_start_address, _text_buffer, _text_buffer_ptr);

        if (_text_lib_buffer_ptr > 0)
            write_srec_segment(_options->text_lib_start_address, _text_lib_buffer, _text_lib_buffer_ptr);

        write_srec_segment(_options->data_start_address, _data_buffer, _data_buffer_ptr);

        // TODO: Add binary files as custom segments here
    }
    else
    {
#if PLATFORM_WIN
        fwrite(_text_buffer, _text_buffer_ptr, 1, _output_target);
#endif        
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

int _input_source_ptr_stack[INPUT_STACK_SIZE];
char _input_source_file_stack[INPUT_STACK_SIZE][128];
int _input_curren_line_stack[INPUT_STACK_SIZE];
int _input_stack_ptr = 0;

void read_input_source(char *source_file)
{
    memcpy(_program_source_file, source_file, strlen(source_file) + 1);
    _current_line = 0;
    _program_source_ptr = 0;

#ifdef PLATFORM_WIN
    FILE *input = fopen(source_file, "r");
    if (input == NULL)
        compiler_error("could not read source file", source_file);

    // TODO: We should make sure _program_source actually can handle the complete file
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

void push_source_file(char *source_file)
{
    assert(_input_stack_ptr < INPUT_STACK_SIZE);

    _input_source_ptr_stack[_input_stack_ptr] = _program_source_ptr;
    _input_curren_line_stack[_input_stack_ptr] = _current_line;
    memcpy(_input_source_file_stack[_input_stack_ptr], _program_source_file, strlen(_program_source_file) + 1);

    _input_stack_ptr++;

    read_input_source(source_file);
}

void pop_source_file(void)
{
    assert(_input_stack_ptr > 0);
    _input_stack_ptr--;

    read_input_source(_input_source_file_stack[_input_stack_ptr]);

    _current_line = _input_curren_line_stack[_input_stack_ptr];
    _program_source_ptr = _input_source_ptr_stack[_input_stack_ptr];
}

void read_stdlib_source(void)
{
    static char * name = "stdlib.k";

    if (foenix_stdlib_len >= PROGRAM_SIZE)
        internal_error("stdlib.k too large", NULL);

    memcpy(_program_source, foenix_stdlib_data, foenix_stdlib_len);
    _program_source_len = foenix_stdlib_len;
    _program_source_ptr = 0;
    memcpy(_program_source_file, name, strlen(name) + 1);
}

void read_input_string(const char *name, const char *str)
{
    _current_line = 0;
    _program_source_ptr = 0;
    memcpy(_program_source_file, name, strlen(name) + 1);
    _program_source_len = strlen(str);
    memcpy(_program_source, str, _program_source_len + 1);

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
    { 7, 1, "%",    TOKEN_BINOP,  OP_MOD      },
    { 6, 1, "+",    TOKEN_BINOP,  OP_ADD      },
    { 7, 1, "*",    TOKEN_BINOP,  OP_MUL      },
    { 0, 1, ",",    TOKEN_COMMA,  0           },
    { 0, 1, "(",    TOKEN_LEFT_PAREN, 0           },
    { 0, 1, ")",    TOKEN_RIGHT_PAREN, 0           },
    { 0, 1, "[",    TOKEN_LEFT_BRACKET, 0           },
    { 0, 1, "]",    TOKEN_RIGHT_BRACKET, 0           },
    { 5, 1, "&",    TOKEN_BINOP,  OP_AND      },
    { 1, 2, "&&",   TOKEN_DISJ,   0           },
    { 6, 1, "-",    TOKEN_BINOP,  OP_SUB      },
    { 5, 1, "^",    TOKEN_BINOP,  OP_XOR      },
    { 0, 1, "@",    TOKEN_ADDROF, 0           },
    { 5, 1, "|",    TOKEN_BINOP,  OP_OR       },
    { 2, 2, "||",   TOKEN_CONJ,   0           },
    { 0, 1, "!",    TOKEN_UNOP,   OP_LOGNOT   },
    { 0, 1, "?",    TOKEN_COND,   0           },
    { 7, 1, "/",    TOKEN_BINOP,  OP_DIV      },
    { 0, 1, "~",    TOKEN_UNOP,   OP_INV      },
    { 0, 1, ":",    TOKEN_COLON,  0           },
    { 0, 2, "::",   TOKEN_BYTEOP, 0           },
    { 3, 2, "!=",   TOKEN_BINOP,  OP_NOT_EQ      },
    { 4, 1, "<",    TOKEN_BINOP,  OP_LESS       },
    { 4, 2, "<=",   TOKEN_BINOP,  OP_LESS_EQ       },
    { 5, 2, "<<",   TOKEN_BINOP,  OP_SHIFT_LEFT      },
    { 4, 1, ">",    TOKEN_BINOP,  OP_GREATER       },
    { 4, 2, ">=",   TOKEN_BINOP,  OP_GREATER_EQ       },
    { 5, 2, ">>",   TOKEN_BINOP,  OP_SHIFT_RIGHT      },
    { 0, 1, "=",    TOKEN_ASSIGN, 0           },
    { 3, 2, "==",   TOKEN_BINOP,  OP_EQ       },
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
            if (!strcmp(str, "const")) return TOKEN_KEYWORD_CONST;
            return 0;
        case 'd':
            if (!strcmp(str, "dec")) return TOKEN_KEYWORD_DEC;
            if (!strcmp(str, "decl")) return TOKEN_KEYWORD_DECL;
            return 0;
        case 'e':
            if (!strcmp(str, "else")) return TOKEN_KEYWORD_ELSE;
            return 0;
        case 'f':
            if (!strcmp(str, "func")) return TOKEN_KEYWORD_FUNC;
            return 0;
        case 'h':
            if (!strcmp(str, "halt")) return TOKEN_KEYWORD_HALT;
            return 0;
        case 'i':
            if (!strcmp(str, "if")) return TOKEN_KEYWORD_IF;
            if (!strcmp(str, "inc")) return TOKEN_KEYWORD_INC;
            if (!strcmp(str, "import")) return TOKEN_KEYWORD_IMPORT;
            return 0;
        case 'l':
            if (!strcmp(str, "leave")) return TOKEN_KEYWORD_LEAVE;
            if (!strcmp(str, "loop")) return TOKEN_KEYWORD_LOOP;
            return 0;
        case 'p':
            if (!strcmp(str, "peek8")) return TOKEN_KEYWORD_PEEK8;
            if (!strcmp(str, "peek16")) return TOKEN_KEYWORD_PEEK16;
            if (!strcmp(str, "peek32")) return TOKEN_KEYWORD_PEEK32;
            if (!strcmp(str, "poke8")) return TOKEN_KEYWORD_POKE8;
            if (!strcmp(str, "poke16")) return TOKEN_KEYWORD_POKE16;
            if (!strcmp(str, "poke32")) return TOKEN_KEYWORD_POKE32;
            return 0;
        case 'r':
            if (!strcmp(str, "return")) return TOKEN_KEYWORD_RETURN;
            return 0;
        case 's':
            if (!strcmp(str, "struct")) return TOKEN_KEYWORD_STRUCT;
            return 0;
        case 'v':
            if (!strcmp(str, "var")) return TOKEN_KEYWORD_VAR;
            return 0;
        case 'w':
            if (!strcmp(str, "while")) return TOKEN_KEYWORD_WHILE;
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
        return TOKEN_ENDFILE;
    }

    if (ch == '{')
        return TOKEN_BLOCK_START;
    if (ch == '}')
        return TOKEN_BLOCK_END;

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

        return TOKEN_SYMBOL;
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
        return TOKEN_INTEGER;
    }

    if (ch == '\'')
    {
        _token_value = read_encoded_char();
        if (read_char() != '\'')
            compiler_error("missing ''' in character", NULL);
        return TOKEN_INTEGER;
    }

    if (ch == '"')
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
        return TOKEN_STRING;
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
    if (_token != TOKEN_ASSIGN || _token_op_id != _equal_op)
        expect(0, "'='");
    scan();
}

void expect_left_paren(void)
{
    expect(TOKEN_LEFT_PAREN, "'('");
    scan();
}

void expect_right_paren(void)
{
    expect(TOKEN_RIGHT_PAREN, "')'");
    scan();
}

int const_factor(void)
{

    int value;
    symbol_t *sym;

    if (_token == TOKEN_INTEGER)
    {
        value = _token_value;
        scan();
        return value;
    }
    else if (_token == TOKEN_SYMBOL)
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
    while (_token == TOKEN_BINOP)
    {
        if (_token_op_id == _mul_op)
        {
            scan();
            value *= const_factor();
        }
        else if (_token_op_id == _add_op)
        {
            scan();
            value += const_factor();
        }
        else
        {
            compiler_error("invalid operation", NULL);
        }
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
        expect(TOKEN_SYMBOL, "symbol");
        size = 1;
        if (glob & SYM_GLOBF)
            var = add(_token_str, glob, 0);
        else
            var = add(_token_str, 0, _local_frame_ptr);

        scan();
        if (TOKEN_LEFT_BRACKET == _token)
        {
            scan();
            size = const_value();
            if (size < 1)
                compiler_error("invalid size", NULL);
            var->flags |= SYM_VECTOR;
            expect(TOKEN_RIGHT_BRACKET, "']'");
            scan();
        }
        else if (TOKEN_BYTEOP == _token)
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
                code_symbol(OP_GLOBAL_VEC, var);
            }
        }
        else
        {
            // TODO: Make sure this works
            code_opcode_value(OP_ALLOC, size * BPW);
            
            _local_frame_ptr -= size * BPW;
            if (var->flags & SYM_VECTOR)
            {
                code_opcode_value(OP_LOCAL_VEC, 0);
                _local_frame_ptr -= BPW;
            }
            var->value = _local_frame_ptr;
        }

        if (_token == TOKEN_ASSIGN)
            compiler_error("not allowed to assign values to variables on declaration", var->name);

        if (_token != TOKEN_COMMA)
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
        expect(TOKEN_SYMBOL, "symbol");
        y = add(_token_str, glob | SYM_CONST, 0);

        scan();
        expect_equal_sign();
        y->value = const_value();

        if (_token != TOKEN_COMMA)
            break;

        scan();
    }
}

void struct_declaration(int glob)
{
    scan();
    expect(TOKEN_SYMBOL, "symbol");
    symbol_t *struct_sym = add(_token_str, glob | SYM_CONST, 0);
    scan();
    int i = 0;

    expect(TOKEN_BLOCK_START, "{");
    scan();

    while (_token != TOKEN_BLOCK_END)
    {
        expect(TOKEN_SYMBOL, "symbol");

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
        expect(TOKEN_SYMBOL, "symbol");
        sym = add(_token_str, SYM_GLOBF|SYM_DECLARATION, 0);
        scan();
        expect_left_paren();
        n = const_value();
        sym->flags |= n << 8;
        expect_right_paren();

        if (n < 0)
            compiler_error("invalid arity", NULL);

        if (_token != TOKEN_COMMA)
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

    code_t *jump = code_opcode(OP_JUMP_FWD);

    scan();
    symbol_t *func_sym = add(_token_str, SYM_GLOBF | SYM_FUNCTION, _text_buffer_ptr);

    scan();
    expect_left_paren();

    int old_symbol_table_ptr = _symbol_table_ptr;
    int old_string_table_ptr = _string_table_ptr;
    int local_base = _symbol_table_ptr;

    while (TOKEN_SYMBOL == _token)
    {
        add(_token_str, 0, local_addr);
        local_addr += BPW;
        number_arguments++;
        scan();
        if (_token != TOKEN_COMMA)
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
    func_sym->code = code_symbol(OP_FUNC_START, func_sym);

    _parsing_function = true;
    
    block_statement();

    _parsing_function = false;
    code_opcode_value(OP_CLEAR, 0);
    code_opcode_value(OP_EXIT, 0);
    code_opcode(OP_FUNC_END);
    
    resolve_jump(jump, code_opcode(OP_JUMP_TARGET));

    _symbol_table_ptr = old_symbol_table_ptr;
    _string_table_ptr = old_string_table_ptr;
    _local_frame_ptr = 0;
}

void declaration(int glob)
{
    switch (_token)
    {
        case TOKEN_KEYWORD_VAR:
            var_declaration(glob);
            break;
        case TOKEN_KEYWORD_CONST:
            const_declaration(glob);
            break;
        case TOKEN_KEYWORD_STRUCT:
            struct_declaration(glob);
            break;
        case TOKEN_KEYWORD_DECL:
            forward_declaration();
            break;
        default:
            function_declaration();
            break;
    }
}

void program(void);

void import(void)
{
    scan();
    if (_token != TOKEN_STRING)
        compiler_error("expected filename to import", _token_str);

    push_source_file(_token_str);
    program();
    pop_source_file();
    scan();
}

void function_call(symbol_t *fn)
{
    int argument_count = 0;

    scan();
    if (fn == NULL)
        compiler_error("call of non-function", NULL);


    while (_token != TOKEN_RIGHT_PAREN)
    {
        expression(0);

        argument_count++;

        if (_token != TOKEN_COMMA)
            break;
        scan();
        
        if (_token == TOKEN_RIGHT_PAREN)
            compiler_error("syntax error", _token_str);
    }

    if (argument_count != (fn->flags >> 8))
        compiler_error("wrong number of arguments", fn->name);

    expect(TOKEN_RIGHT_PAREN, "')'");
    scan();

    code_opcode(OP_CALL_SETUP);

    if (fn->flags & SYM_DECLARATION)
    {
        code_symbol(OP_CALL, fn);
        fn->value = _text_buffer_ptr - BPW;
    }
    else
    {
        if (fn->flags & SYM_FUNCTION)
            code_symbol(OP_CALL, fn);
        else
            code_symbol(OP_CALL_INDIRECT, fn);
    }

    if (argument_count != 0)
        code_opcode_value(OP_DEALLOC, argument_count * BPW);

    code_opcode_value(OP_CALL_CLEANUP, argument_count);
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

    while (_token != TOKEN_RIGHT_BRACKET)
    {
        if (n >= MAXTBL)
            compiler_error("table too big", NULL);

        if (TOKEN_LEFT_PAREN == _token)
        {
            scan();
            dynamic = 1;
            continue;
        }
        else if (dynamic)
        {
            expression(1);
            table_value[n] = 0;
            table_code[n++] = code_opcode_value(OP_STORE_GLOBAL, 0);
            
            if (TOKEN_RIGHT_PAREN == _token)
            {
                scan();
                dynamic = 0;
            }
        }
        else if (_token == TOKEN_INTEGER || _token == TOKEN_SYMBOL)
        {
            table_value[n++] = const_value();
            //table_code[n++] = 0;
        }
        else if (_token == TOKEN_STRING)
        {
            table_value[n++] = make_string(_token_str) + _options->data_start_address;
            //table_code[n++] = 1;
            scan();
        }
        else if (_token == TOKEN_LEFT_BRACKET)
        {
            table_value[n++] = make_table() + _options->data_start_address;
            //table_code[n++] = 1;
        }
        else
        {
            compiler_error("invalid table element", _token_str);
        }

        if (_token != TOKEN_COMMA)
            break;

        scan();
    }

    expect(TOKEN_RIGHT_BRACKET, "']'");
    scan();
    loc = _data_buffer_ptr;

    for (i = 0; i < n; i++)
    {
        data_word(table_value[i]);

        if (table_code[i] != NULL)
            table_code[i]->value = _data_buffer_ptr - 4 + _options->data_start_address;
    }

    return loc;
}

void load(symbol_t *sym)
{
    if (sym->flags & SYM_GLOBF)
        code_symbol(OP_LOAD_GLOBAL, sym);
    else
        code_opcode_value(OP_LOAD_LOCAL, sym->value);
}

void store(symbol_t *sym)
{
    if (sym->flags & SYM_GLOBF)
        code_symbol(OP_STORE_GLOBAL, sym);
    else
        code_opcode_value(OP_STORE_LOCAL, sym->value);
}

void factor(void);

symbol_t *address(int level, int *byte_ptr)
{
    symbol_t *sym = lookup(_token_str, 0);
    scan();

    if (sym->flags & SYM_CONST)
    {
        if (level > 0)
            compiler_error("invalid address", sym->name);

        spill();
        code_opcode_value(OP_LOAD_VALUE, sym->value);
        
    }
    else if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION))
    {
        if (level == 2)
            return sym;
    }
    else if (level == 0 || _token == TOKEN_LEFT_BRACKET || _token == TOKEN_BYTEOP)
    {
        spill();
        load(sym);
    }

    if (_token == TOKEN_LEFT_BRACKET || _token == TOKEN_BYTEOP)
    {
        if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION | SYM_CONST))
            compiler_error("bad subscript", sym->name);
    }

    while (TOKEN_LEFT_BRACKET == _token)
    {
        *byte_ptr = 0;
        scan();
        expression(0);
        expect(TOKEN_RIGHT_BRACKET, "']'");
        scan();

        code_opcode_value(OP_INDEX_WORD, 0);

        sym = NULL;

        if (_token == TOKEN_LEFT_BRACKET || _token == TOKEN_BYTEOP || level == 0)
            code_opcode_value(OP_DEREF_WORD, 0);
    }

    if (_token == TOKEN_BYTEOP)
    {
        *byte_ptr = 1;
        scan();
        factor();
        sym = NULL;
        code_opcode_value(OP_INDEX_BYTE, 0);

        if (level == 0)
            code_opcode_value(OP_DEREF_BYTE, 0);
    }
    return sym;
}

void peek_statement(int opcode);

void factor(void)
{
    symbol_t    *y;
    int op;
    int b;

    if (_token == TOKEN_INTEGER)
    {
        spill();
        code_opcode_value(OP_LOAD_VALUE, _token_value);
        scan();
    }
    else if (_token == TOKEN_SYMBOL)
    {
        y = address(0, &b);

        if (_token == TOKEN_LEFT_PAREN)
        {
            function_call(y);
            code_opcode(OP_FROM_RET);
        }
    }
    else if (_token == TOKEN_STRING)
    {
        spill();
        code_opcode_value(OP_LOAD_GLOBAL_ADDR, make_string(_token_str) + _options->data_start_address);
        scan();
    }
    else if (_token == TOKEN_LEFT_BRACKET)
    {
        spill();
        code_opcode_value(OP_LOAD_GLOBAL_ADDR, make_table() + _options->data_start_address);
    }
    else if (_token == TOKEN_ADDROF)
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
            code_symbol(OP_LOAD_GLOBAL_ADDR, y);
        }
        else
        {
            spill();
            code_opcode_value(OP_LOAD_LOCAL_ADDR, y->value);
        }
    }
    else if (_token == TOKEN_BINOP)
    {
        op = _token_op_id;
        if (_token_op_id != _minus_op)
            compiler_error("syntax error", _token_str);

        scan();
        factor();
        code_opcode(OP_NEG);
    }
    else if (_token == TOKEN_UNOP)
    {
        op = _token_op_id;
        scan();
        factor();
        code_opcode(_operators[op].code);
    }
    else if (_token == TOKEN_LEFT_PAREN)
    {
        scan();
        expression(0);
        expect_right_paren();
    }
    else if (_token == TOKEN_KEYWORD_PEEK8)
    {
        peek_statement(OP_PEEK8);
        code_opcode(OP_FROM_RET);
    }
    else if (_token == TOKEN_KEYWORD_PEEK16)
    {
        peek_statement(OP_PEEK16);
        code_opcode(OP_FROM_RET);
    }
    else if (_token == TOKEN_KEYWORD_PEEK32)
    {
        peek_statement(OP_PEEK32);
        code_opcode(OP_FROM_RET);
    }
    else
    {
        compiler_error("syntax error", _token_str);
    }
}

int emitop(int *operator_stack, int stack_ptr)
{
    int op = operator_stack[stack_ptr - 1];
    code_opcode(_operators[op].code);

    return stack_ptr - 1;
}

void arithmetic(void)
{
    int operator_stack[10];
    int stack_ptr = 0;

    factor();
    while (TOKEN_BINOP == _token)
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

    while (TOKEN_CONJ == _token)
    {
        scan();
        jump_stack[n] = code_opcode(OP_JUMP_FALSE);
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

    while (TOKEN_DISJ == _token)
    {
        scan();
        jump_stack[n] = code_opcode(OP_JUMP_TRUE);
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

    if (_token == TOKEN_COND)
    {
        scan();
        code_t *false_jump = code_opcode(OP_JUMP_FALSE);
        expression(1);
        expect(TOKEN_COLON, "':'");
        scan();
        code_t *fwd_jump = code_opcode(OP_JUMP_FWD);

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
    code_opcode(OP_TO_RET);

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
    
    code_t *jump = code_opcode(OP_JUMP_FALSE);
    
    expect_right_paren();

    block_statement();

    if (_token == TOKEN_KEYWORD_ELSE)
    {
        code_t *else_jump = code_opcode(OP_JUMP_FWD);
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

    code_t *jump_false = code_opcode(OP_JUMP_FALSE);
   

    block_statement();
    
    resolve_jump(code_opcode(OP_JUMP_BACK), while_test);
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

    _leaves[_leaves_ptr++] = code_opcode(OP_JUMP_FWD);
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

    resolve_jump(code_opcode(OP_JUMP_BACK), jump_target);
}

void peek_statement(int opcode)
{
    scan();
    expect_left_paren();
    expression(1);
    expect_right_paren();
    code_opcode(opcode);
}

void poke_statement(int opcode)
{
    scan();
    expect_left_paren();
    expression(1);

    if (_token != TOKEN_COMMA)
        compiler_error("expected comma between arguments in poke", NULL);
    scan();

    expression(0);
    expect_right_paren();
    code_opcode(opcode);

    clear();
}

void inc_statement(void)
{
    scan();
    expect_left_paren();

    if (_token != TOKEN_SYMBOL)
        compiler_error("only possible to increment variables", _token_str);

    symbol_t *var = find(_token_str);
    if (var == NULL)
        compiler_error("unknown operator", _token_str);

    if (var->flags == SYM_GLOBF || var->flags == 0)
    {
        if (var->flags & SYM_GLOBF)
            code_symbol(OP_LOAD_GLOBAL_ADDR, var);
        else
            code_opcode_value(OP_LOAD_LOCAL_ADDR, var->value);
        code_opcode(OP_INC);
    }
    else
    {
        compiler_error("only possible to increment variables", var->name);
    }

    scan();
    expect_right_paren();
}

void dec_statement(void)
{
    scan();
    expect_left_paren();

    if (_token != TOKEN_SYMBOL)
        compiler_error("only possible to decrement variables", _token_str);

    symbol_t *var = find(_token_str);
    if (var == NULL)
        compiler_error("unknown operator", _token_str);

    if (var->flags == SYM_GLOBF || var->flags == 0)
    {
        if (var->flags & SYM_GLOBF)
            code_symbol(OP_LOAD_GLOBAL_ADDR, var);
        else
            code_opcode_value(OP_LOAD_LOCAL_ADDR, var->value);
        code_opcode(OP_DEC);
    }
    else
    {
        compiler_error("only possible to decrement variables", var->name);
    }

    scan();
    expect_right_paren();
}

void assignment_or_call(void)
{
    int byte_addr;

    clear();
    symbol_t *sym = address(1, &byte_addr);

    if (_token == TOKEN_LEFT_PAREN)
    {
        function_call(sym);
    }
    else if (_token == TOKEN_ASSIGN)
    {
        scan();
        expression(0);
        if (sym == NULL)
        {
            if (byte_addr)
                code_opcode(OP_STORE_INDIRECT_BYTE);
            else
                code_opcode(OP_STORE_INDIRECT_WORD);
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
        case TOKEN_KEYWORD_HALT:
            halt_statement();
            break;
        case TOKEN_KEYWORD_IF:
            if_statement();
            break;
        case TOKEN_KEYWORD_LEAVE:
            leave_statement();
            break;
        case TOKEN_KEYWORD_LOOP:
            loop_statement();
            break;
        case TOKEN_KEYWORD_RETURN:
            return_statement();
            break;
        case TOKEN_KEYWORD_WHILE:
            while_statement();
            break;
        case TOKEN_KEYWORD_INC:
            inc_statement();
            break;
        case TOKEN_KEYWORD_DEC:
            dec_statement();
            break;
        case TOKEN_KEYWORD_PEEK8:
            peek_statement(OP_PEEK8);
            break;
        case TOKEN_KEYWORD_PEEK16:
            peek_statement(OP_PEEK16);
            break;
        case TOKEN_KEYWORD_PEEK32:
            peek_statement(OP_PEEK32);
            break;
        case TOKEN_KEYWORD_POKE8:
            poke_statement(OP_POKE8);
            break;
        case TOKEN_KEYWORD_POKE16:
            poke_statement(OP_POKE16);
            break;
        case TOKEN_KEYWORD_POKE32:
            poke_statement(OP_POKE32);
            break;
        case TOKEN_BLOCK_START:
            block_statement();
            break;
        case TOKEN_SYMBOL:
            assignment_or_call();
            break;
        default:
            expect(0, "statement");
            break;
    }
}

void block_statement(void)
{
    expect(TOKEN_BLOCK_START, "{");
    scan();

    int old_symbol_table_ptr = _symbol_table_ptr;
    int old_local_frame_ptr = _local_frame_ptr;

    while (_token == TOKEN_KEYWORD_VAR || _token == TOKEN_KEYWORD_CONST || _token == TOKEN_KEYWORD_STRUCT)
        declaration(0);

    while (_token != TOKEN_BLOCK_END)
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
    int i;

    scan();
    while (_token == TOKEN_KEYWORD_IMPORT)
        import();

    while (_token == TOKEN_KEYWORD_VAR || _token == TOKEN_KEYWORD_CONST || _token == TOKEN_KEYWORD_FUNC || _token == TOKEN_KEYWORD_DECL || _token == TOKEN_KEYWORD_STRUCT)
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

    _start_location = _text_buffer_ptr + _options->text_start_address;
    code_symbol(OP_CALL, main);
    code_opcode_value(OP_DEALLOC, 2 * BPW);     // Deallocate the argc, argv arguments to main
    code_opcode_value(OP_HALT, 0);
}

void embed_data_files(void)
{
    for (int i = 0; i < _options->embed_files_count; ++i)
    {
        koda_embed_t *embed = &_options->embed_files[i];

        // Create global variable pointing to the embedded data
        add(embed->name, SYM_GLOBF, _data_buffer_ptr + _options->data_start_address);
        data_word(_data_buffer_ptr + _options->data_start_address + 4);

#if PLATFORM_WIN
        // Embed the actual data
        FILE *file = fopen(embed->source_file, "r");
        if (file == NULL)
            compiler_error("could not open file for embedding", embed->source_file);

        // Read the entire file into the data buffer
        int len = fread(_data_buffer + _data_buffer_ptr, 1, _options->data_size - _data_buffer_ptr, file);
        fclose(file);

        _data_buffer_ptr += len;
        if (_data_buffer_ptr >= _options->data_size)
            compiler_error("data segment exhausted, the embedded file is to large", embed->source_file);
#endif  
        // Add a constant containing the size of the data
        char buffer[64];
        snprintf(buffer, 64, "%s_len", embed->name);
        add(buffer, SYM_CONST, len);      
    }
}

void include_library(char *filename)
{
    int start = _text_lib_buffer_ptr;

#if PLATFORM_WIN
    FILE *file = fopen(filename, "r");
    if (file == NULL)
        compiler_error("could not open library file", filename);

    // Read the entire file into the data buffer
    int len = fread(_text_lib_buffer + _text_lib_buffer_ptr, 1, _options->text_lib_size - _text_lib_buffer_ptr, file);
    fclose(file);

    _text_lib_buffer_ptr += len;
    if (_text_lib_buffer_ptr > _options->text_lib_size)
        compiler_error("text segment exhausted, library too large", filename);
#endif

    // Function count
    int function_count = _text_lib_buffer[start] << 8 | _text_lib_buffer[start + 1];

    int it = start + 2;
    for (int i = 0; i < function_count; ++i)
    {
        int func_offset = (_text_lib_buffer[it] << 24) | (_text_lib_buffer[it + 1] << 16) | (_text_lib_buffer[it + 2] << 8) | _text_lib_buffer[it + 3];
        it += 4;

        int func_arity = _text_lib_buffer[it];
        it += 1;

        char *func_name = _text_lib_buffer + it;
        it += strlen(func_name) + 1;

        add(func_name, SYM_GLOBF | SYM_FUNCTION | (func_arity << 8), _options->text_lib_start_address + start + func_offset);
    }
}

void include_libraries(void)
{
    for (int i = 0; i < _options->libraries_count; ++i)
    {
        include_library(_options->libraries[i]);
    }
}


/**
 * Main
 */

void init(void)
{
    _text_buffer_ptr = 0;
    _text_lib_buffer_ptr = 0;
    _data_buffer_ptr = 0;
    _symbol_table_ptr = 0;

    _code_start = alloc_code();
    _current_code = _code_start;
    _current_code->opcode = OP_INIT;
    _current_code->value = HEAP_END;
    code_t *jmp = code_opcode(OP_JUMP_FWD);
    
    // Special variables used by the standard library
    symbol_t *sym = add("__heap_ptr", SYM_GLOBF, 0);
    sym->code = code_symbol_value(OP_WRITE_32, sym, HEAP_START);

    sym = add("__buffer", SYM_GLOBF, 0);
    sym->code = code_symbol_value(OP_ALLOC_MEM, sym, 32);

    // Add special math routines
    symbol_t *mul32 = add("__mul32", SYM_GLOBF, 0);
    _mul32_code = code_asm(mul32, INST_MUL32);

    symbol_t *div32 = add("__div32", SYM_GLOBF, 0);
    _div32_code = code_asm(div32, INST_DIV32);

    resolve_jump(jmp, code_opcode(OP_JUMP_TARGET));

    find_operator("="); _equal_op = _token_op_id;
    find_operator("-"); _minus_op = _token_op_id;
    find_operator("*"); _mul_op = _token_op_id;
    find_operator("+"); _add_op = _token_op_id;
    find_operator("/"); _div_op = _token_op_id;
    find_operator("%"); _mod_op = _token_op_id;

    builtin("syscall0", 1, INST_SYSCALL0);
    builtin("syscall1", 2, INST_SYSCALL1);
    builtin("syscall2", 3, INST_SYSCALL2);
    builtin("syscall3", 4, INST_SYSCALL3);
    builtin("memscan", 3, INST_MEMSCAN);
    builtin("memcopy", 3, INST_MEMCOPY);
    builtin("memset", 3, INST_MEMSET);
    builtin("min", 2, INST_MIN);
    builtin("max", 2, INST_MAX);

    add("true", SYM_CONST, -1);
    add("false", SYM_CONST, 0);
    add("HEAP_START", SYM_CONST, HEAP_START);
    add("HEAP_END", SYM_CONST, HEAP_END - INITIAL_STACK_SIZE);
    add("BYTE", SYM_CONST, 1);
    add("WORD", SYM_CONST, 4);
}


int koda_compile(koda_compiler_options_t *options)
{
    _options = options;

#if PLATFORM_WIN
    _text_buffer = malloc(_options->text_size);
    _text_lib_buffer = malloc(_options->text_lib_size);
    _data_buffer = malloc(_options->data_size);
    _string_table = malloc(STRING_TABLE_SIZE);
    _symbol_table = malloc(sizeof(symbol_t) * SYMBOL_TABLE_SIZE);
#else
    void *current_heap_pos = heap_position();

    _text_buffer = heap_alloc(_options->text_size);
    _text_lib_buffer = heap_alloc(_options->text_lib_size);
    _data_buffer = heap_alloc(_options->data_size);
    _string_table = heap_alloc(STRING_TABLE_SIZE);
    _symbol_table = heap_alloc(sizeof(symbol_t) * SYMBOL_TABLE_SIZE);
#endif   

    init();

    // TODO: Use long jump here so we can have the koda_compile(...) function return on error, instead of exiting the program.
    if (_options->embed_files_count > 0)
        embed_data_files();

    if (_options->libraries_count > 0)
        include_libraries();

    // Compile stdlib
    read_stdlib_source();
    program();

    // Compile all input files
    for (int i = 0; i < options->input_files_count; ++i)
    {
        read_input_source(options->input_files[i]);
        program();
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
#if PLATFORM_WIN        
        printf("\nCODE:\n");
#endif        
        int optimized_instruction_count = 0;

        for (code_t *it = _code_start; it != NULL; it = it->next)
            it->position = optimized_instruction_count++;

        for (code_t *it = _code_start; it != NULL; it = it->next)
            print_code(it);

#if PLATFORM_WIN
        printf("\nSYMBOLS:\n");
#endif        
        for (int i = 0; i < _symbol_table_ptr; ++i)
        {
            symbol_t *sym = &_symbol_table[i];
            if (sym->used)
            {
#if PLATFORM_WIN                
                printf("  %06X  %s (%02X)\n", sym->value, sym->name, sym->flags);
#endif                
            }
        }

#if PLATFORM_WIN
        printf("\nSTATISTICS:\n");
        printf("          Code usage: %d / %dkb\n", _text_buffer_ptr / 1024, _options->text_size / 1024);
        printf("          Data usage: %d / %dkb\n", _data_buffer_ptr / 1024, _options->data_size / 1024);
        printf("  Symbol table usage: %d / %d\n", _symbol_table_ptr, SYMBOL_TABLE_SIZE);
        printf("  String table usage: %d / %d\n", _string_table_ptr, STRING_TABLE_SIZE);
        printf("       Optimizations: %d -> %d\n", start_instruction_count, optimized_instruction_count);
#endif        
    }

    save_output(options->output_filename);

    _options = NULL;

#if PLATFORM_WIN
    free(_text_buffer);
    free(_text_lib_buffer);
    free(_data_buffer);
    free(_string_table);
    free(_symbol_table);
#else    
    heap_rewind(current_heap_pos);
#endif    

    return 1;
}

#if PLATFORM_WIN

int koda_opcode_arg_count(int opcode)
{
    return _opcode_arguments[opcode] == OP_ARG_NONE ? 0 : 1;
}

const char *koda_opcode_name(int opcode)
{
    return _opcode_names[opcode];
}

int koda_compile_to_bytecode(koda_compiler_options_t *options, const char *name, const char *code_string, int **bytecode_output, int *bytecode_len)
{
    _options = options;

    _text_buffer = malloc(_options->text_size);
    _data_buffer = malloc(_options->data_size);
    _string_table = malloc(STRING_TABLE_SIZE);
    _symbol_table = malloc(sizeof(symbol_t) * SYMBOL_TABLE_SIZE);
    _symbol_table_ptr = 0;
    _text_buffer_ptr = 0;
    _data_buffer_ptr = 0;
    _string_table_ptr = 0;

    init();   
    
    // Compile stdlib
    read_stdlib_source();
    program();

    read_input_string(name, code_string);
    program();

    resolve_main();
    optimize_code();
    mark_used_symbols();

    // Give global symbols an address value
    for (int i = 0, pos = 0; i < _symbol_table_ptr; ++i)
    {
        symbol_t *sym = &_symbol_table[i];
        if (!sym->used)
            continue;

        // Only allocate data space for global variables
        if ((sym->flags == SYM_GLOBF) || (sym->flags == (SYM_GLOBF | SYM_VECTOR)))
        {
            if (sym->value == 0)
            {
                sym->value = pos + _options->data_start_address;
                pos++;
            }
        }
    }


    generate_bytecode(bytecode_output, bytecode_len);

    _options = NULL;

    free(_text_buffer);
    free(_data_buffer);
    free(_string_table);
    free(_symbol_table);

    return 1; 
}

#endif    
