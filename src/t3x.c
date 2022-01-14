
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#if PLATFORM_FOENIX
    #include "foenix/syscall.h"
    #include "foenix/heap.h"
#endif

#include "t3x.h"


enum {
    BPW                     = 4,
    PROGRAM_SIZE            = 0xF000,

#if T3X_OUTPUT_M68K
    TEXT_VADDR              = 0x00020000,
    DATA_VADDR              = 0x00040000,
#elif T3X_OUTPUT_BYTECODE
    TEXT_VADDR              = 0x00000000,
    DATA_VADDR              = 0x00100000,
#else
    #error "Unknown output format"
#endif

    TEXT_SIZE               = 0x10000,
    DATA_SIZE               = 0x10000,
    RELOCATION_SIZE         = 10000,
    STACK_SIZE              = 100,
    SYMBOL_TABLE_SIZE       = 1000,
    STRING_TABLE_SIZE       = 4096,

    SYM_GLOBF               = 1,
    SYM_CONST               = 2,
    SYM_VECTOR              = 4,
    SYM_DECLARATION         = 8,
    SYM_FUNCTION            = 16,

    MAXTBL                  = 128,
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
    KFOR,
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

typedef unsigned char bool;
#define true 1
#define false 0

typedef struct symbol_t {
    char *name;
    int flags;
    int value;
} symbol_t;

typedef struct relocation_t {
    int addr;
    int seg;
} relocation_t;


int _stack[STACK_SIZE];
int _stack_pointer = 0;

char *_program_source_file;
int _current_line = 1;
bool _has_main_body = false;

#ifdef PLATFORM_WIN
    static FILE * _output_target = NULL;
#else
    static int _output_channel = 0;
#endif

//int _output_type = 0;
//bool _output_labels = false;
//char *_output_labels_filename = NULL;

relocation_t *_relocation_table;

unsigned char *_text_buffer;
unsigned char *_data_buffer;

int _relocation_ptr = 0;
int _text_buffer_ptr = 0;
int _data_buffer_ptr = 0;
int _local_frame_ptr = 0;

int _accumulator_loaded = 0;

char *_string_table;
int _string_table_ptr = 0;

symbol_t *_symbol_table;
int _symbol_table_ptr = 0;

bool _parsing_function = false;

int _loop0 = -1;
int _leaves[MAXLOOP];
int _leaves_ptr = 0;
int _loops[MAXLOOP];
int _loops_ptr = 0;

t3x_compiler_options_t *_options = NULL;


#ifdef T3X_OUTPUT_M68K
    int _div32_routine_address;
    int _mul32_routine_address;
    #include "output_m68k.c"
#elif T3X_OUTPUT_BYTECODE
    #include "output_bytecode.c"
#endif


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

void push(int x)
{
    if (_stack_pointer >= STACK_SIZE)
        compiler_error("too many nesting levels", NULL);
    _stack[_stack_pointer++] = x;
}

int tos(void)
{
    return _stack[_stack_pointer - 1];
}

int pop(void)
{
    if (_stack_pointer < 1)
        internal_error("stack underflow", NULL);
    return _stack[--_stack_pointer];
}

void swap(void)
{
    if (_stack_pointer < 2)
        internal_error("stack underflow", NULL);

    int tmp = _stack[_stack_pointer - 1];
    _stack[_stack_pointer - 1] = _stack[_stack_pointer - 2];
    _stack[_stack_pointer - 2] = tmp;
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
    _symbol_table_ptr++;
    return &_symbol_table[_symbol_table_ptr - 1];
}


/*
 * Emitter
 */

void generate(char *code, int value);

void spill(void)
{
    if (_accumulator_loaded)
        generate(CG_PUSH, 0);
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

void emit_byte(unsigned char value)
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

void generate(char *code, int value)
{
    while (*code)
    {
        if (*code == ',')
        {
            if (code[1] == 'b')
            {
                emit_byte(value);
            }
            else if (code[1] == 'w')
            {
                emit_word(value);
            }
            else if (code[1] == 'l')
            {
                emit_short(value);
            }
            else if (code[1] == 'a')
            {
                emit_word(value);
                tag('t');
            }
            else if (code[1] == 'm')
            {
                push(_text_buffer_ptr);
            }
            else if (code[1] == '>')
            {
                push(_text_buffer_ptr);
                emit_short(0);
            }
            else if (code[1] == '<')
            {
                emit_short(pop() - _text_buffer_ptr);
            }
            else if (code[1] == ']')
            {
                push(_text_buffer_ptr);
                emit_word(0);
            }
            else if (code[1] == 's')
            {
                int address = pop();
                text_patch_word(address, value);
            }
            else if (code[1] == 'r')
            {
                int x = pop();
                text_patch_short(x, _text_buffer_ptr - x);
            }
            else
            {
                internal_error("bad code", NULL);
            }
        }
        else
        {
            emit_byte(hex(code[0]) * 16 + hex(code[1]));
        }
        code += 2;
    }
}

void builtin(char *name, int arity, char *code)
{
    generate(CG_JUMPFWD, 0);
    add(name, SYM_GLOBF | SYM_FUNCTION | (arity << 8), _text_buffer_ptr);
    generate(code, 0);
    generate(CG_RESOLV, 0);
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
        int value = sym->value;

        if (sym->flags & SYM_FUNCTION)
            value += TEXT_VADDR;
        else if (!(sym->flags & SYM_CONST))
            value += DATA_VADDR;

        fprintf(_output_target, "%08X\t%s\n", value, sym->name);
    }

#if T3X_OUTPUT_M68K
    fprintf(_output_target, "%08X\tmul32\n", _mul32_routine_address);
    fprintf(_output_target, "%08X\tdiv32\n", _div32_routine_address);
#endif    

    fclose(_output_target);
    _output_target = NULL;
#endif 
}

void save_output(char *output_filename)
{
#if PLATFORM_WIN
    _output_target = fopen(output_filename, _options->output_type == T3X_OUTPUT_TYPE_PGZ ? "wb" : "w");
    if (_output_target == NULL)
        compiler_error("could not write to output file", output_filename);
#else
    _output_channel = sys_fsys_open(output_filename, FILE_MODE_CREATE_ALWAYS | FILE_MODE_WRITE); 
#endif  

#if T3X_OUTPUT_M68K
    if (_options->output_type == T3X_OUTPUT_TYPE_PGZ)
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
#elif T3X_OUTPUT_BYTECODE
    write_bytecode();
#else
    #error "Unknown output format"
#endif    

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
    char *code;
} operator_t;


operator_t _operators[] = {
    { 7, 1, "%",    BINOP,  CG_MOD      },
    { 6, 1, "+",    BINOP,  CG_ADD      },
    { 7, 1, "*",    BINOP,  CG_MUL      },
    { 0, 1, ",",    COMMA,  NULL        },
    { 0, 1, "(",    LPAREN, NULL        },
    { 0, 1, ")",    RPAREN, NULL        },
    { 0, 1, "[",    LBRACK, NULL        },
    { 0, 1, "]",    RBRACK, NULL        },
    { 5, 1, "&",    BINOP,  CG_AND      },
    { 1, 2, "&&",   DISJ,   NULL        },
    { 6, 1, "-",    BINOP,  CG_SUB      },
    { 5, 1, "^",    BINOP,  CG_XOR      },
    { 0, 1, "@",    ADDROF, NULL        },
    { 5, 1, "|",    BINOP,  CG_OR       },
    { 2, 2, "||",   CONJ,   NULL        },
    { 0, 1, "!",    UNOP,   CG_LOGNOT   },
    { 0, 1, "?",    COND,   NULL        },
    { 7, 1, "/",    BINOP,  CG_DIV      },
    { 0, 1, "~",    UNOP,   CG_INV      },
    { 0, 1, ":",    COLON,  NULL        },
    { 0, 2, "::",   BYTEOP, NULL        },
    { 3, 2, "!=",   BINOP,  CG_NEQ      },
    { 4, 1, "<",    BINOP,  CG_LT       },
    { 4, 2, "<=",   BINOP,  CG_LE       },
    { 5, 2, "<<",   BINOP,  CG_SHL      },
    { 4, 1, ">",    BINOP,  CG_GT       },
    { 4, 2, ">=",   BINOP,  CG_GE       },
    { 5, 2, ">>",   BINOP,  CG_SHR      },
    { 0, 1, "=",    ASSIGN, NULL        },
    { 3, 2, "==",   BINOP,  CG_EQ       },
    { 0, 0, NULL,   0,      NULL        }
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
            if (!strcmp(str, "for")) return KFOR;
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

    if (isalpha(ch) || '_' == ch)
    {
        int i = 0;
        while (isalpha(ch) || '_' == ch || isdigit(ch))
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

/*
 * Parser
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
    return 0; /*LINT*/
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
                generate(CG_ALLOC, size * BPW);
                generate(CG_GLOBVEC, _data_buffer_ptr);
            }
            data_word(0);
        }
        else
        {
            generate(CG_ALLOC, size * BPW);
            _local_frame_ptr -= size * BPW;
            if (var->flags & SYM_VECTOR)
            {
                generate(CG_LOCLVEC, 0);
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
    symbol_t *sym;
    int i;

    scan();
    expect(SYMBOL, "symbol");
    sym = add(_token_str, glob | SYM_CONST, 0);
    scan();
    i = 0;
    expect_equal_sign();

    while (1)
    {
        expect(SYMBOL, "symbol");
        add(_token_str, glob | SYM_CONST, i++);
        scan();

        if (_token != COMMA)
            break;

        scan();
    }

    sym->value = i;
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

void block_statement();
void statement(void);


void function_declaration(void)
{
    // TODO: We should collect all function arguments and variables and allocate space
    //       on the stack in one go

    int local_addr = 2 * BPW;
    int number_arguments = 0;

    generate(CG_JUMPFWD, 0);

    scan();
    symbol_t *func_sym = add(_token_str, SYM_GLOBF | SYM_FUNCTION, _text_buffer_ptr);

    scan();
    expect_left_paren();

    int old_symbol_table_ptr = _symbol_table_ptr;
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
    generate(CG_ENTER, 0);
    _parsing_function = true;
    
    block_statement();

    _parsing_function = false;
    generate(CG_CLEAR, 0);
    generate(CG_EXIT, 0);
    generate(CG_RESOLV, 0);

    _symbol_table_ptr = old_symbol_table_ptr;
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
        generate(CG_CALL, TEXT_VADDR + fn->value);
        fn->value = _text_buffer_ptr - BPW;
    }
    else
    {
        generate(CG_CALL, TEXT_VADDR + fn->value);
    }

    if (argument_count != 0)
        generate(CG_DEALLOC, argument_count * BPW);

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
    int tbl[MAXTBL], af[MAXTBL];
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
            generate(CG_STGLOB, 0);
            tbl[n] = 0;
            af[n++] = _text_buffer_ptr - BPW;
            if (RPAREN == _token)
            {
                scan();
                dynamic = 0;
            }
        }
        else if (INTEGER == _token || SYMBOL == _token)
        {
            tbl[n] = const_value();
            af[n++] = 0;
        }
        else if (STRING == _token)
        {
            tbl[n] = make_string(_token_str);
            af[n++] = 1;
            scan();
        }
        else if (LBRACK == _token)
        {
            tbl[n] = make_table();
            af[n++] = 1;
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
        data_word(tbl[i]);

        if (1 == af[i])
        {
            tag('d');
        }
        else if (af[i] > 1)
        {
            text_patch_word(af[i], _data_buffer_ptr-4);
        }
    }

    return loc;
}

void load(symbol_t *sym)
{
    if (sym->flags & SYM_GLOBF)
        generate(CG_LDGLOBAL, sym->value);
    else
        generate(CG_LDLOCAL, sym->value);
}

void store(symbol_t *sym)
{
    if (sym->flags & SYM_GLOBF)
        generate(CG_STGLOB, sym->value);
    else
        generate(CG_STLOCL, sym->value);
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
        generate(CG_LDVAL, sym->value);
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
        if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION | SYM_CONST))
            compiler_error("bad subscript", sym->name);
    }

    while (LBRACK == _token)
    {
        *byte_ptr = 0;
        scan();
        expression(0);
        expect(RBRACK, "']'");
        scan();
        sym = NULL;
        generate(CG_INDEX, 0);

        if (_token == LBRACK || _token == BYTEOP || level == 0)
            generate(CG_DEREF, 0);
    }

    if (_token == BYTEOP)
    {
        *byte_ptr = 1;
        scan();
        factor();
        sym = NULL;
        generate(CG_INDXB, 0);

        if (level == 0)
            generate(CG_DREFB, 0);
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
        generate(CG_LDVAL, _token_value);
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
        generate(CG_LDADDR, make_string(_token_str));
        scan();
    }
    else if (_token == LBRACK)
    {
        spill();
        generate(CG_LDADDR, make_table());
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
            generate(CG_LDADDR, y->value);
        }
        else
        {
            spill();
            generate(CG_LDLOCALREF, y->value);
        }
    }
    else if (_token == BINOP)
    {
        op = _token_op_id;
        if (_token_op_id != _minus_op)
            compiler_error("syntax error", _token_str);
        scan();
        factor();
        generate(CG_NEG, 0);
    }
    else if (_token == UNOP)
    {
        op = _token_op_id;
        scan();
        factor();
        generate(_operators[op].code, 0);
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

#if T3X_OUTPUT_M68K
    if (op == _div_op || op == _mul_op || op == _mod_op)
        generate(_operators[op].code, op == _mul_op ? _mul32_routine_address : _div32_routine_address);
    else
        generate(_operators[op].code, 0);
#else    
    generate(_operators[op].code, 0);
#endif

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
    int n = 0;

    arithmetic();
    while (CONJ == _token)
    {
        scan();
        generate(CG_JMPFALSE, 0);
        clear();
        arithmetic();
        n++;
    }

    while (n > 0)
    {
        generate(CG_RESOLV, 0);
        n--;
    }
}

void disjn(void)
{
    int n = 0;

    conjn();
    while (DISJ == _token)
    {
        scan();
        generate(CG_JMPTRUE, 0);
        clear();
        conjn();
        n++;
    }

    while (n > 0)
    {
        generate(CG_RESOLV, 0);
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

    if (COND == _token)
    {
        scan();
        generate(CG_JMPFALSE, 0);
        expression(1);
        expect(COLON, "':'");
        scan();
        generate(CG_JUMPFWD, 0);
        swap();
        generate(CG_RESOLV, 0);
        expression(1);
        generate(CG_RESOLV, 0);
    }
}

void halt_statement(void)
{
    scan();
    generate(CG_HALT, const_value());
}

void return_statement(void)
{
    scan();

    if (!_parsing_function)
        compiler_error("can't return from main", 0);

    expression(1);

    if (_local_frame_ptr != 0)
        generate(CG_DEALLOC, -_local_frame_ptr);

    generate(CG_EXIT, 0);
}

void if_statement()
{
    scan();
    expect_left_paren();
    expression(1);
    generate(CG_JMPFALSE, 0);
    expect_right_paren();

    block_statement();

    if (_token == KELSE)
    {
        generate(CG_JUMPFWD, 0);
        swap();
        generate(CG_RESOLV, 0);

        scan();
        statement();
    }

    generate(CG_RESOLV, 0);
}

void while_statement(void)
{
    int old_loop0 = _loop0;
    int old_leaves_ptr = _leaves_ptr;

    scan();
    expect_left_paren();
    generate(CG_MARK, 0);

    _loop0 = tos();
    
    expression(1);

    expect_right_paren();
    generate(CG_JMPFALSE, 0);
    
    statement();
    
    swap();
    generate(CG_JUMPBACK, 0);
    generate(CG_RESOLV, 0);

    while (_leaves_ptr > old_leaves_ptr)
    {
        push(_leaves[_leaves_ptr-1]);
        generate(CG_RESOLV, 0);
        _leaves_ptr--;
    }

    _loop0 = old_loop0;
}

void for_statement(void)
{
    scan();
    int old_loops_ptr = _loops_ptr;
    int old_leaves_ptr = _leaves_ptr;
    int old_loop0 = _loop0;

    _loop0 = 0;

    expect_left_paren();
    expect(SYMBOL, "symbol");
    symbol_t *variable = lookup(_token_str, 0);
    scan();

    if (variable->flags & (SYM_CONST | SYM_FUNCTION | SYM_DECLARATION))
        compiler_error("unexpected type in for loop", variable->name);

    expect_equal_sign();
    expression(1);
    store(variable);
    expect(COMMA, "','");
    scan();
    generate(CG_MARK, 0);
    
    int test = tos();

    load(variable);
    expression(0);

    generate(CG_FOR, 0);
    expect_right_paren();

    block_statement();

    while (_loops_ptr > old_loops_ptr)
    {
        push(_loops[_loops_ptr-1]);
        generate(CG_RESOLV, 0);
        _loops_ptr--;
    }

    if (variable->flags & SYM_GLOBF)
        generate(CG_INCGLOB, variable->value);
    else
        generate(CG_INCLOCL, variable->value);

    swap();
    generate(CG_JUMPBACK, 0);
    generate(CG_RESOLV, 0);

    while (_leaves_ptr > old_leaves_ptr)
    {
        push(_leaves[_leaves_ptr-1]);
        generate(CG_RESOLV, 0);
        _leaves_ptr--;
    }

    _loops_ptr = old_loops_ptr;
    _loop0 = old_loop0;
}

void leave_statement(void)
{
    if (_loop0 < 0)
        compiler_error("LEAVE not in loop context", 0);

    scan();

    if (_leaves_ptr >= MAXLOOP)
        compiler_error("too many LEAVEs", NULL);

    generate(CG_JUMPFWD, 0);
    _leaves[_leaves_ptr++] = pop();
}

void loop_statement(void)
{
    if (_loop0 < 0)
        compiler_error("LOOP not in loop context", 0);

    scan();

    if (_loop0 > 0)
    {
        push(_loop0);
        generate(CG_JUMPBACK, 0);
    }
    else
    {
        if (_loops_ptr >= MAXLOOP)
            compiler_error("too many LOOPs", NULL);
        generate(CG_JUMPFWD, 0);
        _loops[_loops_ptr++] = pop();
    }
}

void assignment_or_call(void)
{
    int b;

    clear();
    symbol_t *sym = address(1, &b);

    if (_token == LPAREN)
    {
        function_call(sym);
    }
    else if (_token == ASSIGN)
    {
        scan();
        expression(0);
        if (NULL == sym)
            generate(b ? CG_STINDB: CG_STINDR, 0);
        else if (sym->flags & (SYM_FUNCTION | SYM_DECLARATION | SYM_CONST | SYM_VECTOR))
            compiler_error("bad location", sym->name);
        else
            store(sym);
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
        case KFOR:
            for_statement();
            break;
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
        generate(CG_DEALLOC, old_local_frame_ptr-_local_frame_ptr);

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

    generate(CG_CALL, main->value + TEXT_VADDR);
    generate(CG_HALT, 0);
}

/**
 * Main
 */

void init(void)
{
    _text_buffer_ptr = 0;
    _data_buffer_ptr = 0;
    _symbol_table_ptr = 0;

    generate(CG_INIT, HEAP_END);

#if T3X_OUTPUT_M68K
    // Add special math routines
    generate(CG_JUMPFWD, 0);
    
    _mul32_routine_address = _text_buffer_ptr + TEXT_VADDR;
    generate(CG_MUL32, 0);

    _div32_routine_address = _text_buffer_ptr + TEXT_VADDR;
    generate(CG_DIV32, 0);


    generate(CG_RESOLV, 0);
#endif    

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

    add("HEAP_START", SYM_CONST, HEAP_START);
    add("HEAP_END", SYM_CONST, HEAP_END - INITIAL_STACK_SIZE);
}


int t3x_compile(t3x_compiler_options_t *options)
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

    // Compile all input files
    for (int i = 0; i < options->input_files_count; ++i)
    {
        read_input_source(options->input_files[i]);
        program();
        resolve();
    }

    resolve_main();
    save_output(options->output_filename);

    if (options->print_usage_statistics)
    {
#if PLATFORM_WIN
        printf("        Code usage: %d / %dkb\n", _text_buffer_ptr / 1024, TEXT_SIZE / 1024);
        printf("        Data usage: %d / %dkb\n", _data_buffer_ptr / 1024, DATA_SIZE / 1024);
        printf("Symbol table usage: %d%%\n", 100 * ((float)_symbol_table_ptr / SYMBOL_TABLE_SIZE));
        printf("String table usage: %d%%\n", 100 * ((float)_string_table_ptr / STRING_TABLE_SIZE));
#endif        
    }

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

