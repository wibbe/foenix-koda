/*
 * T3X9 -> ELF-FreeBSD-386 compiler
 * Nils M Holm, 2017, CC0 license
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#ifdef DEBUG
	#define LOG(msg) printf(msg "\n")
#else
	#define LOG(msg)
#endif


#define BPW					4
#define PROGRAM_SIZE		0x10000
#define TEXT_VADDR			0x00020000
#define DATA_VADDR			0x00040000
#define TEXT_SIZE			0x10000
#define DATA_SIZE			0x10000
#define NRELOC				10000
#define STACK_SIZE			100
#define SYMBOL_TABLE_SIZE	1000

typedef unsigned char  	byte_t;
typedef unsigned int  	word_t;

int	_stack[STACK_SIZE];
int _stack_pointer = 0;

int	_current_line = 1;

void aw(char *m, char *s)
{
	fprintf(stderr, "t3x9: %d: %s", _current_line, m);
	if (s != NULL)
		fprintf(stderr, ": %s", s);
	fputc('\n', stderr);
	exit(1);
}

void oops(char *m, char *s)
{
	fprintf(stderr, "t3x9: internal error\n");
	aw(m, s);
}

void push(int x)
{
	if (_stack_pointer >= STACK_SIZE)
		aw("too many nesting levels", NULL);
	_stack[_stack_pointer++] = x;
}

int tos(void)
{
	return _stack[_stack_pointer - 1];
}

int pop(void)
{
	if (_stack_pointer < 1)
		oops("stack underflow", NULL);
	return _stack[--_stack_pointer];
}

void swap(void)
{
	if (_stack_pointer < 2)
		oops("stack underflow", NULL);

	int tmp = _stack[_stack_pointer - 1];
	_stack[_stack_pointer - 1] = _stack[_stack_pointer - 2];
	_stack[_stack_pointer - 2] = tmp;
}

/*
 * Symbol table
 */

typedef struct symbol_t {
	char *name;
	int	flags;
	int	value;
} symbol_t;

#define SYM_GLOBF		1
#define SYM_CONST		2
#define SYM_VECTOR		4
#define SYM_DECLARATION	8
#define SYM_FUNCTION	16

symbol_t _symbol_table[SYMBOL_TABLE_SIZE];
int	_symbol_table_ptr = 0;


symbol_t *find(char *symbol_name)
{
	int	i;

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
		aw("undefined", symbol_name);
	if ((y->flags & flags) != flags)
		aw("unexpected type", symbol_name);

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
			aw("redefined", symbol_name);
	}

	if (_symbol_table_ptr >= SYMBOL_TABLE_SIZE)
		aw("too many symbols", NULL);

	_symbol_table[_symbol_table_ptr].name = strdup(symbol_name);
	_symbol_table[_symbol_table_ptr].flags = flags;
	_symbol_table[_symbol_table_ptr].value = value;
	_symbol_table_ptr++;
	return &_symbol_table[_symbol_table_ptr - 1];
}

/*
 * Emitter
 */

#define HEADER_SIZE		0x74
#define PAGE_SIZE		0x1000

typedef struct reloc_t {
	int	addr;
	int	seg;
} reloc_t;

reloc_t	_relocation_table[NRELOC];

byte_t _text_buffer[TEXT_SIZE];
byte_t _data_buffer[DATA_SIZE];

int	_relocation_ptr = 0;
int _text_buffer_ptr = 0;
int _data_buffer_ptr = 0;
int _local_frame_ptr = 0;

int	_accumulator_loaded = 0;

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
 * - b[x] will indicate the byte_t at address x
 *
 * Note 680000
 * - Word and long-word_t operands must be aligned on word_t boundaries (even addresses)
 */

#define CG_INIT			""
#define CG_PUSH			"2f00"					// P: = P − 1; S0: = A
#define CG_LDVAL		"2f00203c,w"			// P: = P − 1; S0: = A; A: = w
#define CG_LDADDR		"2f00203c,a"			// P: = P − 1; S0: = A; A: = a
#define CG_LDLOCALREF	"2f00200ed0bc,w"		// P: = P − 1; S0: = A; A: = F + w
#define CG_LDGLOBAL		"2f002039,a"			// P: = P − 1; S0: = A; A: = [a]
#define CG_LDLOCAL		"2f00202e,l"			// P: = P − 1; S0: = A; A: = [F + w]
#define CG_CLEAR		"7000"					// A: = 0
#define CG_STGLOB		"23c0,a201f"			// [a]: = A; A: = S0; P: = P + 1
#define CG_STLOCL		"2f40,l201f"			// [F + w]: = A; A: = S0; P: = P + 1
#define CG_STINDR		"2a5f2a80"				// [S0]: = A; P: = P + 1
#define CG_STINDB		"2a5f1a80"				// b[S0]: = A; P: = P + 1
#define CG_ALLOC		"9ffc,w"				// P: = P − w
#define CG_DEALLOC		"dffc,w"				// P: = P + w
#define CG_LOCLVEC		"2a4f2f0d"				// w: = P; P: = P − 1; S0: = w
#define CG_GLOBVEC		"23cf,a"				// [a]: = P
#define CG_HALT			",w"
#define CG_INDEX		"221fe588d081"			// A: = 4 ⋅ A + S0; P: = P + 1
#define CG_DEREF		"2a402015"				// A: = [A]
#define CG_INDXB		"221fd081"				// A: = A + S0; P: = P + 1
#define CG_DREFB		"2a4070001015"
#define CG_CALL			"4eb9,w"
#define CG_MARK			",m"
#define CG_JUMPFWD		"6000,>"
#define CG_JUMPBACK		"6000,<"
#define CG_ENTER		"2f0e2c4f"
#define CG_EXIT			"2c5f4e75"
#define CG_RESOLV		",r"
#define CG_NEG			""
#define CG_INV			""
#define CG_LOGNOT		""
#define CG_ADD			""
#define CG_SUB			""
#define CG_MUL			""
#define CG_DIV			""
#define CG_MOD			""
#define CG_AND			""
#define CG_OR			""
#define CG_XOR			""
#define CG_SHL			""
#define CG_SHR			""
#define CG_EQ			""
#define CG_NEQ			""
#define CG_LT			""
#define CG_GT			""
#define CG_LE			""
#define CG_GE			""
#define CG_JMPFALSE		",>"
#define CG_JMPTRUE		",>"
#define CG_FOR			",>"
#define CG_FORDOWN		",>"
#define CG_INCGLOB		"52b9,w"
#define CG_INCLOCL		"52ae,l"
#define CG_WORD			",w"

#define CG_P_READ \
	"8b4424048744240c89442404b803000000cd800f830300000031c048c3"
#define CG_P_WRITE \
	"8b4424048744240c89442404b804000000cd800f830300000031c048c3"
#define CG_P_MEMCOMP \
 "8b74240c8b7c24088b4c240441fcf3a609c90f850300000031c0c38a46ff2a47ff66986699c3"
#define CG_P_MEMCOPY \
	"8b74240c8b7c24088b4c2404fcf3a4c3"
#define CG_P_MEMFILL \
	"8b7c240c8b4424088b4c2404fcf3aac3"
#define CG_P_MEMSCAN \
 "8b7c240c8b4424088b4c24044189fafcf2ae09c90f840600000089f829d048c331c048c3"

void generate(char *s, int v);

void spill(void)
{
	LOG("spill");

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

int hex(int c)
{
	if (isdigit(c))
		return c-'0';
	else
		return c-'a'+10;
}

void emit(int x)
{
	_text_buffer[_text_buffer_ptr++] = (byte_t) x;
}

void emitl(int x)
{
	emit((x >> 8) & 0xFF);
	emit(x & 0xFF);
}

void emitw(int x)
{
	emit((x >> 24) & 0xFF);
	emit((x >> 16) & 0xFF);
	emit((x >> 8) & 0xFF);
	emit(x & 0xFF);
}

void text_patchl(int a, int x)
{
	_text_buffer[a + 0] = (x >> 8) & 0xFF;
	_text_buffer[a + 1] = x & 0xFF;
}

void text_patch(int a, int x)
{
	_text_buffer[a + 0] = (x >> 24) & 0xFF;
	_text_buffer[a + 1] = (x >> 16) & 0xFF;
	_text_buffer[a + 2] = (x >> 8) & 0xFF;
	_text_buffer[a + 3] = x & 0xFF;
}

int text_fetch(int a)
{
	return _text_buffer[a + 3] | (_text_buffer[a + 2] << 8) | (_text_buffer[a + 1] << 16) | (_text_buffer[a + 0] << 24);
}

void data(int x)
{
	_data_buffer[_data_buffer_ptr++] = (byte_t) x;
}

void dataw(int x)
{
	data((x >> 24) & 255);
	data((x >> 16) & 255);
	data((x >> 8) & 255);
	data(x);
}

void data_patch(int a, int x)
{
	_data_buffer[a + 0] = (x >> 24) & 0xFF;
	_data_buffer[a + 1] = (x >> 16) & 0xFF;
	_data_buffer[a + 2] = (x >> 8) & 0xFF;
	_data_buffer[a + 3] = x & 0xFF;
}

int data_fetch(int a)
{
	return _data_buffer[a + 3] | (_data_buffer[a + 2]<<8) | (_data_buffer[a + 1]<<16) | (_data_buffer[a + 0]<<24);
}

void tag(int seg)
{
	if (_relocation_ptr >= NRELOC)
		oops("relocation buffer overflow", NULL);

	_relocation_table[_relocation_ptr].seg = seg;
	_relocation_table[_relocation_ptr].addr = seg == 't' ? _text_buffer_ptr - BPW : _data_buffer_ptr - BPW;
	_relocation_ptr++;
}

void resolve(void)
{
	int	i, a, dist;

	dist = DATA_VADDR + (HEADER_SIZE + _text_buffer_ptr) % PAGE_SIZE;
	for (i=0; i<_relocation_ptr; i++)
	{
		if ('t' == _relocation_table[i].seg)
		{
			a = text_fetch(_relocation_table[i].addr);
			a += dist;
			text_patch(_relocation_table[i].addr, a);
		}
		else
		{
			a = data_fetch(_relocation_table[i].addr);
			a += dist;
			data_patch(_relocation_table[i].addr, a);
		}
	}
}

void generate(char *s, int v)
{
	int	x;

	while (*s)
	{
		if (',' == *s)
		{
			if ('b' == s[1])
			{
				emit(v);
			}
			else if ('w' == s[1])
			{
				emitw(v);
			}
			else if (s[1] == 'l')
			{
				emitl(v);
			}
			else if ('a' == s[1])
			{
				emitw(v);
				tag('t');
			}
			else if ('m' == s[1])
			{
				push(_text_buffer_ptr);
			}
			else if ('>' == s[1])
			{
				push(_text_buffer_ptr);
				emitl(0);
			}
			else if ('<' == s[1])
			{
				emitl(pop() - _text_buffer_ptr - 2);
			}
			else if ('r' == s[1])
			{
				x = pop();
				text_patchl(x, _text_buffer_ptr - x - 2);
			}
			else
			{
				oops("bad code", NULL);
			}
		}
		else
		{
			emit(hex(*s) * 16 + hex(s[1]));
		}
		s += 2;
	}
}

void builtin(char *name, int arity, char *code)
{
	generate(CG_JUMPFWD, 0);
	add(name, SYM_GLOBF|SYM_FUNCTION | (arity << 8), _text_buffer_ptr);
	generate(code, 0);
	generate(CG_RESOLV, 0);
}

int align(int x, int a)
{
	return (x+a) & ~(a-1);
}

void hexwrite(char *b)
{
	while (*b)
	{
#ifdef PLATFORM_WIN
		fputc(16*hex(*b)+hex(b[1]), stdout);
#else
		#error "Platform not supported"
#endif
		b += 2;
	}
}

// Write int32 in big-endian format
void lewrite(int x)
{
#ifdef PLATFORM_WIN
	fputc(x>>24 & 0xff, stdout);
	fputc(x>>16 & 0xff, stdout);
	fputc(x>>8 & 0xff, stdout);
	fputc(x & 0xff, stdout);
#else
	#error "Platform not supported"
#endif
}

void lewritec(int c)
{
#ifdef PLATFORM_WIN
	fputc((char)c, stdout);
#else
	#error "Platform not supported"
#endif
}

void pgzheader(void)
{
	lewritec('z');

	// write initial start segment
	lewrite(TEXT_VADDR);	// start address
	lewrite(0);				// size
}

void write_section(word_t load_address, byte_t *start, word_t size)
{
	lewrite(load_address);
	lewrite(size);

#ifdef PLATFORM_WIN
	fwrite(start, size, 1, stdout);
#else
	#error "Platform not supported"
#endif
}

/*
 * Scanner
 */

char _program_source[PROGRAM_SIZE];

int	_program_source_ptr = 0;
int _program_source_len;

void readprog(void)
{
#ifdef PLATFORM_WIN
	_program_source_len = fread(_program_source, 1, PROGRAM_SIZE, stdin);
	if (_program_source_len >= PROGRAM_SIZE)
		aw("program too big", NULL);
#else
	#error "Platform not supported"
#endif
}

int readrc(void)
{
	return _program_source_ptr >= _program_source_len? EOF: _program_source[_program_source_ptr++];
}

int readc(void)
{
	return _program_source_ptr >= _program_source_len? EOF: tolower(_program_source[_program_source_ptr++]);
}

#define META		256

int readec(void)
{
	int	c;

	c = readrc();
	if (c != '\\')
		return c;
	c = readc();
	if ('a' == c) return '\a';
	if ('b' == c) return '\b';
	if ('e' == c) return '\033';
	if ('f' == c) return '\f';
	if ('n' == c) return '\n';
	if ('q' == c) return '"' | META;
	if ('r' == c) return '\r';
	if ('s' == c) return ' ';
	if ('t' == c) return '\t';
	if ('v' == c) return '\v';
	return c;
}

void reject(void)
{
	_program_source_ptr--;
}

#define TOKEN_LEN	128

int	_token;
char _token_str[TOKEN_LEN];
int	_token_value;
int	_token_op_id;

int	_equal_op;
int _minus_op;
int _mul_op;
int _add_op;

typedef struct operator_t
{
	int	prec;
	int	len;
	char	*name;
	int	tok;
	char	*code;
} operator_t;


enum
{
	ENDFILE = -1,
	SYMBOL = 100, INTEGER, STRING,
	ADDROF = 200, ASSIGN, BINOP, BYTEOP, COLON, COMMA, COND,
	CONJ, DISJ, LBRACK, LPAREN, RBRACK, RPAREN, SEMI, UNOP,
	KCONST, KDECL, KDO, KELSE, KEND, KFOR, KHALT, KIE, KIF,
	KLEAVE, KLOOP, KRETURN, KSTRUCT, KVAR, KWHILE
};

operator_t Ops[] = {
	{ 7, 3, "mod",	BINOP,  CG_MOD		},
	{ 6, 1, "+",	BINOP,  CG_ADD		},
	{ 7, 1, "*",	BINOP,  CG_MUL		},
	{ 0, 1, ";",	SEMI,   NULL		},
	{ 0, 1, ",",	COMMA,  NULL		},
	{ 0, 1, "(",	LPAREN, NULL		},
	{ 0, 1, ")",	RPAREN, NULL		},
	{ 0, 1, "[",	LBRACK, NULL		},
	{ 0, 1, "]",	RBRACK, NULL		},
	{ 3, 1, "=",	BINOP,  CG_EQ		},
	{ 5, 1, "&",	BINOP,  CG_AND		},
	{ 5, 1, "|",	BINOP,  CG_OR		},
	{ 5, 1, "^",	BINOP,  CG_XOR		},
	{ 0, 1, "@",	ADDROF, NULL		},
	{ 0, 1, "~",	UNOP,   CG_INV		},
	{ 0, 1, ":",	COLON,  NULL		},
	{ 0, 2, "::",	BYTEOP, NULL		},
	{ 0, 2, ":=",	ASSIGN, NULL		},
	{ 0, 1, "\\",	UNOP,   CG_LOGNOT	},
	{ 1, 2, "\\/",	DISJ,   NULL		},
	{ 3, 2, "!=",	BINOP,  CG_NEQ		},
	{ 4, 1, "<",	BINOP,  CG_LT		},
	{ 4, 2, "<=",	BINOP,  CG_LE		},
	{ 5, 2, "<<",	BINOP,  CG_SHL		},
	{ 4, 1, ">",	BINOP,  CG_GT		},
	{ 4, 2, ">=",   BINOP,  CG_GE		},
	{ 5, 2, ">>",	BINOP,  CG_SHR		},
	{ 6, 1, "-",	BINOP,  CG_SUB		},
	{ 0, 2, "?",	COND,   NULL		},
	{ 7, 1, "/",	BINOP,  CG_DIV		},
	{ 2, 2, "/\\",	CONJ,   NULL		},
	{ 0, 0, NULL,   0,      NULL		}
};

int skip(void)
{
	int	c;

	c = readc();
	for (;;)
	{
		while (' ' == c || '\t' == c || '\n' == c || '\r' == c)
		{
			if ('\n' == c)
				_current_line++;
			c = readc();
		}

		if (c != '#')
			return c;

		while (c != '\n' && c != EOF)
			c = readc();
	}
}

int find_keyword(char *s)
{
	if ('c' == s[0])
	{
		if (!strcmp(s, "const")) return KCONST;
		return 0;
	}
	if ('d' == s[0])
	{
		if (!strcmp(s, "do")) return KDO;
		if (!strcmp(s, "decl")) return KDECL;
		return 0;
	}
	if ('e' == s[0])
	{
		if (!strcmp(s, "else")) return KELSE;
		if (!strcmp(s, "end")) return KEND;
		return 0;
	}
	if ('f' == s[0])
	{
		if (!strcmp(s, "for")) return KFOR;
		return 0;
	}
	if ('h' == s[0])
	{
		if (!strcmp(s, "halt")) return KHALT;
		return 0;
	}
	if ('i' == s[0])
	{
		if (!strcmp(s, "if")) return KIF;
		if (!strcmp(s, "ie")) return KIE;
		return 0;
	}
	if ('l' == s[0])
	{
		if (!strcmp(s, "leave")) return KLEAVE;
		if (!strcmp(s, "loop")) return KLOOP;
		return 0;
	}
	if ('m' == s[0])
	{
		if (!strcmp(s, "mod")) return BINOP;
		return 0;
	}
	if ('r' == s[0])
	{
		if (!strcmp(s, "return")) return KRETURN;
		return 0;
	}
	if ('s' == s[0])
	{
		if (!strcmp(s, "struct")) return KSTRUCT;
		return 0;
	}
	if ('v' == s[0])
	{
		if (!strcmp(s, "var")) return KVAR;
		return 0;
	}
	if ('w' == s[0])
	{
		if (!strcmp(s, "while")) return KWHILE;
		return 0;
	}

	return 0;
}

int scanop(int c)
{
	int	i, j;

	i = 0;
	j = 0;
	_token_op_id = -1;
	while (Ops[i].len > 0)
	{
		if (Ops[i].len > j)
		{
			if (Ops[i].name[j] == c)
			{
				_token_op_id = i;
				_token_str[j] = c;
				c = readc();
				j++;
			}
		}
		else
		{
			break;
		}
		i++;
	}
	if (-1 == _token_op_id)
	{
		_token_str[j++] = c;
		_token_str[j] = 0;
		aw("unknown operator", _token_str);
	}
	_token_str[j] = 0;
	reject();
	return Ops[_token_op_id].tok;
}

void findop(char *s)
{
	int	i;

	i = 0;
	while (Ops[i].len > 0)
	{
		if (!strcmp(s, Ops[i].name))
		{
			_token_op_id = i;
			return;
		}
		i++;
	}
	oops("operator not found", s);
}

int scan(void)
{
	int	c, i, k, sgn;

	c = skip();
	if (EOF == c)
	{
		strcpy(_token_str, "end of file");
		return ENDFILE;
	}

	if (isalpha(c) || '_' == c || '.' == c)
	{
		i = 0;
		while (isalpha(c) || '_' == c || '.' == c || isdigit(c))
		{
			if (i >= TOKEN_LEN-1)
			{
				_token_str[i] = 0;
				aw("symbol too long", _token_str);
			}
			_token_str[i++] = c;
			c = readc();
		}
		_token_str[i] = 0;
		reject();
		if ((k = find_keyword(_token_str)) != 0)
		{
			if (BINOP == k)
				findop(_token_str);
			return k;
		}
		return SYMBOL;
	}
	if (isdigit(c) || '%' == c)
	{
		sgn = 1;
		i = 0;
		if ('%' == c)
		{
			sgn = -1;
			c = readc();
			_token_str[i++] = c;
			if (!isdigit(c))
			{
				reject();
				return scanop('-');
			}
		}
		_token_value = 0;
		while (isdigit(c))
		{
			if (i >= TOKEN_LEN-1)
			{
				_token_str[i] = 0;
				aw("integer too long", _token_str);
			}
			_token_str[i++] = c;
			_token_value = _token_value * 10 + c - '0';
			c = readc();
		}
		_token_str[i] = 0;
		reject();
		_token_value = _token_value * sgn;
		return INTEGER;
	}
	if ('\'' == c)
	{
		_token_value = readec();
		if (readc() != '\'')
			aw("missing ''' in character", NULL);
		return INTEGER;
	}
	if ('"' == c)
	{
		i = 0;
		c = readec();
		while (c != '"' && c != EOF)
		{
			if (i >= TOKEN_LEN-1)
			{
				_token_str[i] = 0;
				aw("string too long", _token_str);
			}
			_token_str[i++] = c & (META-1);
			c = readec();
		}
		_token_str[i] = 0;
		return STRING;
	}
	return scanop(c);
}

/*
 * Parser
 */

#define MAXTBL		128
#define MAXLOOP		100

int	Fun = 0;
int	Loop0 = -1;
int	Leaves[MAXLOOP], Lvp = 0;
int	Loops[MAXLOOP], Llp = 0;

void expect(int t, char *s)
{
	char	b[100];

	if (t == _token)
		return;
	sprintf(b, "%s expected", s);
	aw(b, _token_str);
}

void expect_equal_sign(void)
{
	if (_token != BINOP || _token_op_id != _equal_op)
		expect(0, "'='");
	_token = scan();
}

void expect_semi(void)
{
	expect(SEMI, "';'");
	_token = scan();
}

void expect_left_paren(void)
{
	expect(LPAREN, "'('");
	_token = scan();
}

void expect_right_paren(void)
{
	expect(RPAREN, "')'");
	_token = scan();
}

int const_factor(void)
{
	LOG("const_factor");

	int	v;
	symbol_t *y;

	if (INTEGER == _token)
	{
		v = _token_value;
		_token = scan();
		return v;
	}
	if (SYMBOL == _token)
	{
		y = lookup(_token_str, SYM_CONST);
		_token = scan();
		return y->value;
	}
	aw("constant value expected", _token_str);
	return 0; /*LINT*/
}

int const_value(void)
{
	LOG("const_value");

	int	v;

	v = const_factor();
	if (BINOP == _token && _mul_op == _token_op_id)
	{
		_token = scan();
		v *= const_factor();
	}
	else if (BINOP == _token && _add_op == _token_op_id)
	{
		_token = scan();
		v += const_factor();
	}
	return v;
}

void var_declaration(int glob)
{
	LOG("var_declaration");

	symbol_t *y;
	int	size;

	_token = scan();
	while (1)
	{
		expect(SYMBOL, "symbol");
		size = 1;
		if (glob & SYM_GLOBF)
			y = add(_token_str, glob, _data_buffer_ptr);
		else
			y = add(_token_str, 0, _local_frame_ptr);

		_token = scan();
		if (LBRACK == _token)
		{
			_token = scan();
			size = const_value();
			if (size < 1)
				aw("invalid size", NULL);
			y->flags |= SYM_VECTOR;
			expect(RBRACK, "']'");
			_token = scan();
		}
		else if (BYTEOP == _token)
		{
			_token = scan();
			size = const_value();
			if (size < 1)
				aw("invalid size", NULL);
			size = (size + BPW - 1) / BPW;
			y->flags |= SYM_VECTOR;
		}

		if (glob & SYM_GLOBF)
		{
			if (y->flags & SYM_VECTOR)
			{
				generate(CG_ALLOC, size * BPW);
				generate(CG_GLOBVEC, _data_buffer_ptr);
			}
			dataw(0);
		}
		else
		{
			generate(CG_ALLOC, size * BPW);
			_local_frame_ptr -= size * BPW;
			if (y->flags & SYM_VECTOR)
			{
				generate(CG_LOCLVEC, 0);
				_local_frame_ptr -= BPW;
			}
			y->value = _local_frame_ptr;
		}

		if (_token != COMMA)
			break;

		_token = scan();
	}
	expect_semi();
}

void const_declaration(int glob)
{
	LOG("const_declaration");

	symbol_t	*y;

	_token = scan();
	while (1)
	{
		expect(SYMBOL, "symbol");
		y = add(_token_str, glob | SYM_CONST, 0);

		_token = scan();
		expect_equal_sign();
		y->value = const_value();

		if (_token != COMMA)
			break;

		_token = scan();
	}

	expect_semi();
}

void struct_declaration(int glob)
{
	LOG("struct_declaration");

	symbol_t	*y;
	int	i;

	_token = scan();
	expect(SYMBOL, "symbol");
	y = add(_token_str, glob | SYM_CONST, 0);
	_token = scan();
	i = 0;
	expect_equal_sign();

	while (1)
	{
		expect(SYMBOL, "symbol");
		add(_token_str, glob | SYM_CONST, i++);
		_token = scan();

		if (_token != COMMA)
			break;

		_token = scan();
	}

	y->value = i;
	expect_semi();
}

void forward_declaration(void)
{
	LOG("forward_declaration");

	symbol_t	*y;
	int	n;

	_token = scan();
	while (1) {
		expect(SYMBOL, "symbol");
		y = add(_token_str, SYM_GLOBF|SYM_DECLARATION, 0);
		_token = scan();
		expect_left_paren();
		n = const_value();
		y->flags |= n << 8;
		expect_right_paren();
		if (n < 0)
			aw("invalid arity", NULL);
		if (_token != COMMA)
			break;
		_token = scan();
	}
	expect_semi();
}

void resolve_fwd(int loc, int fn)
{
	int	nloc;

	while (loc != 0)
	{
		nloc = text_fetch(loc);
		text_patch(loc, fn-loc-BPW);
		loc = nloc;
	}
}

void compound_statement(void);
void statememt(void);

void function_declaration(void)
{
	LOG("function_declaration");

	int	l_base, l_addr = 2*BPW;
	int	i, na = 0;
	int	oyp;
	symbol_t	*y;

	generate(CG_JUMPFWD, 0);
	y = add(_token_str, SYM_GLOBF|SYM_FUNCTION, _text_buffer_ptr);
	_token = scan();
	expect_left_paren();
	oyp = _symbol_table_ptr;
	l_base = _symbol_table_ptr;
	while (SYMBOL == _token)
	{
		add(_token_str, 0, l_addr);
		l_addr += BPW;
		na++;
		_token = scan();
		if (_token != COMMA)
			break;
		_token = scan();
	}

	for (i = l_base; i < _symbol_table_ptr; i++)
	{
		_symbol_table[i].value = 12+na*BPW - _symbol_table[i].value;
	}

	if (y->flags & SYM_DECLARATION)
	{
		resolve_fwd(y->value, _text_buffer_ptr);
		if (na != y->flags >> 8)
			aw("redefinition with different type", y->name);

		y->flags &= ~SYM_DECLARATION;
		y->flags |= SYM_FUNCTION;
		y->value = _text_buffer_ptr;
	}

	expect_right_paren();
	y->flags |= na << 8;
	generate(CG_ENTER, 0);
	Fun = 1;
	statememt();
	Fun = 0;
	generate(CG_CLEAR, 0);
	generate(CG_EXIT, 0);
	generate(CG_RESOLV, 0);
	_symbol_table_ptr = oyp;
	_local_frame_ptr = 0;
}

void declaration(int glob)
{
	LOG("declaration");

	if (KVAR == _token)
		var_declaration(glob);
	else if (KCONST == _token)
		const_declaration(glob);
	else if (KSTRUCT== _token)
		struct_declaration(glob);
	else if (KDECL == _token)
		forward_declaration();
	else
		function_declaration();
}

void expr(int clr);

void function_call(symbol_t *fn)
{
	LOG("function_call");

	int	i = 0;

	_token = scan();
	if (NULL == fn)
		aw("call of non-function", NULL);

	while (_token != RPAREN)
	{
		expr(0);
		i++;
		if (COMMA != _token)
			break;
		_token = scan();
		if (RPAREN == _token)
			aw("syntax error", _token_str);
	}
	if (i != (fn->flags >> 8))
		aw("wrong number of arguments", fn->name);

	expect(RPAREN, "')'");
	_token = scan();

	if (loaded())
		spill();

	if (fn->flags & SYM_DECLARATION)
	{
		generate(CG_CALL, fn->value);
		fn->value = _text_buffer_ptr-BPW;
	}
	else
	{
		generate(CG_CALL, fn->value-_text_buffer_ptr-5);	/* TP-BPW+1 */
	}

	if (i != 0)
		generate(CG_DEALLOC, i*BPW);

	_accumulator_loaded = 1;
}

int make_string(char *s)
{
	LOG("make_string");

	int	i, a, k;

	a = _data_buffer_ptr;
	k = strlen(s);

	for (i=0; i<=k; i++)
		data(s[i]);

	while (_data_buffer_ptr % 4 != 0)
		data(0);

	return a;
}

int make_table(void)
{
	LOG("make_table");

	int	n, i;
	int	loc;
	int	tbl[MAXTBL], af[MAXTBL];
	int	dynamic = 0;

	_token = scan();
	n = 0;
	while (_token != RBRACK)
	{
		if (n >= MAXTBL)
			aw("table too big", NULL);

		if (LPAREN == _token)
		{
			_token = scan();
			dynamic = 1;
			continue;
		}
		else if (dynamic)
		{
			expr(1);
			generate(CG_STGLOB, 0);
			tbl[n] = 0;
			af[n++] = _text_buffer_ptr-BPW;
			if (RPAREN == _token)
			{
				_token = scan();
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
			_token = scan();
		}
		else if (LBRACK == _token)
		{
			tbl[n] = make_table();
			af[n++] = 1;
		}
		else
		{
			aw("invalid table element", _token_str);
		}

		if (_token != COMMA)
			break;

		_token = scan();
	}

	expect(RBRACK, "']'");
	_token = scan();
	loc = _data_buffer_ptr;

	for (i = 0; i < n; i++)
	{
		dataw(tbl[i]);
		if (1 == af[i])
		{
			tag('d');
		}
		else if (af[i] > 1)
		{
			text_patch(af[i], _data_buffer_ptr-4);
		}
	}
	return loc;
}

void load(symbol_t *y)
{
	if (y->flags & SYM_GLOBF)
		generate(CG_LDGLOBAL, y->value);
	else
		generate(CG_LDLOCAL, y->value);
}

void store(symbol_t *y)
{
	if (y->flags & SYM_GLOBF)
		generate(CG_STGLOB, y->value);
	else
		generate(CG_STLOCL, y->value);
}

void factor(void);

symbol_t *address(int lv, int *bp)
{
	LOG("address");

	symbol_t	*y;

	y = lookup(_token_str, 0);
	_token = scan();
	if (y->flags & SYM_CONST)
	{
		if (lv > 0) aw("invalid address", y->name);
		spill();
		generate(CG_LDVAL, y->value);
	}
	else if (y->flags & (SYM_FUNCTION|SYM_DECLARATION))
	{
		if (2 == lv) aw("invalid address", y->name);
	}
	else if (0 == lv || LBRACK == _token || BYTEOP == _token)
	{
		spill();
		load(y);
	}
	if (LBRACK == _token || BYTEOP == _token)
		if (y->flags & (SYM_FUNCTION|SYM_DECLARATION|SYM_CONST))
			aw("bad subscript", y->name);

	while (LBRACK == _token)
	{
		*bp = 0;
		_token = scan();
		expr(0);
		expect(RBRACK, "']'");
		_token = scan();
		y = NULL;
		generate(CG_INDEX, 0);
		if (LBRACK == _token || BYTEOP == _token || 0 == lv)
			generate(CG_DEREF, 0);
	}

	if (BYTEOP == _token)
	{
		*bp = 1;
		_token = scan();
		factor();
		y = NULL;
		generate(CG_INDXB, 0);
		if (0 == lv)
			generate(CG_DREFB, 0);
	}
	return y;
}

void factor(void)
{
	LOG("factor");

	symbol_t	*y;
	int	op;
	int	b;

	if (INTEGER == _token)
	{
		LOG("factor - INTEGER");

		spill();
		generate(CG_LDVAL, _token_value);
		_token = scan();
	}
	else if (SYMBOL == _token)
	{
		LOG("factor - SYMBOL");

		y = address(0, &b);
		if (LPAREN == _token)
		{
			function_call(y);
		}
	}
	else if (STRING == _token)
	{
		LOG("factor - STRING");

		spill();
		generate(CG_LDADDR, make_string(_token_str));
		_token = scan();
	}
	else if (LBRACK == _token)
	{
		spill();
		generate(CG_LDADDR, make_table());
	}
	else if (ADDROF == _token)
	{
		_token = scan();
		y = address(2, &b);
		if (NULL == y)
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
	else if (BINOP == _token)
	{
		op = _token_op_id;
		if (_token_op_id != _minus_op)
			aw("syntax error", _token_str);
		_token = scan();
		factor();
		generate(CG_NEG, 0);
	}
	else if (UNOP == _token)
	{
		op = _token_op_id;
		_token = scan();
		factor();
		generate(Ops[op].code, 0);
	}
	else if (LPAREN == _token)
	{
		_token = scan();
		expr(0);
		expect_right_paren();
	}
	else
	{
		aw("syntax error", _token_str);
	}
}

int emitop(int *stk, int sp)
{
	generate(Ops[stk[sp - 1]].code, 0);
	return sp - 1;
}

void arith(void)
{
	LOG("arith");

	int	stk[10], sp;

	sp = 0;
	factor();
	while (BINOP == _token)
	{
		while (sp && Ops[_token_op_id].prec <= Ops[stk[sp-1]].prec)
			sp = emitop(stk, sp);

		stk[sp++] = _token_op_id;
		_token = scan();
		factor();
	}

	while (sp > 0)
	{
		sp = emitop(stk, sp);
	}
}

void conjn(void)
{
	LOG("conjn");

	int	n = 0;

	arith();
	while (CONJ == _token)
	{
		_token = scan();
		generate(CG_JMPFALSE, 0);
		clear();
		arith();
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
	LOG("disjn");

	int	n = 0;

	conjn();
	while (DISJ == _token)
	{
		_token = scan();
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

void expr(int clr)
{
	LOG("expr");

	if (clr)
	{
		clear();
	}

	disjn();

	if (COND == _token)
	{
		_token = scan();
		generate(CG_JMPFALSE, 0);
		expr(1);
		expect(COLON, "':'");
		_token = scan();
		generate(CG_JUMPFWD, 0);
		swap();
		generate(CG_RESOLV, 0);
		expr(1);
		generate(CG_RESOLV, 0);
	}
}

void statememt(void);

void halt_statement(void)
{
	_token = scan();
	generate(CG_HALT, const_value());
	expect_semi();
}

void return_statement(void)
{
	_token = scan();

	if (0 == Fun)
		aw("can't return from main body", 0);

	if (SEMI == _token)
		generate(CG_CLEAR, 0);
	else
		expr(1);

	if (_local_frame_ptr != 0)
		generate(CG_DEALLOC, -_local_frame_ptr);

	generate(CG_EXIT, 0);
	expect_semi();
}

void if_statement(bool expect_else)
{
	LOG("if_statement");

	_token = scan();
	expect_left_paren();
	expr(1);
	generate(CG_JMPFALSE, 0);
	expect_right_paren();
	statememt();

	if (expect_else)
	{
		generate(CG_JUMPFWD, 0);
		swap();
		generate(CG_RESOLV, 0);
		expect(KELSE, "ELSE");
		_token = scan();
		statememt();
	}
	else if (KELSE == _token)
	{
		aw("ELSE without IE", NULL);
	}

	generate(CG_RESOLV, 0);
}

void while_statement(void)
{
	int	olp, olv;

	olp = Loop0;
	olv = Lvp;
	_token = scan();
	expect_left_paren();
	generate(CG_MARK, 0);
	Loop0 = tos();
	expr(1);
	expect_right_paren();
	generate(CG_JMPFALSE, 0);
	statememt();
	swap();
	generate(CG_JUMPBACK, 0);
	generate(CG_RESOLV, 0);

	while (Lvp > olv)
	{
		push(Leaves[Lvp-1]);
		generate(CG_RESOLV, 0);
		Lvp--;
	}
	Loop0 = olp;
}

void for_statement(void)
{
	symbol_t	*y;
	int	step = 1;
	int	oll, olp, olv;
	int	test;

	_token = scan();
	oll = Llp;
	olv = Lvp;
	olp = Loop0;
	Loop0 = 0;
	expect_left_paren();
	expect(SYMBOL, "symbol");
	y = lookup(_token_str, 0);
	_token = scan();

	if (y->flags & (SYM_CONST|SYM_FUNCTION|SYM_DECLARATION))
		aw("unexpected type", y->name);

	expect_equal_sign();
	expr(1);
	store(y);
	expect(COMMA, "','");
	_token = scan();
	generate(CG_MARK, 0);
	test = tos();
	load(y);
	expr(0);

	if (COMMA == _token)
	{
		_token = scan();
		step = const_value();
	}

	generate(step<0? CG_FORDOWN: CG_FOR, 0);
	expect_right_paren();
	statememt();

	while (Llp > oll)
	{
		push(Loops[Llp-1]);
		generate(CG_RESOLV, 0);
		Llp--;
	}

	if (y->flags & SYM_GLOBF)
		generate(CG_INCGLOB, y->value);
	else
		generate(CG_INCLOCL, y->value);

	generate(CG_WORD, step);
	swap();
	generate(CG_JUMPBACK, 0);
	generate(CG_RESOLV, 0);

	while (Lvp > olv)
	{
		push(Leaves[Lvp-1]);
		generate(CG_RESOLV, 0);
		Lvp--;
	}

	Llp = oll;
	Loop0 = olp;
}

void leave_statement(void)
{
	if (Loop0 < 0)
		aw("LEAVE not in loop context", 0);

	_token = scan();
	expect_semi();

	if (Lvp >= MAXLOOP)
		aw("too many LEAVEs", NULL);

	generate(CG_JUMPFWD, 0);
	Leaves[Lvp++] = pop();
}

void loop_statement(void)
{
	if (Loop0 < 0)
		aw("LOOP not in loop context", 0);

	_token = scan();
	expect_semi();

	if (Loop0 > 0)
	{
		push(Loop0);
		generate(CG_JUMPBACK, 0);
	}
	else
	{
		if (Llp >= MAXLOOP)
			aw("too many LOOPs", NULL);
		generate(CG_JUMPFWD, 0);
		Loops[Llp++] = pop();
	}
}

void assignment_or_call(void)
{
	LOG("assignment_or_call");

	symbol_t	*y;
	int	b;

	clear();
	y = address(1, &b);

	if (LPAREN == _token)
	{
		function_call(y);
	}
	else if (ASSIGN == _token)
	{
		_token = scan();
		expr(0);
		if (NULL == y)
			generate(b? CG_STINDB: CG_STINDR, 0);
		else if (y->flags & (SYM_FUNCTION|SYM_DECLARATION|SYM_CONST|SYM_VECTOR))
			aw("bad location", y->name);
		else
			store(y);
	}
	else
	{
		aw("syntax error", _token_str);
	}
	expect_semi();
}

void statememt(void)
{
	LOG("statememt");

	switch (_token)
	{
		case KFOR:
			for_statement();
			break;
		case KHALT:
			halt_statement();
			break;
		case KIE:
			if_statement(1);
			break;
		case KIF:
			if_statement(0);
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
		case KDO:
			compound_statement();
			break;
		case SYMBOL:
			assignment_or_call();
			break;
		case SEMI:
			_token = scan();
			break;
		default:
			expect(0, "statement");
			break;
	}
}

void compound_statement(void)
{
	LOG("compound_statement");

	expect(KDO, "DO");
	_token = scan();
	int old_symbol_table_ptr = _symbol_table_ptr;
	int old_local_frame_ptr = _local_frame_ptr;

	while (KVAR == _token || KCONST == _token || KSTRUCT == _token)
		declaration(0);

	while (_token != KEND)
		statememt();
	_token = scan();

	if (old_local_frame_ptr - _local_frame_ptr != 0)
		generate(CG_DEALLOC, old_local_frame_ptr-_local_frame_ptr);

	_symbol_table_ptr = old_symbol_table_ptr;
	_local_frame_ptr = old_local_frame_ptr;
}

void program(void)
{
	int	i;

	generate(CG_INIT, 0);
	_token = scan();
	while (KVAR == _token || KCONST == _token || SYMBOL == _token || KDECL == _token || KSTRUCT == _token)
		declaration(SYM_GLOBF);

	if (_token != KDO)
		aw("DO or declaration expected", NULL);

	compound_statement();
	generate(CG_HALT, 0);

	for (i = 0; i < _symbol_table_ptr; i++)
		if (_symbol_table[i].flags & SYM_DECLARATION && _symbol_table[i].value)
			aw("undefined function", _symbol_table[i].name);
}

/*
 * Main
 */

void init(void)
{
	findop("="); _equal_op = _token_op_id;
	findop("-"); _minus_op = _token_op_id;
	findop("*"); _mul_op = _token_op_id;
	findop("+"); _add_op = _token_op_id;
	builtin("t.read", 3, CG_P_READ);
	builtin("t.write", 3, CG_P_WRITE);
	builtin("t.memcomp", 3, CG_P_MEMCOMP);
	builtin("t.memcopy", 3, CG_P_MEMCOPY);
	builtin("t.memfill", 3, CG_P_MEMFILL);
	builtin("t.memscan", 3, CG_P_MEMSCAN);
}

int main(void)
{
	init();
	readprog();
	program();
	_text_buffer_ptr = align(_text_buffer_ptr + 4, 16) - 4; /* 16-byte align in file */
	resolve();

	pgzheader();
	write_section(TEXT_VADDR, _text_buffer, _text_buffer_ptr);
	write_section(DATA_VADDR, _data_buffer, _data_buffer_ptr);
	return 0;
}
