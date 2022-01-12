

#define CG_INIT         "35,]"
#define CG_RESOLVE_END  ",s"
#define CG_PUSH         "02"         // P: = P − 1; S0: = A
#define CG_LDVAL        "03,w"       // P: = P − 1; S0: = A; A: = w
#define CG_LDADDR       "04,a"       // P: = P − 1; S0: = A; A: = a
#define CG_LDLOCALREF   "05,w"       // P: = P − 1; S0: = A; A: = F + w
#define CG_LDGLOBAL     "06,a"       // P: = P − 1; S0: = A; A: = [a]
#define CG_LDLOCAL      "07,w"       // P: = P − 1; S0: = A; A: = [F + w]
#define CG_CLEAR        "08"         // A: = 0
#define CG_STGLOB       "09,a"       // [a]: = A; A: = S0; P: = P + 1
#define CG_STLOCL       "0A,w"       // [F + w]: = A; A: = S0; P: = P + 1
#define CG_STINDR       "0B"         // [S0]: = A; P: = P + 1
#define CG_STINDB       "0C"         // b[S0]: = A; P: = P + 1
#define CG_ALLOC        "0D,w"       // P: = P − w
#define CG_DEALLOC      "0E,w"       // P: = P + w
#define CG_LOCLVEC      "0F"         // w: = P; P: = P − 1; S0: = w
#define CG_GLOBVEC      "10,a"       // [a]: = P
#define CG_HALT         "11,w"
#define CG_INDEX        "12"         // A: = 4 ⋅ A + S0; P: = P + 1
#define CG_DEREF        "13"         // A: = [A]
#define CG_INDXB        "33"         // A: = A + S0; P: = P + 1
#define CG_DREFB        "14"
#define CG_CALL         "15,w"
#define CG_MARK         ",m"
#define CG_JUMPFWD      "16,>"
#define CG_JUMPBACK     "17,<"
#define CG_ENTER        "18"
#define CG_EXIT         "19"
#define CG_RESOLV       ",r"
#define CG_NEG          "1A"
#define CG_INV          "1B"
#define CG_LOGNOT       "1C"
#define CG_ADD          "1D"
#define CG_SUB          "1E"
#define CG_MUL          "1F"
#define CG_DIV          "20"
#define CG_MOD          "21"
#define CG_AND          "22"
#define CG_OR           "23"
#define CG_XOR          "24"
#define CG_SHL          "25"
#define CG_SHR          "26"
#define CG_EQ           "27"
#define CG_NEQ          "28"
#define CG_LT           "29"
#define CG_GT           "2A"
#define CG_LE           "2B"
#define CG_GE           "2C"
#define CG_JMPFALSE     "2D,>"
#define CG_JMPTRUE      "2E,>"
#define CG_FOR          "2F,>"
#define CG_INCGLOB      "31,a"
#define CG_INCLOCL      "32,w"
#define CG_INC          "34"

#define CG_FUNC_SYSCALL0    ""
#define CG_FUNC_SYSCALL1    ""
#define CG_FUNC_SYSCALL2    ""
#define CG_FUNC_SYSCALL3    ""  
#define CG_FUNC_MEMSCAN     ""
#define CG_FUNC_MEMCOPY     ""



void write_output_byte(unsigned char ch);
int text_fetch(int a);
int text_fetch_short(int a);


symbol_t * find_symbol_from_address(int address)
{
    for (int i = 0; i < _symbol_table_ptr; ++i)
    {
        symbol_t *sym = &_symbol_table[i];
        if (sym->value == address && sym->flags & SYM_FUNCTION)
            return sym;
    }

    return NULL;
}

void write_bytecode(void)
{
#if PLATFORM_WIN    
    int idx = 0;
    while (idx < _text_buffer_ptr)
    {
        unsigned char op = _text_buffer[idx];
        symbol_t *sym = find_symbol_from_address(idx);

        if (sym != NULL)
        {
            fprintf(_output_target, "\n%s:\n", sym->name);
        }

        switch (op)
        {
            case 0x01:          // CG_INIT
                fprintf(_output_target, "\nmain:\n%06X: INIT\n", idx);
                break;

            case 0x02:          // CG_PUSH
                fprintf(_output_target, "%06X: PUSH\n", idx);
                break;

            case 0x03:          // CG_LDVAL
                fprintf(_output_target, "%06X: LDVAL           %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x04:          // CG_LDADDR
                fprintf(_output_target, "%06X: LDADDR          $%06X\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x05:          // CG_LDLOCALREF
                fprintf(_output_target, "%06X: LDLOCALREF      %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x06:          // CG_LDGLOBAL
                fprintf(_output_target, "%06X: LDGLOBAL        $%06X\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x07:          // CG_LDLOCAL
                fprintf(_output_target, "%06X: LDLOCAL         %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x08:          // CG_CLEAR
                fprintf(_output_target, "%06X: CLEAR\n", idx);
                break;

            case 0x09:          // CG_STGLOB
                fprintf(_output_target, "%06X: STGLOB          $%06X\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x0A:          // CG_STLOCL
                fprintf(_output_target, "%06X: STLOCL          %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x0B:          // CG_STINDR
                fprintf(_output_target, "%06X: STINDR\n", idx);
                break;

            case 0x0C:          // CG_STINDB
                fprintf(_output_target, "%06X: STINDB\n", idx);
                break;

            case 0x0D:          // CG_ALLOC
                fprintf(_output_target, "%06X: ALLOC           %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x0E:          // CG_DEALLOC
                fprintf(_output_target, "%06X: DEALLOC         %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x0F:          // CG_LOCLVEC
                fprintf(_output_target, "%06X: LOCLVEC\n", idx);
                break;

            case 0x10:          // CG_GLOBVEC
                fprintf(_output_target, "%06X: GLOBVEC         $%06X\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x11:          // CG_HALT
                fprintf(_output_target, "%06X: HALT            %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x12:          // CG_INDEX
                fprintf(_output_target, "%06X: INDEX\n", idx);
                break;

            case 0x13:          // CG_DEREF
                fprintf(_output_target, "%06X: DEREF\n", idx);
                break;

            case 0x33:          // CG_INDXB
                fprintf(_output_target, "%06X: INDXB\n", idx);
                break;

            case 0x14:          // CG_DREFB
                fprintf(_output_target, "%06X: DREFB\n", idx);
                break;

            case 0x15:          // CG_CALL
                fprintf(_output_target, "%06X: CALL            $%06X\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x16:          // CG_JUMPFWD
                fprintf(_output_target, "%06X: JUMPFWD         $%06X\n", idx, idx + text_fetch_short(idx + 1) + 1);
                idx += 2;
                break;

            case 0x17:          // CG_JUMPBACK
                fprintf(_output_target, "%06X: JUMPBACK        $%06X\n", idx, idx - text_fetch_short(idx + 1) + 1);
                idx += 2;
                break;

            case 0x18:          // CG_ENTER
                fprintf(_output_target, "%06X: ENTER\n", idx);
                break;

            case 0x19:          // CG_EXIT
                fprintf(_output_target, "%06X: EXIT\n", idx);
                break;

            case 0x1A:          // CG_NEG
                fprintf(_output_target, "%06X: NEG\n", idx);
                break;

            case 0x1B:          // CG_INV
                fprintf(_output_target, "%06X: INV\n", idx);
                break;

            case 0x1C:          // CG_LOGNOT
                fprintf(_output_target, "%06X: LOGNOT\n", idx);
                break;

            case 0x1D:          // CG_ADD
                fprintf(_output_target, "%06X: ADD\n", idx);
                break;

            case 0x1E:          // CG_SUB
                fprintf(_output_target, "%06X: SUB\n", idx);
                break;

            case 0x1F:          // CG_MUL
                fprintf(_output_target, "%06X: MUL\n", idx);
                break;

            case 0x20:          // CG_DIV
                fprintf(_output_target, "%06X: DIV\n", idx);
                break;

            case 0x21:          // CG_MOD
                fprintf(_output_target, "%06X: MOD\n", idx);
                break;

            case 0x22:          // CG_AND
                fprintf(_output_target, "%06X: AND\n", idx);
                break;

            case 0x23:          // CG_OR
                fprintf(_output_target, "%06X: OR\n", idx);
                break;

            case 0x24:          // CG_XOR
                fprintf(_output_target, "%06X: XOR\n", idx);
                break;

            case 0x25:          // CG_SHL
                fprintf(_output_target, "%06X: SHL\n", idx);
                break;

            case 0x26:          // CG_SHR
                fprintf(_output_target, "%06X: SHR\n", idx);
                break;

            case 0x27:          // CG_EQ
                fprintf(_output_target, "%06X: EQ\n", idx);
                break;

            case 0x28:          // CG_NEQ
                fprintf(_output_target, "%06X: NEQ\n", idx);
                break;

            case 0x29:          // CG_LT
                fprintf(_output_target, "%06X: LT\n", idx);
                break;

            case 0x2A:          // CG_GT
                fprintf(_output_target, "%06X: GT\n", idx);
                break;

            case 0x2B:          // CG_LE
                fprintf(_output_target, "%06X: LE\n", idx);
                break;

            case 0x2C:          // CG_GE
                fprintf(_output_target, "%06X: GE\n", idx);
                break;

            case 0x2D:          // CG_JMPFALSE
                fprintf(_output_target, "%06X: JMPFALSE        $%06X\n", idx, idx + text_fetch_short(idx + 1) + 1);
                idx += 2;
                break;

            case 0x2E:          // CG_JMPTRUE
                fprintf(_output_target, "%06X: JMPTRUE         $%06X\n", idx, idx + text_fetch_short(idx + 1));
                idx += 2;
                break;

            case 0x2F:          // CG_FOR
                fprintf(_output_target, "%06X: FOR             $%06X\n", idx, idx + text_fetch_short(idx + 1) + 1);
                idx += 2;
                break;

            case 0x31:          // CG_INCGLOB
                fprintf(_output_target, "%06X: INCGLOB         $%06X\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x32:                  // CG_INCLOCL
                fprintf(_output_target, "%06X: INCLOCL         %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

            case 0x34:
                fprintf(_output_target, "%06X: INC\n", idx);
                break;

            case 0x35:
                fprintf(_output_target, "%06X: INIT         %d\n", idx, text_fetch(idx + 1));
                idx += 4;
                break;

        }
        idx++;
    }
#endif  
}