
#ifndef OPCODES_H
#define OPCODES_H

enum {
    OP_NONE,
    OP_INIT,
    OP_LOAD_VALUE,
    OP_LOAD_GLOBAL_ADDR,
    OP_LOAD_LOCAL_ADDR,
    OP_LOAD_GLOBAL,
    OP_LOAD_LOCAL,
    OP_CLEAR,
    OP_TO_RET,
    OP_FROM_RET,
    OP_FREE_REG,
    OP_STORE_GLOBAL,
    OP_STORE_GLOBAL_NP,
    OP_STORE_LOCAL,
    OP_STORE_LOCAL_NP,
    OP_STORE_INDIRECT_WORD,
    OP_STORE_INDIRECT_BYTE,
    OP_ALLOC,
    OP_DEALLOC,
    OP_LOCAL_VEC,
    OP_GLOBAL_VEC,
    OP_HALT,
    OP_INDEX_WORD,
    OP_INDEX_BYTE,
    OP_DEREF_WORD,
    OP_DEREF_BYTE,
    OP_CALL_SETUP,
    OP_CALL,
    OP_CALL_INDIRECT,
    OP_CALL_CLEANUP,
    OP_FUNC_START,
    OP_FUNC_END,
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
    OP_SHIFT_LEFT,
    OP_SHIFT_RIGHT,
    OP_EQ,
    OP_NOT_EQ,
    OP_LESS,
    OP_LESS_EQ,
    OP_GREATER,
    OP_GREATER_EQ,
    OP_JUMP_FWD,
    OP_JUMP_BACK,
    OP_JUMP_FALSE,
    OP_JUMP_TRUE,
    OP_INC,
    OP_DEC,
    OP_PEEK8,
    OP_PEEK16,
    OP_PEEK32,
    OP_POKE8,
    OP_POKE16,
    OP_POKE32,
    OP_ASM,                 // We have a blob of assembly code
    OP_LIB,
    OP_JUMP_TARGET,

    OP_COUNT,
};

#endif