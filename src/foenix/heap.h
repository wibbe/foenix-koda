
#ifndef HEAP_H
#define HEAP_H

#include <stdint.h>

void *heap_alloc(uint32_t size);
void heap_reset(void);

void *heap_position(void);
void heap_rewind(void *position);

uint32_t heap_free(void);

#endif