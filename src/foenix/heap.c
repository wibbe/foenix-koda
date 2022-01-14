
#include <stdint.h>

static uint8_t *_heap;
static uint8_t *_heap_end;

static uint8_t *_heap_ptr;

void heap_init(uint8_t *heap, uint8_t *heap_end)
{
	_heap = heap;
	_heap_end = heap_end;
	_heap_ptr = _heap;
}

void *heap_alloc(uint32_t size)
{
	size = ((size / 4) + 1) * 4;
	if ((_heap_ptr + size) >= _heap_end)
		return 0;

	void *ptr = _heap_ptr;
	_heap_ptr = _heap_ptr + size;
	return ptr;
}

void heap_reset(void)
{
	_heap_ptr =_heap;
}

void *heap_position(void)
{
	return _heap_ptr;
}

void heap_rewind(void *position)
{
	if (position >= (void *)_heap && position <= (void *)_heap_end)
		_heap_ptr = position;
}

uint32_t heap_free(void)
{
	return (uint32_t)(_heap_end - _heap_ptr);
}
