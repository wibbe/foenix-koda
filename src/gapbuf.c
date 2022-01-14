
#include "gapbuf.h"
#include "foenix/syscall.h"

#include <string.h>




void gapbuf_init(gapbuf_t *buf, char *data, uint32_t size)
{
	buf->total = size;
	buf->gap = size;
	buf->front = 0;
	buf->data = data;
}

void gapbuf_destroy(gapbuf_t *buf)
{
	buf->total = 0;
	buf->data = 0;
}

char gapbuf_fetch(gapbuf_t *buf, uint32_t pos)
{
	if (pos >= buf->total)
		return 0;

	if (pos < buf->front)
	{
		return buf->data[pos];
	}
	else
	{
		pos -= buf->front;
		return buf->data[buf->front + buf->gap + pos];
	}
}

bool gapbuf_insert(gapbuf_t *buf, char ch)
{
	if (!buf->gap)
		return false;

	buf->data[buf->front] = ch;
	buf->front++;
	buf->gap--;
	return true;
}

bool gapbuf_inserts(gapbuf_t *buf, const char* str)
{
	uint32_t len = strlen(str);
	if (buf->gap < len)
		return false;

	memcpy(buf->data + buf->front, str, len);
	buf->front += len;
	buf->gap -= len;
	return true;
}

void gapbuf_delete(gapbuf_t *buf)
{
	if (buf->total > buf->front + buf->gap)
		buf->gap++;
}

void gapbuf_backspace(gapbuf_t *buf)
{
	if (buf->front > 0)
	{
		buf->front--;
		buf->gap++;
	}
}

void gapbuf_move(gapbuf_t *buf, int32_t distance)
{
	uint32_t len;
	char *dest;
	char *source;

	if (distance < 0)
	{
		len = -distance;
		if (len > buf->front)
			len = buf->front;

		dest = buf->data + buf->front + buf->gap - len;
		source = buf->data + buf->front - len;
	}
	else
	{
		uint32_t back = buf->total - buf->front- buf->gap;
		len = distance;
		if (len > back)
			len = back;
		dest = buf->data + buf->front;
		source = buf->data + buf->front + buf->gap;
	}

	memmove(dest, source, len);
}

void gapbuf_backward(gapbuf_t *buf)
{
	if (buf->front > 0)
	{
		buf->data[buf->front + buf->gap -1] = buf->data[buf->front - 1];
		buf->front--;
	}
}

void gapbuf_forward(gapbuf_t *buf)
{
	uint32_t back = buf->total - buf->front - buf->gap;
	if (back > 0)
	{
		buf->data[buf->front] = buf->data[buf->front + buf->gap];
		buf->front++;
	}
}

uint32_t gapbuf_current_line_start(gapbuf_t *buf)
{
	if (buf->front == 0)
		return 0;

	uint32_t it = buf->front - 1;
	while (it > 0 && buf->data[it] != '\n')
		it--;

	return it;
}

void gapbuf_write_all(gapbuf_t *buf, int32_t chan)
{
	sys_chan_write(chan, buf->data, buf->front);
	char *back_start = buf->data + buf->front + buf->gap;
	uint32_t back_len = buf->total - buf->front - buf->gap;
	sys_chan_write(chan, back_start, back_len);
}