/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kazutils.h"

typedef struct _klist_item {
	struct _klist_item *prev;
	struct _klist_item *next;
	char bytes[1];
} _klist_item;

#define _ITEM_HEADER_SIZE (((_klist_item *)NULL)->bytes - (const char*)NULL)
#define _BODY_TO_ITEM(p) ((_klist_item *)((const char *)(p) - _ITEM_HEADER_SIZE))

void klist_clear(klist *l)
{
	_klist_item *item, *tmp;

	if ((item = l->_head) != NULL) {
		l->count = 0;
		do {
			tmp = item->next == l->_head ? NULL : item->next;
			if (l->destroy_item != NULL)
				l->destroy_item(item->bytes);
			free(item);
		} while ((item = tmp) != NULL);
	}
}

void *klist_next(klist *l, const void *cur)
{
	if (l->_head == NULL) {
		return NULL;
	} else if (cur == NULL) {
		return l->_head->bytes;
	} else {
		_klist_item *item = _BODY_TO_ITEM(cur);
		return item->next == l->_head ? NULL : item->next->bytes;
	}
}

void *klist_prev(klist *l, const void *cur)
{
	if (l->_head == NULL) {
		return NULL;
	} else if (cur == NULL) {
		return l->_head->prev->bytes;
	} else {
		_klist_item *item = _BODY_TO_ITEM(cur);
		return item == l->_head ? NULL : item->prev->bytes;
	}
}

void *klist_insert(klist *l, const void *before_bytes, const void *data, size_t sz)
{
	_klist_item *item, *before;

	if ((item = malloc(_ITEM_HEADER_SIZE + sz)) == NULL)
		return NULL;
	if (data != NULL)
		memcpy(item->bytes, data, sz);
	++l->count;

	if (l->_head != NULL) {
		before = before_bytes != NULL ? _BODY_TO_ITEM(before_bytes) : l->_head;
		if (l->_head == before)
			l->_head = item;
		item->next = before;
		item->prev = before->prev;
		item->next->prev = item;
		item->prev->next = item;
	} else {
		assert(before_bytes == NULL);
		item->next = item->prev = item;
		l->_head = item;
	}
	return item->bytes;
}

char *klist_insert_printf(klist *l, const void *before, const char *fmt, ...)
{
	char smallbuf[256], *ret;
	va_list arg;
	int len;

	// determine the length (as well as fill-in the small buf)
	va_start(arg, fmt);
	len = vsnprintf(smallbuf, sizeof(smallbuf), fmt, arg);
	va_end(arg);
	if (len == -1)
		return NULL;

	// allocate
	if ((ret = klist_insert(l, before, NULL, len + 1)) == NULL)
		return NULL;

	// copy from small buf or reprint
	if (len < sizeof(smallbuf)) {
		memcpy(ret, smallbuf, len + 1);
	} else {
		va_start(arg, fmt);
		vsnprintf(ret, len + 1, fmt, arg);
		va_end(arg);
	}

	return ret;
}

void klist_erase(klist *l, const void *cur)
{
	_klist_item *item = _BODY_TO_ITEM(cur);

	if (l->destroy_item != NULL)
		l->destroy_item(item->bytes);

	--l->count;
	if (item->next == item) {
		assert(l->count == 0);
		assert(l->_head == item);
		l->_head = NULL;
	} else {
		item->prev->next = item->next;
		item->next->prev = item->prev;
		if (l->_head == item)
			l->_head = item->next;
	}
}
