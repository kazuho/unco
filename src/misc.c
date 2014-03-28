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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "unco.h"

ssize_t unco_read_nosig(int fd, void *data, size_t len)
{
	ssize_t ret;
	while ((ret = read(fd, data, len)) == -1
		&& (errno == EAGAIN || errno == EWOULDBLOCK))
		;
	return ret;
}

int unco_full_write(int fd, const void *data, size_t len)
{
	ssize_t wret;
	size_t off = 0, chunksz;

	while (off != len) {
		chunksz = len - off;
		if (chunksz >= 10485760)
			chunksz = 10485760;
		wret = write(fd, (const char*)data + off, chunksz);
		if (wret == -1) {
			if (! (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return -1;
			}
		} else {
			off += wret;
		}
	}

	return 0;
}

int unco_copyfd(int srcfd, int dstfd)
{
	char buf[4096];
	ssize_t rret;

	while ((rret = unco_read_nosig(srcfd, buf, sizeof(buf))) > 0) {
		if (unco_full_write(dstfd, buf, rret) != 0)
			return -1;
	}

	return rret;
}

int unco_utimes(int fd, const struct stat *st, int (*futimes)(int, const struct timeval times[2]))
{
	struct timeval times[2];

	times[0].tv_sec = st->st_atime;
	times[0].tv_usec = 0;
	times[1].tv_sec = st->st_mtime;
	times[1].tv_usec = 0;
	return futimes(fd, times);
}

int unco_get_default_dir(char *dir)
{
	char *env;

	// $HOME/.unco
	if ((env = getenv("HOME")) == NULL) {
		fprintf(stderr, "unco:$HOME is not set\n");
		return -1;
	}
	snprintf(dir, PATH_MAX, "%s/.unco", env);

	// mkdir
	if (mkdir(dir, 0700) == 0 || errno == EEXIST) {
		// ok
	} else {
		fprintf(stderr, "failed to create dir:%s:%d\n", dir, errno);
		return -1;
	}
	return 0;
}

static int _log_exists(const char *dir, long long log_index, int *exists)
{
	struct stat st;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%lld", dir, log_index);

	if (lstat(path, &st) == 0) {
		*exists = 1;
	} else if (errno == ENOENT) {
		*exists = 0;
	} else {
		fprintf(stderr, "failed to stat file:%s:%d\n", path, errno);
		return -1;
	}

	return 0;
}

long long unco_get_next_logindex(const char *dir)
{
	long long min, max, mid;
	int exists;

	// index starts from 1; search using Elias encoding (i.e. search at 1,2,4,8,16,... and then perform binary search)
	for (max = 1; ; max *= 2) {
		if (_log_exists(dir, max, &exists) != 0)
			goto Error;
		if (! exists)
			break;
	}
	// binary search within [min, max)
	min = max / 2 + 1;
	while (min != max) {
		mid = (min + max) / 2;
		if (_log_exists(dir, mid, &exists) != 0)
			goto Error;
		if (exists)
			min = mid + 1;
		else
			max = mid;
	}
	return min;

Error:
	return -1;
}

struct _uncolist_item {
	struct _uncolist_item *prev;
	struct _uncolist_item *next;
	char bytes[1];
};

#define _ITEM_HEADER_SIZE (((struct _uncolist_item *)NULL)->bytes - (const char*)NULL)
#define _BODY_TO_ITEM(p) ((struct _uncolist_item *)((const char *)(p) - _ITEM_HEADER_SIZE))

void uncolist_clear(struct uncolist *l)
{
	struct _uncolist_item *item, *tmp;

	if ((item = l->_head) != NULL) {
		do {
			tmp = item->next == l->_head ? NULL : item->next;
			if (l->destroy_item != NULL)
				l->destroy_item(item->bytes);
			free(item);
		} while ((item = tmp) != NULL);
	}
}

void *uncolist_next(struct uncolist *l, const void *cur)
{
	if (l->_head == NULL) {
		return NULL;
	} else if (cur == NULL) {
		return l->_head->bytes;
	} else {
		struct _uncolist_item *item = _BODY_TO_ITEM(cur);
		return item->next == l->_head ? NULL : item->next->bytes;
	}
}

void *uncolist_prev(struct uncolist *l, const void *cur)
{
	if (l->_head == NULL) {
		return NULL;
	} else if (cur == NULL) {
		return l->_head->prev->bytes;
	} else {
		struct _uncolist_item *item = _BODY_TO_ITEM(cur);
		return item == l->_head ? NULL : item->prev->bytes;
	}
}

void *uncolist_insert(struct uncolist *l, const void *before_bytes, const void *data, size_t sz)
{
	struct _uncolist_item *item, *before;

	if ((item = malloc(_ITEM_HEADER_SIZE + sz)) == NULL)
		return NULL;
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

void uncolist_erase(struct uncolist *l, const void *cur)
{
	struct _uncolist_item *item = _BODY_TO_ITEM(cur);

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
