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
#ifndef kazutils_h
#define kazutils_h

#ifdef __cplusplus
extern "C" {
#endif

typedef struct klist {
	struct _klist_item *_head;
	size_t count;
	void (*destroy_item)(void *item);
} klist;

void klist_clear(klist *l);
void *klist_next(klist *l, const void *cur);
void *klist_prev(klist *l, const void *cur);
void *klist_insert(klist *l, const void *before, const void *data, size_t sz);
char *klist_insert_printf(klist *l, const void *before, const char *fmt, ...);
void klist_erase(klist *l, const void *cur);

typedef struct kstrbuf {
	char *str;
	size_t len;
	size_t capacity;
} kstrbuf;

void kstrbuf_clear(kstrbuf *sbuf);
char *kstrbuf_append_str(kstrbuf *sbuf, const char *str);
char *kstrbuf_append_char(kstrbuf *sbuf, int ch);

char *ksprintf(const char *fmt, ...);
char *kshellquote(const char *raw);
char *kdirname(const char *path);

ssize_t kread_nosig(int fd, void *data, size_t len);
void *kread_full(int fd, size_t *len);
int kwrite_full(int fd, const void *data, size_t len);
int kcopyfd(int srcfd, int dstfd);
int kunlink_recursive(const char *path);

#define KFREE_PTRS_INIT(n) \
	void *_kfree_ptrs[n]; \
	int _kfree_ptr_index = 0
#define KFREE_PTRS() \
	do { \
		if (_kfree_ptr_index != 0) \
			do \
				free(_kfree_ptrs[--_kfree_ptr_index]); \
			while (_kfree_ptr_index != 0); \
	} while (0)
#define KFREE_PTRS_PUSH(p) (_kfree_ptrs[_kfree_ptr_index++] = (p))

#define kerr_printf(fmt, ...) (fprintf(stderr, fmt, __VA_ARGS__), perror(""))

#ifdef __cplusplus
}
#endif

#endif
