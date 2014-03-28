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
#ifndef unco_h
#define unco_h

#include <sys/param.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uncolog_fp {
	int _fd;
	int (*_default_open)(const char *, int, ...);
	char _path[PATH_MAX];
};

void uncolog_init_fp(struct uncolog_fp *ufp);
void uncolog_set_error(struct uncolog_fp *ufp, const char *fmt, ...);

int uncolog_open(struct uncolog_fp *ufp, const char *path, int mode, int (*default_open)(const char *, int, ...), int (*default_mkdir)(const char *, mode_t));
int uncolog_close(struct uncolog_fp *ufp);
int uncolog_get_fd(struct uncolog_fp *ufp);

int uncolog_write_action(struct uncolog_fp *ufp, const char *action, int argc);
int uncolog_write_argn(struct uncolog_fp *ufp, off_t n);
int uncolog_write_argbuf(struct uncolog_fp *ufp, const void *data, size_t len);
int uncolog_write_argfn(struct uncolog_fp *ufp, const char *path);
int uncolog_get_linkname(struct uncolog_fp *ufp, char *link);

int uncolog_read_action(struct uncolog_fp *ufp, char *action, int *argc);
int uncolog_read_argn(struct uncolog_fp *ufp, off_t *n);
void *uncolog_read_argbuf(struct uncolog_fp *ufp, size_t *sz);

int uncolog_delete(const char *path, int force);

ssize_t unco_read_nosig(int fd, void *data, size_t len);
int unco_full_write(int fd, const void *data, size_t len);
int unco_copyfd(int srcfd, int dstfd);
int unco_utimes(int fd, const struct stat *st, int (*futimes)(int, const struct timeval times[2]));

int unco_get_default_dir(char *dir);
long long unco_get_next_logindex(const char *dir);

#ifdef __cplusplus
}
#endif

#endif
