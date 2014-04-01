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
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kazutils.h"

ssize_t kread_nosig(int fd, void *data, size_t len)
{
	ssize_t ret;
	while ((ret = read(fd, data, len)) == -1
		&& (errno == EAGAIN || errno == EWOULDBLOCK))
		;
	return ret;
}

void *kread_full(int fd, size_t *len)
{
	char *bytes, *tmp;
	size_t bufsz = 4096, offset = 0;
	ssize_t rret;

	if ((bytes = malloc(bufsz)) == NULL)
		return NULL;

	while ((rret = kread_nosig(fd, bytes + offset, bufsz - offset)) != 0) {
		if (rret == -1)
			goto Exit;
		offset += rret;
		if (offset == bufsz) {
			bufsz *= 2;
			if ((tmp = realloc(bytes, bufsz)) == NULL)
				goto Exit;
			bytes = tmp;
		}
	}

Exit:
	if (rret == 0) {
		*len = offset;
	} else {
		free(bytes);
		bytes = NULL;
	}
	return bytes;
}

int kwrite_full(int fd, const void *data, size_t len)
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

int kcopyfd(int srcfd, int dstfd)
{
	char buf[4096];
	ssize_t rret;

	while ((rret = kread_nosig(srcfd, buf, sizeof(buf))) > 0) {
		if (kwrite_full(dstfd, buf, rret) != 0)
			return -1;
	}

	return rret;
}

int kunlink_recursive(const char *path)
{
	struct stat st;
	DIR *dp;
	struct dirent *ent, entbuf;
	char *fnbuf = NULL;
	int ret = -1;

	if (lstat(path, &st) != 0)
		return -1;
	if ((st.st_mode & S_IFMT) != S_IFDIR)
		return unlink(path);

	// rm -rf
	if ((dp = opendir(path)) == NULL)
		return -1;
	while (readdir_r(dp, &entbuf, &ent) == 0 && ent != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
			// skip
		} else {
			if ((fnbuf = ksprintf("%s/%s", path, ent->d_name)) == NULL)
				goto Exit;
			if (kunlink_recursive(fnbuf) != 0)
				goto Exit;
			free(fnbuf);
			fnbuf = NULL;
		}
	}
	closedir(dp);
	dp = NULL;
	if (rmdir(path) != 0)
		goto Exit;

	ret = 0;
Exit:
	if (dp != NULL)
		closedir(dp);
	free(fnbuf);
	return ret;
}
