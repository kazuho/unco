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
#include "kazutils.h"
#include "unco.h"

int unco_utimes(int fd, const struct stat *st, int (*futimes)(int, const struct timeval times[2]))
{
	struct timeval times[2];

	times[0].tv_sec = st->st_atime;
	times[0].tv_usec = 0;
	times[1].tv_sec = st->st_mtime;
	times[1].tv_usec = 0;
	return futimes(fd, times);
}

char *unco_get_default_dir()
{
	char *home, *dir;

	if ((dir = getenv("UNCO_HOME")) != NULL) {
		// got it
		if ((dir = strdup(dir)) == NULL) {
			perror("unco");
			return NULL;
		}
	} else {
		// $HOME/.unco
		if ((home = getenv("HOME")) == NULL) {
			fprintf(stderr, "unco:$HOME is not set\n");
			return NULL;
		}
		if ((dir = ksprintf("%s/.unco", home)) == NULL) {
			perror("unco");
			return NULL;
		}
	}

	// mkdir
	if (mkdir(dir, 0700) == 0 || errno == EEXIST) {
		// ok
	} else {
		kerr_printf("failed to create dir:%s", dir);
		free(dir);
		return NULL;
	}
	return dir;
}

static int _log_exists(const char *dir, long long log_index, int *exists)
{
	struct stat st;
	char *path;
	int ret = -1;

	if ((path = ksprintf("%s/%lld", dir, log_index)) == NULL) {
		perror("unco");
		return -1;
	}

	if (lstat(path, &st) == 0) {
		*exists = 1;
	} else if (errno == ENOENT) {
		*exists = 0;
	} else {
		kerr_printf("failed to stat file:%s", path);
		goto Exit;
	}

	ret = 0;
Exit:
	free(path);
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
