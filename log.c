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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include "unco.h"

static int errorclose(struct uncolog_fp *ufp)
{
	if (ufp->_fd != -1) {
		close(ufp->_fd);
		ufp->_fd = -1;
	}
	return -1;
}

static int safewrite(struct uncolog_fp *ufp, const void *data, size_t len)
{
	if (ufp->_fd == -1) {
		return -1;
	}
	if (unco_full_write(ufp->_fd, data, len) != 0) {
		perror("unco:log_write_error");
		return errorclose(ufp);
	}
	return 0;
}

static int read_short_line(struct uncolog_fp *ufp, char *buf, size_t sz)
{
	char *lf;
	ssize_t rlen;

	if (ufp->_fd == -1)
		return -1;

	// read to buffer
	rlen = unco_read_nosig(ufp->_fd, buf, sz - 1);
	if (rlen == -1) {
		perror("unco:failed to read log");
		return errorclose(ufp);
	} else if (rlen == 0) {
		return errorclose(ufp); // eof
	}
	buf[rlen] = '\0';

	// find LF and replace to NIL
	if ((lf = strchr(buf, '\n')) == NULL) {
		fprintf(stderr, "unexpected input:%s\n", buf);
		return errorclose(ufp);
	}
	*lf = '\0';

	// seek to the beginning of next line
	if (lseek(ufp->_fd, lf + 1 - buf - rlen, SEEK_CUR) == -1) {
		perror("unco:seek failed");
		return errorclose(ufp);
	}

	return 0;
}

void uncolog_init_fp(struct uncolog_fp *ufp)
{
	ufp->_fd = -1;
	ufp->_default_open = NULL;
	strcpy(ufp->_path, "/nonexistent");
}

void uncolog_set_error(struct uncolog_fp *ufp, const char *fmt, ...)
{
	va_list arg;
	va_start(arg, fmt);
	if (ufp->_fd != -1) {
		vfprintf(stderr, fmt, arg);
	}
	va_end(arg);

	errorclose(ufp);
}

int uncolog_open(struct uncolog_fp *ufp, const char *path, int mode, int (*default_open)(const char *, int, ...), int (*default_mkdir)(const char *, mode_t))
{
	int oflag = 0, logfd;
	char logfn[PATH_MAX];

	// reset
	uncolog_init_fp(ufp);

	if (strlen(path) >= PATH_MAX - 20) {
		fprintf(stderr, "unco:given path is too long:%s\n", path);
		return -1;
	}

	// setup oflag
	switch (mode) {
/* "w" is intentionally disabled, since more than one process (i.e. forked processes) might write to the same log
	case 'w':
		oflag = O_CREAT | O_WRONLY;
		break;
*/
	case 'a':
		oflag = O_CREAT | O_WRONLY | O_APPEND;
		break;
	case 'r':
		oflag = O_RDONLY;
		break;
	default:
		assert(!"unknown mode");
	}

	// create dir if necessary
	if ((oflag & O_WRONLY) != 0) {
		if (default_mkdir(path, 0700) == 0 || errno == EEXIST) {
			// ok
		} else {
			fprintf(stderr, "unco:failed create dir:%s:%d\n", path, errno);
			return -1;
		}
	}
	// open file
	snprintf(logfn, sizeof(logfn), "%s/log", path);
	if ((logfd = default_open(logfn, oflag, 0600)) == -1) {
		fprintf(stderr, "unco:failed to open file:%s:%d\n", logfn, errno);
		if ((oflag & O_WRONLY) != 0)
			rmdir(path);
		return -1;
	}

	// success, setup ufp
	ufp->_fd = logfd;
	ufp->_default_open = default_open;
	strcpy(ufp->_path, path);

	return 0;
}

int uncolog_close(struct uncolog_fp *ufp)
{
	if (ufp->_fd != -1)
		return 0;

	close(ufp->_fd);
	ufp->_fd = -1;
	return 0;
}

int uncolog_write_action(struct uncolog_fp *ufp, const char *action, int argc)
{
	char buf[32];

	if (safewrite(ufp, action, strlen(action)) != 0)
		return -1;
	snprintf(buf, sizeof(buf), ":%d\n", argc);
	if (safewrite(ufp, buf, strlen(buf)) != 0)
		return -1;
	return 0;
}

int uncolog_read_action(struct uncolog_fp *ufp, char *action, int *argc)
{
	char buf[256], *colon;

	if (read_short_line(ufp, buf, sizeof(buf)) != 0)
		return -1;
	if ((colon = strchr(buf, ':')) == NULL
		|| sscanf(colon + 1, "%d", argc) != 1) {
		fprintf(stderr, "unexpected log line:%s\n", buf);
		return errorclose(ufp);
	}
	*colon = '\0';
	strcpy(action, buf);
	return 0;
}

int uncolog_write_argn(struct uncolog_fp *ufp, off_t n)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%lld\n", n);
	return safewrite(ufp, buf, strlen(buf));
}

int uncolog_read_argn(struct uncolog_fp *ufp, off_t *n)
{
	char buf[256];

	if (read_short_line(ufp, buf, sizeof(buf)) != 0)
		return -1;
	if (sscanf(buf, "%lld", n) != 1) {
		fprintf(stderr, "unexpected log line:%s\n", buf);
		return errorclose(ufp);
	}
	return 0;
}

int uncolog_write_argbuf(struct uncolog_fp *ufp, const void *data, size_t len)
{
	if (uncolog_write_argn(ufp, len) != 0
		|| safewrite(ufp, data ,len) != 0
		|| safewrite(ufp, "\n", 1) != 0)
		return -1;
	return 0;
}

void *uncolog_read_argbuf(struct uncolog_fp *ufp, size_t *outlen)
{
	off_t off, len;
	char *buf = NULL;
	ssize_t rlen;

	// read length
	if (uncolog_read_argn(ufp, &len) != 0)
		return NULL;

	// allocate
	if ((buf = (char *)malloc(len + 1)) == NULL) {
		perror("no memory");
		goto Error;
	}
	// set length
	if (outlen != NULL)
		*outlen = len;
	// read data (len + 1 bytes)
	for (off = 0; off != len + 1;) {
		rlen = unco_read_nosig(ufp->_fd, buf + off, len + 1 - off);
		if (rlen == -1) {
			perror("unco:failed to read log");
			goto Error;
		} else if (rlen == 0) {
			fprintf(stderr, "unco:unexpected EOF\n");
			goto Error;
		}
		off += rlen;
	}
	if (buf[len] != '\n') {
		fprintf(stderr, "unco:expected LF but got %c\n", buf[len]);
		goto Error;
	}
	buf[len] = '\0';

	return buf;

Error:
	errorclose(ufp);
	free(buf);
	buf = NULL;
	return NULL;
}

int uncolog_write_argfn(struct uncolog_fp *ufp, const char *path)
{
	char cwd[PATH_MAX], abspath[PATH_MAX * 2];

	if (ufp->_fd == -1)
		return -1;

	/* change path to absolute
	 * Cannot use realpath since it resolves symlinks, since the function needs
	 * to support non-existent filenames.  Also, patterns like "foo/.." should
	 * be preserved since it might not point back if foo is a symlink.
	 */
	if (path[0] != '/') {
		getcwd(cwd, sizeof(cwd));
		if (strlen(cwd) + 1 + strlen(path) > sizeof(abspath) - 1) {
			fprintf(stderr, "unco:given path is too long:%s/%s\n", cwd, path);
		}
		sprintf(abspath, "%s/%s", cwd, path);
		path = abspath;
	}

	return uncolog_write_argbuf(ufp, path, strlen(path));
}

int uncolog_get_linkname(struct uncolog_fp *ufp, char *link)
{
	unsigned id;
	struct stat st;

	if (ufp->_fd == -1)
		return -1;

	for (id = 0; ; ++id) {
		snprintf(link, PATH_MAX, "%s/l%08x", ufp->_path, id);
		if (stat(link, &st) != 0)
			return 0;
	}
}

int uncolog_delete(const char *path, int force)
{
	DIR *dp;
	struct dirent *ent;
	char fnbuf[PATH_MAX];
	int ret = -1;

	if ((dp = opendir(path)) == NULL) {
		if (force)
			ret = 0;
		else
			fprintf(stderr, "unco:could not find unco log at:%s:%d\n", path, errno);
		goto Exit;
	}
	while ((ent = readdir(dp)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0
			|| strcmp(ent->d_name, "..") == 0) {
			// skip
		} else {
			snprintf(fnbuf, sizeof(fnbuf), "%s/%s", path, ent->d_name);
			if (unlink(fnbuf) != 0) {
				fprintf(stderr, "unco:failed to unlink file:%s:%d\n", fnbuf, errno);
				goto Exit;
			}
		}
	}

	ret = 0;
Exit:
	if (dp != NULL)
		closedir(dp);
	return ret;
}
