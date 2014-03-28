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
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <crt_externs.h>
#include "unco.h"

static int (*default_open)(const char *path, int oflag, ...);
static int (*default_mkdir)(const char *path, mode_t mode);
static int (*default_futimes)(int fildes, const struct timeval times[2]);

static int _log_is_open = 0;
static struct uncolog_fp _log_fp;

static void init_defaults()
{
	if (default_open != NULL)
		return;

	default_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
	default_mkdir = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "mkdir");
	default_futimes = (int (*)(int, const struct timeval[2]))dlsym(RTLD_NEXT, "futimes");
}

static void log_meta(struct uncolog_fp *ufp)
{
	char cmdbuf[4096], **argv, cwd[PATH_MAX];
	int i, argc;

	uncolog_write_action(ufp, "meta", 4);

	// log argv
	argc = *_NSGetArgc();
	argv = *_NSGetArgv();
	cmdbuf[0] = '\0';
	for (i = 0; i != argc; ++i)
		snprintf(cmdbuf + strlen(cmdbuf), sizeof(cmdbuf) - strlen(cmdbuf),
		i == 0 ? "%s" : " %s",
		argv[i]);
	uncolog_write_argbuf(ufp, cmdbuf, strlen(cmdbuf));

	// log cwd
	getcwd(cwd, sizeof(cwd));
	uncolog_write_argbuf(ufp, cwd, strlen(cwd));

	// log pid
	uncolog_write_argn(ufp, getpid());

	// log ppid
	uncolog_write_argn(ufp, getppid());
}

static struct uncolog_fp *log_fp()
{
	char *logfn, *env, dir[PATH_MAX], fnbuf[PATH_MAX];
	long long log_index;

	if (_log_is_open)
		return &_log_fp;
	_log_is_open = 1; // always set to true, and the error state is handled within _log_fp

	// determine the filename
	if ((env = getenv("UNCO_LOG")) != NULL) {
		if (env[0] == '/') {
			logfn = env;
		} else {
			if (getcwd(dir, sizeof(dir)) == NULL) {
				perror("unco:could not obtain cwd");
				goto Error;
			}
			snprintf(fnbuf, sizeof(fnbuf), "%s/%s", dir, env);
			logfn = fnbuf;
		}
	} else {
		// default
		if (unco_get_default_dir(dir) != 0)
			goto Error;
		if ((log_index = unco_get_next_logindex(dir)) == -1)
			goto Error;
		snprintf(fnbuf, sizeof(fnbuf), "%s/%lld", dir, log_index);
		logfn = fnbuf;
		// set UNCO_LOG, so that child processes would write to the same file
		setenv("UNCO_LOG", logfn, 1);
	}

	// open
	uncolog_open(&_log_fp, logfn, 'a', default_open, default_mkdir);

	// if it is a new file, set meta (FIXME should do this at __attribute__((constructor)))
	if (uncolog_get_fd(&_log_fp) != -1) {
		if (lseek(uncolog_get_fd(&_log_fp), 0, SEEK_CUR) == 0)
			log_meta(&_log_fp);
	}
	return &_log_fp;
Error:
	uncolog_init_fp(&_log_fp);
	return &_log_fp;
}

static int backup_file(struct uncolog_fp *ufp, int srcfd, const char *srcpath)
{
	struct stat st;
	char linkfn[PATH_MAX];
	int linkfd = -1;

	fstat(srcfd, &st); // TODO need to check error?

	// create backup file
	if (uncolog_get_linkname(ufp, linkfn) != 0)
		goto Error;
	if ((linkfd = default_open(linkfn, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
		fprintf(stderr, "failed to create backup file:%s:%d\n", linkfn, errno);
		goto Error;
	}
	// copy contents
	if (unco_copyfd(srcfd, linkfd) != 0) {
		fprintf(stderr, "failed to backup file:%s:%d\n", srcpath, errno);
		goto Error;
	}

	// copy file attributes that need to be restored on undo: times
	if (unco_utimes(linkfd, &st, default_futimes) != 0) {
		fprintf(stderr, "failed to update times of backup file:%s:%d\n", linkfn, errno);
		goto Error;
	}
	// close linkfd
	close(linkfd);
	linkfd = -1;
	// write log
	if (uncolog_write_argfn(ufp, linkfn) != 0)
		goto Error;

	return 0;
Error:
	if (linkfd != -1)
		close(linkfd);
	return -1;
}

static void before_writeopen(const char *path, int oflag)
{
	int cur_fd;

	if (strncmp(path, "/dev/", 5) == 0)
		return;
	if ((oflag & O_SYMLINK) != 0) {
		uncolog_set_error(log_fp(), "do not know how to handle open(O_SYMLINK) against file:%s\n", path);
		return;
	}

	// open the existing file
	if ((cur_fd = default_open(path, oflag & (O_SYMLINK | O_NOFOLLOW))) == -1) {
		// file does not exist
		uncolog_write_action(log_fp(), "create", 1);
		uncolog_write_argfn(log_fp(), path);
		return;
	}

	// file exists, back it up
	uncolog_write_action(log_fp(), "overwrite", 2);
	uncolog_write_argfn(log_fp(), path);
	backup_file(log_fp(), cur_fd, path);

	close(cur_fd);
}

#define WRAP(Fn, RetType, Args, Body) \
extern RetType Fn Args { \
	static RetType (*orig) Args; \
	if (orig == NULL) { \
		orig = (RetType (*) Args)dlsym(RTLD_NEXT, #Fn); \
		init_defaults(); \
	} \
	Body \
}

WRAP(open, int, (const char *path, int oflag, ...), {
	va_list arg;
	mode_t mode = 0;

	if ((oflag & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC)) != 0) {
		before_writeopen(path, oflag);
	}

	if ((oflag & O_CREAT) != 0) {
		va_start(arg, oflag);
		mode = va_arg(arg, int);
		va_end(arg);
	}
	return orig(path, oflag, mode);
})

WRAP(fopen, FILE*, (const char *path, const char *mode), {
	if (strchr(mode, 'w') != NULL || strchr(mode, 'a') != NULL) {
		before_writeopen(path, 0);
	}
	return orig(path, mode);
})

WRAP(rename, int, (const char *old, const char *new), {
	char backup[PATH_MAX];

	// create backup link
	if (uncolog_get_linkname(log_fp(), backup) == 0) {
		if (link(new, backup) != 0) {
			if (errno != ENOENT)
				uncolog_set_error(log_fp(), "failed to create backup link for file:%s:%d\n", new, errno);
			backup[0] = '\0';
		}
	} else {
		backup[0] = '\0';
	}

	// take the action
	int ret = orig(old, new);

	if (ret == 0) {
		uncolog_write_action(log_fp(), "rename", backup[0] != '\0' ? 3 : 2);
		uncolog_write_argfn(log_fp(), old);
		uncolog_write_argfn(log_fp(), new);
		if (backup[0] != '\0')
			uncolog_write_argfn(log_fp(), backup);
	}
	return ret;
})

WRAP(unlink, int, (const char *path), {
	char backup[PATH_MAX];
	int linkerrno = 0;

	// create backup link
	if (uncolog_get_linkname(log_fp(), backup) == 0) {
		if (link(path, backup) != 0) {
			backup[0] = '\0';
			linkerrno = errno;
		}
	} else {
		backup[0] = '\0';
	}

	// unlink
	int ret = orig(path);

	if (ret == 0) {
		// log the link
		if (backup[0] != '\0') {
			uncolog_write_action(log_fp(), "unlink", 2);
			uncolog_write_argfn(log_fp(), path);
			uncolog_write_argfn(log_fp(), backup);
		} else if (linkerrno != 0) {
			uncolog_set_error(log_fp(), "failed to create link of:%s:%d\n", path, linkerrno);
		}
	} else {
		if (backup[0] != '\0')
			unlink(backup);
	}

	return ret;
})
