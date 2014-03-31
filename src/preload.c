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
#include "kazutils.h"
#include "unco.h"
#include "config.h"

static int (*default_open)(const char *path, int oflag, ...);
static int (*default_mkdir)(const char *path, mode_t mode);
static int (*default_futimes)(int fildes, const struct timeval times[2]);

static struct uncolog_fp ufp;

static void spawn_finalizer()
{
	int pipe_fds[2];

	if (pipe(pipe_fds) != 0) {
		uncolog_set_error(&ufp, errno, "pipe failed");
		return;
	}
	switch (fork()) {
	case 0: // child proc
		break;
	case -1: // fork failed
		uncolog_set_error(&ufp, errno, "fork failed");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return;
	default: // fork succeeded (and I am the parent)
		close(pipe_fds[0]);
		return;
	}
	// only child proc enters here

	// close files, and change pipe reader to stdin
	dup2(pipe_fds[0], 0);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	uncolog_close(&ufp);

	// unset the preload
	unsetenv("DYLD_INSERT_LIBRARIES");
	unsetenv("DYLD_FORCE_FLAT_NAMESPACE");

	// exec uncolog _finalize
	execl(WITH_BINDIR "/unco", "unco", "_finalize", NULL);
	perror("failed to exec:" WITH_BINDIR "/unco");
	exit(1);
}

static void log_meta(void)
{
	char cmdbuf[4096], **argv, *cwd;
	int i, argc;

	uncolog_write_action(&ufp, "meta", 4);

	// log argv
	argc = *_NSGetArgc();
	argv = *_NSGetArgv();
	cmdbuf[0] = '\0';
	for (i = 0; i != argc; ++i)
		snprintf(cmdbuf + strlen(cmdbuf), sizeof(cmdbuf) - strlen(cmdbuf),
		i == 0 ? "%s" : " %s",
		argv[i]);
	uncolog_write_argbuf(&ufp, cmdbuf, strlen(cmdbuf));

	// log cwd
	cwd = getcwd(NULL, 0);
	uncolog_write_argbuf(&ufp, cwd != NULL ? cwd : "", cwd != NULL ? strlen(cwd): 0);
	free(cwd);

	// log pid
	uncolog_write_argn(&ufp, getpid());

	// log ppid
	uncolog_write_argn(&ufp, getppid());
}

__attribute__((constructor))
extern void _setup_unco_preload()
{
	char *logfn, *env, *dir = NULL, *fnbuf = NULL;
	long long log_index;
	int open_mode;

	// load default handlers
	default_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
	default_mkdir = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "mkdir");
	default_futimes = (int (*)(int, const struct timeval[2]))dlsym(RTLD_NEXT, "futimes");

	// determine the filename
	if ((env = getenv("UNCO_LOG")) != NULL) {
		if (env[0] == '/') {
			logfn = env;
		} else {
			if ((dir = getcwd(NULL, 0)) == NULL) {
				perror("unco:could not obtain cwd");
				goto Error;
			}
			if ((fnbuf = ksprintf("%s/%s", dir, env)) == NULL) {
				perror("unco");
				goto Error;
			}
			logfn = fnbuf;
		}
		open_mode = 'a';
	} else {
		// default
		if ((dir = unco_get_default_dir()) == NULL)
			goto Error;
		if ((log_index = unco_get_next_logindex(dir)) == -1)
			goto Error;
		if ((fnbuf = ksprintf("%s/%lld", dir, log_index)) == NULL) {
			perror("unco");
			goto Error;
		}
		logfn = fnbuf;
		// set UNCO_LOG, so that child processes would write to the same file
		setenv("UNCO_LOG", logfn, 1);
		open_mode = 'w';
	}

	// open the log
	uncolog_open(&ufp, logfn, open_mode, default_open, default_mkdir);

	// setup procedures for a new log
	if (open_mode == 'w' && uncolog_get_fd(&ufp) != -1) {
		log_meta();
		spawn_finalizer();
	}

	free(dir);
	free(fnbuf);
	return;
Error:
	free(dir);
	free(fnbuf);
	uncolog_init_fp(&ufp);
}

static int backup_file(int srcfd, const char *srcpath)
{
	struct stat st;
	char *linkfn;
	int linkfd = -1;

	fstat(srcfd, &st); // TODO need to check error?

	// create backup file
	if ((linkfn = uncolog_get_linkname(&ufp)) == NULL)
		goto Error;
	if ((linkfd = default_open(linkfn, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1) {
		kerr_printf("failed to create backup file:%s", linkfn);
		goto Error;
	}
	// copy contents
	if (kcopyfd(srcfd, linkfd) != 0) {
		kerr_printf("failed to backup file:%s", srcpath);
		goto Error;
	}

	// copy file attributes that need to be restored on undo: times
	if (unco_utimes(linkfd, &st, default_futimes) != 0) {
		kerr_printf("failed to update times of backup file:%s", linkfn);
		goto Error;
	}
	// close linkfd
	close(linkfd);
	linkfd = -1;
	// write log
	if (uncolog_write_argfn(&ufp, linkfn) != 0)
		goto Error;

	return 0;
Error:
	if (linkfd != -1)
		close(linkfd);
	free(linkfn);
	return -1;
}

static void before_writeopen(const char *path, int oflag)
{
	int cur_fd;

	if (strncmp(path, "/dev/", 5) == 0)
		return;
	if ((oflag & O_SYMLINK) != 0) {
		uncolog_set_error(&ufp, 0, "do not know how to handle open(O_SYMLINK) against file:%s", path);
		return;
	}

	// open the existing file
	if ((cur_fd = default_open(path, oflag & (O_SYMLINK | O_NOFOLLOW))) == -1) {
		// file does not exist
		uncolog_write_action(&ufp, "create", 1);
		uncolog_write_argfn(&ufp, path);
		return;
	}

	// file exists, back it up
	uncolog_write_action(&ufp, "overwrite", 2);
	uncolog_write_argfn(&ufp, path);
	backup_file(cur_fd, path);

	close(cur_fd);
}

#define WRAP(Fn, RetType, Args, Body) \
extern RetType Fn Args { \
	static RetType (*orig) Args; \
	if (orig == NULL) { \
		orig = (RetType (*) Args)dlsym(RTLD_NEXT, #Fn); \
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
	char* backup;
	int ret;

	// create backup link
	if ((backup = uncolog_get_linkname(&ufp)) != NULL) {
		if (link(new, backup) != 0) {
			if (errno != ENOENT)
				uncolog_set_error(&ufp, errno, "failed to create backup link for file:%s", new);
			free(backup);
			backup = NULL;
		}
	}

	// take the action
	ret = orig(old, new);

	if (ret == 0) {
		uncolog_write_action(&ufp, "rename", backup[0] != '\0' ? 3 : 2);
		uncolog_write_argfn(&ufp, old);
		uncolog_write_argfn(&ufp, new);
		if (backup != NULL)
			uncolog_write_argfn(&ufp, backup);
	}
	free(backup);
	return ret;
})

WRAP(unlink, int, (const char *path), {
	char *backup;
	int linkerrno = 0;
	int ret;

	// create backup link
	if ((backup = uncolog_get_linkname(&ufp)) != NULL) {
		if (link(path, backup) != 0) {
			free(backup);
			backup = NULL;
			linkerrno = errno;
		}
	}

	// unlink
	ret = orig(path);

	if (ret == 0) {
		// log the link
		if (backup != NULL) {
			uncolog_write_action(&ufp, "unlink", 2);
			uncolog_write_argfn(&ufp, path);
			uncolog_write_argfn(&ufp, backup);
		} else if (linkerrno != 0) {
			uncolog_set_error(&ufp, linkerrno, "failed to create link of:%s", path);
		}
	} else {
		if (backup != NULL)
			unlink(backup);
	}

	free(backup);
	return ret;
})
