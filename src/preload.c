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
static int (*default_link)(const char *path1, const char *path2);
static int (*default_symlink)(const char *path1, const char *path2);
static int (*default_unlink)(const char *path);
static int (*default_rmdir)(const char *path);
static int (*default_chown)(const char *path, uid_t owner, gid_t group);

static struct uncolog_fp ufp;

static int is_symlink(const char *path)
{
	struct stat st;
	if (lstat(path, &st) != 0)
		return 0;
	return (st.st_mode & S_IFMT) == S_IFLNK;
}

static char *strip_trailing_slashes(const char *path)
{
	char *ret;
	size_t len = strlen(path);

	if ((ret = malloc(len + 1)) == NULL)
		return NULL;
	memcpy(ret, path, len);
	while (len != 0 && ret[len - 1] == '/')
		--len;
	ret[len] = '\0';

	return ret;
}

static void spawn_finalizer()
{
	int pipe_fds[2];

	if (pipe(pipe_fds) != 0) {
		uncolog_set_error(&ufp, errno, "unco:pipe failed");
		return;
	}
	switch (fork()) {
	case 0: // child proc
		break;
	case -1: // fork failed
		uncolog_set_error(&ufp, errno, "unco:fork failed");
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

static int set_uncolog_osx(const char *logfn)
{
	// we need to rewrite an existing entry of environ
	char **env = *_NSGetEnviron();
	size_t n;

	if (strlen(logfn) >= UNCO_LOG_PATH_MAX) {
		fprintf(stderr, "log file name is too long:%s\n", logfn);
		return -1;
	}

	// find and replace
	for (n = 0; env[n] != NULL; ++n) {
		if (strncmp(env[n], "UNCO_LOG_PLACEHOLDER=", sizeof("UNCO_LOG_PLACEHOLDER=") - 1) == 0)
			break;
	}
	if (env[n] == NULL) {
		fprintf(stderr, "env var UNCO_LOG_PLACEHOLDER not set\n");
		return -1;
	}
	snprintf(env[n], strlen(env[n]) + 1, "UNCO_LOG=%s", logfn);

	return 0;
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
	default_link = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "link");
	default_symlink = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "symlink");
	default_unlink = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
	default_rmdir = (int (*)(const char *))dlsym(RTLD_NEXT, "rmdir");
	default_chown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");

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
		if ((dir = unco_get_default_dir(default_mkdir)) == NULL)
			goto Error;
		if ((log_index = unco_get_next_logindex(dir)) == -1)
			goto Error;
		if ((fnbuf = ksprintf("%s/%lld", dir, log_index)) == NULL) {
			perror("unco");
			goto Error;
		}
		logfn = fnbuf;
		// set UNCO_LOG, so that child processes would write to the same file
#if 1
		if (set_uncolog_osx(logfn) != 0)
			goto Error;
#else
		setenv("UNCO_LOG", logfn, 1);
#endif
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

static char *backup_as_link(const char *path)
{
	char *backup;
	char symlinkbuf[PATH_MAX];
	ssize_t symlinklen;
	int success = 0;

	if ((backup = uncolog_get_linkname(&ufp)) == NULL)
		return NULL;

	if (is_symlink(path)) {
		if ((symlinklen = readlink(path, symlinkbuf, sizeof(symlinkbuf) - 1)) == -1)
			goto Exit;
		symlinkbuf[symlinklen] = '\0';
		if (default_symlink(symlinkbuf, backup) != 0)
			goto Exit;
	} else {
		if (default_link(path, backup) != 0)
			goto Exit;
	}

	success = 1;
Exit:
	if (! success) {
		free(backup);
		backup = NULL;
	}
	return backup;
}

static char *backup_as_dir(const char *path, int *errnum)
{
	char *backup;
	struct stat st;
	int success = 0;

	if (lstat(path, &st) != 0) {
		*errnum = errno;
		return NULL;
	}

	if ((backup = uncolog_get_linkname(&ufp)) == NULL)
		return NULL;
	if (default_mkdir(backup, st.st_mode & ~S_IFMT) != 0
		|| default_chown(backup, st.st_uid, st.st_gid) != 0)
		goto Exit;

	success = 1;
Exit:
	if (! success) {
		free(backup);
		backup = NULL;
	}
	return backup;
}

static char *before_writeopen(const char *path, int *errnum)
{
	char *backup = NULL;
	int srcfd = -1, dstfd = -1, success = 0;
	struct stat st;

	// FIXME better blacklisting
	if (strncmp(path, "/dev/", 5) == 0) {
		*errnum = 0;
		return NULL;
	}

	// open source
	if ((srcfd = default_open(path, O_RDONLY)) == -1) {
		*errnum = errno;
		goto Exit;
	}
	fstat(srcfd, &st); // TODO need to check error?

	// create backup and copy, update the times, and return
	if ((backup = uncolog_get_linkname(&ufp)) == NULL)
		return NULL;
	if ((dstfd = default_open(backup, O_WRONLY | O_CREAT | O_EXCL)) == -1) {
		*errnum = errno;
		goto Exit;
	}
	if (kcopyfd(srcfd, dstfd) != 0) {
		*errnum = errno;
		goto Exit;
	}
	if (unco_utimes(dstfd, &st, default_futimes) != 0) {
		*errnum = errno;
		goto Exit;
	}

	success = 1;
Exit:
	if (! success) {
		if (srcfd != -1)
			close(srcfd);
		free(backup);
		if (dstfd != -1)
			close(dstfd);
	}
	return backup;
}

static void on_writeopen_success(const char *path, char *backup, int backup_errno)
{
	if (backup != NULL) {
		uncolog_write_action(&ufp, "overwrite", 2);
		uncolog_write_argfn(&ufp, path, 1);
		uncolog_write_argfn(&ufp, backup, 0);
		free(backup);
	} else if (backup_errno == ENOENT) {
		uncolog_write_action(&ufp, "create", 1);
		uncolog_write_argfn(&ufp, path, 1);
	} else if (backup_errno != 0) {
		uncolog_set_error(&ufp, backup_errno, "failed to create backup of file:%s", path);
	}
}

#define WRAP(Fn, RetType, Args, Body) \
extern RetType Fn Args { \
	static RetType (*orig) Args; \
	if (orig == NULL) { \
		orig = (RetType (*) Args)dlsym(RTLD_NEXT, #Fn); \
	} \
	do { \
		Body \
	} while (0); \
}

WRAP(open, int, (const char *path, int oflag, ...), {
	va_list arg;
	char *backup = NULL;
	int is_write;
	int backup_errno;
	int ret;
	mode_t mode = 0;

	is_write = (oflag & (O_WRONLY | O_RDWR)) != 0;

	if (is_write) {
		if ((oflag & (O_NOFOLLOW | O_SYMLINK)) != 0) {
			uncolog_set_error(&ufp, 0, "unco:open:cannot handle open with O_NOFOLLOW|O_SYMLINK against file:%s", path);
			backup_errno = 0;
		} else {
			backup = before_writeopen(path, &backup_errno);
		}
	}

	if ((oflag & O_CREAT) != 0) {
		va_start(arg, oflag);
		mode = va_arg(arg, int);
		va_end(arg);
	}
	ret = orig(path, oflag, mode);

	if (ret != -1 && is_write)
		on_writeopen_success(path, backup, backup_errno);

	return ret;
})

WRAP(fopen, FILE*, (const char *path, const char *mode), {
	char *backup = NULL;
	int is_write;
	int backup_errno;
	FILE *ret;

	is_write = strchr(mode, 'w') != NULL || strchr(mode, 'a') != NULL;

	if (is_write)
		backup = before_writeopen(path, &backup_errno);

	ret = orig(path, mode);

	if (ret != NULL && is_write)
		on_writeopen_success(path, backup, backup_errno);

	return ret;
})

WRAP(rename, int, (const char *old, const char *new), {
	char* backup;
	int ret;

	// create backup link
	if ((backup = backup_as_link(new)) == NULL) {
		if (! (errno == ENOENT || errno == ENOTDIR))
			uncolog_set_error(&ufp, errno, "unco:rename:failed to create backup link for file:%s", new);
	}

	// take the action
	ret = orig(old, new);

	if (ret == 0) {
		uncolog_write_action(&ufp, "rename", backup != NULL ? 3 : 2);
		uncolog_write_argfn(&ufp, old, 0);
		uncolog_write_argfn(&ufp, new, 0);
		if (backup != NULL)
			uncolog_write_argfn(&ufp, backup, 0);
	}
	free(backup);
	return ret;
})

WRAP(unlink, int, (const char *path), {
	char *backup;
	int backup_errno = 0;
	int ret;

	// create backup link
	if ((backup = backup_as_link(path)) == NULL)
		backup_errno = errno;

	// unlink
	ret = orig(path);

	if (ret == 0) {
		// log the link
		if (backup != NULL) {
			uncolog_write_action(&ufp, "unlink", 2);
			uncolog_write_argfn(&ufp, path, 0);
			uncolog_write_argfn(&ufp, backup, 0);
		} else if (backup_errno != 0) {
			uncolog_set_error(&ufp, backup_errno, "unco:unlink:failed to create backup link of:%s", path);
		}
	} else {
		if (backup != NULL)
			default_unlink(backup);
	}

	free(backup);
	return ret;
})

WRAP(link, int, (const char *path1, const char *path2), {
	int ret = orig(path1, path2);
	if (ret == 0) {
		// log the action
		uncolog_write_action(&ufp, "link", 2);
		uncolog_write_argfn(&ufp, path1, 1);
		uncolog_write_argfn(&ufp, path2, 1);
	}
	return ret;
})

WRAP(symlink, int, (const char *path1, const char*path2), {
	int ret = orig(path1, path2);
	if (ret == 0) {
		uncolog_write_action(&ufp, "symlink", 1);
		uncolog_write_argfn(&ufp, path2, 0); // we only need the affected fn
	}
	return ret;
})

WRAP(mkstemp, int, (char *template), {
	int ret;

	ret = orig(template);

	if (ret != -1) {
		uncolog_write_action(&ufp, "create", 1);
		uncolog_write_argfn(&ufp, template, 1);
	}
	return ret;
})

WRAP(mkdir, int, (const char *path, mode_t mode), {
	int ret;
	char *path_normalized;

	ret = orig(path, mode);

	if (ret == 0) {
		uncolog_write_action(&ufp, "mkdir", 1);
		if ((path_normalized = strip_trailing_slashes(path)) != NULL) {
			uncolog_write_argfn(&ufp, path_normalized, 0);
			free(path_normalized);
		} else {
			uncolog_set_error(&ufp, errno, "unco");
		}
	}
	return ret;
})

WRAP(rmdir, int, (const char *path), {
	char *path_normalized;
	char *backup;
	int ret;
	int backup_errno;

	if ((path_normalized = strip_trailing_slashes(path)) == NULL) {
		uncolog_set_error(&ufp, errno, "unco");
		return orig(path);
	}
	backup = backup_as_dir(path, &backup_errno);

	ret = orig(path);

	if (ret == 0) {
		if (backup != NULL) {
			uncolog_write_action(&ufp, "rmdir", 2);
			uncolog_write_argfn(&ufp, path_normalized, 0);
			uncolog_write_argfn(&ufp, backup, 1);
		} else {
			uncolog_set_error(&ufp, backup_errno, "unco:failed to create backup file of:%s", path_normalized);
		}
	} else {
		if (backup != NULL)
			default_rmdir(backup);
	}

	free(path_normalized);
	free(backup);
	return ret;
})

WRAP(chmod, int, (const char *path, mode_t mode), {
	struct stat st;
	int ret;
	int stat_errno = 0;

	if (stat(path, &st) != 0)
		stat_errno = errno;

	ret = orig(path, mode);

	if (ret == 0) {
		uncolog_write_action(&ufp, "chmod", 2);
		uncolog_write_argfn(&ufp, path, 1);
		uncolog_write_argn(&ufp, st.st_mode & ~S_IFMT);
	} else {
		uncolog_set_error(&ufp, stat_errno, "failed to stat file:%s", path);
	}

	return ret;
})

WRAP(fchmod, int, (int filedes, mode_t mode), {
	struct stat st;
	int ret;
	int stat_errno = 0;

	if (fstat(filedes, &st) != 0)
		stat_errno = errno;

	ret = orig(filedes, mode);

	if (ret == 0) {
		uncolog_write_action(&ufp, "chmod", 2);
		uncolog_write_argfd(&ufp, filedes);
		uncolog_write_argn(&ufp, st.st_mode & ~S_IFMT);
	} else {
		uncolog_set_error(&ufp, stat_errno, "failed to stat file descriptor:%d", filedes);
	}

	return ret;
})

WRAP(chown, int, (const char *path, uid_t owner, gid_t group), {
	struct stat st;
	int ret;
	int stat_errno = 0;

	if (stat(path, &st) != 0)
		stat_errno = errno;

	ret = orig(path, owner, group);

	if (ret == 0) {
		uncolog_write_action(&ufp, "lchown", 3);
		uncolog_write_argfn(&ufp, path, 1);
		uncolog_write_argn(&ufp, st.st_uid);
		uncolog_write_argn(&ufp, st.st_gid);
	} else {
		uncolog_set_error(&ufp, stat_errno, "failed to stat file:%s", path);
	}

	return ret;
})

WRAP(lchown, int, (const char *path, uid_t owner, gid_t group), {
	struct stat st;
	int ret;
	int stat_errno = 0;

	if (lstat(path, &st) != 0)
		stat_errno = errno;

	ret = orig(path, owner, group);

	if (ret == 0) {
		uncolog_write_action(&ufp, "lchown", 3);
		uncolog_write_argfn(&ufp, path, 0);
		uncolog_write_argn(&ufp, st.st_uid);
		uncolog_write_argn(&ufp, st.st_gid);
	} else {
		uncolog_set_error(&ufp, stat_errno, "failed to stat file:%s", path);
	}

	return ret;
})

WRAP(fchown, int, (int filedes, uid_t owner, gid_t group), {
	struct stat st;
	int ret;
	int stat_errno = 0;

	if (fstat(filedes, &st) != 0)
		stat_errno = errno;

	ret = orig(filedes, owner, group);

	if (ret == 0) {
		uncolog_write_action(&ufp, "lchown", 3);
		uncolog_write_argfd(&ufp, filedes);
		uncolog_write_argn(&ufp, st.st_uid);
		uncolog_write_argn(&ufp, st.st_gid);
	} else {
		uncolog_set_error(&ufp, stat_errno, "failed to stat file descriptor:%d", filedes);
	}

	return ret;
})
