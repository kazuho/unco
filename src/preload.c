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
#ifdef __linux__
# define _GNU_SOURCE
# define _ATFILE_SOURCE
#endif
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
#ifdef __APPLE__
# include <crt_externs.h>
#endif
#include "kazutils.h"
#include "unco.h"
#include "config.h"

struct backup_info {
	char *backup;
	int errnum;
};

struct attr_info {
	struct stat st;
	int errnum;
};

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
#ifdef __linux__
	unsetenv("LD_PRELOAD");
#elif defined(__APPLE__)
	unsetenv("DYLD_INSERT_LIBRARIES");
	unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
#endif

	// exec uncolog _finalize
	execl(WITH_BINDIR "/unco", "unco", "_finalize", NULL);
	perror("failed to exec:" WITH_BINDIR "/unco");
	exit(1);
}

static void log_meta(void)
{
	char *cwd;

	uncolog_write_action_start(&ufp, "meta", 4);

	// log argv
#ifdef __APPLE__
	do {
		char cmdbuf[4096], **argv;
		int i, argc;
		argc = *_NSGetArgc();
		argv = *_NSGetArgv();
		cmdbuf[0] = '\0';
		for (i = 0; i != argc; ++i)
			snprintf(cmdbuf + strlen(cmdbuf), sizeof(cmdbuf) - strlen(cmdbuf),
			i == 0 ? "%s" : " %s",
			argv[i]);
		uncolog_write_argbuf(&ufp, cmdbuf, strlen(cmdbuf));
	} while (0);
#elif defined(__linux__)
	do {
		int fd;
		char *cmd = NULL;
		size_t cmdlen, i;
		if ((fd = open("/proc/self/cmdline", O_RDONLY)) != -1) {
			cmd = kread_full(fd, &cmdlen);
			close(fd);
		}
		if (cmd != NULL) {
			for (i = 0; i < cmdlen; ++i)
				if (cmd[i] == '\0')
					cmd[i] = ' ';
			uncolog_write_argbuf(&ufp, cmd, cmdlen);
		} else {
			uncolog_write_argbuf(&ufp, "(unknown)", sizeof("(unknown)") - 1);
		}
	} while (0);	
#else
# error "unknown env"
#endif

	// log cwd
	cwd = getcwd(NULL, 0);
	uncolog_write_argbuf(&ufp, cwd != NULL ? cwd : "", cwd != NULL ? strlen(cwd): 0);
	free(cwd);

	// log pid
	uncolog_write_argn(&ufp, getpid());

	// log ppid
	uncolog_write_argn(&ufp, getppid());

	uncolog_write_action_end(&ufp);
}

static int set_uncolog_osx(const char *logfn)
{
	char **env;
	size_t n;

#ifdef __linux__
	env = environ;
#elif defined(__APPLE__)
	env = *_NSGetEnviron();
#else
# error "unknown env"
#endif

	if (strlen(logfn) >= UNCO_LOG_PATH_MAX) {
		fprintf(stderr, "unco:log file name is too long:%s\n", logfn);
		return -1;
	}

	// find and replace
	for (n = 0; env[n] != NULL; ++n) {
		if (strncmp(env[n], "UNCO_LOG_PLACEHOLDER=", sizeof("UNCO_LOG_PLACEHOLDER=") - 1) == 0)
			break;
	}
	if (env[n] == NULL) {
		fprintf(stderr, "unco:env var UNCO_LOG_PLACEHOLDER not set\n");
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
	int dirlock_fd = -1;

	// load default handlers
	default_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
	default_mkdir = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "mkdir");
	default_futimes = (int (*)(int, const struct timeval[2]))dlsym(RTLD_NEXT, "futimes");
	default_link = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "link");
	default_symlink = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "symlink");
	default_unlink = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
	default_rmdir = (int (*)(const char *))dlsym(RTLD_NEXT, "rmdir");
	default_chown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");

	// open the log file
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
		uncolog_open(&ufp, logfn, 'a', default_open, default_mkdir);
	} else {
		// no path given; create a new entry in the default dir
		if ((dir = unco_get_default_dir(default_mkdir)) == NULL)
			goto Error;
		// lock the directory
		if ((fnbuf = ksprintf("%s/lock", dir)) == NULL) {
			perror("unco");
			goto Error;
		}
		if ((dirlock_fd = default_open(fnbuf, O_WRONLY | O_CREAT | O_TRUNC | O_EXLOCK, 0600)) == -1) {
			kerr_printf("failed to open file:%s", fnbuf);
			goto Error;
		}
		free(fnbuf);
		fnbuf = NULL;
		// obtain logindex
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
		// open the log
		uncolog_open(&ufp, logfn, 'w', default_open, default_mkdir);
		// unlock the directory
		close(dirlock_fd);
		dirlock_fd = -1;
		// append meta
		if (uncolog_get_fd(&ufp) != -1) {
			// setup procedures for a new log
			log_meta();
			spawn_finalizer();
		}
	}

	free(dir);
	free(fnbuf);
	return;
Error:
	if (dirlock_fd != -1)
		close(dirlock_fd);
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

static void before_open(const char *path, int oflag, struct backup_info *info)
{
	int srcfd = -1, dstfd = -1, success = 0;
	struct stat st;

	memset(info, 0, sizeof(*info));

	// bail out if not write
	if ((oflag & (O_WRONLY | O_RDWR)) == 0)
		return;
	// FIXME better blacklisting
	if (strncmp(path, "/dev/", 5) == 0)
		return;
	// not implemented
	if ((oflag & O_NOFOLLOW) != 0) {
		uncolog_set_error(&ufp, 0, "unco:unsupported operation: open with O_NOFOLLOW against file:%s", path);
		return;
	}

	// open source
	if ((srcfd = default_open(path, O_RDONLY)) == -1) {
		info->errnum = errno;
		goto Exit;
	}
	fstat(srcfd, &st); // TODO need to check error?

	// create backup and copy, update the times, and return
	if ((info->backup = uncolog_get_linkname(&ufp)) == NULL) {
		// errror reported by caller
		goto Exit;
	}
	if ((dstfd = default_open(info->backup, O_WRONLY | O_CREAT | O_EXCL)) == -1) {
		info->errnum = errno;
		goto Exit;
	}
	if (kcopyfd(srcfd, dstfd) != 0) {
		info->errnum = errno;
		goto Exit;
	}
	if (unco_utimes(dstfd, &st, default_futimes) != 0) {
		info->errnum = errno;
		goto Exit;
	}

	success = 1;
Exit:
	if (! success) {
		if (srcfd != -1)
			close(srcfd);
		free(info->backup);
		info->backup = NULL;
		if (dstfd != -1)
			close(dstfd);
	}
}

static void after_open(int success, const char *path, struct backup_info *info)
{
	if (success) {
		if (info->backup != NULL) {
			uncolog_write_action_start(&ufp, "overwrite", 2);
			uncolog_write_argfn(&ufp, path, 1);
			uncolog_write_argfn(&ufp, info->backup, 0);
			uncolog_write_action_end(&ufp);
		} else if (info->errnum == ENOENT) {
			uncolog_write_action_start(&ufp, "create", 1);
			uncolog_write_argfn(&ufp, path, 1);
			uncolog_write_action_end(&ufp);
		} else if (info->errnum != 0) {
			uncolog_set_error(&ufp, info->errnum, "unco:open:failed to create backup of file:%s", path);
		}
	}
	free(info->backup);
}

static void before_backup1(const char *path, struct backup_info *info)
{
	info->errnum = 0;
	if ((info->backup = backup_as_link(path)) == NULL)
		info->errnum = errno;
}

static void after_rename(int ret, const char *old, const char *new, struct backup_info *info)
{
	if (ret == 0) {
		if (info->backup != NULL) {
			uncolog_write_action_start(&ufp, "rename", 3);
			uncolog_write_argfn(&ufp, old, 0);
			uncolog_write_argfn(&ufp, new, 0);
			uncolog_write_argfn(&ufp, info->backup, 0);
			uncolog_write_action_end(&ufp);
		} else if (info->errnum == ENOENT || info->errnum == ENOTDIR) {
			uncolog_write_action_start(&ufp, "rename", 2);
			uncolog_write_argfn(&ufp, old, 0);
			uncolog_write_argfn(&ufp, new, 0);
			uncolog_write_action_end(&ufp);
		} else {
			uncolog_set_error(&ufp, info->errnum, "unco:rename:failed to create backup link for file:%s", new);
		}
	} else if (info->backup != NULL) {
		default_unlink(info->backup);
	}
	free(info->backup);
}

static void after_unlink(int ret, const char *path, struct backup_info *info)
{
	if (ret == 0) {
		if (info->backup != NULL) {
			uncolog_write_action_start(&ufp, "unlink", 2);
			uncolog_write_argfn(&ufp, path, 0);
			uncolog_write_argfn(&ufp, info->backup, 0);
			uncolog_write_action_end(&ufp);
		} else if (info->errnum != 0) {
			uncolog_set_error(&ufp, info->errnum, "unco:unlink:failed to create backup link of:%s", path);
		}
	} else if (info->backup != NULL) {
		default_unlink(info->backup);
	}
	free(info->backup);
}

static void after_link(int ret, const char *path1, int follow_path1, const char *path2)
{
	if (ret == 0) {
		uncolog_write_action_start(&ufp, "link", 2);
		uncolog_write_argfn(&ufp, path1, follow_path1);
		uncolog_write_argfn(&ufp, path2, 1);
		uncolog_write_action_end(&ufp);
	}
}

static void after_symlink(int ret, const char *path2)
{
	if (ret == 0) {
		uncolog_write_action_start(&ufp, "symlink", 1);
		uncolog_write_argfn(&ufp, path2, 0); // we only need the affected fn
		uncolog_write_action_end(&ufp);
	}
}

static void after_mkdir(int success, const char *path)
{
	char *path_normalized;

	if (success) {
		if ((path_normalized = strip_trailing_slashes(path)) != NULL) {
			uncolog_write_action_start(&ufp, "mkdir", 1);
			uncolog_write_argfn(&ufp, path_normalized, 0);
			uncolog_write_action_end(&ufp);
			free(path_normalized);
		} else {
			uncolog_set_error(&ufp, errno, "unco");
		}
	}
}

static void before_rmdir(const char *path, struct backup_info* info)
{
	char *path_normalized;

	memset(info, 0, sizeof(*info));

	if ((path_normalized = strip_trailing_slashes(path)) == NULL) {
		info->errnum = errno;
		return;
	}
	info->backup = backup_as_dir(path, &info->errnum);
}

static void after_rmdir(int ret, const char *path, struct backup_info *info)
{
	char *path_normalized;

	if (ret == 0) {
		if (info->backup != NULL) {
			if ((path_normalized = strip_trailing_slashes(path)) != NULL) {
				uncolog_write_action_start(&ufp, "rmdir", 2);
				uncolog_write_argfn(&ufp, path_normalized, 0);
				uncolog_write_argfn(&ufp, info->backup, 0);
				uncolog_write_action_end(&ufp);
				free(path_normalized);
			} else {
				uncolog_set_error(&ufp, info->errnum, "unco");
			}
		} else {
			uncolog_set_error(&ufp, info->errnum, "unco:failed to create backup file of:%s", path);
		}
	} else if (info->backup != NULL) {
		default_rmdir(info->backup);
	}
	free(info->backup);
}

static void before_attrchange(const char *path, int follow, struct attr_info *info)
{
	memset(info, 0, sizeof(*info));

	if ((follow ? stat : lstat)(path, &info->st) != 0)
		info->errnum = errno;
}

static void before_attrchange_fd(int filedes, struct attr_info *info)
{
	memset(info, 0, sizeof(*info));

	if (fstat(filedes, &info->st) != 0)
		info->errnum = errno;
}

static void after_chmod(int ret, const char *path, int follow, struct attr_info *info)
{
	if (ret == 0) {
		uncolog_write_action_start(&ufp, "chmod", 2);
		uncolog_write_argfn(&ufp, path, follow);
		uncolog_write_argn(&ufp, info->st.st_mode & ~S_IFMT);
		uncolog_write_action_end(&ufp);
	} else {
		uncolog_set_error(&ufp, info->errnum, "unco:failed to stat file:%s", path);
	}
}

static void after_fchmod(int ret, int filedes, struct attr_info *info)
{
	if (ret == 0) {
		uncolog_write_action_start(&ufp, "chmod", 2);
		uncolog_write_argfd(&ufp, filedes);
		uncolog_write_argn(&ufp, info->st.st_mode & ~S_IFMT);
		uncolog_write_action_end(&ufp);
	} else {
		uncolog_set_error(&ufp, info->errnum, "unco:failed to stat file descriptor:%d", filedes);
	}
}

static void after_chown(int ret, const char *path, uid_t owner, gid_t group, int follow, struct attr_info *info)
{
	if (ret == 0) {
		uncolog_write_action_start(&ufp, "lchown", 3);
		uncolog_write_argfn(&ufp, path, follow);
		uncolog_write_argn(&ufp, info->st.st_uid);
		uncolog_write_argn(&ufp, info->st.st_gid);
		uncolog_write_action_end(&ufp);
	} else {
		uncolog_set_error(&ufp, info->errnum, "unco:failed to stat file:%s", path);
	}
}

static void after_fchown(int ret, int filedes, uid_t owner, gid_t group, struct attr_info *info)
{
	if (ret == 0) {
		uncolog_write_action_start(&ufp, "lchown", 3);
		uncolog_write_argfd(&ufp, filedes);
		uncolog_write_argn(&ufp, info->st.st_uid);
		uncolog_write_argn(&ufp, info->st.st_gid);
		uncolog_write_action_end(&ufp);
	} else {
		uncolog_set_error(&ufp, info->errnum, "unco:failed to stat file descriptor:%d", filedes);
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
#ifdef __linux__
# define WRAP_OPEN(Fn, RetType, Args, Body) \
	WRAP(Fn, RetType, Args, Body) \
	WRAP(Fn ## 64, RetType, Args, Body)
#else
# define WRAP_OPEN WRAP
#endif

WRAP_OPEN(open, int, (const char *path, int oflag, ...), {
	va_list arg;
	mode_t mode = 0;
	struct backup_info info;
	int ret;

	if ((oflag & O_CREAT) != 0) {
		va_start(arg, oflag);
		mode = va_arg(arg, int);
		va_end(arg);
	}

	before_open(path, oflag, &info);
	ret = orig(path, oflag, mode);
	after_open(ret != -1, path, &info);

	return ret;
})

WRAP_OPEN(creat, int, (const char *path, mode_t mode), {
	struct backup_info info;
	int ret;

	before_open(path, O_CREAT | O_WRONLY | O_TRUNC, &info);
	ret = orig(path, mode);
	after_open(ret != -1, path, &info);

	return ret;
})

WRAP_OPEN(fopen, FILE*, (const char *path, const char *mode), {
	int oflag;
	struct backup_info info;
	FILE *ret;

	if (strchr(mode, 'w') != NULL) {
		oflag = O_CREAT | O_WRONLY | O_TRUNC;
	} else if (strchr(mode, 'a') != NULL) {
		oflag = O_CREAT | O_WRONLY | O_APPEND;
	} else {
		oflag = 0;
	}

	before_open(path, oflag, &info);
	ret = orig(path, mode);
	after_open(ret != NULL, path, &info);

	return ret;
})

WRAP_OPEN(mkstemp, int, (char *template), {
	int ret;

	ret = orig(template);

	if (ret != -1) {
		uncolog_write_action_start(&ufp, "create", 1);
		uncolog_write_argfn(&ufp, template, 1);
		uncolog_write_action_end(&ufp);
	}
	return ret;
})

WRAP(rename, int, (const char *old, const char *new), {
	struct backup_info info;
	int ret;

	before_backup1(new, &info);
	ret = orig(old, new);
	after_rename(ret, old, new, &info);

	return ret;
})

WRAP(unlink, int, (const char *path), {
	struct backup_info info;
	int ret;

	before_backup1(path, &info);
	ret = orig(path);
	after_unlink(ret, path, &info);

	return ret;
})

WRAP(link, int, (const char *path1, const char *path2), {
	int ret = orig(path1, path2);
	after_link(ret, path1, 1, path2);
	return ret;
})

WRAP(symlink, int, (const char *path1, const char*path2), {
	int ret = orig(path1, path2);
	after_symlink(ret, path2);
	return ret;
})

WRAP(mkdir, int, (const char *path, mode_t mode), {
	int ret = orig(path, mode);
	after_mkdir(ret == 0, path);
	return ret;
})

WRAP(mkdtemp, char *, (char *template), {
	char *ret = orig(template);
	after_mkdir(ret != NULL, template);
	return ret;
})

WRAP(rmdir, int, (const char *path), {
	struct backup_info info;
	int ret;

	before_rmdir(path, &info);
	ret = orig(path);
	after_rmdir(ret, path, &info);

	return ret;
})

WRAP(chmod, int, (const char *path, mode_t mode), {
	struct attr_info info;
	int ret;

	before_attrchange(path, 1, &info);
	ret = orig(path, mode);
	after_chmod(ret, path, 1, &info);

	return ret;
})

WRAP(fchmod, int, (int filedes, mode_t mode), {
	struct attr_info info;
	int ret;

	before_attrchange_fd(filedes, &info);
	ret = orig(filedes, mode);
	after_fchmod(ret, filedes, &info);

	return ret;
})

WRAP(chown, int, (const char *path, uid_t owner, gid_t group), {
	struct attr_info info;
	int ret;

	before_attrchange(path, 1, &info);
	ret = orig(path, owner, group);
	after_chown(ret, path, owner, group, 1, &info);

	return ret;
})

WRAP(lchown, int, (const char *path, uid_t owner, gid_t group), {
	struct attr_info info;
	int ret;

	before_attrchange(path, 0, &info);
	ret = orig(path, owner, group);
	after_chown(ret, path, owner, group, 0, &info);

	return ret;
})

WRAP(fchown, int, (int filedes, uid_t owner, gid_t group), {
	struct attr_info info;
	int ret;

	before_attrchange_fd(filedes, &info);
	ret = orig(filedes, owner, group);
	after_fchown(ret, filedes, owner, group, &info);

	return ret;
})

#ifdef __linux__

static char *normalize_atpath(int dirfd, const char *path)
{
	char *ret, *dirpath;

	if (path[0] == '/' || dirfd == AT_FDCWD) {
		if ((ret = strdup(path)) == NULL)
			uncolog_set_error(&ufp, errno, "unco");
		return ret;
	}
	if ((dirpath = kgetpath(dirfd)) == NULL) {
		uncolog_set_error(&ufp, 0, "unco:failed to determine path of filedes:%d", dirfd);
		return NULL;
	}
	if ((ret = ksprintf("%s/%s", dirpath, path)) == NULL)
		uncolog_set_error(&ufp, errno, "unco");
	free(dirpath);
	return ret;
}

WRAP_OPEN(openat, int, (int dirfd, const char *path, int oflag, ...), {
	va_list arg;
	mode_t mode;
	char *path_normalized;
	struct backup_info info;
	int ret;

	if ((oflag & O_CREAT) != 0) {
		va_start(arg, oflag);
		mode = va_arg(arg, int);
		va_end(arg);
	}

	if ((path_normalized = normalize_atpath(dirfd, path)) == NULL)
		return orig(dirfd, path, oflag, mode);

	if (path_normalized != NULL)
		before_open(path_normalized, oflag, &info);
	ret = orig(dirfd, path, oflag, mode);
	if (path_normalized != NULL)
		after_open(ret != -1, path_normalized, &info);

	free(path_normalized);
	return ret;
})

WRAP(unlinkat, int, (int dirfd, const char *path, int flags), {
	char *path_normalized;
	int ret;

	if ((path_normalized = normalize_atpath(dirfd, path)) == NULL)
		return orig(dirfd, path, flags);

	if ((flags & AT_REMOVEDIR) != 0)
		ret = rmdir(path_normalized);
	else
		ret = unlink(path_normalized);

	free(path_normalized);
	return ret;
})

WRAP(renameat, int, (int olddirfd, const char *oldpath, int newdirfd, const char *newpath), {
	char *oldpath_normalized = NULL;
	char *newpath_normalized = NULL;
	struct backup_info info;
	int can_hook = 0;
	int ret;

	if ((oldpath_normalized = normalize_atpath(olddirfd, oldpath)) != NULL
		&& (newpath_normalized = normalize_atpath(newdirfd, newpath)) != NULL)
		can_hook = 1;

	if (can_hook)
		before_backup1(newpath_normalized, &info);
	ret = orig(olddirfd, oldpath, newdirfd, newpath);
	if (can_hook)
		after_rename(ret, oldpath_normalized, newpath_normalized, &info);

	free(oldpath_normalized);
	free(newpath_normalized);
	return ret;
})

WRAP(linkat, int, (int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags), {
	char *oldpath_normalized = NULL;
	char *newpath_normalized = NULL;
	int can_hook = 0;
	int ret;

	if ((oldpath_normalized = normalize_atpath(olddirfd, oldpath)) != NULL
		&& (newpath_normalized = normalize_atpath(newdirfd, newpath)) != NULL)
		can_hook = 1;

	ret = orig(olddirfd, oldpath, newdirfd, newpath, flags);
	if (can_hook)
		after_link(ret, oldpath_normalized, (flags & AT_SYMLINK_FOLLOW) != 0, newpath_normalized);

	free(oldpath_normalized);
	free(newpath_normalized);
	return ret;
})

WRAP(symlinkat, int, (const char *oldpath, int newdirfd, const char *newpath), {
	char *newpath_normalized = NULL;
	int ret;

	newpath_normalized = normalize_atpath(newdirfd, newpath);

	ret = orig(oldpath, newdirfd, newpath);
	after_symlink(ret, newpath_normalized);

	free(newpath_normalized);
	return ret;
})

WRAP(mkdirat, int, (int dirfd, const char *path, mode_t mode), {
	char *newpath_normalized = NULL;
	int ret;

	newpath_normalized = normalize_atpath(dirfd, path);

	ret = orig(dirfd, path, mode);
	after_mkdir(ret, newpath_normalized);

	free(newpath_normalized);
	return ret;
})

WRAP(fchmodat, int, (int dirfd, const char *path, mode_t mode, int flags), {
	char *path_normalized = NULL;
	struct attr_info info;
	int ret;

	path_normalized = normalize_atpath(dirfd, path);

	before_attrchange(path_normalized, (flags & AT_SYMLINK_NOFOLLOW) == 0, &info);
	ret = orig(dirfd, path, mode, flags);
	after_chmod(ret, path_normalized, (flags & AT_SYMLINK_NOFOLLOW) == 0, &info);

	free(path_normalized);
	return ret;
})

WRAP(fchownat, int, (int dirfd, const char *path, uid_t owner, gid_t group, int flags), {
	char *path_normalized = NULL;
	struct attr_info info;

	int ret;

	path_normalized = normalize_atpath(dirfd, path);

	before_attrchange(path_normalized, (flags & AT_SYMLINK_NOFOLLOW) == 0, &info);
	ret = orig(dirfd, path, owner, group, flags);
	after_chown(ret, path_normalized, owner, group, (flags & AT_SYMLINK_NOFOLLOW) == 0, &info);

	free(path_normalized);
	return ret;
})

#endif
