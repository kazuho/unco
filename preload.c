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

static struct uncolog_fp *log_fp()
{
	char *logfn, *env, cwd[PATH_MAX], fnbuf[PATH_MAX];

	if (_log_is_open)
		return &_log_fp;
	_log_is_open = 1; // always set to true, and the error state is handled within _log_fp

	// determine the filename
	if ((env = getenv("UNCO_LOG")) != NULL) {
		if (env[0] == '/') {
			logfn = env;
		} else {
			if (getcwd(cwd, sizeof(cwd)) == NULL) {
				perror("unco:could not obtain cwd");
				goto Error;
			}
			snprintf(fnbuf, sizeof(fnbuf), "%s/%s", cwd, env);
			logfn = fnbuf;
		}
	} else {
		if ((env = getenv("HOME")) == NULL) {
			fprintf(stderr, "unco:$HOME is not set\n");
			goto Error;
		}
		snprintf(fnbuf, sizeof(fnbuf), "%s/.unco-log", env);
		logfn = fnbuf;
	}

	// open and return
	uncolog_open(&_log_fp, logfn, 'a', default_open, default_mkdir);
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
