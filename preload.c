#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include "unco.h"

static int (*default_open)(const char *path, int oflag, ...);
static int (*default_mkdir)(const char *path, mode_t mode);
static int _log_is_open = 0;
static struct uncolog_fp _log_fp;

static void init_defaults()
{
	if (default_open != NULL)
		return;

	default_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
	default_mkdir = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "mkdir");
}

static struct uncolog_fp *log_fp()
{
	char logfn[PATH_MAX];
	char *home;

	if (_log_is_open)
		return &_log_fp;
	_log_is_open = 1; // always set to true, and the error state is handled within _log_fp

	// open log
	if ((home = getenv("HOME")) == NULL) {
		fprintf(stderr, "$HOME is not set\n");
		uncolog_init_fp(&_log_fp);
		return &_log_fp;
	}
	snprintf(logfn, sizeof(logfn), "%s/.unco-log", home);
	uncolog_open(&_log_fp, logfn, default_open, default_mkdir);

	return &_log_fp;
}

static void before_writeopen(const char* path, int oflag)
{
	int cur_fd;

	if (strncmp(path, "/dev/", 5) == 0)
		return;

	// open the existing file
	if ((cur_fd = default_open(path, oflag & (O_SYMLINK | O_NOFOLLOW))) == -1) {
		// file does not exist
		uncolog_write_action(log_fp(), "create", 2);
		uncolog_write_argfn(log_fp(), path);
		return;
	}

	// file exists, back it up
	uncolog_write_action(log_fp(), "overwrite", 3);
	uncolog_write_argfn(log_fp(), path);
	uncolog_write_argn(log_fp(), (oflag & O_NOFOLLOW) == 0);
	uncolog_write_argfd(log_fp(), cur_fd);

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

WRAP(open, int, (const char* path, int oflag, ...), {
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

WRAP(fopen, FILE*, (const char* path, const char* mode), {
	if (strchr(mode, 'w') != NULL || strchr(mode, 'a') != NULL) {
		before_writeopen(path, 0);
	}
	return orig(path, mode);
})

WRAP(rename, int, (const char *old, const char *new), {
	int ret = orig(old, new);
	if (ret == 0) {
		uncolog_write_action(log_fp(), "rename", 2);
		uncolog_write_argfn(log_fp(), old);
		uncolog_write_argfn(log_fp(), new);
	}
	return ret;
})

WRAP(unlink, int, (const char *path), {
	char backup[PATH_MAX];
	int linkerrno = 0;

	// create backup link
	if (uncolog_get_linkname(log_fp(), backup) == 0) {
		if (link(path, backup) != 0)
			backup[0] = '\0';
			linkerrno = errno;
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
