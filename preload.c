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
static int _log_is_open = 0;
static struct uncolog_fp _log_fp;

static void init_defaults()
{
	if (default_open != NULL)
		return;

	default_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
}

static struct uncolog_fp *log_fp()
{
	char logfn[PATH_MAX];
	char *home;

	init_defaults();

	if (_log_is_open)
		return &_log_fp;
	_log_is_open = 1; // always set to true, and the error state is handled within _log_fp

	// open log
	if ((home = getenv("HOME")) == NULL) {
		fprintf(stderr, "$HOME is not set\n");
		uncolog_init_fp(&_log_fp);
		return &_log_fp;
	}
	snprintf(logfn, sizeof(logfn), "%s/.undo.log", home);
	uncolog_open(&_log_fp, logfn, default_open);

	return &_log_fp;
}

static void on_writeopen(const char* path, int oflag)
{
	int cur_fd;
	char abspath[PATH_MAX];

	init_defaults();

	// open the existing file
	if ((cur_fd = default_open(path, oflag & (O_SYMLINK | O_NOFOLLOW))) == -1) {
		// file does not exist
		uncolog_write_action(log_fp(), "create", 1);
		uncolog_write_argbuf(log_fp(), path, strlen(path));
		return;
	}

	// file exists, back it up
	if (realpath(path, abspath) == NULL) {
		fprintf(stderr, "undo:failed to obtain realpath for:%s:%d", path, errno);
		// TODO disable the log
		return;
	}
	uncolog_write_action(log_fp(), "overwrite", 1);
	uncolog_write_argfile(log_fp(), abspath, cur_fd);

	// close cur_fd
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

WRAP(open, int, (const char* path, int oflag, ...), {
	va_list arg;
	mode_t mode = 0;

	if ((oflag & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC)) != 0) {
		on_writeopen(path, oflag);
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
		on_writeopen(path, 0);
	}
	return orig(path, mode);
})
