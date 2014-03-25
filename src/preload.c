#include <alloca.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

static int (*default_open)(const char* path, int oflag, ...);
static int log_fd = -1;

static void init_defaults()
{
	if (default_open != NULL)
		return;

	default_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
}

static void log_begin(const char* action, int argc)
{
	char buf[32];

	if (log_fd == -1) {
		char logfn[PATH_MAX];
		char* home = getenv("HOME");
		if (home == NULL) {
			fprintf(stderr, "$HOME is not set\n");
			return;
		}
		snprintf(logfn, sizeof(logfn), "%s/.undo.log", home);
		if ((log_fd = default_open(logfn, O_CREAT | O_WRONLY, 0600)) == -1) {
			fprintf(stderr, "undo:failed to open /tmp/undo.log:%d\n", errno);
			return;
		}
	}

	write(log_fd, action, strlen(action));
	snprintf(buf, sizeof(buf), ":%d\n", argc);
	write(log_fd, buf, strlen(buf));
}

static void log_num(size_t n)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%zd\n", n);
	write(log_fd, buf, strlen(buf));
}

static void log_buf(const void* data, size_t len)
{
	log_num(len);
	write(log_fd, data, len);
	write(log_fd, "\n", 1);
}

static void on_writeopen(const char* path, int oflag)
{
	int cur_fd;
	struct stat stats;
	ssize_t readlen;
	char abspath[PATH_MAX], readbuf[4096];

	init_defaults();

	// open the existing file
	if ((cur_fd = default_open(path, oflag & (O_SYMLINK | O_NOFOLLOW))) == -1) {
		// file does not exist
		log_begin("create", 1);
		log_buf(path, strlen(path));
		return;
	}

	// file exists, back it up
	fstat(cur_fd, &stats);
	if (realpath(path, abspath) == NULL) {
		fprintf(stderr, "undo:failed to obtain realpath for:%s:%d", path, errno);
		// TODO disable the log
		return;
	}
	log_begin("overwrite", 7);
	log_buf(abspath, strlen(abspath));
	log_num(stats.st_mode);
	log_num(stats.st_uid);
	log_num(stats.st_gid);
	log_num(stats.st_ctime);
	log_num(stats.st_mtime);
	log_num(stats.st_size);
	while ((readlen = read(cur_fd, readbuf, sizeof(readbuf))) != 0) {
		if (readlen > 0)
			write(log_fd, readbuf, readlen);
	}
	write(log_fd, "\n", 1);

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
