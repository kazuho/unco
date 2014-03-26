#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "unco.h"

static ssize_t read_nosig(int fd, void *data, size_t len)
{
	ssize_t ret;
	while ((ret = read(fd, data, len)) == -1
		&& (errno == EAGAIN || errno == EWOULDBLOCK))
		;
	return ret;
}

static int errorclose(struct uncolog_fp* ufp)
{
	if (ufp->_fd != -1) {
		close(ufp->_fd);
		ufp->_fd = -1;
	}
	return -1;
}

static int safewrite(struct uncolog_fp *ufp, const void* data, size_t len)
{
	size_t off;

	if (ufp->_fd == -1) {
		return -1;
	}

	off = 0;
	while (off != len) {
		ssize_t ret = write(ufp->_fd, (const char*)data + off, len - off);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// continue
			} else {
				goto Error;
			}
		}
		off += ret;
	}
	return 0;

Error:
	perror("unco:log_write_error");
	return errorclose(ufp);
}

void uncolog_init_fp(struct uncolog_fp *ufp)
{
	ufp->_fd = -1;
}

int uncolog_open(struct uncolog_fp *ufp, const char* path, int (*default_open)(const char *, int, ...))
{
	if ((ufp->_fd = default_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600)) == -1) {
		return -1;
	}

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

int uncolog_write_argn(struct uncolog_fp* ufp, size_t n)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%zd\n", n);
	return safewrite(ufp, buf, strlen(buf));
}

int uncolog_write_argbuf(struct uncolog_fp* ufp, const void* data, size_t len)
{
	if (uncolog_write_argn(ufp, len) != 0
		|| safewrite(ufp, data ,len) != 0
		|| safewrite(ufp, "\n", 1) != 0)
		return -1;
	return 0;
}

int uncolog_write_argfile(struct uncolog_fp* ufp, const char* abspath, int fd)
{
	struct stat st;
	ssize_t rret;
	size_t off, rlen;
	char readbuf[4096];

	// write fn
	if (uncolog_write_argbuf(ufp, abspath, strlen(abspath)) != 0)
		return -1;

	// write attributes
	fstat(fd, &st); // TODO need to check error?
	if (uncolog_write_argn(ufp, st.st_mode) != 0
		|| uncolog_write_argn(ufp, st.st_uid) != 0
		|| uncolog_write_argn(ufp, st.st_gid) != 0
		|| uncolog_write_argn(ufp, st.st_ctime) != 0
		|| uncolog_write_argn(ufp, st.st_mtime) != 0
		|| uncolog_write_argn(ufp, st.st_size) != 0)
		return -1;

	// write body
	off = 0;
	while (off != st.st_size) {
		rlen = st.st_size - off;
		if (rlen > sizeof(readbuf))
			rlen = sizeof(readbuf);
		rret = read_nosig(fd, readbuf, rlen);
		switch (rret) {
		case 0:
			goto SizeChangeError;
		case -1:
			goto ReadError;
		default:
			if (safewrite(ufp, readbuf, rret) != 0)
				return -1;
			off += rret;
		}
	}
	// eof check
	switch (read_nosig(fd, readbuf, 1)) {
	case 0: // ok, is EOF
		break;
	case -1:
		goto ReadError;
	default:
		goto SizeChangeError;
	}
	// write last return
	if (safewrite(ufp, "\n", 1) != 0)
		return -1;

	return 0;

SizeChangeError:
	fprintf(stderr, "unco:file altered during backup:%s:%d\n", abspath, errno);
	return errorclose(ufp);

ReadError:
	fprintf(stderr, "unco:failed to read file for backup:%s:%d\n", abspath, errno);
	return errorclose(ufp);
}
