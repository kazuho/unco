#ifndef unco_h
#define unco_h

#include <sys/param.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uncolog_fp {
	int _fd;
	int (*_default_open)(const char *, int, ...);
	char _path[PATH_MAX];
};

void uncolog_init_fp(struct uncolog_fp *ufp);
void uncolog_set_error(struct uncolog_fp *ufp, const char *fmt, ...);

int uncolog_open(struct uncolog_fp *ufp, const char *path, int mode, int (*default_open)(const char *, int, ...), int (*default_mkdir)(const char *, mode_t));
int uncolog_close(struct uncolog_fp *ufp);

int uncolog_write_action(struct uncolog_fp *ufp, const char *action, int argc);
int uncolog_write_argn(struct uncolog_fp *ufp, off_t n);
int uncolog_write_argbuf(struct uncolog_fp *ufp, const void *data, size_t len);
int uncolog_write_argfn(struct uncolog_fp *ufp, const char *path);
int uncolog_get_linkname(struct uncolog_fp *ufp, char *link);

int uncolog_read_action(struct uncolog_fp *ufp, char *action, int *argc);
int uncolog_read_argn(struct uncolog_fp *ufp, off_t *n);
void *uncolog_read_argbuf(struct uncolog_fp *ufp, size_t *sz);

int uncolog_delete(const char *path, int force);

ssize_t unco_read_nosig(int fd, void *data, size_t len);
int unco_full_write(int fd, const void *data, size_t len);
int unco_copyfd(int srcfd, int dstfd);
int unco_utimes(int fd, const struct stat *st, int (*futimes)(int, const struct timeval times[2]));

#ifdef __cplusplus
}
#endif

#endif
