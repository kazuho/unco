#ifndef unco_h
#define unco_h

#include <sys/param.h>

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
int uncolog_open(struct uncolog_fp *ufp, const char* path, int (*default_open)(const char *, int, ...), int (*default_mkdir)(const char *, mode_t));
int uncolog_write_action(struct uncolog_fp *ufp, const char *action, int argc);
int uncolog_write_argn(struct uncolog_fp *ufp, size_t n);
int uncolog_write_argbuf(struct uncolog_fp *ufp, const void *data, size_t len);
int uncolog_write_argfn(struct uncolog_fp *ufp, const char *path);
int uncolog_write_argfd(struct uncolog_fp *ufp, int fd);
int uncolog_get_linkname(struct uncolog_fp *ufp, char *link);

#ifdef __cplusplus
}
#endif

#endif
