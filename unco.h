#ifndef unco_h
#define unco_h

#ifdef __cplusplus
extern "C" {
#endif

struct uncolog_fp {
	int _fd;
};

void uncolog_init_fp(struct uncolog_fp *ufp);
int uncolog_open(struct uncolog_fp *ufp, const char* path, int (*default_open)(const char *, int, ...));
int uncolog_write_action(struct uncolog_fp *ufp, const char *action, int argc);
int uncolog_write_argn(struct uncolog_fp *ufp, size_t n);
int uncolog_write_argbuf(struct uncolog_fp *ufp, const void *data, size_t len);
int uncolog_write_argfile(struct uncolog_fp *ufp, const char *abspath, int fd);

#ifdef __cplusplus
}
#endif

#endif
