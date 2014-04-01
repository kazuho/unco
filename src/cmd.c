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
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kazutils.h"
#include "sha1.h"
#include "config.h"
#include "unco.h"

// http://www.freebsd.org/cgi/man.cgi?query=sysexits
#ifndef EX_USAGE
# define EX_USAGE 64
#endif
#ifndef EX_DATAERR
# define EX_DATAERR 65
#endif
#ifndef EX_SOFTWARE
# define EX_SOFTWARE 70
#endif
#ifndef EX_OSERR
# define EX_OSERR 71
#endif

enum {
	ACTION_META,
	ACTION_CREATE,
	ACTION_OVERWRITE,
	ACTION_RENAME,
	ACTION_UNLINK,
	ACTION_LINK,
	ACTION_SYMLINK,
	ACTION_MKDIR,
	ACTION_RMDIR,
	ACTION_FINALIZE_FILEHASH,
	ACTION_FINALIZE_FILEREMOVE,
	ACTION_FINALIZE,
	NUM_ACTIONS
};

struct action {
	int type;
	int argc;
	union {
		struct {
			char *cmd;
			char *cwd;
			pid_t pid;
			pid_t ppid;
		} meta;
		struct {
			char *path;
		} create;
		struct {
			char *path;
			char *backup;
		} overwrite;
		struct {
			char *old;
			char *new;
			char *backup;
		} rename;
		struct {
			char *path;
			char *backup;
		} unlink;
		struct {
			char *path1;
			char *path2;
		} link;
		struct {
			char *path2;
		} symlink;
		struct {
			char *path;
		} mkdir;
		struct {
			char *path;
			char *backup;
		} rmdir;
		struct {
			char *path;
			char *sha1hex;
		} finalize_filehash;
		struct {
			char *path;
		} finalize_fileremove;
	};
};

static int sha1hex_file(const char *fn, char *sha1hex)
{
	SHA1Context ctx;
	int fd, i;
	unsigned char buf[4096], sha1bin[SHA1HashSize];
	ssize_t rlen;

	SHA1Reset(&ctx);

	// read
	if ((fd = open(fn, O_RDONLY)) == -1)
		return -1;
	while ((rlen = kread_nosig(fd, buf, sizeof(buf))) != 0) {
		if (rlen == -1)
			return -1;
		SHA1Input(&ctx, buf, rlen);
	}
	close(fd);

	SHA1Result(&ctx, sha1bin);

	for (i = 0; i != 20; ++i) {
		sha1hex[i * 2] =     "0123456789abcdef"[sha1bin[i] >> 4];
		sha1hex[i * 2 + 1] = "0123456789abcdef"[sha1bin[i] & 0xf];
	}
	sha1hex[SHA1HashSize * 2] = '\0';

	return 0;
}

static int consume_log(const char *logpath, int (*cb)(struct action *action, void *cb_arg), void *cb_arg)
{
#define READ_ARGSTR(dst) \
	do { \
		if ((dst = (char *)uncolog_read_argbuf(ufp, NULL)) == NULL) \
			goto Exit; \
		KFREE_PTRS_PUSH(dst); \
	} while (0)
#define READ_ARGN(dst) \
	do { \
		off_t t; \
		if (uncolog_read_argn(ufp, &t) != 0) \
			goto Exit; \
		dst = t; \
	} while (0)

	struct uncolog_fp _ufp, *ufp = &_ufp;
	struct action action;
	char name[256];
	int ret = -1;

	KFREE_PTRS_INIT(16);

	if (uncolog_open(ufp, logpath, 'r', open, mkdir) != 0)
		return -1;

	while (1) {
		memset(&action, 0, sizeof(action));
		if (uncolog_read_action(ufp, name, &action.argc) != 0)
			break;
		if (strcmp(name, "meta") == 0) {
			assert(action.argc == 4);
			action.type = ACTION_META;
			READ_ARGSTR(action.meta.cmd);
			READ_ARGSTR(action.meta.cwd);
			READ_ARGN(action.meta.pid);
			READ_ARGN(action.meta.ppid);
		} else if (strcmp(name, "create") == 0) {
			assert(action.argc == 1);
			action.type = ACTION_CREATE;
			READ_ARGSTR(action.create.path);
		} else if (strcmp(name, "overwrite") == 0) {
			assert(action.argc == 2);
			action.type = ACTION_OVERWRITE;
			READ_ARGSTR(action.overwrite.path);
			READ_ARGSTR(action.overwrite.backup);
		} else if (strcmp(name, "rename") == 0) {
			assert(action.argc == 2 || action.argc == 3);
			action.type = ACTION_RENAME;
			READ_ARGSTR(action.rename.old);
			READ_ARGSTR(action.rename.new);
			if (action.argc == 3)
				READ_ARGSTR(action.rename.backup);
		} else if (strcmp(name, "unlink") == 0) {
			assert(action.argc == 2);
			action.type = ACTION_UNLINK;
			READ_ARGSTR(action.unlink.path);
			READ_ARGSTR(action.unlink.backup);
		} else if (strcmp(name, "link") == 0) {
			assert(action.argc == 2);
			action.type = ACTION_LINK;
			READ_ARGSTR(action.link.path1);
			READ_ARGSTR(action.link.path2);
		} else if (strcmp(name, "symlink") == 0) {
			assert(action.argc == 1);
			action.type = ACTION_SYMLINK;
			READ_ARGSTR(action.symlink.path2);
		} else if (strcmp(name, "mkdir") == 0) {
			assert(action.argc == 1);
			action.type = ACTION_MKDIR;
			READ_ARGSTR(action.mkdir.path);
		} else if (strcmp(name, "rmdir") == 0) {
			assert(action.argc == 2);
			action.type = ACTION_RMDIR;
			READ_ARGSTR(action.rmdir.path);
			READ_ARGSTR(action.rmdir.backup);
		} else if (strcmp(name, "finalize_filehash") == 0) {
			assert(action.argc == 2);
			action.type = ACTION_FINALIZE_FILEHASH;
			READ_ARGSTR(action.finalize_filehash.path);
			READ_ARGSTR(action.finalize_filehash.sha1hex);
		} else if (strcmp(name, "finalize_fileremove") == 0) {
			assert(action.argc == 1);
			action.type = ACTION_FINALIZE_FILEREMOVE;
			READ_ARGSTR(action.finalize_fileremove.path);
		} else if (strcmp(name, "finalize") == 0) {
			assert(action.argc == 0);
			action.type = ACTION_FINALIZE;
		} else {
			fprintf(stderr, "unknown action:%s\n", name);
			goto Exit;
		}
		if (cb(&action, cb_arg) != 0)
			goto Exit;
		KFREE_PTRS();
	}
	// TODO check eof

	ret = 0;
Exit:
	KFREE_PTRS();
	uncolog_close(ufp);
	return ret;

#undef READ_ARGSTR
#undef READ_ARGN
}

struct _finalize_info {
	char *existing_files_dir;
	char *removed_files_dir;
	int is_finalized;
};

static char *_finalize_encode_fn(const char *fn)
{
	kstrbuf buf;

	memset(&buf, 0, sizeof(buf));
	for (; *fn != '\0'; fn++) {
		switch (*fn) {
		case '/': // becomes %
			if (kstrbuf_append_char(&buf, '%') == NULL)
				goto Error;
			break;
		case '%': // becomes %%
			if (kstrbuf_append_str(&buf, "%%") == NULL)
				goto Error;
			break;
		default:
			if (kstrbuf_append_char(&buf, *fn) == NULL)
				goto Error;
		}
	}
	return buf.str;

Error:
	free(buf.str);
	return NULL;
}

static char *_finalize_decode_fn(const char *enc)
{
	kstrbuf buf;
	int ch;

	memset(&buf, 0, sizeof(buf));
	while ((ch = *enc++) != '\0') {
		if (ch == '%') {
			if (*enc == '%')
				++enc;
			else
				ch = '/';
		}
		if (kstrbuf_append_char(&buf, ch) == NULL) {
			free(buf.str);
			return NULL;
		}
	}

	return buf.str;
}

static int _finalize_mark_file_in_list(const char *dir, const char *fn, int exists)
{
	char *fn_encoded = NULL, *path = NULL;
	int ret = -1;
	struct stat st;

	if ((fn_encoded = _finalize_encode_fn(fn)) == NULL)
		goto Exit;
	if ((path = ksprintf("%s/%s", dir, fn_encoded)) == NULL)
		goto Exit;

	if (lstat(path, &st) == 0 != exists) {
		if (exists) {
			if (symlink(dir, path) != 0)
				goto Exit;
		} else {
			if (unlink(path) != 0)
				goto Exit;
		}
	}

	ret = 0;
Exit:
	free(fn_encoded);
	free(path);
	return ret;
}

static int _finalize_mark_file(struct _finalize_info *info, const char* fn, int exists)
{
	if (_finalize_mark_file_in_list(info->existing_files_dir, fn, exists) != 0
		|| _finalize_mark_file_in_list(info->removed_files_dir, fn, ! exists) != 0)
		return -1;
	return 0;
}

static int _finalize_action_handler(struct action *action, void *cb_arg)
{
	struct _finalize_info *info = cb_arg;

	switch (action->type) {
	case ACTION_META:
		break; // skip
	case ACTION_CREATE:
		if (_finalize_mark_file(info, action->create.path, 1) != 0)
			return -1;
		break;
	case ACTION_OVERWRITE:
		if (_finalize_mark_file(info, action->overwrite.path, 1) != 0)
			return -1;
		break;
	case ACTION_RENAME:
		if (_finalize_mark_file(info, action->rename.old, 0) != 0
			|| _finalize_mark_file(info, action->rename.new, 1) != 0)
			return -1;
		break;
	case ACTION_UNLINK:
		if (_finalize_mark_file(info, action->unlink.path, 0) != 0)
			return -1;
		break;
	case ACTION_LINK:
		if (_finalize_mark_file(info, action->link.path2, 1) != 0)
			return -1;
		break;
	case ACTION_SYMLINK:
		if (_finalize_mark_file(info, action->symlink.path2, 1) != 0)
			return -1;
		break;
	case ACTION_MKDIR:
		if (_finalize_mark_file(info, action->mkdir.path, 1) != 0)
			return -1;
		break;
	case ACTION_RMDIR:
		if (_finalize_mark_file(info, action->rmdir.path, 0) != 0)
			return -1;
		break;
	case ACTION_FINALIZE_FILEHASH:
	case ACTION_FINALIZE_FILEREMOVE:
	case ACTION_FINALIZE:
		fprintf(stderr, "log is already finalized\n");
		return -1;
	default:
		assert(0);
		return -1;
	}

	return 0;
}

static int _finalize_append_action_dir(struct uncolog_fp *ufp, const char *dir, int is_existing)
{
	DIR *dp;
	struct dirent *ent, entbuf;
	char *fn = NULL;
	char sha1hex[SHA1HashSize * 2 + 1];
	struct stat st;
	int ret = -1;

	if ((dp = opendir(dir)) == NULL) {
		uncolog_set_error(ufp, errno, "unco:failed to opendir temporary dir:%s", dir);
		return -1;
	}
	while (readdir_r(dp, &entbuf, &ent) == 0 && ent != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
			// skip
		} else {
			if ((fn = _finalize_decode_fn(ent->d_name)) == NULL) {
				uncolog_set_error(ufp, errno, "unco");
				goto Exit;
			}

			if (is_existing) {
				// file should exist, append its sha1
				if (lstat(fn, &st) != 0) {
					uncolog_set_error(ufp, 0, "unexpected condition, file logged as being created/modified does not exist:%s", fn);
					goto Exit;
				}
				if ((st.st_mode & S_IFMT) == S_IFREG) {
					if (sha1hex_file(fn, sha1hex) != 0) {
						uncolog_set_error(ufp, errno, "unco:failed to sha1 file:%s", fn);
						goto Exit;
					}
				} else {
					// TODO collect appropriate hash depending on the file type
					sha1hex[0] = '\0';
				}
				if (uncolog_write_action(ufp, "finalize_filehash", 2) != 0
					|| uncolog_write_argbuf(ufp, fn, strlen(fn)) != 0
					|| uncolog_write_argbuf(ufp, sha1hex, strlen(sha1hex)) != 0)
					goto Exit;
			} else {
				// file should not exist
				if (lstat(fn, &st) == 0) {
					uncolog_set_error(ufp, 0, "unexpected condition, file logged as being removed exists:%s", fn);
					goto Exit;
				}
				if (uncolog_write_action(ufp, "finalize_fileremove", 1) != 0
					|| uncolog_write_argbuf(ufp, fn, strlen(fn)) != 0)
					goto Exit;
			}

			free(fn);
			fn = NULL;
		}
	}

	ret = 0;
Exit:
	closedir(dp);
	free(fn);
	return ret;
}

static int _finalize_append_action(struct uncolog_fp* ufp, struct _finalize_info* info)
{
	if (_finalize_append_action_dir(ufp, info->existing_files_dir, 1) != 0)
		return -1;

	if (_finalize_append_action_dir(ufp, info->removed_files_dir, 0) != 0)
		return -1;

	if (uncolog_write_action(ufp, "finalize", 0) != 0)
		return -1;

	return 0;
}

static int finalize(const char *logfn)
{
	struct _finalize_info info;
	struct uncolog_fp ufp;
	int ret;

	memset(&info, 0, sizeof(info));
	uncolog_init_fp(&ufp);

	// determine the files that should be finalized
	if ((info.existing_files_dir = strdup("/tmp/unco.XXXXXX")) == NULL
		|| mkdtemp(info.existing_files_dir) == NULL
		|| (info.removed_files_dir = strdup("/tmp/unco.XXXXXX")) == NULL
		|| mkdtemp(info.removed_files_dir) == NULL) {
		perror("unco:failed to create temporary directories");
		ret = EX_OSERR;
		goto Exit;
	}
	if (consume_log(logfn, _finalize_action_handler, &info) != 0) {
		ret = EX_DATAERR;
		goto Exit;
	}

	// open log and finalize
	if (uncolog_open(&ufp, logfn, 'a', open, mkdir) != 0) {
		ret = EX_SOFTWARE;
		goto Exit;
	}
	if (_finalize_append_action(&ufp, &info) != 0) {
		ret = EX_OSERR;
		goto Exit;
	}

	ret = 0;
Exit:
	uncolog_close(&ufp);
	if (info.existing_files_dir != NULL) {
		kunlink_recursive(info.existing_files_dir);
		free(info.existing_files_dir);
	}
	if (info.removed_files_dir != NULL) {
		kunlink_recursive(info.removed_files_dir);
		free(info.removed_files_dir);
	}
	return 0;
}

static int do_record(int argc, char **argv)
{
	static struct option longopts[] = {
		{ "log", required_argument, NULL, 'l' },
		{ "append", no_argument, NULL, 'a' },
		{ NULL }
	};
	const char *log_file = NULL;
	int opt_ch, append = 0;

	// fetch opts
	while ((opt_ch = getopt_long(argc + 1, argv - 1, "l:a", longopts, NULL)) != -1) {
		switch (opt_ch) {
		case 'l':
			log_file = optarg;
			break;
		case 'a':
			append = 1;
			break;
		default:
			fprintf(stderr, "unknown option: %c\n", opt_ch);
			return EX_USAGE;
		}
	}
	argc -= optind - 1;
	argv += optind - 1;
	if (argc == 0) {
		fprintf(stderr, "no command given\n");
		return EX_USAGE;
	}

	if (append) {
		if (log_file == NULL) {
			fprintf(stderr, "cannot use --apend without --log\n");
			return EX_USAGE;
		}
	} else {
		if (log_file != NULL) {
			if (kunlink_recursive(log_file) != 0 && ! (errno = EEXIST || errno == ENOENT)) {
				kerr_printf("failed to remove log:%s", log_file);
				return EX_OSERR;
			}
		}
	}

	// set environment variables and exec
	setenv("DYLD_INSERT_LIBRARIES", WITH_LIBDIR "/libunco-preload.dylib", 1);
	setenv("DYLD_FORCE_FLAT_NAMESPACE", "YES", 1);
	if (log_file != NULL) {
		setenv("UNCO_LOG", log_file, 1);
	} else {
		char placeholder[UNCO_LOG_PATH_MAX];
		memset(placeholder, ' ', sizeof(placeholder) - 1);
		placeholder[sizeof(placeholder) - 1] = '\0';
		setenv("UNCO_LOG_PLACEHOLDER", placeholder, 1);
	}
	execvp(argv[0], argv);
	kerr_printf("failed to exec:%s", argv[0]);
	return 127; // FIXME what is the right code?
}

struct revert_info {
	klist lines;
	int is_finalized;
	char *header;
};

static int _revert_action_handler(struct action *action, void *cb_arg)
{
	struct revert_info *info = cb_arg;
	int ret = -1;
	KFREE_PTRS_INIT(16);

	switch (action->type) {

	case ACTION_META:
		info->header = ksprintf(
			"# generated by unco version " UNCO_VERSION "\n"
			"#\n"
			"# undo script for:\n"
			"#   cmd:  %s\n"
			"#   cwd:  %s\n"
			"#   pid:  %d\n"
			"#   ppid: %d\n"
			"#\n"
			"\n",
			action->meta.cmd, action->meta.cwd, (int)action->meta.pid, (int)action->meta.ppid);
		break;

	case ACTION_CREATE:
		{
			char *path_quoted;

			if (KFREE_PTRS_PUSH((path_quoted = kshellquote(action->create.path))) == NULL)
				goto Exit;
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
					"# revert create\n"
					"rm %s || exit 1\n",
					path_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_OVERWRITE:
		{
			char *path_quoted, *backup_quoted;

			if (KFREE_PTRS_PUSH(path_quoted = kshellquote(action->overwrite.path)) == NULL
				|| KFREE_PTRS_PUSH(backup_quoted = kshellquote(action->overwrite.backup)) == NULL)
				goto Exit;
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
					"# revert overwrite\n"
					"ls %s > /dev/null || exit 1\n" // target should exist
					"cat %s > %s || exit 1\n"
					"touch -r %s %s || exit 1\n",
					path_quoted, backup_quoted, path_quoted, backup_quoted, path_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_RENAME:
		{
			char *old_quoted, *new_quoted, *backup_quoted;

			if (KFREE_PTRS_PUSH(old_quoted = kshellquote(action->rename.old)) == NULL
				|| KFREE_PTRS_PUSH(new_quoted = kshellquote(action->rename.new)) == NULL)
				goto Exit;
			if (action->rename.backup == NULL) {
				if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
						"# revert rename\n"
						"mv -n %s %s || exit 1\n",
						new_quoted, old_quoted) == NULL)
					goto Exit;
			} else {
				if (KFREE_PTRS_PUSH(backup_quoted = kshellquote(action->rename.backup)) == NULL)
					goto Exit;
				if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
						"# revert rename (replacing)\n"
						"mv -n %s %s || exit 1\n"
						"cat %s > %s || exit 1\n",
						new_quoted, old_quoted, backup_quoted, new_quoted) == NULL)
					goto Exit;
			}
		}
		break;

	case ACTION_UNLINK:
		{
			char *path_quoted, *backup_quoted;
			struct stat st;

			if (KFREE_PTRS_PUSH(path_quoted = kshellquote(action->overwrite.path)) == NULL
				|| KFREE_PTRS_PUSH(backup_quoted = kshellquote(action->overwrite.backup)) == NULL)
				goto Exit;
			if (lstat(action->overwrite.backup, &st) != 0)
				goto Exit;
			if ((st.st_mode & S_IFMT) == S_IFLNK) {
				if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
						"# revert unlink of symlink\n"
						"ln -s `readlink %s` %s || exit 1\n",
						backup_quoted, path_quoted) == NULL)
					goto Exit;
			} else {
				if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
						"# revert unlink\n"
						"ln %s %s || exit 1\n",
						backup_quoted, path_quoted) == NULL)
					goto Exit;
			}
		}
		break;

	case ACTION_LINK:
		{
			char *path2_quoted;

			if (KFREE_PTRS_PUSH(path2_quoted = kshellquote(action->link.path2)) == NULL)
				goto Exit;
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
				"# revert link\n"
				"rm %s || exit 1\n",
				path2_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_SYMLINK:

		{
			char *path2_quoted;

			if (KFREE_PTRS_PUSH(path2_quoted = kshellquote(action->symlink.path2)) == NULL)
				goto Exit;
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
				"# revert symlink\n"
				"rm %s || exit 1\n",
				path2_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_MKDIR:

		{
			char *path_quoted;

			if (KFREE_PTRS_PUSH(path_quoted = kshellquote(action->mkdir.path)) == NULL)
				goto Exit;
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
				"# revert mkdir\n"
				"rmdir %s || exit 1\n",
				path_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_RMDIR:

		{
			char *path_quoted;
			struct stat st;

			if (KFREE_PTRS_PUSH(path_quoted = kshellquote(action->rmdir.path)) == NULL)
				goto Exit;
			if (lstat(action->rmdir.backup, &st) != 0) {
				kerr_printf("unco:cannot stat dir:%s", action->rmdir.backup);
				goto Exit;
			}
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
				"# revert rmdir\n"
				"mkdir %s || exit 1\n"
				"chown %d:%d %s || exit 1\n"
				"chmod %o %s || exit 1\n",
				path_quoted, st.st_uid, st.st_gid, path_quoted, st.st_mode & ~S_IFMT, path_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_FINALIZE_FILEHASH:
		{
			char *path_quoted;

			if (action->finalize_filehash.sha1hex[0] != '\0') {
				if (KFREE_PTRS_PUSH(path_quoted = kshellquote(action->finalize_filehash.path)) == NULL)
					goto Exit;
				if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
						"# check that file has not been altered since the recorded change\n"
						"SHA1HEX=`openssl sha1 < %s`\n"
						"[ $? -eq 0 ] || exit 1\n"
						"if [ \"$SHA1HEX\" != \"%s\" ] ; then\n"
						"    echo 'file altered since recorded change:%s' >&2\n"
						"    exit 1\n"
						"fi\n",
						path_quoted, action->finalize_filehash.sha1hex, path_quoted) == NULL)
					goto Exit;
			}
		}
		break;

	case ACTION_FINALIZE_FILEREMOVE:
		{
			char *path_quoted;

			if (KFREE_PTRS_PUSH(path_quoted = kshellquote(action->finalize_fileremove.path)) == NULL)
				goto Exit;
			if (klist_insert_printf(&info->lines, klist_next(&info->lines, NULL),
					"# check that file has not been recreated since the recorded removal\n"
					"if [ -e %s ] ; then\n"
					"    echo 'file recreated since recorded removal:%s' >&2\n"
					"    exit 1\n"
					"fi\n",
					path_quoted, path_quoted) == NULL)
				goto Exit;
		}
		break;

	case ACTION_FINALIZE:

		info->is_finalized = 1;
		break;

	default:
		assert(0);
		goto Exit;

	}

	// success
	ret = 0;
Exit:
	KFREE_PTRS();
	return ret;
}

static int do_revert(int argc, char **argv, int is_redo)
{
	static struct option longopts[] = {
		{ "print", no_argument, NULL, 'p' },
		{ NULL }
	};
	char *logfn, *unco_dir, *unco_cmd_quoted, *undo_logfn, *undo_logfn_quoted, *shellcmd, *lines;
	int opt_ch, logindex, print = 0, exit = EX_SOFTWARE;
	struct revert_info info;
	struct stat st;
	FILE *outfp;
	KFREE_PTRS_INIT(16);

	memset(&info, 0, sizeof(info));

	// fetch opts
	while ((opt_ch = getopt_long(argc + 1, argv - 1, "p", longopts, NULL)) != -1) {
		switch (opt_ch) {
		case 'p':
			print = 1;
			break;
		default:
			exit = EX_USAGE;
			goto Exit;
		}
	}
	argc -= optind - 1;
	argv += optind - 1;

	// normalize logfn (if it looks like a number then it's the id)
	if (argc == 0) {
		fprintf(stderr, "no args, should specify log number or filename\n");
		exit = EX_USAGE;
		goto Exit;
	}
	if (sscanf(*argv, "%d", &logindex) == 1) {
		if (KFREE_PTRS_PUSH(unco_dir = unco_get_default_dir()) == NULL)
			goto Exit;
		if (KFREE_PTRS_PUSH(logfn = ksprintf("%s/%s", unco_dir, *argv)) == NULL) {
			perror("unco");
			goto Exit;
		}
	} else {
		logfn = *argv;
	}
	argv++, --argc;

	// check undo status
	if (KFREE_PTRS_PUSH(undo_logfn = ksprintf("%s/undo", logfn)) == NULL) {
		perror("unco");
		goto Exit;
	}
	if (is_redo != (stat(undo_logfn, &st) == 0)) {
		if (is_redo) {
			fprintf(stderr, "aborting; the recorded changes has not been undone\n");
		} else {
			fprintf(stderr, "aborting; the recorded changes has already been undone\n");
		}
		return EX_DATAERR;
	}

	// swap logfn to undo_logfn if is a redo
	if (is_redo)
		logfn = undo_logfn;

	// read the log
	if (consume_log(logfn, _revert_action_handler, &info) != 0) {
		exit = EX_DATAERR;
		goto Exit;
	}

	if (! info.is_finalized)
		fprintf(stderr, "\n    !!! WARNING !!! the command is still running\n\n");

	// setup output
	if (! print) {
		if (KFREE_PTRS_PUSH(unco_cmd_quoted = kshellquote(WITH_BINDIR "/unco")) == NULL) {
			perror("unco");
			exit = EX_OSERR;
			goto Exit;
		}
		if (is_redo) {
			shellcmd = "sh";
		} else {
			// record the undo log
			if (KFREE_PTRS_PUSH(undo_logfn_quoted = kshellquote(undo_logfn)) == NULL
				|| KFREE_PTRS_PUSH(shellcmd = ksprintf("UNCO_UNDO=1 %s record --log=%s -- sh", unco_cmd_quoted, undo_logfn_quoted)) == NULL) {
				perror("unco");
				exit = EX_OSERR;
				goto Exit;
			}
		}
		if ((outfp = popen(shellcmd, "w")) == NULL) {
			perror("failed to invoke sh");
			exit = EX_OSERR;
			goto Exit;
		}
	} else {
		outfp = stdout;
	}
	// dump the commands
	if (info.header != NULL)
		fputs(info.header, outfp);
	for (lines = NULL; (lines = klist_next(&info.lines, lines)) != NULL; ) {
		fputs(lines, outfp);
	}
	// close the pipe
	if (! print) {
		// close the command
		if (pclose(outfp) != 0) {
			exit = EX_OSERR; // error is reported by shell
			goto Exit;
		}
		if (is_redo) {
			// remove undo log
			if (kunlink_recursive(undo_logfn) != 0) {
				kerr_printf("failed to remove undo log at:%s", undo_logfn);
				exit = EX_DATAERR;
				goto Exit;
			}
		} else {
			// finalize the undo
			if ((exit = finalize(undo_logfn)) != 0)
				goto Exit;
		}
	}

	// success
	exit = 0;
Exit:
	KFREE_PTRS();
	free(info.header);
	klist_clear(&info.lines);
	return exit;
}

struct history_info {
	int logindex;
	char *logfn;
	pid_t grep_ppid; // -1 if not filtered
	char *grep_cmd; // NULL if not filtered
	char *grep_cwd; // NULL if not filtered
};

static int _history_action_handler(struct action *action, void *cb_arg)
{
	struct history_info *info = cb_arg;
	int matched, undone;
	char *undo_logfn;
	struct stat st;

	switch (action->type) {
	case ACTION_META:
		matched = 1;
		if (matched && info->grep_ppid != -1 && action->meta.ppid != info->grep_ppid)
			matched = 0;
		if (matched && info->grep_cmd != NULL && strncmp(action->meta.cmd, info->grep_cmd, strlen(info->grep_cmd)) != 0)
			matched = 0;
		if (matched && info->grep_cwd != NULL && strcmp(action->meta.cwd, info->grep_cwd) != 0)
			matched = 0;
		if (matched) {
			if ((undo_logfn = ksprintf("%s/undo", info->logfn)) == NULL) {
				perror("unco");
				return -1;
			}
			undone = stat(undo_logfn, &st) == 0;
			free(undo_logfn);
			printf("%6d %c %s", info->logindex, undone ? '*' : ' ', action->meta.cmd);
			printf("\n");
		}
		return -1; // bail-out
	}

	return 0;
}

static int do_history(int argc, char **argv)
{
	char *unco_dir, *logfn = NULL;
	int logindex;
	struct stat st;
	struct history_info info;

	if ((unco_dir = unco_get_default_dir()) == NULL)
		return EX_OSERR;

	memset(&info, 0, sizeof(info));
	info.grep_ppid = getppid(); // default rule

	// TODO getopt

	printf("index    command (*=undone)\n");
	for (logindex = 1; ; ++logindex) {
		if ((logfn = ksprintf("%s/%d", unco_dir, logindex)) == NULL)
			break;
		info.logindex = logindex;
		info.logfn = logfn;
		if (lstat(logfn, &st) != 0)
			break;
		consume_log(logfn, _history_action_handler, &info);
	}

	free(unco_dir);
	free(logfn);
	return 0;
}

static int do_finalize()
{
	const char *logfn;
	char rdbuf;
	int rdret;

	// prepare and wait
	if ((logfn = getenv("UNCO_LOG")) == NULL) {
		fprintf(stderr, "$UNCO_LOG not set\n");
		return EX_USAGE;
	}
	while ((rdret = read(0, &rdbuf, 1)) != 0) {
		if (rdret == -1 && ! (errno == EAGAIN || errno == EWOULDBLOCK)) {
			perror("I/O error while waiting for stdin to get closed");
			return EX_OSERR;
		}
	}

	// ready to finalize NOW!
	return finalize(logfn);
}

static int help(int retval)
{
	printf(
	    "unco version " UNCO_VERSION "\n"
		"\n"
		"SYNOPSIS:\n"
		"\n"
		"    # records changes to fs made by command\n"
		"    unco record command...\n"
		"\n"
		"    # displays list of the recorded commands\n"
		"    unco history\n"
		"\n"
		"    # undoes the changes specified by the index\n"
		"    unco undo <index>\n"
		"\n");

	return retval;
}

int main(int argc, char **argv)
{
	const char *cmd;

	if (argc == 1)
		return help(0);

	// determine the subcommand handler
	argv++, argc--;
	cmd = *argv++, argc--;
	if (strcmp(cmd, "record") == 0)
		return do_record(argc, argv);
	else if (strcmp(cmd, "undo") == 0)
		return do_revert(argc, argv, 0);
	else if (strcmp(cmd, "redo") == 0)
		return do_revert(argc, argv, 1);
	else if (strcmp(cmd, "history") == 0)
		return do_history(argc, argv);
	else if (strcmp(cmd, "_finalize") == 0)
		return do_finalize();
	else if (strcmp(cmd, "help") == 0)
		return help(0);
	else
		return help(EX_USAGE);
}
