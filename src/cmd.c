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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
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

#define FREE_PTRS_INIT(n) \
	void *free_ptrs[n]; \
	int free_ptr_index = 0
#define FREE_PTRS() \
	do { \
		if (free_ptr_index != 0) \
			do \
				free(free_ptrs[--free_ptr_index]); \
			while (free_ptr_index != 0); \
	} while (0)
#define FREE_PTRS_PUSH(p) (free_ptrs[free_ptr_index++] = (p))

struct action {
	char name[256];
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
			char *path;
			char *sha1hex;
		} finalize_filehash;
		struct {
			char *path;
		} finalize_fileremove;
	};
};

static char *shellquote(const char *raw)
{
	char *quoted;
	int raw_idx, quoted_idx;

	// empty string => ''
	if (raw[0] == '\0')
		return strdup("''");

	if ((quoted = (char *)malloc(strlen(raw) * 2 + 1)) == NULL) {
		perror("");
		return NULL;
	}
	quoted_idx = 0;
	for (raw_idx = 0; raw[raw_idx] != '\0'; ++raw_idx) {
		if (isalnum(raw[raw_idx])) {
			// ok
		} else if (strchr("!%+,-./:@^", raw[raw_idx]) != NULL) {
			// ok
		} else {
			// needs backslash
			quoted[quoted_idx++] = '\\';
		}
		quoted[quoted_idx++] = raw[raw_idx];
	}
	quoted[quoted_idx++] = '\0';

	return quoted;
}

static char *prepend_printf(struct uncolist *l, const char *fmt, ...)
{
	va_list arg;
	char buf[16384];

	va_start(arg, fmt);
	vsnprintf(buf, sizeof(buf), fmt, arg);
	va_end(arg);

	return uncolist_insert(l, uncolist_next(l, NULL), buf, strlen(buf) + 1);
}

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
	while ((rlen = unco_read_nosig(fd, buf, sizeof(buf))) != 0) {
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
		FREE_PTRS_PUSH(dst); \
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
	int found_meta = 0, ret = -1;

	FREE_PTRS_INIT(16);

	if (uncolog_open(ufp, logpath, 'r', open, mkdir) != 0)
		return -1;

	while (1) {
		memset(&action, 0, sizeof(action));
		if (uncolog_read_action(ufp, action.name, &action.argc) != 0)
			break;
		if (strcmp(action.name, "meta") == 0) {
			assert(action.argc == 4);
			READ_ARGSTR(action.meta.cmd);
			READ_ARGSTR(action.meta.cwd);
			READ_ARGN(action.meta.pid);
			READ_ARGN(action.meta.ppid);
			found_meta = 1;
		} else if (strcmp(action.name, "create") == 0) {
			assert(action.argc == 1);
			READ_ARGSTR(action.create.path);
		} else if (strcmp(action.name, "overwrite") == 0) {
			assert(action.argc == 2);
			READ_ARGSTR(action.overwrite.path);
			READ_ARGSTR(action.overwrite.backup);
		} else if (strcmp(action.name, "rename") == 0) {
			assert(action.argc == 2 || action.argc == 3);
			READ_ARGSTR(action.rename.old);
			READ_ARGSTR(action.rename.new);
			if (action.argc == 3)
				READ_ARGSTR(action.rename.backup);
		} else if (strcmp(action.name, "unlink") == 0) {
			assert(action.argc == 2);
			READ_ARGSTR(action.unlink.path);
			READ_ARGSTR(action.unlink.backup);
		} else if (strcmp(action.name, "finalize_filehash") == 0) {
			assert(action.argc == 2);
			READ_ARGSTR(action.finalize_filehash.path);
			READ_ARGSTR(action.finalize_filehash.sha1hex);
		} else if (strcmp(action.name, "finalize_fileremove") == 0) {
			assert(action.argc == 1);
			READ_ARGSTR(action.finalize_fileremove.path);
		} else if (strcmp(action.name, "finalize") == 0) {
			assert(action.argc == 0);
		} else {
			fprintf(stderr, "unknown action:%s\n", action.name);
			goto Exit;
		}
		if (cb(&action, cb_arg) != 0)
			goto Exit;
		FREE_PTRS();
	}
	if (! found_meta) {
		fprintf(stderr, "mandatory action:meta is missing\n");
		goto Exit;
	}
	// TODO check eof

	ret = 0;
Exit:
	FREE_PTRS();
	uncolog_close(ufp);
	return ret;

#undef READ_ARGSTR
#undef READ_ARGN
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
			if (uncolog_delete(log_file, 1) != 0)
				return EX_OSERR;
		}
	}

	// set environment variables and exec
	setenv("DYLD_INSERT_LIBRARIES", WITH_LIBDIR "/libunco-preload.dylib", 1);
	setenv("DYLD_FORCE_FLAT_NAMESPACE", "YES", 1);
	if (log_file != NULL)
		setenv("UNCO_LOG", log_file, 1);
	execvp(argv[0], argv);
	fprintf(stderr, "failed to exec:%s:%d\n", argv[0], errno);
	return 127; // FIXME what is the right code?
}

struct revert_info {
	struct uncolist lines;
	int is_finalized;
	char header[8192];
};

static int _revert_action_handler(struct action *action, void *cb_arg)
{
	struct revert_info *info = cb_arg;
	int ret = -1;
	FREE_PTRS_INIT(16);

	if (strcmp(action->name, "meta") == 0) {

		snprintf(info->header, sizeof(info->header) - 1,
			"# generated by unco version " UNCO_VERSION "\n"
			"#\n"
			"# undo script for:\n"
			"#   cmd:  %s\n"
			"#   cwd:  %s\n"
			"#   pid:  %d\n"
			"#   ppid: %d\n"
			"#\n",
			action->meta.cmd, action->meta.cwd, (int)action->meta.pid, (int)action->meta.ppid);
		strcat(info->header, "\n");

	} else if (strcmp(action->name, "create") == 0) {

		char *path_quoted;

		if (FREE_PTRS_PUSH((path_quoted = shellquote(action->create.path))) == NULL)
			goto Exit;
		if (prepend_printf(&info->lines,
				"# revert create\n"
				"rm %s || exit 1\n",
				path_quoted) == NULL)
			goto Exit;

	} else if (strcmp(action->name, "overwrite") == 0) {

		char *path_quoted, *backup_quoted;

		if (FREE_PTRS_PUSH(path_quoted = shellquote(action->overwrite.path)) == NULL
			|| FREE_PTRS_PUSH(backup_quoted = shellquote(action->overwrite.backup)) == NULL)
			goto Exit;
		if (prepend_printf(&info->lines,
				"# revert overwrite\n"
				"ls %s > /dev/null || exit 1\n" // target should exist
				"cat %s > %s || exit 1\n",
				path_quoted, backup_quoted, path_quoted) == NULL)
			goto Exit;
		// TODO: adjust mtime

	} else if (strcmp(action->name, "rename") == 0) {

		char *old_quoted, *new_quoted, *backup_quoted;

		if (FREE_PTRS_PUSH(old_quoted = shellquote(action->rename.old)) == NULL
			|| FREE_PTRS_PUSH(new_quoted = shellquote(action->rename.new)) == NULL)
			goto Exit;
		if (action->rename.backup == NULL) {
			if (prepend_printf(&info->lines,
					"# revert rename\n"
					"mv -n %s %s || exit 1\n",
					new_quoted, old_quoted) == NULL)
				goto Exit;
		} else {
			if (FREE_PTRS_PUSH(backup_quoted = shellquote(action->rename.backup)) == NULL)
				goto Exit;
			if (prepend_printf(&info->lines,
					"# revert rename (replacing)\n"
					"mv -n %s %s || exit 1\n"
					"cat %s > %s || exit 1\n",
					new_quoted, old_quoted, backup_quoted, new_quoted) == NULL)
				goto Exit;
		}

	} else if (strcmp(action->name, "unlink") == 0) {

		char *path_quoted, *backup_quoted;

		if (FREE_PTRS_PUSH(path_quoted = shellquote(action->overwrite.path)) == NULL
			|| FREE_PTRS_PUSH(backup_quoted = shellquote(action->overwrite.backup)) == NULL)
			goto Exit;
		if (prepend_printf(&info->lines,
				"# revert unlink\n"
				"ln %s %s || exit 1\n",
				backup_quoted, path_quoted) == NULL)
			goto Exit;

	} else if (strcmp(action->name, "finalize_filehash") == 0) {

		char *path_quoted;

		if (FREE_PTRS_PUSH(path_quoted = shellquote(action->finalize_filehash.path)) == NULL)
			goto Exit;
		if (prepend_printf(&info->lines,
				"# check that file has not been altered since the recorded change\n"
				"SHA1HEX=`openssl sha1 < %s`\n"
				"[ $? -eq 0 ] || exit 1\n"
				"if [ \"$SHA1HEX\" != \"%s\" ] ; then\n"
				"    echo 'file altered since recorded change:%s' >&2\n"
				"    exit 1\n"
				"fi\n",
				path_quoted, action->finalize_filehash.sha1hex, path_quoted) == NULL)
			goto Exit;

	} else if (strcmp(action->name, "finalize_fileremove") == 0) {

		char *path_quoted;

		if (FREE_PTRS_PUSH(path_quoted = shellquote(action->finalize_fileremove.path)) == NULL)
			goto Exit;
		if (prepend_printf(&info->lines,
				"# check that file has not been recreated since the recorded removal\n"
				"if [ -e %s ] ; then\n"
				"    echo 'file recreated since recorded removal:%s' >&2\n"
				"    exit 1\n"
				"fi\n",
				path_quoted, path_quoted) == NULL)
			goto Exit;

	} else if (strcmp(action->name, "finalize") == 0) {

		info->is_finalized = 1;

	} else {

		fprintf(stderr, "unknown action:%s\n", action->name);
		goto Exit;

	}

	// success
	ret = 0;
Exit:
	FREE_PTRS();
	return ret;
}

static int do_revert(int argc, char **argv)
{
	static struct option longopts[] = {
		{ "log", required_argument, NULL, 'l' },
		{ "run", no_argument, NULL, 'r' },
		{ NULL }
	};
	const char *log_file, *lines;
	int opt_ch, run = 0, exit = EX_SOFTWARE;
	struct revert_info info;
	FILE *outfp;

	memset(&info, 0, sizeof(info));

	// fetch opts
	while ((opt_ch = getopt_long(argc + 1, argv - 1, "l:r", longopts, NULL)) != -1) {
		switch (opt_ch) {
		case 'l':
			log_file = optarg;
			break;
		case 'r':
			run = 1;
			break;
		default:
			fprintf(stderr, "unknown option: %c\n", opt_ch);
			exit = EX_USAGE;
			goto Exit;
		}
	}
	if (log_file == NULL) {
		fprintf(stderr, "missing mandatory option: --log\n");
		exit = EX_USAGE;
		goto Exit;
	}
	argc -= optind - 1;
	argv += optind - 1;

	// read the log
	if (consume_log(log_file, _revert_action_handler, &info) != 0) {
		exit = EX_DATAERR;
		goto Exit;
	}

	if (! info.is_finalized)
		fprintf(stderr, "\n    !!! WARNING !!! the command is still running\n\n");

	// setup output
	if (run) {
		if ((outfp = popen("sh", "w")) == NULL) {
			perror("failed to invoke sh");
			exit = EX_OSERR;
			goto Exit;
		}
	} else {
		outfp = stdout;
	}
	// dump the commands
	fputs(info.header, outfp);
	for (lines = NULL; (lines = uncolist_next(&info.lines, lines)) != NULL; ) {
		fputs(lines, outfp);
	}
	// close the pipe
	if (run) {
		if (pclose(outfp) != 0)
			exit = EX_OSERR; // error is reported by shell
	}

	// success
	exit = 0;
Exit:
	uncolist_clear(&info.lines);
	return exit;
}

struct finalize_info {
	struct uncolist existing_files;
	struct uncolist removed_files;
	int is_finalized;
};

static int _finalize_mark_file_in_list(struct uncolist *l, const char *fn, int exists)
{
	char *item;

	for (item = NULL; (item = uncolist_next(l, item)) != NULL; )
		if (strcpy(item, fn) == 0)
			break;

	if ((item != NULL) != exists) {
		if (exists) {
			if (uncolist_insert(l, NULL, fn, strlen(fn) + 1) == NULL)
				return -1;
		} else {
			uncolist_erase(l, item);
		}
	}

	return 0;
}

static int _finalize_mark_file(struct finalize_info *info, const char* fn, int exists)
{
	if (_finalize_mark_file_in_list(&info->existing_files, fn, exists) != 0
		|| _finalize_mark_file_in_list(&info->removed_files, fn, ! exists) != 0)
		return -1;
	return 0;
}

static int _finalize_action_handler(struct action *action, void *cb_arg)
{
	struct finalize_info *info = cb_arg;

	if (strcmp(action->name, "meta") == 0) {
		// skip
	} else if (strcmp(action->name, "create") == 0) {
		if (_finalize_mark_file(info, action->create.path, 1) != 0)
			return -1;
	} else if (strcmp(action->name, "overwrite") == 0) {
		if (_finalize_mark_file(info, action->overwrite.path, 1) != 0)
			return -1;
	} else if (strcmp(action->name, "rename") == 0) {
		if (_finalize_mark_file(info, action->rename.old, 0) != 0
			|| _finalize_mark_file(info, action->rename.new, 1) != 0)
			return -1;
	} else if (strcmp(action->name, "unlink") == 0) {
		if (_finalize_mark_file(info, action->unlink.path, 0) != 0)
			return -1;
	} else if (strncmp(action->name, "finalize_", sizeof("finalize_") - 1) == 0
		|| strcmp(action->name, "finalize") == 0) {
		fprintf(stderr, "log is already finalized\n");
		return -1;
	} else {
		fprintf(stderr, "unknown action:%s\n", action->name);
		return -1;
	}

	return 0;
}

static int _finalize_append_action(struct uncolog_fp* ufp, struct finalize_info* info)
{
	const char *fn;
	char sha1hex[SHA1HashSize * 2 + 1];
	struct stat st;

	// append existing files
	for (fn = NULL; (fn = uncolist_next(&info->existing_files, fn)) != NULL; ) {
		if (sha1hex_file(fn, sha1hex) != 0) {
			uncolog_set_error(ufp, "failed to sha1 file:%s:%d\n", fn, errno);
			return -1;
		}
		if (uncolog_write_action(ufp, "finalize_filehash", 2) != 0
			|| uncolog_write_argbuf(ufp, fn, strlen(fn)) != 0
			|| uncolog_write_argbuf(ufp, sha1hex, strlen(sha1hex)) != 0)
			return -1;
	}
	// append removed files
	for (fn = NULL; (fn = uncolist_next(&info->removed_files, fn)) != NULL; ) {
		if (lstat(fn, &st) == 0) {
			uncolog_set_error(ufp, "unexpected condition, file logged as being removed exists:%s\n", fn);
			return -1;
		}
		if (uncolog_write_action(ufp, "finalize_fileremove", 1) != 0
			|| uncolog_write_argbuf(ufp, fn, strlen(fn)) != 0)
			return -1;
	}

	// append action
	if (uncolog_write_action(ufp, "finalize", 0) != 0)
		return -1;

	return 0;
}

static int do_finalize()
{
	const char *logfn;
	char rdbuf;
	int rdret;
	struct finalize_info info;
	struct uncolog_fp ufp;

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

	// determine the files that should be finalized
	memset(&info, 0, sizeof(info));
	if (consume_log(logfn, _finalize_action_handler, &info) != 0)
		return EX_DATAERR;

	// open log and finalize
	if (uncolog_open(&ufp, logfn, 'a', open, mkdir) != 0)
		return EX_SOFTWARE;
	if (_finalize_append_action(&ufp, &info) != 0) {
		uncolog_close(&ufp);
		return EX_OSERR;
	}
	uncolog_close(&ufp);

	return 0;
}

static int help(int retval)
{
	printf(
	    "unco version " UNCO_VERSION "\n"
		"\n"
		"SYNOPSIS:\n"
		"\n"
		"    # records changes to fs made by command\n"
		"    unco record [--log=<log-path>] command...\n"
		"\n"
		"    # displays shell-script to undo the changes\n"
		"    unco revert --log=<log-path>\n"
		"\n"
		"    # actually undoes the recorded changes\n"
		"    unco revert --log=<log-path> --run\n"
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
	else if (strcmp(cmd, "revert") == 0)
		return do_revert(argc, argv);
	else if (strcmp(cmd, "_finalize") == 0)
		return do_finalize();
	else if (strcmp(cmd, "help") == 0)
		return help(0);
	else
		return help(EX_USAGE);
}
