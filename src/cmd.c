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
#include "config.h"
#include "unco.h"

// http://www.freebsd.org/cgi/man.cgi?query=sysexits
#ifndef EX_USAGE
# define EX_USAGE 64
#endif
#ifndef EX_DATAERR
# define EX_DATAERR 65
#endif
#ifndef EX_OSERR
# define EX_OSERR 71
#endif

struct metainfo {
	char cmd[4096];
	char cwd[PATH_MAX];
	pid_t pid;
	pid_t ppid;
};

struct script {
	struct script *next;
	char block[PATH_MAX * 10];
};

static int prepend_script(struct script **script, const char *fmt, ...)
{
	struct script *head;
	va_list arg;

	if ((head = (struct script *)malloc(sizeof(struct script))) == NULL) {
		perror("");
		return -1;
	}
	head->next = *script;

	va_start(arg, fmt);
	vsnprintf(head->block, sizeof(head->block), fmt, arg);
	va_end(arg);

	*script = head;

	return 0;
}

static void free_script(struct script *script)
{
	struct script *t;

	while (script != NULL) {
		t = script->next;
		free(script);
		script = t;
	}
}

static char *read_argfn_quoted(struct uncolog_fp *ufp)
{
	char *raw, *quoted;
	size_t raw_idx, quoted_idx;

	if ((raw = (char *)uncolog_read_argbuf(ufp, NULL)) == NULL)
		return NULL;

	// empty string => ''
	if (raw[0] == '\0') {
		quoted = strdup("''");
		goto Exit;
	}

	if ((quoted = (char *)malloc(strlen(raw) * 2 + 1)) == NULL) {
		perror("");
		goto Exit;
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

Exit:
	free(raw);
	return quoted;
}

static int on_meta(struct uncolog_fp *ufp, int argc, struct metainfo *meta)
{
	char *sarg;
	off_t narg;

#define READ_STRARG(n) \
	do { \
		if ((sarg = (char *)uncolog_read_argbuf(ufp, NULL)) == NULL) \
			return -1; \
		snprintf(meta->n, sizeof(meta->n), "%s", sarg); \
		free(sarg); \
	} while (0)
#define READ_NARG(n) \
	do { \
		if (uncolog_read_argn(ufp, &narg) != 0) \
			return -1; \
		meta->n = narg; \
	} while (0)

	assert(argc == 4);
	READ_STRARG(cmd);
	READ_STRARG(cwd);
	READ_NARG(pid);
	READ_NARG(ppid);

	return 0;

#undef READ_STRARG
#undef READ_NARG
}

static int on_create(struct uncolog_fp *ufp, int argc, struct script **script)
{
	char *path_quoted = NULL;
	int ret = -1;

	// read the args
	assert(argc == 1);
	if ((path_quoted = read_argfn_quoted(ufp)) == NULL)
		goto Exit;
	// print cmd
	ret = prepend_script(script,
		"# revert create\n"
		"rm %s || exit 1\n",
		path_quoted);

Exit:
	free(path_quoted);
	return ret;
}

static int on_overwrite(struct uncolog_fp *ufp, int argc, struct script **script)
{
	char *target_quoted = NULL, *backup_quoted = NULL;
	int ret = -1;

	// read the args
	assert(argc == 2);
	if ((target_quoted = read_argfn_quoted(ufp)) == NULL
		|| (backup_quoted = read_argfn_quoted(ufp)) == NULL)
		goto Exit;
	// print cmd
	ret = prepend_script(script,
		"# revert overwrite\n"
		"ls %s > /dev/null || exit 1\n" // target should exist
		"cat %s > %s || exit 1\n",
		target_quoted, backup_quoted, target_quoted);
	// TODO: adjust mtime

Exit:
	free(target_quoted);
	free(backup_quoted);
	return ret;
}

static int on_rename(struct uncolog_fp *ufp, int argc, struct script **script)
{
	char *old_quoted = NULL, *new_quoted = NULL, *backup_quoted = NULL;
	int ret = -1;

	// read the args
	assert(argc == 2 || argc == 3);
	if ((old_quoted = read_argfn_quoted(ufp)) == NULL
		|| (new_quoted = read_argfn_quoted(ufp)) == NULL
		|| (argc == 3 && (backup_quoted = read_argfn_quoted(ufp)) == NULL))
		goto Exit;
	// print cmd
	if (argc == 2) {
		ret = prepend_script(script,
			"# revert rename\n"
			"mv -n %s %s || exit 1\n",
			new_quoted, old_quoted);
	} else {
		ret = prepend_script(script,
			"# revert rename (replacing)\n"
			"mv -n %s %s || exit 1\n"
			"cat %s > %s || exit 1\n",
			new_quoted, old_quoted, backup_quoted, new_quoted);
	}

Exit:
	free(old_quoted);
	free(new_quoted);
	return ret;
}

static int on_unlink(struct uncolog_fp *ufp, int argc, struct script **script)
{
	char *path_quoted = NULL, *backup_quoted = NULL;
	int ret = -1;

	assert(argc == 2);
	// read the args
	if ((path_quoted = read_argfn_quoted(ufp)) == NULL
		|| (backup_quoted = read_argfn_quoted(ufp)) == NULL)
		goto Exit;
	// print cmd
	ret = prepend_script(script,
		"# revert unlink\n"
		"ln %s %s || exit 1\n",
		backup_quoted, path_quoted);

Exit:
	free(path_quoted);
	free(backup_quoted);
	return ret;
}

static int consume_log(const char *logpath, struct metainfo *meta, struct script **script)
{
	struct uncolog_fp _ufp, *ufp = &_ufp;
	char action[256];
	int action_argc, found_meta = 0, ret = -1;

	if (uncolog_open(ufp, logpath, 'r', open, mkdir) != 0)
		return -1;

	*script = NULL;
	while (uncolog_read_action(ufp, action, &action_argc) == 0) {
		if (strcmp(action, "meta") == 0) {
			found_meta = 1;
			if (on_meta(ufp, action_argc, meta))
				goto Exit;
		} else if (strcmp(action, "create") == 0) {
			if (on_create(ufp, action_argc, script))
				goto Exit;
		} else if (strcmp(action, "overwrite") == 0) {
			if (on_overwrite(ufp, action_argc, script))
				goto Exit;
		} else if (strcmp(action, "rename") == 0) {
			if (on_rename(ufp, action_argc, script))
				goto Exit;
		} else if (strcmp(action, "unlink") == 0) {
			if (on_unlink(ufp, action_argc, script))
				goto Exit;
		} else {
			fprintf(stderr, "unknown action:%s\n", action);
			goto Exit;
		}
	}
	if (! found_meta) {
		fprintf(stderr, "mandatory action:meta is missing\n");
		goto Exit;
	}
	// TODO check eof

	ret = 0;
Exit:
	uncolog_close(ufp);
	if (ret != 0) {
		free_script(*script);
		*script = NULL;
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
	const char *log_file;
	int opt_ch, append = 0;
	char uncodir[PATH_MAX], fnbuf[PATH_MAX];
	long long logindex;

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
		} else {
			if (unco_get_default_dir(uncodir) != 0
				|| (logindex = unco_get_next_logindex(uncodir)) == -1)
				return EX_DATAERR;
			snprintf(fnbuf, sizeof(fnbuf), "%s/%lld", uncodir, logindex);
			log_file = fnbuf;
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

static int do_revert(int argc, char **argv)
{
	static struct option longopts[] = {
		{ "log", required_argument, NULL, 'l' },
		{ "run", no_argument, NULL, 'r' },
		{ NULL }
	};
	const char *log_file;
	int opt_ch, run = 0;
	struct metainfo meta;
	struct script *script = NULL, *script_block;
	FILE *outfp;

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
			return EX_USAGE;
		}
	}
	if (log_file == NULL) {
		fprintf(stderr, "missing mandatory option: --log\n");
		return EX_USAGE;
	}
	argc -= optind - 1;
	argv += optind - 1;

	// read the log
	if (consume_log(log_file, &meta, &script) != 0)
		return EX_DATAERR;

	// setup output
	if (run) {
		if ((outfp = popen("sh", "w")) == NULL) {
			perror("failed to invoke sh");
			return EX_OSERR;
		}
	} else {
		outfp = stdout;
	}
	// dump the commands
	fprintf(stderr,
		"# generated by unco version " UNCO_VERSION "\n"
		"#\n"
		"# undo script for:\n"
		"#   cmd:  %s\n"
		"#   cwd:  %s\n"
		"#   pid:  %d\n"
		"#   ppid: %d\n"
		"#\n"
		"\n",
		meta.cmd, meta.cwd, (int)meta.pid, (int)meta.ppid);
	for (script_block = script; script_block != NULL; script_block = script_block->next) {
		fputs(script_block->block, outfp);
	}
	// close outfp
	if (run)
		pclose(outfp);

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
		"    unco record --log=<log-path> command...\n"
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
	else if (strcmp(cmd, "help") == 0)
		return help(0);
	else
		return help(EX_USAGE);
}
