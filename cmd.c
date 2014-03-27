#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "unco.h"

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

static int consume_log(const char *logpath, struct script** script)
{
	struct uncolog_fp _ufp, *ufp = &_ufp;
	char action[256];
	int action_argc, ret = -1;

	if (uncolog_open(ufp, logpath, 'r', open, mkdir) != 0)
		return -1;

	*script = NULL;
	while (uncolog_read_action(ufp, action, &action_argc) == 0) {
		int (*handler)(struct uncolog_fp *ufp, int argc, struct script **script);
		if (strcmp(action, "create") == 0)
			handler = on_create;
		else if (strcmp(action, "overwrite") == 0)
			handler = on_overwrite;
		else if (strcmp(action, "rename") == 0)
			handler = on_rename;
		else if (strcmp(action, "unlink") == 0)
			handler = on_unlink;
		else {
			fprintf(stderr, "unknown action:%s\n", action);
			goto Exit;
		}
		if (handler(ufp, action_argc, script) != 0)
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

int main(int argc, char **argv)
{
	// TODO check argv
	if (argc == 3 && strcmp(argv[1], "undo") == 0) {
		struct script *script, *script_block;
		if (consume_log(argv[2], &script) != 0)
			return 2;
		for (script_block = script; script_block != NULL; script_block = script_block->next)
			fputs(script_block->block, stdout);
	} else {
		fprintf(stderr, "Usage: %s undo <undo-log>\n", argv[0]);
		return 1;
	}

	return 0;
}
