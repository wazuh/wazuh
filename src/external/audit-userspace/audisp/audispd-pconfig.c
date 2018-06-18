/* audispd-pconfig.c -- 
 * Copyright 2007,2010,2015 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 * 
 */

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include "audispd-pconfig.h"
#include "private.h"

/* Local prototypes */
struct nv_pair
{
	const char *name;
	const char *value;
	const char *option;
};

struct kw_pair 
{
	const char *name;
	int (*parser)(struct nv_pair *, int, plugin_conf_t *);
	int max_options;
};

struct nv_list
{ 
	const char *name;
	int option;
};

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
		const char *file);
static int nv_split(char *buf, struct nv_pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int active_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config);
static int direction_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config);
static int path_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config);
static int service_type_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config);
static int args_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config);
static int format_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config);
static int sanity_check(plugin_conf_t *config, const char *file);

static const struct kw_pair keywords[] = 
{
  {"active",                   active_parser,			0 },
  {"direction",                direction_parser,		0 },
  {"path",                     path_parser,			0 },
  {"type",                     service_type_parser,		0 },
  {"args",                     args_parser,			2 },
  {"format",                   format_parser,			0 },
  { NULL,                      NULL,				0 }
};

static const struct nv_list active[] =
{
  {"yes",  A_YES },
  {"no",   A_NO },
  { NULL,  0 }
};

static const struct nv_list directions[] =
{
//  {"in",   D_IN },	FIXME: not supported yet
  {"out",  D_OUT },
  { NULL,  0 }
};

static const struct nv_list service_type[] =
{
  {"builtin",  S_BUILTIN },
  {"always",   S_ALWAYS },
  { NULL,  0 }
};

static const struct nv_list formats[] =
{
  {"binary",  F_BINARY },
  {"string",  F_STRING },
  { NULL,  0 }
};

/*
 * Set everything to its default value
*/
void clear_pconfig(plugin_conf_t *config)
{
	int i;

	config->active = A_NO;
	config->direction = D_UNSET;
	config->path = NULL;
	config->type = S_ALWAYS;
	for (i=0; i< (MAX_PLUGIN_ARGS + 2); i++)
		config->args[i] = NULL;
	config->format = F_STRING;
	config->plug_pipe[0] = -1;
	config->plug_pipe[1] = -1;
	config->pid = 0;
	config->inode = 0;
	config->checked = 0;
	config->name = NULL;
	config->restart_cnt = 0;
}

int load_pconfig(plugin_conf_t *config, char *file)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[160];

	clear_pconfig(config);

	/* open the file */
	mode = O_RDONLY;
	rc = open(file, mode);
	if (rc < 0) {
		if (errno != ENOENT) {
			audit_msg(LOG_ERR, "Error opening %s (%s)", file,
				strerror(errno));
			return 1;
		}
		audit_msg(LOG_WARNING,
			"Config file %s doesn't exist, skipping", file);
		return 0;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	if (fstat(fd, &st) < 0) {
		audit_msg(LOG_ERR, "Error fstat'ing config file (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		audit_msg(LOG_ERR, "Error - %s isn't owned by root", 
			file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		audit_msg(LOG_ERR, "Error - %s is world writable", 
			file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		audit_msg(LOG_ERR, "Error - %s is not a regular file", 
			file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		audit_msg(LOG_ERR, "Error - fdopen failed (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf, sizeof(buf), &lineno, file)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				audit_msg(LOG_ERR, 
				"Wrong number of arguments for line %d in %s", 
					lineno, file);
				break;
			case 2: // no '=' sign
				audit_msg(LOG_ERR, 
					"Missing equal sign for line %d in %s", 
					lineno, file);
				break;
			default: // something else went wrong... 
				audit_msg(LOG_ERR, 
					"Unknown error for line %d in %s", 
					lineno, file);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			audit_msg(LOG_ERR, 
				"Unknown keyword \"%s\" in line %d of %s", 
				nv.name, lineno, file);
			fclose(f);
			return 1;
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			audit_msg(LOG_ERR, 
				"Keyword \"%s\" has invalid option "
				"\"%s\" in line %d of %s", 
				nv.name, nv.option, lineno, file);
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(&nv, lineno, config);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}

		lineno++;
	}

	fclose(f);
	config->name = strdup(basename(file));
	if (lineno > 1)
		return sanity_check(config, file);
	return 0;
}

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
	 const char *file)
{
	int too_long = 0;

	while (fgets_unlocked(buf, size, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr) {
			if (!too_long) {
				*ptr = 0;
				return buf;
			}
			// Reset and start with the next line
			too_long = 0;
			*lineno = *lineno + 1;
		} else {
			// If a line is too long skip it.
			// Only output 1 warning
			if (!too_long)
				audit_msg(LOG_ERR,
					"Skipping line %d in %s: too long",
					*lineno, file);
			too_long = 1;
		}
	}
	return NULL;
}

static int nv_split(char *buf, struct nv_pair *nv)
{
	/* Get the name part */
	char *ptr, *saved;

	nv->name = NULL;
	nv->value = NULL;
	nv->option = NULL;
	ptr = strtok_r(buf, " ", &saved);
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = strtok_r(NULL, " ", &saved);
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = strtok_r(NULL, " ", &saved);
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* See if there's an option */
	ptr = strtok_r(NULL, " ", &saved);
	if (ptr) {
		nv->option = ptr;

		/* Make sure there's nothing else */
		ptr = strtok_r(NULL, " ", &saved);
		if (ptr)
			return 1;
	}

	/* Everything is OK */
	return 0;
}

static const struct kw_pair *kw_lookup(const char *val)
{
	int i = 0;
	while (keywords[i].name != NULL) {
		if (strcasecmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}
 
static int active_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config)
{
	int i;

	for (i=0; active[i].name != NULL; i++) {
		if (strcasecmp(nv->value, active[i].name) == 0) {
			config->active = active[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int direction_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config)
{
	int i;

	for (i=0; directions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, directions[i].name) == 0) {
			config->direction = directions[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int path_parser(struct nv_pair *nv, int line,
	plugin_conf_t *config)
{
	char *dir = NULL, *tdir;
	struct stat buf;

	if (nv->value == NULL) {
		config->path = NULL;
		return 0;
	}

	if (strncasecmp(nv->value, "builtin_", 8) == 0) {
		config->path = strdup(nv->value);
		return 0;
	}

	/* get dir form name. */
	tdir = strdup(nv->value);
	if (tdir)
		dir = dirname(tdir);
	if (dir == NULL || strlen(dir) < 4) { //  '/var' is shortest dirname
		audit_msg(LOG_ERR,
			"The directory name: %s is too short - line %d",
			dir, line);
		free(tdir);
		return 1;
	}

	free((void *)tdir);
	/* If the file exists, see that its regular, owned by root,
	 * and not world anything */
	if (stat(nv->value, &buf) < 0) {
		audit_msg(LOG_ERR, "Unable to stat %s (%s)", nv->value,
			strerror(errno));
		return 1;
	}
	if (!S_ISREG(buf.st_mode)) {
		audit_msg(LOG_ERR, "%s is not a regular file", nv->value);
		return 1;
	}
	if (buf.st_uid != 0) {
		audit_msg(LOG_ERR, "%s is not owned by root", nv->value);
		return 1;
	}
	if ((buf.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP)) !=
			   (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP)) {
		audit_msg(LOG_ERR, "%s permissions should be 0750", nv->value);
		return 1;
	}
	free((void *)config->path);
	config->path = strdup(nv->value);
	config->inode = buf.st_ino;
	if (config->path == NULL)
		return 1;
	return 0;
}

static int service_type_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config)
{
	int i;

	for (i=0; service_type[i].name != NULL; i++) {
		if (strcasecmp(nv->value, service_type[i].name) == 0) {
			config->type = service_type[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int args_parser(struct nv_pair *nv, int line,
	plugin_conf_t *config)
{
	int i;

	for (i=0; i < (MAX_PLUGIN_ARGS + 2); i++) {
		free((void *)config->args[i]);
		config->args[i] = NULL;
	}

	config->args[1] = strdup(nv->value);
	if (nv->option)
		config->args[2] = strdup(nv->option);
	return 0;
}

static int format_parser(struct nv_pair *nv, int line, 
		plugin_conf_t *config)
{
	int i;

	for (i=0; formats[i].name != NULL; i++) {
		if (strcasecmp(nv->value, formats[i].name) == 0) {
			config->format = formats[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

/*
 * This function is where we do the integrated check of the audispd config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(plugin_conf_t *config, const char *file)
{
	/* Error checking */
	if (config->active == A_YES && config->path == NULL) {
		audit_msg(LOG_ERR, 
		    "Error - plugin (%s) is active but no path given", file);
		return 1;
	}
	return 0;
}

void free_pconfig(plugin_conf_t *config)
{
	int i;

	if (config == NULL)
		return;

	for (i=0; i < (MAX_PLUGIN_ARGS + 2); i++)
		free(config->args[i]);
	if (config->plug_pipe[0] >= 0)
		close(config->plug_pipe[0]);
	if (config->plug_pipe[1] >= 0)
		close(config->plug_pipe[1]);
	free((void *)config->path);
	free((void *)config->name);
}

