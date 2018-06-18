/* audispd-config.c -- 
 * Copyright 2007-08,2010,2014-15 Red Hat Inc., Durham, North Carolina.
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
#include <ctype.h>
#include <limits.h>
#include "audispd-config.h"
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
	int (*parser)(struct nv_pair *, int, daemon_conf_t *);
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
static int q_depth_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config);
static int name_format_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config);
static int name_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config);
static int overflow_action_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config);
static int priority_boost_parser(struct nv_pair *nv, int line,
		daemon_conf_t *config);
static int max_restarts_parser(struct nv_pair *nv, int line,
		daemon_conf_t *config);
static int plugin_dir_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config);
static int sanity_check(daemon_conf_t *config, const char *file);

static const struct kw_pair keywords[] = 
{
  {"q_depth",                  q_depth_parser,			0 },
  {"name_format",              name_format_parser,		0 },
  {"name",                     name_parser,			0 },
  {"overflow_action",          overflow_action_parser,		0 },
  {"priority_boost",           priority_boost_parser,		0 },
  {"max_restarts",             max_restarts_parser,		0 },
  {"plugin_dir",               plugin_dir_parser,		0 },
  { NULL,                      NULL,				0 }
};

static const struct nv_list node_name_formats[] =
{
  {"none",      N_NONE },
  {"hostname",  N_HOSTNAME },
  {"fqd",       N_FQD },
  {"numeric",   N_NUMERIC },
  {"user",      N_USER },
  { NULL,  0 }
};

static const struct nv_list overflow_actions[] =
{
  {"ignore",  O_IGNORE },
  {"syslog",  O_SYSLOG },
  {"suspend", O_SUSPEND },
  {"single",  O_SINGLE },
  {"halt",    O_HALT },
  { NULL,     0 }
};

/*
 * Set everything to its default value
*/
void clear_config(daemon_conf_t *config)
{
	config->q_depth = 80;
	config->overflow_action = O_SYSLOG;
	config->priority_boost = 4;
	config->max_restarts = 10;
	config->node_name_format = N_NONE;
	config->name = NULL;
}

int load_config(daemon_conf_t *config, const char *file)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[160];

	clear_config(config);

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
			audit_msg(LOG_ERR, 
				"Not processing any more lines in %s", file);
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
			//  Only output 1 warning
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
 
static int q_depth_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			audit_msg(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}

        /* convert to unsigned long */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		audit_msg(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	if (i > 99999) {
		audit_msg(LOG_ERR, "q_depth must be 99999 or less");
		return 1;
	}
	config->q_depth = i;
	return 0;

}

static int name_format_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config)
{
	int i;

	for (i=0; node_name_formats[i].name != NULL; i++) {
		if (strcasecmp(nv->value, node_name_formats[i].name) == 0) {
			config->node_name_format = node_name_formats[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int name_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config)
{
	if (nv->value == NULL)
		config->name = NULL;
	else
		config->name = strdup(nv->value);
	return 0;
}

static int overflow_action_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config)
{
	int i;

	for (i=0; overflow_actions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, overflow_actions[i].name) == 0) {
                        config->overflow_action = overflow_actions[i].option;
                        return 0;
                }
        }
        audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int priority_boost_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "priority_boost_parser called with: %s",
       				nv->value);

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			audit_msg(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}
	/* convert to unsigned int */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		audit_msg(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	/* Check its range */
	if (i > INT_MAX) {
		audit_msg(LOG_ERR,
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	config->priority_boost = (unsigned int)i;
	return 0;
}

static int max_restarts_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "max_restarts_parser called with: %s",
       				nv->value);

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			audit_msg(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}
	/* convert to unsigned int */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		audit_msg(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	/* Check its range */
	if (i > INT_MAX) {
		audit_msg(LOG_ERR,
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	config->max_restarts = (unsigned int)i;
	return 0;
}

static int plugin_dir_parser(struct nv_pair *nv, int line, 
		daemon_conf_t *config)
{
	if (nv->value == NULL)
		config->plugin_dir = NULL;
	else {
		size_t len = strlen(nv->value);
		config->plugin_dir = malloc(len + 2);
		if (config->plugin_dir) {
			strcpy(config->plugin_dir, nv->value);
			if (config->plugin_dir[len - 1] != '/')
				config->plugin_dir[len] = '/';
			config->plugin_dir[len + 1] = 0;
		}
	}
	return 0;
}

/*
 * This function is where we do the integrated check of the audispd config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(daemon_conf_t *config, const char *file)
{
	/* Error checking */
	if (config->node_name_format == N_USER && config->name == NULL) {
		audit_msg(LOG_ERR, 
	    "Error - node_name_format is user supplied but none given (%s)",
			file);
		return 1;
	}
	if (config->plugin_dir == NULL)
		config->plugin_dir = strdup("/etc/audisp/plugins.d/");
	return 0;
}

void free_config(daemon_conf_t *config)
{
	free((void *)config->name);
	free((void *)config->plugin_dir);
}

