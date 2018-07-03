/*
 *  auditd-config.c - This is a greatly reduced config file parser
 *
 * Copyright 2007,2014,2016 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 * 
 */

#include "config.h"
#include "internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <dirent.h>
#include <ctype.h>

/* Local prototypes */
struct _pair
{
	const char *name;
	const char *value;
};

struct kw_pair 
{
	const char *name;
	int (*parser)(auparse_state_t *, const char *, int,
						struct daemon_conf *);
};

struct nv_list
{ 
	const char *name;
	int option;
};

static char *get_line(auparse_state_t *au, FILE *f, char *buf, unsigned size,
	int *lineno, const char *file);
static int nv_split(char *buf, struct _pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int log_file_parser(auparse_state_t *au, const char *val, int line, 
		struct daemon_conf *config);

static const struct kw_pair keywords[] = 
{
  {"log_file",		log_file_parser },
  { NULL,		NULL }
};

/*
 * Set everything to its default value
*/
void clear_config(struct daemon_conf *config)
{
	config->local_events = 1;
	config->qos = QOS_NON_BLOCKING;
	config->sender_uid = 0;
	config->sender_pid = 0;
	config->sender_ctx = NULL;
	config->write_logs = 1;
	config->log_file = strdup("/var/log/audit/audit.log");
	config->log_format = LF_RAW;
	config->log_group = 0;
	config->priority_boost = 4;
	config->flush =  FT_NONE;
	config->freq = 0;
	config->num_logs = 0L;
	config->dispatcher = NULL;
	config->node_name_format = N_NONE;
	config->node_name = NULL;
	config->max_log_size = 0L;
	config->max_log_size_action = SZ_IGNORE;
	config->space_left = 0L;
	config->space_left_action = FA_IGNORE;
	config->space_left_exe = NULL;
	config->action_mail_acct = NULL;
	config->admin_space_left= 0L;
	config->admin_space_left_action = FA_IGNORE;
	config->admin_space_left_exe = NULL;
	config->disk_full_action = FA_IGNORE;
	config->disk_full_exe = NULL;
	config->disk_error_action = FA_SYSLOG;
	config->disk_error_exe = NULL;
}

int aup_load_config(auparse_state_t *au, struct daemon_conf *config,
		log_test_t lt)
{
	int fd, lineno = 1;
	FILE *f;
	char buf[160];

	clear_config(config);
	lt = lt;

	/* open the file */
	fd = open(CONFIG_FILE, O_RDONLY|O_NOFOLLOW);
	if (fd < 0) {
		if (errno != ENOENT) {
			audit_msg(au, LOG_ERR, "Error opening config file (%s)", 
				strerror(errno));
			return 1;
		}
		audit_msg(au, LOG_WARNING,
			"Config file %s doesn't exist, skipping", CONFIG_FILE);
		return 0;
	}

	/* Make into FILE struct and read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		audit_msg(au, LOG_ERR, "Error - fdopen failed (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(au, f,  buf, sizeof(buf), &lineno, CONFIG_FILE)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct _pair nv;
		int rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				audit_msg(au, LOG_ERR, 
				"Wrong number of arguments for line %d in %s", 
					lineno, CONFIG_FILE);
				break;
			case 2: // no '=' sign
				audit_msg(au, LOG_ERR, 
					"Missing equal sign for line %d in %s", 
					lineno, CONFIG_FILE);
				break;
			default: // something else went wrong... 
				audit_msg(au, LOG_ERR, 
					"Unknown error for line %d in %s", 
					lineno, CONFIG_FILE);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			audit_msg(au, LOG_ERR,
				"Not processing any more lines in %s",
				CONFIG_FILE);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name) {
			/* dispatch to keyword's local parser */
			rc = kw->parser(au, nv.value, lineno, config);
			if (rc != 0) {
				fclose(f);
				return 1; // local parser puts message out
			}
		}

		lineno++;
	}

	fclose(f);
	return 0;
}

static char *get_line(auparse_state_t *au, FILE *f, char *buf, unsigned size,
		int *lineno, const char *file)
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
				audit_msg(au, LOG_ERR,
					"Skipping line %d in %s: too long",
					*lineno, file);
			too_long = 1;
		}
	}
	return NULL;
}

static int nv_split(char *buf, struct _pair *nv)
{
	/* Get the name part */
	char *ptr;

	nv->name = NULL;
	nv->value = NULL;
	ptr = audit_strsplit(buf);
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = audit_strsplit(NULL);
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = audit_strsplit(NULL);
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* Make sure there's nothing else */
	ptr = audit_strsplit(NULL);
	if (ptr) {
		/* Allow one option, but check that there's not 2 */
		ptr = audit_strsplit(NULL);
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
 
static int log_file_parser(auparse_state_t *au, const char *val, int line,
		struct daemon_conf *config)
{
	char *dir = NULL, *tdir, *base;
	DIR *d;
	int fd, mode;

	/* split name into dir and basename. */
	tdir = strdup(val);
	if (tdir)
		dir = dirname(tdir);
	if (dir == NULL || strlen(dir) < 4) { //  '/var' is shortest dirname
		audit_msg(au, LOG_ERR, 
			"The directory name: %s is too short - line %d", 
			dir, line);
		free((void *)tdir);
		return 1;
	}

	base = basename((char *)val);
	if (base == 0 || strlen(base) == 0) {
		audit_msg(au, LOG_ERR,
			"The file name: %s is too short - line %d", base, line);
		free((void *)tdir);
		return 1;
	}
	
	/* verify the directory path exists */
	d = opendir(dir);
	if (d == NULL) {
		audit_msg(au, LOG_ERR, "Could not open dir %s (%s)", dir, 
			strerror(errno));
		free((void *)tdir);
		return 1;
	}
	free((void *)tdir);
	closedir(d);

	/* Verify the log file can be opened. */
	mode = O_RDONLY;
	fd = open(val, mode);
	if (fd < 0) {
		audit_msg(au, LOG_ERR, "Unable to open %s (%s)", val, 
					strerror(errno));
		return 1;
	}
	close(fd);

	free((void *)config->log_file);
	config->log_file = strdup(val);
	if (config->log_file == NULL)
		return 1;
	return 0;
}

void free_config(struct daemon_conf *config)
{
	free((void*)config->log_file);
}

