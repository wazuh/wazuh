/* remote-config.c -- 
 * Copyright 2008,2009,2011,2015-16 Red Hat Inc., Durham, North Carolina.
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
#include <syslog.h>
#include <ctype.h>
#include <limits.h>
#include "remote-config.h"

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
	int (*parser)(struct nv_pair *, int, remote_conf_t *);
	int max_options;
};

struct nv_list
{ 
	const char *name;
	int option;
};

static char *get_line(FILE *f, char *buf);
static int nv_split(char *buf, struct nv_pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int server_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int port_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int local_port_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int transport_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int mode_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int queue_file_parser(struct nv_pair *nv, int line,
		remote_conf_t *config);
static int depth_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int format_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int heartbeat_timeout_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int enable_krb5_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int krb5_principal_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int krb5_client_name_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int krb5_key_file_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int network_retry_time_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int max_tries_per_record_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int max_time_per_record_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
#define AP(x) static int x##_action_parser(struct nv_pair *nv, int line,  \
		remote_conf_t *config);
AP(network_failure)
AP(disk_low)
AP(disk_full)
AP(disk_error)
AP(generic_error)
AP(generic_warning)
AP(queue_error)
#undef AP
static int remote_ending_action_parser(struct nv_pair *nv, int line,
                remote_conf_t *config);
static int overflow_action_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int sanity_check(remote_conf_t *config, const char *file);

static const struct kw_pair keywords[] = 
{
  {"remote_server",    server_parser,		0 },
  {"port",             port_parser,		0 },
  {"local_port",       local_port_parser,	0 },
  {"transport",        transport_parser,	0 },
  {"mode",             mode_parser,		0 },
  {"queue_file",       queue_file_parser,	0 },
  {"queue_depth",      depth_parser,		0 },
  {"format",           format_parser,		0 },
  {"network_retry_time",     network_retry_time_parser,         0 },
  {"max_tries_per_record",   max_tries_per_record_parser,       0 },
  {"max_time_per_record",    max_time_per_record_parser,        0 },
  {"heartbeat_timeout",      heartbeat_timeout_parser,          0 },
  {"enable_krb5",            enable_krb5_parser,                0 },
  {"krb5_principal",         krb5_principal_parser,             0 },
  {"krb5_client_name",       krb5_client_name_parser,           0 },
  {"krb5_key_file",          krb5_key_file_parser,              0 },
  {"network_failure_action", network_failure_action_parser,	1 },
  {"disk_low_action",        disk_low_action_parser,		1 },
  {"disk_full_action",       disk_full_action_parser,		1 },
  {"disk_error_action",      disk_error_action_parser,		1 },
  {"remote_ending_action",   remote_ending_action_parser,	1 },
  {"generic_error_action",   generic_error_action_parser,	1 },
  {"generic_warning_action", generic_warning_action_parser,	1 },
  {"queue_error_action",     queue_error_action_parser,		1 },
  {"overflow_action",        overflow_action_parser,		1 },
  { NULL,                    NULL,                              0 }
};

static const struct nv_list transport_words[] =
{
  {"tcp",  T_TCP  },
  { NULL,  0 }
};

static const struct nv_list mode_words[] =
{
  {"immediate",  M_IMMEDIATE },
  {"forward",    M_STORE_AND_FORWARD },
  { NULL,  0 }
};

static const struct nv_list fail_action_words[] =
{
  {"ignore",    FA_IGNORE },
  {"syslog",    FA_SYSLOG },
  {"exec",      FA_EXEC },
  {"warn_once_continue", FA_WARN_ONCE_CONT },
  {"warn_once", FA_WARN_ONCE },
  {"suspend",   FA_SUSPEND },
  {"single",    FA_SINGLE },
  {"halt",      FA_HALT },
  {"stop",      FA_STOP },
  { NULL,  0 }
};

static const struct nv_list overflow_action_words[] =
{
  {"ignore",   OA_IGNORE },
  {"syslog",   OA_SYSLOG },
  {"suspend",  OA_SUSPEND },
  {"single",   OA_SINGLE },
  {"halt",     OA_HALT },
  { NULL,  0 }
};

static const struct nv_list format_words[] =
{
  {"ascii",    F_ASCII },
  {"managed",  F_MANAGED },
  { NULL,  0 }
};

#ifdef USE_GSSAPI
static const struct nv_list enable_krb5_values[] =
{
  {"yes",  1 },
  {"no", 0 },
  { NULL,  0 }
};
#endif

/*
 * Set everything to its default value
*/
void clear_config(remote_conf_t *config)
{
	config->remote_server = NULL;
	config->port = 60;
	config->local_port = 0;
	config->transport = T_TCP;
	config->mode = M_IMMEDIATE;
	config->queue_file = NULL;
	config->queue_depth = 2048;
	config->format = F_MANAGED;

	config->network_retry_time = 1;
	config->max_tries_per_record = 3;
	config->max_time_per_record = 5;
	config->heartbeat_timeout = 0;

#define IA(x,f) config->x##_action = f; config->x##_exe = NULL
	IA(network_failure, FA_STOP);
	IA(disk_low, FA_IGNORE);
	IA(disk_full, FA_WARN_ONCE);
	IA(disk_error, FA_WARN_ONCE);
	IA(remote_ending, FA_RECONNECT);
	IA(generic_error, FA_SYSLOG);
	IA(generic_warning, FA_SYSLOG);
	IA(queue_error, FA_STOP);
#undef IA
	config->overflow_action = OA_SYSLOG;

	config->enable_krb5 = 0;
	config->krb5_principal = NULL;
	config->krb5_client_name = NULL;
	config->krb5_key_file = NULL;
}

int load_config(remote_conf_t *config, const char *file)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[128];

	clear_config(config);

	/* open the file */
	mode = O_RDONLY;
	rc = open(file, mode);
	if (rc < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Error opening %s (%s)", file,
				strerror(errno));
			return 1;
		}
		syslog(LOG_WARNING,
			"Config file %s doesn't exist, skipping", file);
		return 0;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "Error fstat'ing config file (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		syslog(LOG_ERR, "Error - %s isn't owned by root", 
			file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		syslog(LOG_ERR, "Error - %s is world writable", 
			file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_ERR, "Error - %s is not a regular file", 
			file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		syslog(LOG_ERR, "Error - fdopen failed (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				syslog(LOG_ERR, 
				"Wrong number of arguments for line %d in %s", 
					lineno, file);
				break;
			case 2: // no '=' sign
				syslog(LOG_ERR, 
					"Missing equal sign for line %d in %s", 
					lineno, file);
				break;
			default: // something else went wrong... 
				syslog(LOG_ERR, 
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
			syslog(LOG_ERR, 
				"Unknown keyword \"%s\" in line %d of %s", 
				nv.name, lineno, file);
			fclose(f);
			return 1;
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			syslog(LOG_ERR, 
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

static char *get_line(FILE *f, char *buf)
{
	if (fgets_unlocked(buf, 128, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
			*ptr = 0;
		return buf;
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

static int check_exe_name(const char *val, int line)
{
	struct stat buf;

	if (val == NULL) {
		syslog(LOG_ERR, "Executable path needed for line %d", line);
		return -1;
	}

	if (*val != '/') {
		syslog(LOG_ERR, "Absolute path needed for %s - line %d",
			val, line);
		return -1;
	}

	if (stat(val, &buf) < 0) {
		syslog(LOG_ERR, "Unable to stat %s (%s) - line %d", val,
			strerror(errno), line);
		return -1;
	}
	if (!S_ISREG(buf.st_mode)) {
		syslog(LOG_ERR, "%s is not a regular file - line %d", val,
			line);
		return -1;
	}
	if (buf.st_uid != 0) {
		syslog(LOG_ERR, "%s is not owned by root - line %d", val,
			line);
		return -1;
	}
	if ((buf.st_mode & (S_IRWXU|S_IRWXG|S_IWOTH)) !=
			   (S_IRWXU|S_IRGRP|S_IXGRP)) {
		syslog(LOG_ERR, "%s permissions should be 0750 - line %d", val,
			line);
		return -1;
	}
	return 0;
}
 
static int server_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config)
{
	if (nv->value)
		config->remote_server = strdup(nv->value);
	else
		config->remote_server = NULL;
	return 0;
}

static int parse_uint (const struct nv_pair *nv, int line, unsigned int *valp,
		unsigned int min, unsigned int max)
{
	const char *ptr = nv->value;
	unsigned int i;

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			syslog(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}

	/* convert to unsigned int */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		syslog(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	/* Check its range */
	if (min != 0 && i < (int)min) {
		syslog(LOG_ERR,
			"Error - converted number (%s) is too small - line %d",
			nv->value, line);
		return 1;
	}
	if (max != 0 && i > max) {
		syslog(LOG_ERR,
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	*valp = (unsigned int)i;
	return 0;
}

static int port_parser(struct nv_pair *nv, int line, remote_conf_t *config)
{
	return parse_uint (nv, line, &(config->port), 0, 65535);
}

static int local_port_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	if ((strcasecmp(nv->value, "any") == 0))
		return 0;	// The default is 0, which means any port
	return parse_uint (nv, line, &(config->local_port), 0, 65535);
}

static int transport_parser(struct nv_pair *nv, int line, remote_conf_t *config)
{
	int i;
	for (i=0; transport_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, transport_words[i].name) == 0) {
			config->transport = transport_words[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int mode_parser(struct nv_pair *nv, int line, remote_conf_t *config)
{
	int i;
	for (i=0; mode_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, mode_words[i].name) == 0) {
			config->mode = mode_words[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int queue_file_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	if (nv->value) {
		if (*nv->value != '/') {
			syslog(LOG_ERR, "Absolute path needed for %s - line %d",
			       nv->value, line);
			return 1;
		}
		config->queue_file = strdup(nv->value);
	} else
		config->queue_file = NULL;
	return 0;
}

static int depth_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	return parse_uint (nv, line, &(config->queue_depth), 1, INT_MAX);
}

static int action_parser(struct nv_pair *nv, int line,
			 failure_action_t *actp, const char **exep)
{
	int i;
	for (i=0; fail_action_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, fail_action_words[i].name) == 0) {
			if (fail_action_words[i].option == FA_EXEC) {
				if (check_exe_name(nv->option, line))
					return 1;
				*exep = strdup(nv->option);
			}
			*actp = fail_action_words[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
 	return 1;
}

#define AP(x) \
static int x##_action_parser(struct nv_pair *nv, int line, \
	remote_conf_t *config) \
{ \
	return action_parser(nv,line,&(config->x##_action),&(config->x##_exe));\
} \

AP(network_failure)
AP(disk_low)
AP(disk_full)
AP(disk_error)
AP(generic_error)
AP(generic_warning)
AP(queue_error)
#undef AP

static int overflow_action_parser(struct nv_pair *nv, int line,
	remote_conf_t *config)
{
        int i;

        for (i=0; overflow_action_words[i].name != NULL; i++) {
                if (strcasecmp(nv->value, overflow_action_words[i].name) == 0) {
                        config->overflow_action = overflow_action_words[i].option;
                        return 0;
                }
        }
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int remote_ending_action_parser(struct nv_pair *nv, int line,
                remote_conf_t *config)
{
	if (strcasecmp(nv->value, "reconnect") == 0) {
		config->remote_ending_action = FA_RECONNECT;
		return 0;
	}
	return action_parser(nv, line, &config->remote_ending_action,
			&config->remote_ending_exe);
}

static int format_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	int i;
	for (i=0; format_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, format_words[i].name) == 0) {
			config->format = format_words[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
 	return 1;
}

static int network_retry_time_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	return parse_uint(nv, line, &config->network_retry_time, 1, INT_MAX);
}

static int max_tries_per_record_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	return parse_uint(nv, line, &config->max_tries_per_record, 1, INT_MAX);
}

static int max_time_per_record_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	return parse_uint(nv, line, &(config->max_time_per_record), 1, INT_MAX);
}

static int heartbeat_timeout_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
	return parse_uint (nv, line, &(config->heartbeat_timeout), 0, INT_MAX);
}

static int enable_krb5_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
#ifndef USE_GSSAPI
	syslog(LOG_INFO,
		"GSSAPI support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
	unsigned long i;

	for (i=0; enable_krb5_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, enable_krb5_values[i].name) == 0) {
			config->enable_krb5 = enable_krb5_values[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
#endif
}

static int krb5_principal_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
#ifndef USE_GSSAPI
	syslog(LOG_INFO,
		"GSSAPI support is not enabled, ignoring value at line %d",
		line);
#else
	if (config->krb5_principal)
		free ((char *)config->krb5_principal);

	config->krb5_principal = strdup(nv->value);
#endif
	return 0;
}

static int krb5_client_name_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
#ifndef USE_GSSAPI
	syslog(LOG_INFO,
		"GSSAPI support is not enabled, ignoring value at line %d",
		line);
#else
	if (config->krb5_client_name)
		free ((char *)config->krb5_client_name);

	config->krb5_client_name = strdup(nv->value);
#endif
	return 0;
}

static int krb5_key_file_parser(struct nv_pair *nv, int line,
		remote_conf_t *config)
{
#ifndef USE_GSSAPI
        syslog(LOG_INFO,
                "GSSAPI support is not enabled, ignoring value at line %d",
                line);
#else
	if (config->krb5_key_file)
		free ((char *)config->krb5_key_file);

	config->krb5_key_file = strdup(nv->value);
#endif
	return 0;
}

/*
 * This function is where we do the integrated check of the audispd config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(remote_conf_t *config, const char *file)
{
	/* Error checking */
// server should have string
// port should be less that 32k
// queue_depth should be less than 100k
// If fail_action is F_EXEC, fail_exec must exist
	if (config->mode == M_STORE_AND_FORWARD
	    && config->format != F_MANAGED) {
		syslog(LOG_ERR, "\"mode=forward\" is valid only with "
		       "\"format=managed\"");
		return 1;
	}
	return 0;
}

void free_config(remote_conf_t *config)
{
	free((void *)config->remote_server);
	free((void *)config->queue_file);
	free((void *)config->network_failure_exe);
	free((void *)config->disk_low_exe);
	free((void *)config->disk_full_exe);
	free((void *)config->disk_error_exe);
	free((void *)config->remote_ending_exe);
	free((void *)config->generic_error_exe);
	free((void *)config->generic_warning_exe);
	free((void *)config->queue_error_exe);
	free((void *)config->krb5_principal);
	free((void *)config->krb5_client_name);
	free((void *)config->krb5_key_file);
}

