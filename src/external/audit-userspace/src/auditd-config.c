/* auditd-config.c -- 
 * Copyright 2004-2011,2013-14,2016 Red Hat Inc., Durham, North Carolina.
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
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>	/* O_NOFOLLOW needs gnu defined */
#include <libgen.h>
#include <arpa/inet.h>
#include <limits.h>	/* INT_MAX */
#include "auditd-config.h"
#include "libaudit.h"
#include "private.h"

#define TCP_PORT_MAX 65535

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
	int (*parser)(struct nv_pair *, int, struct daemon_conf *);
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
static int local_events_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int write_logs_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int log_file_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int num_logs_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int log_group_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int qos_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int dispatch_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int name_format_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int name_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int max_log_size_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int max_log_size_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int log_format_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int flush_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int freq_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int space_left_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int space_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int action_mail_acct_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int verify_email_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int admin_space_left_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int admin_space_left_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int disk_full_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int disk_error_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config);
static int priority_boost_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int tcp_listen_port_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int tcp_listen_queue_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int tcp_max_per_addr_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int use_libwrap_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int tcp_client_ports_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int tcp_client_max_idle_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int enable_krb5_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int krb5_principal_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int krb5_key_file_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int distribute_network_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config);
static int sanity_check(struct daemon_conf *config);

static const struct kw_pair keywords[] = 
{
  {"local_events",             local_events_parser,		0},
  {"write_logs",               write_logs_parser,		0 },
  {"log_file",                 log_file_parser,			0 },
  {"log_format",               log_format_parser,		0 },
  {"log_group",                log_group_parser,		0 },
  {"flush",                    flush_parser,			0 },
  {"freq",                     freq_parser,			0 },
  {"num_logs",                 num_logs_parser,			0 },
  {"dispatcher",               dispatch_parser,			0 },
  {"name_format",              name_format_parser,		0 },
  {"name",                     name_parser,			0 },
  {"disp_qos",                 qos_parser,			0 },
  {"max_log_file",             max_log_size_parser,		0 },
  {"max_log_file_action",      max_log_size_action_parser,	0 },
  {"space_left",               space_left_parser,		0 },
  {"space_left_action",        space_action_parser,		1 },
  {"action_mail_acct",         action_mail_acct_parser,		0 },
  {"verify_email",             verify_email_parser,		0 },
  {"admin_space_left",         admin_space_left_parser,		0 },
  {"admin_space_left_action",  admin_space_left_action_parser,	1 },
  {"disk_full_action",         disk_full_action_parser,		1 },
  {"disk_error_action",        disk_error_action_parser,	1 },
  {"priority_boost",           priority_boost_parser,		0 },
  {"tcp_listen_port",          tcp_listen_port_parser,          0 },
  {"tcp_listen_queue",         tcp_listen_queue_parser,         0 },
  {"tcp_max_per_addr",         tcp_max_per_addr_parser,         0 },
  {"use_libwrap",              use_libwrap_parser,              0 },
  {"tcp_client_ports",         tcp_client_ports_parser,         0 },
  {"tcp_client_max_idle",      tcp_client_max_idle_parser,      0 },
  {"enable_krb5",              enable_krb5_parser,              0 },
  {"krb5_principal",           krb5_principal_parser,           0 },
  {"krb5_key_file",            krb5_key_file_parser,            0 },
  {"distribute_network",       distribute_network_parser,       0 },
  { NULL,                      NULL,                            0 }
};

static const struct nv_list log_formats[] =
{
  {"raw",  LF_RAW },
  {"nolog", LF_NOLOG },
  {"enriched", LF_ENRICHED },
  { NULL,  0 }
};

static const struct nv_list flush_techniques[] =
{
  {"none",        FT_NONE },
  {"incremental", FT_INCREMENTAL },
  {"incremental_async", FT_INCREMENTAL_ASYNC },
  {"data",        FT_DATA },
  {"sync",        FT_SYNC },
  { NULL,         0 }
};

static const struct nv_list failure_actions[] =
{
  {"ignore",  FA_IGNORE },
  {"syslog",  FA_SYSLOG },
  {"rotate",  FA_ROTATE },
  {"email",   FA_EMAIL },
  {"exec",    FA_EXEC },
  {"suspend", FA_SUSPEND },
  {"single",  FA_SINGLE },
  {"halt",    FA_HALT },
  { NULL,     0 }
};

// Future ideas: e-mail, run command
static const struct nv_list size_actions[] =
{
  {"ignore",  SZ_IGNORE },
  {"syslog",  SZ_SYSLOG },
  {"suspend", SZ_SUSPEND },
  {"rotate",  SZ_ROTATE },
  {"keep_logs", SZ_KEEP_LOGS},
  { NULL,     0 }
};

static const struct nv_list qos_options[] =
{
  {"lossy",     QOS_NON_BLOCKING },
  {"lossless",  QOS_BLOCKING },
  { NULL,     0 }
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

static const struct nv_list yes_no_values[] =
{
  {"yes",  1 },
  {"no", 0 },
  { NULL,  0 }
};

const char *email_command = "/usr/lib/sendmail";
static int allow_links = 0;
static const char *config_dir = NULL;
static char *config_file = NULL;


void set_allow_links(int allow)
{
	allow_links = allow;
}

int set_config_dir(const char *val)
{
	config_dir = strdup(val);
	if (config_dir == NULL)
		return 1;
	if (asprintf(&config_file, "%s/auditd.conf", config_dir) < 0)
		return 1;
	return 0;
}

const char *get_config_dir(void)
{
	/* This function is used to determine if audispd is started with
	 * a -c parameter followed by the config_dir location. If we are
	 * using the standard location, do not pass back a location. */
	if (config_file && strcmp(config_file, CONFIG_FILE) == 0)
		return NULL;
	return config_dir;
}

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
	config->action_mail_acct = strdup("root");
	config->verify_email = 1;
	config->admin_space_left= 0L;
	config->admin_space_left_action = FA_IGNORE;
	config->admin_space_left_exe = NULL;
	config->disk_full_action = FA_IGNORE;
	config->disk_full_exe = NULL;
	config->disk_error_action = FA_SYSLOG;
	config->disk_error_exe = NULL;
	config->tcp_listen_port = 0;
	config->tcp_listen_queue = 5;
	config->tcp_max_per_addr = 1;
	config->use_libwrap = 1;
	config->tcp_client_min_port = 0;
	config->tcp_client_max_port = TCP_PORT_MAX;
	config->tcp_client_max_idle = 0;
	config->enable_krb5 = 0;
	config->krb5_principal = NULL;
	config->krb5_key_file = NULL;
	config->distribute_network_events = 0;
}

static log_test_t log_test = TEST_AUDITD;
int load_config(struct daemon_conf *config, log_test_t lt)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[160];

	clear_config(config);
	log_test = lt;
	if (config_file == NULL)
		config_file = strdup(CONFIG_FILE);

	/* open the file */
	mode = O_RDONLY;
	if (allow_links == 0)
		mode |= O_NOFOLLOW;
	rc = open(config_file, mode);
	if (rc < 0) {
		if (errno != ENOENT) {
			audit_msg(LOG_ERR, "Error opening config file (%s)", 
				strerror(errno));
			return 1;
		}
		audit_msg(LOG_WARNING,
			"Config file %s doesn't exist, skipping", config_file);
		return 0;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	audit_msg(LOG_DEBUG, "Config file %s opened for parsing", 
			config_file);
	if (fstat(fd, &st) < 0) {
		audit_msg(LOG_ERR, "Error fstat'ing config file (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		audit_msg(LOG_ERR, "Error - %s isn't owned by root", 
			config_file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		audit_msg(LOG_ERR, "Error - %s is world writable", 
			config_file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		audit_msg(LOG_ERR, "Error - %s is not a regular file", 
			config_file);
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

	while (get_line(f, buf, sizeof(buf), &lineno, config_file)) {
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
					lineno, config_file);
				break;
			case 2: // no '=' sign
				audit_msg(LOG_ERR, 
					"Missing equal sign for line %d in %s", 
					lineno, config_file);
				break;
			default: // something else went wrong... 
				audit_msg(LOG_ERR, 
					"Unknown error for line %d in %s", 
					lineno, config_file);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			audit_msg(LOG_ERR,
				"Not processing any more lines in %s",
				config_file);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			audit_msg(LOG_ERR, 
				"Unknown keyword \"%s\" in line %d of %s", 
				nv.name, lineno, config_file);
			fclose(f);
			return 1;
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			audit_msg(LOG_ERR, 
				"Keyword \"%s\" has invalid option "
				"\"%s\" in line %d of %s", 
				nv.name, nv.option, lineno, config_file);
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
		return sanity_check(config);
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
	char *ptr;

	nv->name = NULL;
	nv->value = NULL;
	nv->option = NULL;
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

	/* See if there's an option */
	ptr = audit_strsplit(NULL);
	if (ptr) {
		nv->option = ptr;

		/* Make sure there's nothing else */
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
 
static int local_events_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	unsigned long i;

	audit_msg(LOG_DEBUG, "local_events_parser called with: %s",
		  nv->value);

	for (i=0; yes_no_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, yes_no_values[i].name) == 0) {
			config->local_events = yes_no_values[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int write_logs_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	unsigned long i;

	audit_msg(LOG_DEBUG, "write_logs_parser called with: %s",
		  nv->value);

	for (i=0; yes_no_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, yes_no_values[i].name) == 0) {
			config->write_logs = yes_no_values[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int log_file_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	char *dir = NULL, *tdir;
	DIR *d;
	int fd, mode;
	struct stat buf;

	audit_msg(LOG_DEBUG, "log_file_parser called with: %s", nv->value);

	/* get dir from name. */
	tdir = strdup(nv->value);
	if (tdir)
		dir = dirname(tdir);
	if (dir == NULL || strlen(dir) < 4) { //  '/var' is shortest dirname
		audit_msg(LOG_ERR, 
			"The directory name: %s is too short - line %d", 
			dir, line);
		free((void *)tdir);
		return 1;
	}

	/* verify the directory path exists */
	d = opendir(dir);
	if (d == NULL) {
		audit_msg(LOG_ERR, "Could not open dir %s (%s)", dir, 
			strerror(errno));
		free((void *)tdir);
		return 1;
	}
	free((void *)tdir);
	closedir(d);

	/* if the file exists, see that its regular, owned by root, 
	 * and not world anything */
	if (log_test == TEST_AUDITD)
		mode = O_APPEND;
	else
		mode = O_RDONLY;

	fd = open(nv->value, mode);
	if (fd < 0) {
		if (errno == ENOENT)
			goto finish_up;	// Will create the log later
		else {
			audit_msg(LOG_ERR, "Unable to open %s (%s)", nv->value, 
					strerror(errno));
			return 1;
		}
	}
	if (fstat(fd, &buf) < 0) {
		audit_msg(LOG_ERR, "Unable to stat %s (%s)", 
					nv->value, strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);
	if (!S_ISREG(buf.st_mode)) {
		audit_msg(LOG_ERR, "%s is not a regular file", nv->value);
		return 1;
	}
	if (buf.st_uid != 0) {
		audit_msg(LOG_ERR, "%s is not owned by root", nv->value);
		return 1;
	}
	if ( (buf.st_mode & (S_IXUSR|S_IWGRP|S_IXGRP|S_IRWXO)) ) {
		audit_msg(LOG_WARNING, "%s permissions should be 0600 or 0640",
				nv->value);
	}
	if ( !(buf.st_mode & S_IWUSR) ) {
		audit_msg(LOG_WARNING, "audit log is not writable by owner");
	}

finish_up:
	free((void *)config->log_file);
	config->log_file = strdup(nv->value);
	if (config->log_file == NULL)
		return 1;
	return 0;
}

static int num_logs_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "num_logs_parser called with: %s", nv->value);

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
	if (i > 999) {
		audit_msg(LOG_ERR, "num_logs must be 999 or less");
		return 1;
	}
	config->num_logs = i;
	return 0;
}

static int qos_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "qos_parser called with: %s", nv->value);
	for (i=0; qos_options[i].name != NULL; i++) {
		if (strcasecmp(nv->value, qos_options[i].name) == 0) {
			config->qos = qos_options[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int dispatch_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	char *dir = NULL, *tdir;
	int fd;
	struct stat buf;

	audit_msg(LOG_DEBUG, "dispatch_parser called with: %s", nv->value);
	if (nv->value == NULL) {
		config->dispatcher = NULL;
		return 0;
	}

	/* get dir from name. */
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

	/* Bypass the perms check if group is not root since
	 * this will fail under normal circumstances */
	if ((config->log_group != 0 && getuid() != 0) ||
				(log_test == TEST_SEARCH)) 
		goto bypass;

	/* if the file exists, see that its regular, owned by root,
	 * and not world anything */
	fd = open(nv->value, O_RDONLY);
	if (fd < 0) {
		audit_msg(LOG_ERR, "Unable to open %s (%s)", nv->value,
			strerror(errno));
		return 1;
	}
	if (fstat(fd, &buf) < 0) {
		audit_msg(LOG_ERR, "Unable to stat %s (%s)", nv->value,
			strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);
	if (!S_ISREG(buf.st_mode)) {
		audit_msg(LOG_ERR, "%s is not a regular file", nv->value);
		return 1;
	}
	if (buf.st_uid != 0) {
		audit_msg(LOG_ERR, "%s is not owned by root", nv->value);
		return 1;
	}
	if ((buf.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) !=
			   (S_IRWXU|S_IRGRP|S_IXGRP) && 
	    (buf.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) !=
			   (S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)) {
		audit_msg(LOG_ERR, "%s permissions should be 0750 or 0755",
				nv->value);
		return 1;
	}
bypass:
	free((void *)config->dispatcher);
	config->dispatcher = strdup(nv->value);
	if (config->dispatcher == NULL)
		return 1;
	return 0;
}

static int name_format_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "name_format_parser called with: %s", nv->value);
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
		struct daemon_conf *config)
{
	audit_msg(LOG_DEBUG, "name_parser called with: %s", nv->value);
	if (nv->value == NULL)
		config->node_name = NULL;
	else
		config->node_name = strdup(nv->value);
	return 0;
}

static int max_log_size_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "max_log_size_parser called with: %s", nv->value);

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
	config->max_log_size = i;
	return 0;
}

static int max_log_size_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "max_log_size_action_parser called with: %s",
		nv->value);
	for (i=0; size_actions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, size_actions[i].name) == 0) {
			config->max_log_size_action = size_actions[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int log_format_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "log_format_parser called with: %s", nv->value);
	for (i=0; log_formats[i].name != NULL; i++) {
		if (strcasecmp(nv->value, log_formats[i].name) == 0) {
			config->log_format = log_formats[i].option;
			if (config->log_format == LF_NOLOG) {
				audit_msg(LOG_WARNING,
				    "The NOLOG option to log_format is deprecated. Please use the write_logs option.");
				if (config->write_logs != 0)
					audit_msg(LOG_WARNING,
					    "The NOLOG option is overriding the write_logs current setting.");
				config->write_logs = 0;
			}
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int log_group_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	gid_t gid = 0;
	
	audit_msg(LOG_DEBUG, "log_group_parser called with: %s",
							nv->value);
	if (isdigit(nv->value[0])) {
		errno = 0;
		gid = strtoul(nv->value,NULL,10);
		if (errno) {
			audit_msg(LOG_ERR,
		    "Numeric group ID conversion error (%s) for %s - line %d\n",
				strerror(errno), nv->value, line);
			return 1;
		}
	} else {
		struct group *gr ;

		gr = getgrnam(nv->value);
		if (gr == NULL) {
			audit_msg(LOG_ERR,
			 "Group ID is non-numeric and unknown (%s) - line %d\n",
				nv->value, line);
			return 1;
		}
		gid = gr->gr_gid;
	}
	config->log_group = gid;
	return 0;
}

static int flush_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "flush_parser called with: %s", nv->value);
	for (i=0; flush_techniques[i].name != NULL; i++) {
		if (strcasecmp(nv->value, flush_techniques[i].name) == 0) {
			config->flush = flush_techniques[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int freq_parser(struct nv_pair *nv, int line,
		struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "freq_parser called with: %s", nv->value);

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
	config->freq = (unsigned int)i;
	return 0;
}

static int space_left_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "space_left_parser called with: %s", nv->value);

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
	config->space_left = i;
	return 0;
}

static int check_exe_name(const char *val, int line)
{
	struct stat buf;

	if (val == NULL) {
		audit_msg(LOG_ERR, "Executable path needed for line %d", line);
		return -1;
	}

	if (*val != '/') {
		audit_msg(LOG_ERR, "Absolute path needed for %s - line %d",
			val, line);
		return -1;
	}

	if (stat(val, &buf) < 0) {
		audit_msg(LOG_ERR, "Unable to stat %s (%s) - line %d", val,
			strerror(errno), line);
		return -1;
	}
	if (!S_ISREG(buf.st_mode)) {
		audit_msg(LOG_ERR, "%s is not a regular file - line %d", val,
			line);
		return -1;
	}
	if (buf.st_uid != 0) {
		audit_msg(LOG_ERR, "%s is not owned by root - line %d", val,
			line);
		return -1;
	}
	if ((buf.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) !=
			   (S_IRWXU|S_IRGRP|S_IXGRP) &&
	    (buf.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) !=
			   (S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)) {
		audit_msg(LOG_ERR,
			"%s permissions should be 0750 or 0755 - line %d",
			val, line);
		return -1;
	}
	return 0;
}

static int space_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "space_action_parser called with: %s", nv->value);
	for (i=0; failure_actions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, failure_actions[i].name) == 0) {
			if (failure_actions[i].option == FA_EMAIL) {
				if (access(email_command, X_OK)) {
					audit_msg(LOG_ERR,
		"Email option is specified but %s doesn't seem executable.",
						 email_command);
				}
			} else if (failure_actions[i].option == FA_EXEC) {
				if (check_exe_name(nv->option, line))
					return 1;
				config->space_left_exe = strdup(nv->option);
			}
			config->space_left_action = failure_actions[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

// returns 0 if OK, 1 on temp error, 2 on permanent error
static int validate_email(const char *acct)
{
	int i, len;
	char *ptr1;

	if (acct == NULL)
		return 2;

	len = strlen(acct);
	if (len < 2) {
		audit_msg(LOG_ERR,
		    "email: %s is too short, expecting at least 2 characters",
			 acct);
		return 2;
	}

	// look for illegal char
	for (i=0; i<len; i++) {
		if (! (isalnum(acct[i]) || (acct[i] == '@') ||
				(acct[i]=='.') || (acct[i]=='-') ||
				(acct[i] == '_')) ) {
			audit_msg(LOG_ERR, "email: %s has illegal character",
				acct);
			return 2;
		}
	}

	if ((ptr1 = strchr(acct, '@'))) {
		char *ptr2;
		int rc2;
		struct addrinfo *ai;
		struct addrinfo hints;

		ptr2 = strrchr(acct, '.');        // get last dot - sb after @
		if ((ptr2 == NULL) || (ptr1 > ptr2)) {
			audit_msg(LOG_ERR, "email: %s should have . after @",
				acct);
			return 2;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
		hints.ai_socktype = SOCK_STREAM;

		rc2 = getaddrinfo(ptr1+1, NULL, &hints, &ai);
		if (rc2 != 0) {
			if ((h_errno == HOST_NOT_FOUND) ||
						(h_errno == NO_RECOVERY)) {
				audit_msg(LOG_ERR,
			"validate_email: failed looking up host for %s (%s)",
					ptr1+1, gai_strerror(rc2));
				// FIXME: How can we tell that we truly have
				// a permanent failure and what is that? For
				// now treat all as temp failure.
			} else if (h_errno == TRY_AGAIN) {
				audit_msg(LOG_DEBUG,
		"validate_email: temporary failure looking up domain for %s",
					ptr1+1);
			}
			return 1;
		}
		freeaddrinfo(ai);
	}
	return 0;
}

static int action_mail_acct_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	char *tmail;
	
	audit_msg(LOG_DEBUG, "action_mail_acct_parser called with: %s",
							nv->value);
	tmail = strdup(nv->value);
	if (tmail == NULL)
		return 1;

	if (config->verify_email && validate_email(tmail) > 1) {
		free(tmail);
		return 1;
	}


	if (config->action_mail_acct)
		free((void *)config->action_mail_acct);
	config->action_mail_acct = tmail;
	return 0;
}

static int verify_email_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	unsigned long i;
	audit_msg(LOG_DEBUG, "verify_email_parser called with: %s",
		  nv->value);


	for (i=0; yes_no_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, yes_no_values[i].name) == 0) {
			config->verify_email = yes_no_values[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int admin_space_left_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "admin_space_left_parser called with: %s",
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

	/* convert to unsigned long */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		audit_msg(LOG_ERR, 
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	config->admin_space_left = i;
	return 0;
}

static int admin_space_left_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "admin_space_left_action_parser called with: %s",
								nv->value);
	for (i=0; failure_actions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, failure_actions[i].name) == 0) {
			if (failure_actions[i].option == FA_EMAIL) {
				if (access(email_command, X_OK)) {
					audit_msg(LOG_ERR,
		"Email option is specified but %s doesn't seem executable.",
						 email_command);
				}
			} else if (failure_actions[i].option == FA_EXEC) {
				if (check_exe_name(nv->option, line))
					return 1;
				config->admin_space_left_exe = 
							strdup(nv->option);
			}
			config->admin_space_left_action = 
						failure_actions[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int disk_full_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "disk_full_action_parser called with: %s",
								nv->value);
	for (i=0; failure_actions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, failure_actions[i].name) == 0) {
			if (failure_actions[i].option == FA_EMAIL) {
				audit_msg(LOG_ERR, 
			"Illegal option %s for disk_full_action - line %d",
					nv->value, line);
				return 1;
			} else if (failure_actions[i].option == FA_EXEC) {
				if (check_exe_name(nv->option, line))
					return 1;
				config->disk_full_exe = strdup(nv->option);
			}
			config->disk_full_action = failure_actions[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int disk_error_action_parser(struct nv_pair *nv, int line, 
		struct daemon_conf *config)
{
	int i;

	audit_msg(LOG_DEBUG, "disk_error_action_parser called with: %s",
								nv->value);
	for (i=0; failure_actions[i].name != NULL; i++) {
		if (strcasecmp(nv->value, failure_actions[i].name) == 0) {
			if (failure_actions[i].option == FA_EMAIL ||
				failure_actions[i].option == FA_ROTATE) {
				audit_msg(LOG_ERR, 
			"Illegal option %s for disk_error_action - line %d",
					nv->value, line);
				return 1;
			} else if (failure_actions[i].option == FA_EXEC) {
				if (check_exe_name(nv->option, line))
					return 1;
				config->disk_error_exe = strdup(nv->option);
			}
			config->disk_error_action = failure_actions[i].option;
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

static int tcp_listen_port_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "tcp_listen_port_parser called with: %s",
		  nv->value);

#ifndef USE_LISTENER
	audit_msg(LOG_DEBUG,
		"Listener support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
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
	if (i > TCP_PORT_MAX) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	if (i < 1) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too small - line %d",
			nv->value, line);
		return 1;
	}
	config->tcp_listen_port = (unsigned int)i;
	return 0;
#endif
}

static int tcp_listen_queue_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "tcp_listen_queue_parser called with: %s",
		  nv->value);

#ifndef USE_LISTENER
	audit_msg(LOG_DEBUG,
		"Listener support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
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
	/* Check its range.  While this value is technically
	   unlimited, it's limited by the kernel, and we limit it here
	   for sanity. */
	if (i > TCP_PORT_MAX) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	if (i < 1) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too small - line %d",
			nv->value, line);
		return 1;
	}
	config->tcp_listen_queue = (unsigned int)i;
	return 0;
#endif
}


static int tcp_max_per_addr_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "tcp_max_per_addr_parser called with: %s",
		  nv->value);

#ifndef USE_LISTENER
	audit_msg(LOG_DEBUG,
		"Listener support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
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
	/* Check its range.  While this value is technically
	   unlimited, it's limited by the kernel, and we limit it here
	   for sanity. */
	if (i > 1024) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	if (i < 1) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too small - line %d",
			nv->value, line);
		return 1;
	}
	config->tcp_max_per_addr = (unsigned int)i;
	return 0;
#endif
}

static int use_libwrap_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	unsigned long i;

	audit_msg(LOG_DEBUG, "use_libwrap_parser called with: %s",
		  nv->value);

	for (i=0; yes_no_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, yes_no_values[i].name) == 0) {
			config->use_libwrap = yes_no_values[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int tcp_client_ports_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i, minv, maxv;
	const char *saw_dash = NULL;

	audit_msg(LOG_DEBUG, "tcp_listen_queue_parser called with: %s",
		  nv->value);

#ifndef USE_LISTENER
	audit_msg(LOG_DEBUG,
		"Listener support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
	/* check that all chars are numbers, with an optional inclusive '-'. */
	for (i=0; ptr[i]; i++) {
		if (i > 0 && ptr[i] == '-' && ptr[i+1] != '\0') {
			saw_dash = ptr + i;
			continue;
		}
		if (!isdigit(ptr[i])) {
			audit_msg(LOG_ERR, 
				"Value %s should only be numbers, or "
				"two numbers separated by a dash - line %d",
				nv->value, line);
			return 1;
		}
	}
	for (; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			audit_msg(LOG_ERR, 
				"Value %s should only be numbers, or "
				"two numbers separated by a dash - line %d",
				nv->value, line);
			return 1;
		}
	}

	/* convert to unsigned int */
	errno = 0;
	maxv = minv = strtoul(nv->value, NULL, 10);
	if (errno) {
		audit_msg(LOG_ERR, 
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	if (saw_dash) {
		maxv = strtoul(saw_dash + 1, NULL, 10);
		if (errno) {
			audit_msg(LOG_ERR, 
			  "Error converting string to a number (%s) - line %d",
				  strerror(errno), line);
			return 1;
		}
	}
	/* Check their ranges. */
	if (minv > TCP_PORT_MAX) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%ld) is too large - line %d",
			  minv, line);
		return 1;
	}
	if (maxv > TCP_PORT_MAX) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%ld) is too large - line %d",
			  maxv, line);
		return 1;
	}
	if (minv > maxv) {
		audit_msg(LOG_ERR, 
		     "Error - converted range (%ld-%ld) is reversed - line %d",
			  minv, maxv, line);
		return 1;
	}
	config->tcp_client_min_port = (unsigned int)minv;
	config->tcp_client_max_port = (unsigned int)maxv;
	return 0;
#endif
}

static int tcp_client_max_idle_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	const char *ptr = nv->value;
	unsigned long i;

	audit_msg(LOG_DEBUG, "tcp_client_max_idle_parser called with: %s",
		  nv->value);

#ifndef USE_LISTENER
	audit_msg(LOG_DEBUG,
		"Listener support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
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
	/* Check its range.  While this value is technically
	   unlimited, it's limited by the kernel, and we limit it here
	   for sanity. */
	if (i > INT_MAX) {
		audit_msg(LOG_ERR, 
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	config->tcp_client_max_idle = (unsigned int)i;
	return 0;
#endif
}

static int enable_krb5_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	audit_msg(LOG_DEBUG, "enable_krb5_parser called with: %s",
		  nv->value);

#ifndef USE_GSSAPI
	audit_msg(LOG_DEBUG,
		"GSSAPI support is not enabled, ignoring value at line %d",
		line);
	return 0;
#else
	unsigned long i;

	for (i=0; yes_no_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, yes_no_values[i].name) == 0) {
			config->enable_krb5 = yes_no_values[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
#endif
}

static int krb5_principal_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	audit_msg(LOG_DEBUG,"krb5_principal_parser called with: %s",nv->value);
#ifndef USE_GSSAPI
	audit_msg(LOG_DEBUG,
		"GSSAPI support is not enabled, ignoring value at line %d",
		line);
#else
	config->krb5_principal = strdup(nv->value);
#endif
	return 0;
}

static int krb5_key_file_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	audit_msg(LOG_DEBUG, "krb5_key_file_parser called with: %s", nv->value);
#ifndef USE_GSSAPI
	audit_msg(LOG_DEBUG,
		"GSSAPI support is not enabled, ignoring value at line %d",
		line);
#else
	config->krb5_key_file = strdup(nv->value);
#endif
	return 0;
}

static int distribute_network_parser(struct nv_pair *nv, int line,
	struct daemon_conf *config)
{
	unsigned long i;
	audit_msg(LOG_DEBUG, "distribute_network_parser called with: %s",
		  nv->value);


	for (i=0; yes_no_values[i].name != NULL; i++) {
		if (strcasecmp(nv->value, yes_no_values[i].name) == 0) {
			config->distribute_network_events =
						yes_no_values[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

/*
 * This function is where we do the integrated check of the audit config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(struct daemon_conf *config)
{
	/* Error checking */
	if (config->space_left <= config->admin_space_left) {
		audit_msg(LOG_ERR, 
	    "Error - space_left(%lu) must be larger than admin_space_left(%lu)",
		    config->space_left, config->admin_space_left);
		return 1;
	}
	if ((config->flush == FT_INCREMENTAL || config->flush == FT_INCREMENTAL_ASYNC) &&
			config->freq == 0) {
		audit_msg(LOG_ERR, 
		"Error - incremental flushing chosen, but 0 selected for freq");
		return 1;
	}
	/* Warnings */
	if (config->flush > FT_INCREMENTAL_ASYNC && config->freq != 0) {
		audit_msg(LOG_WARNING, 
           "Warning - freq is non-zero and incremental flushing not selected.");
	}
	return 0;
}

const char *audit_lookup_format(int fmt)
{
	int i;

	for (i=0; log_formats[i].name != NULL; i++) {
                if (log_formats[i].option == fmt)
			return log_formats[i].name;
	}
	return NULL;
}

int create_log_file(const char *val)
{
	int fd;
	mode_t u;

	u = umask(S_IRWXO);
	fd = open(val, O_CREAT|O_EXCL|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP);
	if (fd < 0) 
		audit_msg(LOG_ERR, "Unable to create %s (%s)", val,
			strerror(errno));
	umask(u);
	return fd;
}

void free_config(struct daemon_conf *config)
{
	free((void *)config->sender_ctx);
	free((void *)config->log_file);
	free((void *)config->dispatcher);
	free((void *)config->node_name);
	free((void *)config->action_mail_acct);
	free((void *)config->space_left_exe);
        free((void *)config->admin_space_left_exe);
        free((void *)config->disk_full_exe);
        free((void *)config->disk_error_exe);
        free((void *)config->krb5_principal);
        free((void *)config->krb5_key_file);
        free((void *)config_dir);
        free(config_file);
}

int resolve_node(struct daemon_conf *config)
{
	int rc = 0;
	char tmp_name[255];

	/* Get the host name representation */
	switch (config->node_name_format)
	{
		case N_NONE:
			break;
		case N_HOSTNAME:
			if (gethostname(tmp_name, sizeof(tmp_name))) {
				audit_msg(LOG_ERR,
					"Unable to get machine name");
				rc = -1;
			} else
				config->node_name = strdup(tmp_name);
			break;
		case N_USER:
			if (config->node_name == NULL) {
				audit_msg(LOG_ERR, "User defined name missing");
				rc = -1;
			}
			break;
		case N_FQD:
			if (gethostname(tmp_name, sizeof(tmp_name))) {
				audit_msg(LOG_ERR,
					"Unable to get machine name");
				rc = -1;
			} else {
				int rc2;
				struct addrinfo *ai;
				struct addrinfo hints;

				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
				hints.ai_socktype = SOCK_STREAM;

				rc2 = getaddrinfo(tmp_name, NULL, &hints, &ai);
				if (rc2 != 0) {
					audit_msg(LOG_ERR,
					"Cannot resolve hostname %s (%s)",
					tmp_name, gai_strerror(rc2));
					rc = -1;
					break;
				}
				config->node_name = strdup(ai->ai_canonname);
				freeaddrinfo(ai);
			}
			break;
 		case N_NUMERIC:
			if (gethostname(tmp_name, sizeof(tmp_name))) {
				audit_msg(LOG_ERR,
						"Unable to get machine name");
				rc = -1;
			} else {
				int rc2;
				struct addrinfo *ai;
				struct addrinfo hints;

				audit_msg(LOG_DEBUG,
					"Resolving numeric address for %s",
					tmp_name);
				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
				hints.ai_socktype = SOCK_STREAM;

				rc2 = getaddrinfo(tmp_name, NULL, &hints, &ai);
				if (rc2) {
					audit_msg(LOG_ERR,
					"Cannot resolve hostname %s (%s)",
					tmp_name, gai_strerror(rc2));
					rc = -1;
					break;
				}
				inet_ntop(ai->ai_family,
						ai->ai_family == AF_INET ?
		(void *) &((struct sockaddr_in *)ai->ai_addr)->sin_addr :
		(void *) &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
						tmp_name, INET6_ADDRSTRLEN);
				freeaddrinfo(ai);
				config->node_name = strdup(tmp_name);
			}
			break;
	}
	if (rc == 0 && config->node_name)
		audit_msg(LOG_DEBUG, "Resolved node name: %s",
				config->node_name);
	return rc;
}
