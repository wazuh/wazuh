/* prelude-config.c -- 
 * Copyright 2008,2010-2011 Red Hat Inc., Durham, North Carolina.
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
#include <pwd.h>
#include "prelude-config.h"

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
	int (*parser)(struct nv_pair *, int, prelude_conf_t *);
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
static int profile_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int avc_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int avc_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_failure_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_failure_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_session_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_session_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_location_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_location_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_time_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int login_time_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int abends_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int abends_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int promiscuous_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int promiscuous_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int mac_status_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int mac_status_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int group_auth_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int group_auth_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_acct_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_acct_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_accounts_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_syscall_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_syscall_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_file_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_file_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_exec_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_exec_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_mk_exe_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int watched_mk_exe_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int tty_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int tty_act_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config);
static int sanity_check(prelude_conf_t *config, const char *file);

static const struct kw_pair keywords[] = 
{
  {"profile",                    profile_parser,		0 },
  {"detect_avc",                 avc_parser,			0 },
  {"avc_action",                 avc_act_parser,		0 },
  {"detect_logins",              login_parser,			0 },
  {"login_action",               login_act_parser,		0 },
  {"detect_login_fail_max",      login_failure_parser,		0 },
  {"login_fail_max_action",      login_failure_act_parser,	0 },
  {"detect_login_session_max",   login_session_parser,		0 },
  {"login_session_max_action",   login_session_act_parser,	0 },
  {"detect_login_location",      login_location_parser,		0 },
  {"login_location_action",      login_location_act_parser,	0 },
  {"detect_login_time",          login_time_parser,		0 },
  {"login_time_action",          login_time_act_parser,		0 },
  {"detect_abend",               abends_parser,			0 },
  {"abend_action",               abends_act_parser,		0 },
  {"detect_promiscuous",         promiscuous_parser,		0 },
  {"promiscuous_action",         promiscuous_act_parser,	0 },
  {"detect_mac_status",          mac_status_parser,		0 },
  {"mac_status_action",          mac_status_act_parser,		0 },
  {"detect_group_auth",          group_auth_parser,		0 },
  {"group_auth_action",          group_auth_act_parser,		0 },
  {"detect_watched_acct",        watched_acct_parser,		0 },
  {"watched_acct_action",        watched_acct_act_parser,	0 },
  {"watched_accounts",           watched_accounts_parser,	1 },
  {"detect_watched_syscall",     watched_syscall_parser,	0 },
  {"watched_syscall_action",     watched_syscall_act_parser,	0 },
  {"detect_watched_file",        watched_file_parser,		0 },
  {"watched_file_action",        watched_file_act_parser,	0 },
  {"detect_watched_exec",        watched_exec_parser,		0 },
  {"watched_exec_action",        watched_exec_act_parser,	0 },
  {"detect_watched_mk_exe",      watched_mk_exe_parser,		0 },
  {"watched_mk_exe_action",      watched_mk_exe_act_parser,	0 },
  {"detect_tty",                 tty_parser,		0 },
  {"tty_action",                 tty_act_parser,	0 },
  { NULL,             NULL }
};

static const struct nv_list enabler_words[] =
{
  {"no",   E_NO },
  {"yes",  E_YES },
  { NULL,  0 }
};

static const struct nv_list action_words[] =
{
  {"ignore",   A_IGNORE },
  {"idmef",    A_IDMEF },
//  {"kill",     A_KILL },
//  {"session",  A_SESSION },
//  {"single",   A_SINGLE },
//  {"halt",     A_HALT },
  { NULL,      0 }
};

/*
 * Set everything to its default value
*/
void clear_config(prelude_conf_t *config)
{
	config->profile = strdup("auditd");
	config->avcs = E_YES;
	config->avcs_act = A_IDMEF;
	config->logins = E_YES;
	config->logins_act = A_IDMEF;
	config->login_failure_max = E_YES;
	config->login_failure_max_act = A_IDMEF;
	config->login_session_max = E_YES;
	config->login_session_max_act = A_IDMEF;
	config->login_location = E_YES;
	config->login_location_act = A_IDMEF;
	config->login_time = E_YES;
	config->login_time_act = A_IDMEF;
	config->abends = E_YES;
	config->abends_act = A_IDMEF;
	config->promiscuous = E_YES;
	config->promiscuous_act = A_IDMEF;
	config->mac_status = E_YES;
	config->mac_status_act = A_IDMEF;
	config->group_auth = E_YES;
	config->group_auth_act = A_IDMEF;
	config->watched_acct = E_YES;
	config->watched_acct_act = A_IDMEF;
	config->watched_syscall = E_YES;
	config->watched_syscall_act = A_IDMEF;
	config->watched_file = E_YES;
	config->watched_file_act = A_IDMEF;
	config->watched_exec = E_YES;
	config->watched_exec_act = A_IDMEF;
	config->watched_mk_exe = E_YES;
	config->watched_mk_exe_act = A_IDMEF;
	config->tty = E_NO;
	config->tty_act = A_IDMEF;
	ilist_create(&config->watched_accounts);
}

int load_config(prelude_conf_t *config, const char *file)
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
		free_config(config);
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
		free_config(config);
		syslog(LOG_ERR, "Error fstat'ing config file (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		free_config(config);
		syslog(LOG_ERR, "Error - %s isn't owned by root", 
			file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		free_config(config);
		syslog(LOG_ERR, "Error - %s is world writable", 
			file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		free_config(config);
		syslog(LOG_ERR, "Error - %s is not a regular file", 
			file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		free_config(config);
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
			free_config(config);
			fclose(f);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			free_config(config);
			syslog(LOG_ERR, 
				"Unknown keyword \"%s\" in line %d of %s", 
				nv.name, lineno, file);
			fclose(f);
			return 1;
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			free_config(config);
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
			free_config(config);
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
 
static int profile_parser(struct nv_pair *nv, int line, 
		prelude_conf_t *config)
{
	if (nv->value) {
		free((char*)config->profile);
		config->profile = strdup(nv->value);
	}
	return 0;
}

static int lookup_enabler(const char *value, enable_t *enabled)
{
	int i;
	for (i=0; enabler_words[i].name != NULL; i++) {
		if (strcasecmp(value, enabler_words[i].name) == 0) {
                        *enabled = enabler_words[i].option;
                        return 0;
                }
        }
	return 1;
}

static int lookup_action(const char *value, action_t *action)
{
	int i;
	for (i=0; action_words[i].name != NULL; i++) {
		if (strcasecmp(value, action_words[i].name) == 0) {
                        *action = action_words[i].option;
                        return 0;
                }
        }
	return 1;
}

static int avc_parser(struct nv_pair *nv, int line, prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->avcs) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int avc_act_parser(struct nv_pair *nv, int line, prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->avcs_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_parser(struct nv_pair *nv, int line, prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->logins) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->logins_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_failure_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->login_failure_max) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_failure_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->login_failure_max_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_session_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->login_session_max) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_session_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->login_session_max_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_location_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->login_location) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_location_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->login_location_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_time_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->login_time) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int login_time_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->login_time_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int abends_parser(struct nv_pair *nv, int line, prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->abends) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int abends_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->abends_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int promiscuous_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->promiscuous) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int promiscuous_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->promiscuous_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int mac_status_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->mac_status) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int mac_status_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->mac_status_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int group_auth_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->group_auth) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int group_auth_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->group_auth_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_acct_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->watched_acct) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_acct_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->watched_acct_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int string_is_numeric(const char *s)
{
	if (*s == 0)
		return 0;
	do {
		if (!isdigit(*s))
			return 0;
		s++;
	} while (*s);
	return 1;
}

static int watched_accounts_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	char *str = (char *)nv->value;
	do {
		char *ptr = strchr(str, '-');
		if (ptr) {
			char *user1, *user2;
			int start, end, i;

			user1 = str;
			*ptr = 0;
			user2 = ptr+1;
			if (string_is_numeric(user1)) {
				start = strtoul(user1, NULL, 10);
			} else {
				struct passwd *pw;
				pw = getpwnam(user1);
				if (pw == NULL) {
					syslog(LOG_ERR,
				"user %s is invalid - line %d, skipping",
						user1, line);
					continue;
				}
				start = pw->pw_uid;
			}
			i = strlen(user2);
			if (i>0 && user2[i-1] == ',')
				user2[i-1] = 0;
			if (string_is_numeric(user2)) {
				end = strtoul(user2, NULL, 10);
			} else {
				struct passwd *pw;
				pw = getpwnam(user2);
				if (pw == NULL) {
					syslog(LOG_ERR,
				"user %s is invalid - line %d, skipping",
						user2, line);
					continue;
				}
				end = pw->pw_uid;
			}
			if (start >= end) {
				syslog(LOG_ERR,
			"%s is larger or equal to %s, please fix, skipping",
					user1, user2);
				continue;
			}
			for (i=start; i<=end; i++) {
				ilist_add_if_uniq(
						&config->watched_accounts, i);
			}
		} else {
			int acct;
			if (string_is_numeric(str))
				acct = strtoul(str, NULL, 10);
			else {
				struct passwd *pw;
				pw = getpwnam(str);
				if (pw == NULL) {
					syslog(LOG_ERR,
				"user %s is invalid - line %d, skipping",
						str, line);
					continue;
				}
				acct = pw->pw_uid;
			}
			ilist_add_if_uniq(&config->watched_accounts, acct);
		}
		str = strtok(NULL, ", ");
	} while(str);

        return 0;
}

static int watched_syscall_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->watched_syscall) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_syscall_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->watched_syscall_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_file_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->watched_file) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_file_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->watched_file_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_exec_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->watched_exec) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_exec_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->watched_exec_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_mk_exe_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->watched_mk_exe) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int watched_mk_exe_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->watched_mk_exe_act) == 0)
		return 0;
        syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
        return 1;
}

static int tty_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_enabler(nv->value, &config->tty) == 0)
		return 0;
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int tty_act_parser(struct nv_pair *nv, int line,
	prelude_conf_t *config)
{
	if (lookup_action(nv->value, &config->tty_act) == 0)
		return 0;
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}
/*
 * This function is where we do the integrated check of the audispd config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(prelude_conf_t *config, const char *file)
{
	/* Error checking */
	return 0;
}

void free_config(prelude_conf_t *config)
{
	free((void *)config->profile);
	ilist_clear(&config->watched_accounts);
}

