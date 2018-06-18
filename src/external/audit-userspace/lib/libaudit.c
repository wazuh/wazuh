/* libaudit.c -- 
 * Copyright 2004-2009,2012,2014,2016-17 Red Hat Inc., Durham, North Carolina.
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
 *      Steve Grubb <sgrubb@redhat.com>
 *      Rickard E. (Rik) Faith <faith@redhat.com>
 *      Richard Guy Briggs <rgb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>	/* O_NOFOLLOW needs gnu defined */
#include <limits.h>	/* for PATH_MAX */
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "private.h"
#include "errormsg.h"

/* #defines for the audit failure query  */
#define CONFIG_FILE "/etc/libaudit.conf"

/* Local prototypes */
struct nv_pair
{
        const char *name;
        const char *value;
};

struct kw_pair
{
        const char *name;
        int (*parser)(const char *, int);
};

struct nv_list
{
        const char *name;
        int option;
};

struct libaudit_conf
{
        auditfail_t failure_action;
};

static const struct nv_list failure_actions[] =
{
  {"ignore",		FAIL_IGNORE },
  {"log",		FAIL_LOG },
  {"terminate",		FAIL_TERMINATE },
  { NULL,		0 }
};

int _audit_permadded = 0;
int _audit_archadded = 0;
int _audit_syscalladded = 0;
int _audit_exeadded = 0;
int _audit_filterfsadded = 0;
unsigned int _audit_elf = 0U;
static struct libaudit_conf config;

static int audit_failure_parser(const char *val, int line);
static int audit_name_to_uid(const char *name, uid_t *uid);
static int audit_name_to_gid(const char *name, gid_t *gid);

static const struct kw_pair keywords[] =
{
  {"failure_action",	audit_failure_parser },
  { NULL,		NULL }
};

static int audit_priority(int xerrno)
{
	/* If they've compiled their own kernel and did not include
	 * the audit susbsystem, they will get ECONNREFUSED. We'll
	 * demote the message to debug so its not lost entirely. */
	if (xerrno == ECONNREFUSED)
		return LOG_DEBUG;
	else
		return LOG_WARNING;
}

int audit_request_status(int fd)
{
	int rc = audit_send(fd, AUDIT_GET, NULL, 0);
	if (rc < 0) 
		audit_msg(audit_priority(errno),
			"Error sending status request (%s)", strerror(-rc));
	return rc;
}

/*
 * Set everything to its default value
 */
static void clear_config(void)
{
        config.failure_action = FAIL_IGNORE;
}

/* Get 1 line from file */
static char *get_line(FILE *f, char *buf, size_t len)
{
	if (fgets(buf, len, f)) {
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
	char *ptr, *saved=NULL;

	nv->name = NULL;
	nv->value = NULL;
	ptr = audit_strsplit_r(buf, &saved);
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = audit_strsplit_r(NULL, &saved);
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = audit_strsplit_r(NULL, &saved);
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* Make sure there's nothing else */
	ptr = audit_strsplit_r(NULL, &saved);
	if (ptr)
		return 1;

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

static int audit_failure_parser(const char *val, int line)
{
	int i;

	audit_msg(LOG_DEBUG, "audit_failure_parser called with: %s", val);
	for (i=0; failure_actions[i].name != NULL; i++) {
		if (strcasecmp(val, failure_actions[i].name) == 0) {
			config.failure_action = failure_actions[i].option;
			return 0;
		}
	}
	audit_msg(LOG_ERR, "Option %s not found - line %d", val, line);
	return 1;
}

/*
 *  Read the /etc/libaudit.conf file and all tunables.
 */
static int load_libaudit_config(const char *path)
{
	int fd, rc, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[128];

	/* open the file */
	rc = open(path, O_NOFOLLOW|O_RDONLY);
	if (rc < 0) {
		if (errno != ENOENT) {
			audit_msg(LOG_ERR, "Error opening %s (%s)",
				path, strerror(errno));
			return 1;
		}
		audit_msg(LOG_WARNING,
			"Config file %s doesn't exist, skipping", path);
		return 0;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	audit_msg(LOG_DEBUG, "Config file %s opened for parsing", path);
	if (fstat(fd, &st) < 0) {
		audit_msg(LOG_ERR, "Error fstat'ing %s (%s)",
			path, strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		audit_msg(LOG_ERR, "Error - %s isn't owned by root", path);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		audit_msg(LOG_ERR, "Error - %s is world writable", path);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		audit_msg(LOG_ERR, "Error - %s is not a regular file", path);
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

	while (get_line(f, buf, sizeof(buf))) {
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
					lineno, path);
				break;
			case 2: // no '=' sign
				audit_msg(LOG_ERR,
					"Missing equal sign for line %d in %s",
					lineno, path);
				break;
			default: // something else went wrong...
				audit_msg(LOG_ERR,
					"Unknown error for line %d in %s",
					lineno, path);
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
				nv.name, lineno, path);
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(nv.value, lineno);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}

		lineno++;
	}

	fclose(f);
	return 0;
}


/*
 * This function is called to get the value of the failure_action 
 * tunable stored in /etc/libaudit.conf.  The function returns 1 if
 * the tunable is not found or there is an error. If the tunable is found,
 * 0 is returned the the tunable value is saved in the failmode parameter.
 */
int get_auditfail_action(auditfail_t *failmode)
{
	clear_config();

	if (load_libaudit_config(CONFIG_FILE)) {
		*failmode = config.failure_action;
		return 1;
	}

	*failmode = config.failure_action;
	return 0;
}

int audit_set_enabled(int fd, uint32_t enabled)
{
	int rc;
	struct audit_status s;

	memset(&s, 0, sizeof(s));
	s.mask    = AUDIT_STATUS_ENABLED;
	s.enabled = enabled;
	rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending enable request (%s)", strerror(-rc));
	return rc;
}

/* 
 * This function will return 0 if auditing is NOT enabled and
 * 1 if enabled, and -1 on error.
 */
int audit_is_enabled(int fd)
{
	int rc;

	if (fd < 0)
		return 0;

	if ((rc = audit_request_status(fd)) > 0) {
		struct audit_reply rep;
		int i;
		int timeout = 40; /* tenths of seconds */
		struct pollfd pfd[1];

		pfd[0].fd = fd;
		pfd[0].events = POLLIN;

	        for (i = 0; i < timeout; i++) {
			do {
				rc = poll(pfd, 1, 100);
			} while (rc < 0 && errno == EINTR);

			rc = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING,0);
			if (rc > 0) {
                	        /* If we get done or error, break out */
                        	if (rep.type == NLMSG_DONE || 
					rep.type == NLMSG_ERROR)
	                                break;

        	                /* If its not status, keep looping */
	                        if (rep.type != AUDIT_GET)
        	                        continue;

				/* Found it... */
				return rep.status->enabled;
			}
		}
	}
	if (rc == -ECONNREFUSED) {
		/* This is here to let people that build their own kernel
		   and disable the audit system get in. ECONNREFUSED is
		   issued by the kernel when there is "no on listening". */
		return 0;
	} else if (rc == -EPERM && !audit_can_control()) {
		/* If we get this, then the kernel supports auditing
		 * but we don't have enough privilege to write to the
		 * socket. Therefore, we have already been authenticated
		 * and we are a common user. Just act as though auditing
		 * is not enabled. Any other error we take seriously.
		 * This is here basically to satisfy Xscreensaver. */
		return 0;
	}
	return -1;
}

int audit_set_failure(int fd, uint32_t failure)
{
	int rc;
	struct audit_status s;

	memset(&s, 0, sizeof(s));
	s.mask    = AUDIT_STATUS_FAILURE;
	s.failure = failure;
	rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
	if (rc < 0)
		audit_msg(audit_priority(errno), 
			"Error sending failure mode request (%s)", 
			strerror(-rc));
	return rc;
}

/*
 * This function returns -1 on error and 1 on success.
 */
int audit_set_pid(int fd, uint32_t pid, rep_wait_t wmode)
{
	struct audit_status s;
	struct audit_reply rep;
	struct pollfd pfd[1];
	int rc;

	memset(&s, 0, sizeof(s));
	s.mask    = AUDIT_STATUS_PID;
	s.pid     = pid;
	rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
	if (rc < 0) {
		audit_msg(audit_priority(errno), 
			"Error setting audit daemon pid (%s)", 
			strerror(-rc));
		return rc;
	}
	if (wmode == WAIT_NO)
		return 1;

	/* Now we'll see if there's any reply message. This only
           happens on error. It is not fatal if there is no message.
	   As a matter of fact, we don't do anything with the message
	   besides gobble it. */
	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	do {
		rc = poll(pfd, 1, 100);	/* .1 second */
	} while (rc < 0 && errno == EINTR);

	(void)audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
	return 1;
}

int audit_set_rate_limit(int fd, uint32_t limit)
{
	int rc;
	struct audit_status s;

	memset(&s, 0, sizeof(s));
	s.mask       = AUDIT_STATUS_RATE_LIMIT;
	s.rate_limit = limit;
	rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending rate limit request (%s)", 
			strerror(-rc));
	return rc;
}

int audit_set_backlog_limit(int fd, uint32_t limit)
{
	int rc;
	struct audit_status s;

	memset(&s, 0, sizeof(s));
	s.mask          = AUDIT_STATUS_BACKLOG_LIMIT;
	s.backlog_limit = limit;
	rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending backlog limit request (%s)", 
			strerror(-rc));
	return rc;
}

int audit_set_backlog_wait_time(int fd, uint32_t bwt)
{
	int rc = -1;
#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
    HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1
	struct audit_status s;

	memset(&s, 0, sizeof(s));
	s.mask          = AUDIT_STATUS_BACKLOG_WAIT_TIME;
	s.backlog_wait_time = bwt;
	rc = audit_send(fd, AUDIT_SET, &s, sizeof(s));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending backlog limit request (%s)", 
			strerror(-rc));
#endif
	return rc;
}

int audit_reset_lost(int fd)
{
	int rc;
	int seq;
	struct audit_status s;

	if ((audit_get_features() & AUDIT_FEATURE_BITMAP_LOST_RESET) == 0)
		return -EAU_FIELDNOSUPPORT;

	memset(&s, 0, sizeof(s));
	s.mask = AUDIT_STATUS_LOST;
	s.lost = 0;
	rc = __audit_send(fd, AUDIT_SET, &s, sizeof(s), &seq);
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending lost reset request (%s)", 
			strerror(-rc));
	return rc;
}

int audit_set_feature(int fd, unsigned feature, unsigned value, unsigned lock)
{
#if defined(HAVE_DECL_AUDIT_FEATURE_VERSION) && \
    defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
	int rc;
	struct audit_features f;

	memset(&f, 0, sizeof(f));
	f.mask = AUDIT_FEATURE_TO_MASK(feature);
	if (value)
		f.features = AUDIT_FEATURE_TO_MASK(feature);
	if (lock)
		f.lock = AUDIT_FEATURE_TO_MASK(feature);
	rc = audit_send(fd, AUDIT_SET_FEATURE, &f, sizeof(f));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error setting feature (%s)", 
			strerror(-rc));
	return rc;
#else
	errno = EINVAL;
	return -1;
#endif
}

int audit_request_features(int fd)
{
#if defined(HAVE_DECL_AUDIT_FEATURE_VERSION) && \
    defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
	int rc;
	struct audit_features f;

	memset(&f, 0, sizeof(f));
	rc = audit_send(fd, AUDIT_GET_FEATURE, &f, sizeof(f));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error getting feature (%s)", 
			strerror(-rc));
	return rc;
#else
	errno = EINVAL;
	return -1;
#endif
}

extern int  audit_set_loginuid_immutable(int fd)
{
#if defined(HAVE_DECL_AUDIT_FEATURE_VERSION) && \
    defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
	return audit_set_feature(fd, AUDIT_FEATURE_LOGINUID_IMMUTABLE, 1, 1);
#else
	errno = EINVAL;
	return -1;
#endif
}

#define AUDIT_FEATURES_UNSET 0xFFFFFFFF
#define AUDIT_FEATURES_UNSUPPORTED 0xEFFFFFFF
static uint32_t features_bitmap = AUDIT_FEATURES_UNSET;
static void load_feature_bitmap(void)
{
	int rc, fd;

	fd = audit_open();
	if (fd < 0) {
		features_bitmap = AUDIT_FEATURES_UNSUPPORTED;
		return;
	}

#if defined(HAVE_DECL_AUDIT_FEATURE_VERSION) && \
    defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
	if ((rc = audit_request_status(fd)) > 0) {
		struct audit_reply rep;
		int i;
		int timeout = 40; /* tenths of seconds */
		struct pollfd pfd[1];

		pfd[0].fd = fd;
		pfd[0].events = POLLIN;

	        for (i = 0; i < timeout; i++) {
			do {
				rc = poll(pfd, 1, 100);
			} while (rc < 0 && errno == EINTR);

			rc = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING,0);
			if (rc > 0) {
                	        /* If we get done or error, break out */
                        	if (rep.type == NLMSG_DONE || 
					rep.type == NLMSG_ERROR)
	                                break;

        	                /* If its not status, keep looping */
	                        if (rep.type != AUDIT_GET)
        	                        continue;

				/* Found it... */
				features_bitmap = rep.status->feature_bitmap;
				return;
			}
		}
	}
#endif
	features_bitmap = AUDIT_FEATURES_UNSUPPORTED;
}

uint32_t audit_get_features(void)
{
	if (features_bitmap == AUDIT_FEATURES_UNSET)
		load_feature_bitmap();

	if (features_bitmap == AUDIT_FEATURES_UNSUPPORTED)
		return 0;

	return features_bitmap;
}

int audit_request_rules_list_data(int fd)
{
	int rc = audit_send(fd, AUDIT_LIST_RULES, NULL, 0);
	if (rc < 0 && rc != -EINVAL)
		audit_msg(audit_priority(errno),
			"Error sending rule list data request (%s)", 
			strerror(-rc));
	return rc;
}

int audit_request_signal_info(int fd)
{
	int rc = audit_send(fd, AUDIT_SIGNAL_INFO, NULL, 0);
	if (rc < 0)
		audit_msg(LOG_WARNING,
			"Error sending signal_info request (%s)",
			strerror(-rc));
	return rc;
}

int audit_update_watch_perms(struct audit_rule_data *rule, int perms)
{
	unsigned int i, done=0;

	if (rule->field_count < 1)
		return -1;

	// First see if we have an entry we are updating
	for (i=0; i< rule->field_count; i++) {
		if (rule->fields[i] == AUDIT_PERM) {
			rule->values[i] = perms;
			done = 1;
		}
	}
	if (!done) {
		// If not check to see if we have room to add a field
		if (rule->field_count >= (AUDIT_MAX_FIELDS - 1))
			return -2;
	
		// Add the perm
		rule->fields[rule->field_count] = AUDIT_PERM;
		rule->fieldflags[rule->field_count] = AUDIT_EQUAL;
		rule->values[rule->field_count] = perms;
		rule->field_count++;
	}
	return 0;
}

int audit_add_watch(struct audit_rule_data **rulep, const char *path)
{
	return audit_add_watch_dir(AUDIT_WATCH, rulep, path);
}

int audit_add_dir(struct audit_rule_data **rulep, const char *path)
{
	return audit_add_watch_dir(AUDIT_DIR, rulep, path);
}

int audit_add_watch_dir(int type, struct audit_rule_data **rulep,
			const char *path)
{
	size_t len = strlen(path);
	struct audit_rule_data *rule = *rulep;

	if (rule && rule->field_count) {
		audit_msg(LOG_ERR, "Rule is not empty\n");
		return -1;
	}
	if (type != AUDIT_WATCH && type != AUDIT_DIR) {
		audit_msg(LOG_ERR, "Invalid type used\n");
		return -1;
	}

	*rulep = realloc(rule, len + sizeof(*rule));
	if (*rulep == NULL) {
		free(rule);
		audit_msg(LOG_ERR, "Cannot realloc memory!\n");
		return -1;
	}
	rule = *rulep;
	memset(rule, 0, len + sizeof(*rule));

	rule->flags = AUDIT_FILTER_EXIT;
	rule->action = AUDIT_ALWAYS;
	audit_rule_syscallbyname_data(rule, "all");
	rule->field_count = 2;
	rule->fields[0] = type;
	rule->values[0] = len;
	rule->fieldflags[0] = AUDIT_EQUAL;
	rule->buflen = len;
	memcpy(&rule->buf[0], path, len);

	// Default to all permissions
	rule->fields[1] = AUDIT_PERM;
	rule->fieldflags[1] = AUDIT_EQUAL;
	rule->values[1] = AUDIT_PERM_READ | AUDIT_PERM_WRITE |
				AUDIT_PERM_EXEC | AUDIT_PERM_ATTR;
	
	_audit_permadded = 1;

	return  0;
}

int audit_add_rule_data(int fd, struct audit_rule_data *rule,
                        int flags, int action)
{
	int rc;

	rule->flags  = flags;
	rule->action = action;
	rc = audit_send(fd, AUDIT_ADD_RULE, rule, 
			sizeof(struct audit_rule_data) + rule->buflen);
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending add rule data request (%s)",
				errno == EEXIST ? 
				"Rule exists" : strerror(-rc));
	return rc;
}

int audit_delete_rule_data(int fd, struct audit_rule_data *rule,
                           int flags, int action)
{
	int rc;

	rule->flags  = flags;
	rule->action = action;
	rc = audit_send(fd, AUDIT_DEL_RULE, rule, 
			sizeof(struct audit_rule_data) + rule->buflen);
	if (rc < 0) {
		if (rc == -ENOENT)
			audit_msg(LOG_WARNING,
			"Error sending delete rule request (No rule matches)");
		else
			audit_msg(audit_priority(errno),
				"Error sending delete rule data request (%s)",
				strerror(-rc));
	}
	return rc;
}

/*
 * This function is part of the directory auditing code
 */
int audit_trim_subtrees(int fd)
{
	int rc = audit_send(fd, AUDIT_TRIM, NULL, 0);
	if (rc < 0) 
		audit_msg(audit_priority(errno),
			"Error sending trim subtrees command (%s)",
			strerror(-rc));
	return rc;
}

/*
 * This function is part of the directory auditing code
 */
int audit_make_equivalent(int fd, const char *mount_point,
			 const char *subtree)
{
	int rc;
	size_t len1 = strlen(mount_point);
	size_t len2 = strlen(subtree);
 	struct {
 		uint32_t sizes[2];
 		unsigned char buf[];
 	} *cmd = malloc(sizeof(*cmd) + len1 + len2);

 	memset(cmd, 0, sizeof(*cmd) + len1 + len2);

 	cmd->sizes[0] = len1;
 	cmd->sizes[1] = len2;
 	memcpy(&cmd->buf[0], mount_point, len1);
 	memcpy(&cmd->buf[len1], subtree, len2);

 	rc = audit_send(fd, AUDIT_MAKE_EQUIV, cmd, sizeof(*cmd) + len1 + len2);
	if (rc < 0) 
		audit_msg(audit_priority(errno),
			"Error sending make_equivalent command (%s)",
			strerror(-rc));
	free(cmd);
	return rc;
}

/*
 * This function will retrieve the loginuid or -1 if there
 * is an error.
 */
uid_t audit_getloginuid(void)
{
	uid_t uid;
	int len, in;
	char buf[16];

	errno = 0;
	in = open("/proc/self/loginuid", O_NOFOLLOW|O_RDONLY);
	if (in < 0)
		return -1;
	do {
		len = read(in, buf, sizeof(buf));
	} while (len < 0 && errno == EINTR);
	close(in);
	if (len < 0 || len >= sizeof(buf))
		return -1;
	buf[len] = 0;
	errno = 0;
	uid = strtol(buf, 0, 10);
	if (errno)
		return -1;
	else
		return uid;
}

/*
 * This function returns 0 on success and 1 on failure
 */
int audit_setloginuid(uid_t uid)
{
	char loginuid[16];
	int o, count, rc = 0;

	errno = 0;
	count = snprintf(loginuid, sizeof(loginuid), "%u", uid);
	o = open("/proc/self/loginuid", O_NOFOLLOW|O_WRONLY|O_TRUNC);
	if (o >= 0) {
		int block, offset = 0;

		while (count > 0) {
			block = write(o, &loginuid[offset], (unsigned)count);

			if (block < 0) {
				if (errno == EINTR)
					continue;
				audit_msg(LOG_ERR, "Error writing loginuid");
				close(o);
				return 1;
			}
			offset += block;
			count -= block;
		}
		close(o);
	} else {
		audit_msg(LOG_ERR, "Error opening /proc/self/loginuid");
		rc = 1;
	}
	return rc;
}

/*
 * This function will retrieve the login session or -2 if there
 * is an error.
 */
uint32_t audit_get_session(void)
{
	uint32_t ses;
	int len, in;
	char buf[16];

	errno = 0;
	in = open("/proc/self/sessionid", O_NOFOLLOW|O_RDONLY);
	if (in < 0)
		return -2;
	do {
		len = read(in, buf, sizeof(buf));
	} while (len < 0 && errno == EINTR);
	close(in);
	if (len < 0 || len >= sizeof(buf))
		return -2;
	buf[len] = 0;
	errno = 0;
	ses = strtoul(buf, 0, 10);
	if (errno)
		return -2;
	else
		return ses;
}

int audit_rule_syscall_data(struct audit_rule_data *rule, int scall)
{
	int word = AUDIT_WORD(scall);
	int bit  = AUDIT_BIT(scall);

	if (word > (AUDIT_BITMASK_SIZE-1)) 
		return -1;
	rule->mask[word] |= bit;
	return 0;
}

int audit_rule_syscallbyname_data(struct audit_rule_data *rule,
                                  const char *scall)
{
	int nr, i;
	int machine;

	if (!strcmp(scall, "all")) {
		for (i = 0; i < AUDIT_BITMASK_SIZE; i++) 
			rule->mask[i] = ~0;
		return 0;
	}
	if (!_audit_elf)
		machine = audit_detect_machine();
	else
		machine = audit_elf_to_machine(_audit_elf);
	if (machine < 0)
		return -2;
	nr = audit_name_to_syscall(scall, machine);
	if (nr < 0) {
		if (isdigit(scall[0]))
			nr = strtol(scall, NULL, 0);
	}
	if (nr >= 0) 
		return audit_rule_syscall_data(rule, nr);
	return -1;
}

int audit_rule_interfield_comp_data(struct audit_rule_data **rulep,
					 const char *pair,
					 int flags)
{
	const char *f = pair;
	char       *v;
	int        op;
	int        field1, field2;
	struct audit_rule_data *rule = *rulep;

	if (f == NULL)
		return -EAU_FILTERMISSING;

	if (rule->field_count >= (AUDIT_MAX_FIELDS - 1))
		return -EAU_FIELDTOOMANY;

	/* look for 2-char operators first
	   then look for 1-char operators afterwards
	   when found, null out the bytes under the operators to split
	   and set value pointer just past operator bytes
	*/
	if ( (v = strstr(pair, "!=")) ) {
		*v++ = '\0';
		*v++ = '\0';
		op = AUDIT_NOT_EQUAL;
	} else if ( (v = strstr(pair, "=")) ) {
		*v++ = '\0';
		op = AUDIT_EQUAL;
	} else {
		return -EAU_OPEQNOTEQ;
	}

	if (*f == 0)
		return -EAU_COMPFIELDNAME;

	if (*v == 0)
		return -EAU_COMPVAL;

	if ((field1 = audit_name_to_field(f)) < 0)
		return -EAU_COMPFIELDUNKNOWN;

	if ((field2 = audit_name_to_field(v)) < 0)
		return -EAU_COMPVALUNKNOWN;

	/* Interfield comparison can only be in exit filter */
	if (flags != AUDIT_FILTER_EXIT)
		return -EAU_EXITONLY;

	// It should always be AUDIT_FIELD_COMPARE
	rule->fields[rule->field_count] = AUDIT_FIELD_COMPARE;
	rule->fieldflags[rule->field_count] = op;
	/* oh god, so many permutations */
	switch (field1)
	{
		/* UID comparison */
		case AUDIT_EUID:
			switch(field2) {
			case AUDIT_LOGINUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_EUID;
				break;
			case AUDIT_FSUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EUID_TO_FSUID;
				break;
			case AUDIT_OBJ_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EUID_TO_OBJ_UID;
				break;
			case AUDIT_SUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EUID_TO_SUID;
				break;
			case AUDIT_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_EUID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_FSUID:
			switch(field2) {
			case AUDIT_LOGINUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_FSUID;
				break;
			case AUDIT_EUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EUID_TO_FSUID;
				break;
			case AUDIT_OBJ_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_FSUID_TO_OBJ_UID;
				break;
			case AUDIT_SUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SUID_TO_FSUID;
				break;
			case AUDIT_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_FSUID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_LOGINUID:
			switch(field2) {
			case AUDIT_EUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_EUID;
				break;
			case AUDIT_FSUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_FSUID;
				break;
			case AUDIT_OBJ_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_OBJ_UID;
				break;
			case AUDIT_SUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_SUID;
				break;
			case AUDIT_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_AUID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_SUID:
			switch(field2) {
			case AUDIT_LOGINUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_SUID;
				break;
			case AUDIT_EUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EUID_TO_SUID;
				break;
			case AUDIT_FSUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SUID_TO_FSUID;
				break;
			case AUDIT_OBJ_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SUID_TO_OBJ_UID;
				break;
			case AUDIT_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_SUID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_OBJ_UID:
			switch(field2) {
			case AUDIT_LOGINUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_AUID_TO_OBJ_UID;
				break;
			case AUDIT_EUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EUID_TO_OBJ_UID;
				break;
			case AUDIT_FSUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_FSUID_TO_OBJ_UID;
				break;
			case AUDIT_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_OBJ_UID;
				break;
			case AUDIT_SUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SUID_TO_OBJ_UID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_UID:
			switch(field2) {
			case AUDIT_LOGINUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_AUID;
				break;
			case AUDIT_EUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_EUID;
				break;
			case AUDIT_FSUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_FSUID;
				break;
			case AUDIT_OBJ_UID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_OBJ_UID;
				break;
			case AUDIT_SUID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_UID_TO_SUID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;

		/* GID comparisons */
		case AUDIT_EGID:
			switch(field2) {
			case AUDIT_FSGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EGID_TO_FSGID;
				break;
			case AUDIT_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_EGID;
				break;
			case AUDIT_OBJ_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EGID_TO_OBJ_GID;
				break;
			case AUDIT_SGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EGID_TO_SGID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_FSGID:
			switch(field2) {
			case AUDIT_SGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SGID_TO_FSGID;
				break;
			case AUDIT_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_FSGID;
				break;
			case AUDIT_OBJ_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_FSGID_TO_OBJ_GID;
				break;
			case AUDIT_EGID:
				rule->values[rule->field_count] =
						 AUDIT_COMPARE_EGID_TO_FSGID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_GID:
			switch(field2) {
			case AUDIT_EGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_EGID;
				break;
			case AUDIT_FSGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_FSGID;
				break;
			case AUDIT_OBJ_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_OBJ_GID;
				break;
			case AUDIT_SGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_SGID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_OBJ_GID:
			switch(field2) {
			case AUDIT_EGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EGID_TO_OBJ_GID;
				break;
			case AUDIT_FSGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_FSGID_TO_OBJ_GID;
				break;
			case AUDIT_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_OBJ_GID;
				break;
			case AUDIT_SGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SGID_TO_OBJ_GID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		case AUDIT_SGID:
			switch(field2) {
			case AUDIT_FSGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SGID_TO_FSGID;
				break;
			case AUDIT_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_GID_TO_SGID;
				break;
			case AUDIT_OBJ_GID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_SGID_TO_OBJ_GID;
				break;
			case AUDIT_EGID:
				rule->values[rule->field_count] =
						AUDIT_COMPARE_EGID_TO_SGID;
				break;
			default:
				return -EAU_COMPINCOMPAT;
			}
			break;
		default:
			return -EAU_COMPINCOMPAT;
			break;
	}
	rule->field_count++;
	return 0;
}

int audit_determine_machine(const char *arch)
{	// What do we want? i686, x86_64, ia64 or b64, b32
	int machine;
	unsigned int bits = 0;

	if (strcasecmp("b64", arch) == 0) {
		bits = __AUDIT_ARCH_64BIT;
		machine = audit_detect_machine();
	} else if (strcasecmp("b32", arch) == 0) {
		bits = ~__AUDIT_ARCH_64BIT;
		machine = audit_detect_machine();
	} else { 
		machine = audit_name_to_machine(arch);
		if (machine < 0) {
			// See if its numeric
			unsigned int ival;
			errno = 0;
			ival = strtoul(arch, NULL, 16);
			if (errno)
				return -4;
			machine = audit_elf_to_machine(ival);
		}
	}

	if (machine < 0) 
		return -4;

	/* Here's where we fixup the machine. For example, they give
	 * x86_64 & want 32 bits we translate that to i686. */
	if (bits == ~__AUDIT_ARCH_64BIT && machine == MACH_86_64)
		machine = MACH_X86;
	else if (bits == ~__AUDIT_ARCH_64BIT && machine == MACH_PPC64)
		machine = MACH_PPC;
	else if (bits == ~__AUDIT_ARCH_64BIT && machine == MACH_S390X)
		machine = MACH_S390;
	else if (bits == ~__AUDIT_ARCH_64BIT && machine == MACH_AARCH64)
		machine = MACH_ARM;

	/* Check for errors - return -6 
	 * We don't allow 32 bit machines to specify 64 bit. */
	switch (machine)
	{
		case MACH_X86:
			if (bits == __AUDIT_ARCH_64BIT)
				return -6;
			break;
		case MACH_IA64:
			if (bits == ~__AUDIT_ARCH_64BIT)
				return -6;
			break;
		case MACH_PPC:
			if (bits == __AUDIT_ARCH_64BIT)
				return -6;
			break;
		case MACH_S390:
			if (bits == __AUDIT_ARCH_64BIT)
				return -6;
			break;
#ifdef WITH_ARM
		case MACH_ARM:
			if (bits == __AUDIT_ARCH_64BIT)
				return -6; // Deadcode - just incase of mistake
			break;
#endif
#ifdef WITH_AARCH64
		case MACH_AARCH64:
			if (bits && bits != __AUDIT_ARCH_64BIT)
				return -6; // Deadcode - just incase of mistake
			break;
#endif
		case MACH_86_64:   /* fallthrough */
		case MACH_PPC64:   /* fallthrough */
		case MACH_PPC64LE: /* fallthrough */
		case MACH_S390X:   /* fallthrough */
			break;
		default:
			return -6;
	}
	return machine;
}

int audit_rule_fieldpair_data(struct audit_rule_data **rulep, const char *pair,
                              int flags)
{
	const char *f = pair;
	char       *v;
	int        op;
	int        field;
	int        vlen;
	int        offset;
	struct audit_rule_data *rule = *rulep;

	if (f == NULL)
		return -EAU_FILTERMISSING;

	if (rule->field_count >= (AUDIT_MAX_FIELDS - 1))
		return -EAU_FIELDTOOMANY;

	/* look for 2-char operators first
	   then look for 1-char operators afterwards
	   when found, null out the bytes under the operators to split
	   and set value pointer just past operator bytes
	*/
	if ( (v = strstr(pair, "!=")) ) {
		*v++ = '\0';
		*v++ = '\0';
		op = AUDIT_NOT_EQUAL;
	} else if ( (v = strstr(pair, ">=")) ) {
		*v++ = '\0';
		*v++ = '\0';
		op = AUDIT_GREATER_THAN_OR_EQUAL;
	} else if ( (v = strstr(pair, "<=")) ) {
		*v++ = '\0';
		*v++ = '\0';
		op = AUDIT_LESS_THAN_OR_EQUAL;
	} else if ( (v = strstr(pair, "&=")) ) {
		*v++ = '\0';
		*v++ = '\0';
		op = AUDIT_BIT_TEST;
	} else if ( (v = strstr(pair, "=")) ) {
		*v++ = '\0';
		op = AUDIT_EQUAL;
	} else if ( (v = strstr(pair, ">")) ) {
		*v++ = '\0';
		op = AUDIT_GREATER_THAN;
	} else if ( (v = strstr(pair, "<")) ) {
		*v++ = '\0';
		op = AUDIT_LESS_THAN;
	} else if ( (v = strstr(pair, "&")) ) {
		*v++ = '\0';
		op = AUDIT_BIT_MASK;
	}

	if (v == NULL)
		return -EAU_OPMISSING;
	
	if (*f == 0)
		return -EAU_FIELDNAME;

	if (*v == 0)
		return -EAU_FIELDVALMISSING;

	if ((field = audit_name_to_field(f)) < 0) 
		return -EAU_FIELDUNKNOWN;

	/* Exclude filter can be used only with MSGTYPE and cred fields */
	if (flags == AUDIT_FILTER_EXCLUDE) {
		uint32_t features = audit_get_features();
		if ((features & AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND) == 0) {
			if (field != AUDIT_MSGTYPE)
				return -EAU_FIELDNOSUPPORT;
		} else {
			switch(field) {
				case AUDIT_PID:
				case AUDIT_UID:
				case AUDIT_GID:
				case AUDIT_LOGINUID:
				case AUDIT_MSGTYPE:
				case AUDIT_SUBJ_USER:
				case AUDIT_SUBJ_ROLE:
				case AUDIT_SUBJ_TYPE:
				case AUDIT_SUBJ_SEN:
				case AUDIT_SUBJ_CLR:
					break;
				default:
					return -EAU_MSGTYPECREDEXCLUDE;
			}
		}
	}

	/* FS filter can be used only with FSTYPE field */
	if (flags == AUDIT_FILTER_FS) {
		uint32_t features = audit_get_features();
		if ((features & AUDIT_FEATURE_BITMAP_FILTER_FS) == 0) {
			return -EAU_FILTERNOSUPPORT;
		}
	}

	rule->fields[rule->field_count] = field;
	rule->fieldflags[rule->field_count] = op;
	switch (field)
	{
		case AUDIT_UID:
		case AUDIT_EUID:
		case AUDIT_SUID:
		case AUDIT_FSUID:
		case AUDIT_LOGINUID:
		case AUDIT_OBJ_UID:
			// Do positive & negative separate for 32 bit systems
			vlen = strlen(v);
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtoul(v, NULL, 0);
			else if (vlen >= 2 && *(v)=='-' &&
						(isdigit((char)*(v+1))))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else {
				if (strcmp(v, "unset") == 0)
					rule->values[rule->field_count] =
								4294967295;
				else if (audit_name_to_uid(v, 
					&rule->values[rule->field_count])) {
					audit_msg(LOG_ERR, "Unknown user: %s",
						v);
					return -2;
				}
			}
			break;
		case AUDIT_GID:
		case AUDIT_EGID:
		case AUDIT_SGID:
		case AUDIT_FSGID:
		case AUDIT_OBJ_GID:
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtol(v, NULL, 0);
			else {
				if (audit_name_to_gid(v, 
					&rule->values[rule->field_count])) {
					audit_msg(LOG_ERR, "Unknown group: %s",
						v);
					return -2;
				}
			}
			break;
		case AUDIT_EXIT:
			if (flags != AUDIT_FILTER_EXIT)
				return -EAU_EXITONLY;
			vlen = strlen(v);
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtol(v, NULL, 0);
			else if (vlen >= 2 && *(v)=='-' && 
						(isdigit((char)*(v+1)))) 
				rule->values[rule->field_count] = 
					strtol(v, NULL, 0);
			else {
				rule->values[rule->field_count] = 
						audit_name_to_errno(v);
				if (rule->values[rule->field_count] == 0) 
					return -EAU_ERRUNKNOWN;
			}
			break;
		case AUDIT_MSGTYPE:
			if (flags != AUDIT_FILTER_EXCLUDE &&
					flags != AUDIT_FILTER_USER)
				return -EAU_MSGTYPEEXCLUDEUSER;

			if (isdigit((char)*(v)))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else
				if (audit_name_to_msg_type(v) > 0)
					rule->values[rule->field_count] =
						audit_name_to_msg_type(v);
				else
					return -EAU_MSGTYPEUNKNOWN;
			break;
		/* These next few are strings */
		case AUDIT_OBJ_USER:
		case AUDIT_OBJ_ROLE:
		case AUDIT_OBJ_TYPE:
		case AUDIT_OBJ_LEV_LOW:
		case AUDIT_OBJ_LEV_HIGH:
		case AUDIT_WATCH:
		case AUDIT_DIR:
			/* Watch & object filtering is invalid on anything
			 * but exit */
			if (flags != AUDIT_FILTER_EXIT)
				return -EAU_EXITONLY;
			if (field == AUDIT_WATCH || field == AUDIT_DIR)
				_audit_permadded = 1;

			/* fallthrough */
		case AUDIT_SUBJ_USER:
		case AUDIT_SUBJ_ROLE:
		case AUDIT_SUBJ_TYPE:
		case AUDIT_SUBJ_SEN:
		case AUDIT_SUBJ_CLR:
		case AUDIT_FILTERKEY:
		case AUDIT_EXE:
			if (field == AUDIT_EXE) {
				uint32_t features = audit_get_features();
				if ((features & AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH) == 0)
					return -EAU_FIELDNOSUPPORT;
				if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL))
					return -EAU_OPEQNOTEQ;
				_audit_exeadded = 1;
			}
			if (field == AUDIT_FILTERKEY &&
				!(_audit_syscalladded || _audit_permadded ||
				_audit_exeadded ||
				_audit_filterfsadded))
                                return -EAU_KEYDEP;
			vlen = strlen(v);
			if (field == AUDIT_FILTERKEY &&
					vlen > AUDIT_MAX_KEY_LEN)
				return -EAU_STRTOOLONG;
			else if (vlen > PATH_MAX)
				return -EAU_STRTOOLONG;
			rule->values[rule->field_count] = vlen;
			offset = rule->buflen;
			rule->buflen += vlen;
			*rulep = realloc(rule, sizeof(*rule) + rule->buflen);
			if (*rulep == NULL) {
				free(rule);
				audit_msg(LOG_ERR, "Cannot realloc memory!\n");
				return -3;
			} else {
				rule = *rulep;
			}
			strncpy(&rule->buf[offset], v, vlen);

			break;
		case AUDIT_ARCH:
			if (_audit_syscalladded) 
				return -EAU_ARCHMISPLACED;
			if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL))
				return -EAU_OPEQNOTEQ;
			if (isdigit((char)*(v))) {
				int machine;

				errno = 0;
				_audit_elf = strtoul(v, NULL, 0);
				if (errno) 
					return -EAU_ELFUNKNOWN;

				// Make sure we have a valid mapping
				machine = audit_elf_to_machine(_audit_elf);
				if (machine < 0)
					return -EAU_ELFUNKNOWN;
			}
			else {
				const char *arch=v;
				unsigned int machine, elf;
				machine = audit_determine_machine(arch);
				/* OK, we have the machine type, now convert
				   to elf. */
				elf = audit_machine_to_elf(machine);
				if (elf == 0)
					return -EAU_ELFUNKNOWN;

				_audit_elf = elf;
			}
			rule->values[rule->field_count] = _audit_elf; 
			_audit_archadded = 1;
			break;
		case AUDIT_PERM:
			if (flags != AUDIT_FILTER_EXIT)
				return -EAU_EXITONLY;
			else if (op != AUDIT_EQUAL)
				return -EAU_OPEQ;
			else {
				unsigned int i, len, val = 0;

				len = strlen(v);
				if (len > 4)
					return -EAU_STRTOOLONG;

				for (i = 0; i < len; i++) {
					switch (tolower(v[i])) {
						case 'r':
							val |= AUDIT_PERM_READ;
							break;
						case 'w':
							val |= AUDIT_PERM_WRITE;
							break;
						case 'x':
							val |= AUDIT_PERM_EXEC;
							break;
						case 'a':
							val |= AUDIT_PERM_ATTR;
							break;
						default:
							return -EAU_PERMRWXA;
					}
				}
				rule->values[rule->field_count] = val;
			}
			break;
		case AUDIT_FILETYPE:
			if (!(flags == AUDIT_FILTER_EXIT))
				return -EAU_EXITONLY;
			rule->values[rule->field_count] = 
				audit_name_to_ftype(v);
			if ((int)rule->values[rule->field_count] < 0) {
				return -EAU_FILETYPEUNKNOWN;
			}
			break;
		case AUDIT_FSTYPE:
			if (!(flags == AUDIT_FILTER_FS))
				return -EAU_FIELDUNAVAIL;
			if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL))
				return -EAU_OPEQNOTEQ;
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtoul(v, NULL, 0);
			else
				rule->values[rule->field_count] = 
					audit_name_to_fstype(v);
			if ((int)rule->values[rule->field_count] == -1) {
				return -EAU_FSTYPEUNKNOWN;
			}
			_audit_filterfsadded = 1;
			break;
		case AUDIT_ARG0...AUDIT_ARG3:
			vlen = strlen(v);
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtoul(v, NULL, 0);
			else if (vlen >= 2 && *(v)=='-' &&
						(isdigit((char)*(v+1))))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else 
				return -EAU_FIELDVALNUM;
			break;
		case AUDIT_SESSIONID:
			if ((audit_get_features() &
				AUDIT_FEATURE_BITMAP_SESSIONID_FILTER) == 0)
				return -EAU_FIELDNOSUPPORT;
			if (flags != AUDIT_FILTER_EXCLUDE &&
			    flags != AUDIT_FILTER_USER &&
			    flags != AUDIT_FILTER_EXIT)
				return -EAU_FIELDNOFILTER;
			// Do positive & negative separate for 32 bit systems
			vlen = strlen(v);
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtoul(v, NULL, 0);
			else if (vlen >= 2 && *(v)=='-' &&
						(isdigit((char)*(v+1))))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else if (strcmp(v, "unset") == 0)
				rule->values[rule->field_count] = 4294967295;
			break;
		case AUDIT_DEVMAJOR...AUDIT_INODE:
		case AUDIT_SUCCESS:
			if (flags != AUDIT_FILTER_EXIT)
				return -EAU_EXITONLY;
			/* fallthrough */
		default:
			if (field == AUDIT_INODE) {
				if (!(op == AUDIT_NOT_EQUAL ||
							op == AUDIT_EQUAL))
					return -EAU_OPEQNOTEQ;
			}

			if (field == AUDIT_PPID && !(flags==AUDIT_FILTER_EXIT))
				return -EAU_EXITONLY;
			
			if (!isdigit((char)*(v)))
				return -EAU_FIELDVALNUM;

			if (field == AUDIT_INODE)
				rule->values[rule->field_count] =
					strtoul(v, NULL, 0);
			else
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			break;
	}
	rule->field_count++;
	return 0;
}

void audit_rule_free_data(struct audit_rule_data *rule)
{
	free(rule);
}

// This use is OK because its creating rules for the local
// machine and is looking up a local user.
static int audit_name_to_uid(const char *name, uid_t *uid)
{
	struct passwd *pw;

	pw = getpwnam(name);
	if (pw == NULL) 
		return 1;

	memset(pw->pw_passwd, ' ', strlen(pw->pw_passwd));
	*uid = pw->pw_uid;
	return 0;
}

static int audit_name_to_gid(const char *name, gid_t *gid)
{
	struct group *gr;

	gr = getgrnam(name);
	if (gr == NULL) 
		return 1;
 
	*gid = gr->gr_gid;
	return 0;
}

int audit_detect_machine(void)
{
	struct utsname uts;
	if (uname(&uts) == 0)
//		strcpy(uts.machine, "x86_64");
		return audit_name_to_machine(uts.machine);
	return -1;
}

#ifndef NO_TABLES
void audit_number_to_errmsg(int errnumber, const char *opt)
{
	unsigned int i;
	
	for (i = 0; i < sizeof(err_msgtab)/sizeof(struct msg_tab); i++) {
		if (err_msgtab[i].key == errnumber) {
			switch (err_msgtab[i].position)
			{
				case 0:
					fprintf(stderr, "%s\n",
						err_msgtab[i].cvalue);
					break;
				case 1:
					fprintf(stderr, "%s %s\n", opt,
						err_msgtab[i].cvalue);
					break;
				case 2:
					fprintf(stderr, "%s %s\n",
						err_msgtab[i].cvalue, opt);
					break;
				default:
					break;
			}
			return;
		}
	}
}
#endif

int audit_can_control(void)
{
#ifdef HAVE_LIBCAP_NG
	void *state = capng_save_state();
	int rc = capng_have_capability(CAPNG_EFFECTIVE, CAP_AUDIT_CONTROL);
	capng_restore_state(&state);

	return rc;
#else
	return (geteuid() == 0);
#endif
}

int audit_can_write(void)
{
#ifdef HAVE_LIBCAP_NG
	void *state = capng_save_state();
	int rc = capng_have_capability(CAPNG_EFFECTIVE, CAP_AUDIT_WRITE);
	capng_restore_state(&state);

	return rc;
#else
	return (geteuid() == 0);
#endif
}

int audit_can_read(void)
{
#if defined ( HAVE_LIBCAP_NG ) && ( CAP_AUDIT_READ )
	void *state = capng_save_state();
	int rc = capng_have_capability(CAPNG_EFFECTIVE, CAP_AUDIT_READ);
	capng_restore_state(&state);

	return rc;
#else
	return (geteuid() == 0);
#endif
}

