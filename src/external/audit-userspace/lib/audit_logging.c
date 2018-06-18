/* audit_logging.c -- 
 * Copyright 2005-2008,2010,2011,2013,2017 Red Hat Inc., Durham, North Carolina.
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
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <netinet/in.h> // inet6 addrlen
#include <netdb.h>	// gethostbyname
#include <arpa/inet.h>	// inet_ntop
#include <utmp.h>
#include <limits.h>	// PATH_MAX
#include <fcntl.h>

#include "libaudit.h"
#include "private.h"

#define TTY_PATH	32
#define MAX_USER	(UT_NAMESIZE * 2) + 8

// NOTE: The kernel fills in pid, uid, and loginuid of sender. Therefore,
// these routines do not need to send them.

/*
 * resolve's the hostname - caller must pass a INET6_ADDRSTRLEN byte buffer
 * Returns string w/ numerical address, or "?" on failure
 */
static void _resolve_addr(char buf[], const char *host)
{
	struct addrinfo *ai;
	struct addrinfo hints;
	int e;

	buf[0] = '?';
	buf[1] = 0;
	/* Short circuit this lookup if NULL, or empty */
	if (host == NULL || *host == 0)
		return;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;

	e = getaddrinfo(host, NULL, &hints, &ai);
	if (e != 0) {
		audit_msg(LOG_ERR, 
			"resolve_addr: cannot resolve hostname %s (%s)",
			host, gai_strerror(e));
		return;
	}
	// What to do if more than 1 addr?
	inet_ntop(ai->ai_family, ai->ai_family == AF_INET ?
		(void *) &((struct sockaddr_in *)ai->ai_addr)->sin_addr :
		(void *) &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		buf, INET6_ADDRSTRLEN);
	freeaddrinfo(ai);
}

/*
 * This function checks a string to see if it needs encoding. It
 * return 1 if needed and 0 if not
 */
int audit_value_needs_encoding(const char *str, unsigned int size)
{
	unsigned int i;

	if (str == NULL)
		return 0;

	for (i=0; i<size; i++) {
		// we don't test for > 0x7f because str[] is signed.
		if (str[i] == '"' || str[i] < 0x21 || str[i] == 0x7F)
			return 1;
	}
	return 0;
}

/*
 * This function does encoding of "untrusted" names just like the kernel
 */
char *audit_encode_value(char *final, const char *buf, unsigned int size)
{
	unsigned int i;
	char *ptr = final;
	const char *hex = "0123456789ABCDEF";

	if (final == NULL)
		return NULL;

	if (buf == NULL) {
		*final = 0;
		return final;
	}

	for (i=0; i<size; i++) {
		*ptr++ = hex[(buf[i] & 0xF0)>>4]; /* Upper nibble */
		*ptr++ = hex[buf[i] & 0x0F];      /* Lower nibble */
	}
	*ptr = 0;
	return final;
}

char *audit_encode_nv_string(const char *name, const char *value,
		unsigned int vlen)
{
	char *str;

	if (vlen == 0 && value)
		vlen = strlen(value);

	if (value && audit_value_needs_encoding(value, vlen)) {
		char *tmp = malloc(2*vlen + 1);
		if (tmp) {
			audit_encode_value(tmp, value, vlen);
			if (asprintf(&str, "%s=%s", name, tmp) < 0)
				str = NULL;
			free(tmp);
		} else
			str = NULL;
	} else
		if (asprintf(&str, "%s=\"%s\"", name, value ? value : "?") < 0)
			str = NULL;
	return str;
}

/*
 * Get the executable's name 
 */
static char *_get_exename(char *exename, int size)
{
	int res;
	char tmp[PATH_MAX+1];

	/* get the name of the current executable */
	if ((res = readlink("/proc/self/exe", tmp, PATH_MAX)) == -1) {
		strcpy(exename, "\"?\"");
		audit_msg(LOG_ERR, "get_exename: cannot determine executable");
	} else {
		tmp[res] = '\0';
		if (audit_value_needs_encoding(tmp, res))
			return audit_encode_value(exename, tmp, res);
		snprintf(exename, size, "\"%s\"", tmp);
	}
	return exename;
}

/*
 * Get the command line name 
 * NOTE: at the moment, this only escapes what the user sent
 */
static char *_get_commname(const char *comm, char *commname, unsigned int size)
{
	unsigned int len;
	char tmp_comm[20];
	
	if (comm == NULL) {
		int len;
		int fd = open("/proc/self/comm", O_RDONLY);
		if (fd < 0) {
			strcpy(commname, "\"?\"");
			return commname;
		}
		len = read(fd, tmp_comm, sizeof(tmp_comm));
		close(fd);
		if (len > 0)
			tmp_comm[len-1] = 0;
		else {
			strcpy(commname, "\"?\"");
			return commname;
		}
		comm = tmp_comm;
	}

	len = strlen(comm);
	if (audit_value_needs_encoding(comm, len))
		audit_encode_value(commname, comm, len);
	else
		snprintf(commname, size, "\"%s\"", comm);

	return commname;
}

static int check_ttyname(const char *ttyn)
{
	struct stat statbuf;

	if (lstat(ttyn, &statbuf)
		|| !S_ISCHR(statbuf.st_mode)
		|| (statbuf.st_nlink > 1 && strncmp(ttyn, "/dev/", 5))) {
		audit_msg(LOG_ERR, "FATAL: bad tty %s", ttyn);
		return 1;
        }
	return 0;
}

static const char *_get_tty(char *tname, int size)
{
	int rc, i, found = 0;

	for (i=0; i<3 && !found; i++) {
		rc = ttyname_r(i, tname, size);
		if (rc == 0 && tname[0] != '\0')
			found = 1;
	}

	if (!found)
		return NULL;
	
	if (check_ttyname(tname)) 
		return NULL;

	if (strncmp(tname, "/dev/", 5) == 0)
		return &tname[5];

	return tname;
}

#define HOSTLEN 64
static char _host[HOSTLEN] = "";
static const char *_get_hostname(const char *ttyn)
{
	if (ttyn && ((strncmp(ttyn, "pts", 3) == 0) ||
		(strncmp(ttyn, "tty", 3) == 0) ||
		(strncmp(ttyn, "/dev/tty", 8) == 0) )) {
		if (_host[0] == 0) {
			gethostname(_host, HOSTLEN);
			_host[HOSTLEN - 1] = 0;
		}
		return _host;
	}
	return NULL;
}

/*
 * This function will log a message to the audit system using a predefined
 * message format. This function should be used by all console apps that do
 * not manipulate accounts or groups.
 *
 * audit_fd - The fd returned by audit_open
 * type - type of message, ex: AUDIT_USER, AUDIT_USYS_CONFIG, AUDIT_USER_LOGIN
 * message - the message being sent
 * hostname - the hostname if known
 * addr - The network address of the user
 * tty - The tty of the user
 * result - 1 is "success" and 0 is "failed"
 *
 * It returns the sequence number which is > 0 on success or <= 0 on error.
 */
int audit_log_user_message(int audit_fd, int type, const char *message,
	const char *hostname, const char *addr, const char *tty, int result)
{
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	char addrbuf[INET6_ADDRSTRLEN];
	static char exename[PATH_MAX*2]="";
	char ttyname[TTY_PATH];
	const char *success;
	int ret;

	if (audit_fd < 0)
		return 0;

	if (result)
		success = "success";
	else
		success = "failed";

	/* If hostname is empty string, make it NULL ptr */
	if (hostname && *hostname == 0)
		hostname = NULL;

	/* See if we can deduce addr */
	addrbuf[0] = 0;
	if (addr == NULL || strlen(addr) == 0)
		_resolve_addr(addrbuf, hostname);
	else
		strncat(addrbuf, addr, sizeof(addrbuf)-1);

	/* Fill in exec name if needed */
	if (exename[0] == 0)
		_get_exename(exename, sizeof(exename));

	/* Fill in tty if needed */
	if (tty == NULL) 
		tty = _get_tty(ttyname, TTY_PATH);
	else if (*tty == 0)
		tty = NULL;

	/* Get the local name if we have a real tty */
	if (hostname == NULL && tty)
		hostname = _get_hostname(tty);

	snprintf(buf, sizeof(buf),
		"%s exe=%s hostname=%s addr=%s terminal=%s res=%s",
		message, exename,
		hostname ? hostname : "?",
		addrbuf,
		tty ? tty : "?",
		success
		);

	errno = 0;
	ret = audit_send_user_message( audit_fd, type, HIDE_IT, buf );
	if ((ret < 1) && errno == 0)
		errno = ret;
	return ret;
}

/*
 * This function will log a message to the audit system using a predefined
 * message format. This function should be used by all console apps that do
 * not manipulate accounts or groups and are executing a script. An example
 * would be python or crond wanting to say what they are executing.
 *
 * audit_fd - The fd returned by audit_open
 * type - type of message, ex: AUDIT_USER, AUDIT_USYS_CONFIG, AUDIT_USER_LOGIN
 * message - the message being sent
 * comm - the program command line name
 * hostname - the hostname if known
 * addr - The network address of the user
 * tty - The tty of the user
 * result - 1 is "success" and 0 is "failed"
 *
 * It returns the sequence number which is > 0 on success or <= 0 on error.
 */
int audit_log_user_comm_message(int audit_fd, int type, const char *message,
	const char *comm, const char *hostname, const char *addr,
	const char *tty, int result)
{
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	char addrbuf[INET6_ADDRSTRLEN];
	static char exename[PATH_MAX*2]="";
	char commname[PATH_MAX*2];
	char ttyname[TTY_PATH];
	const char *success;
	int ret;

	if (audit_fd < 0)
		return 0;

	if (result)
		success = "success";
	else
		success = "failed";

	/* If hostname is empty string, make it NULL ptr */
	if (hostname && *hostname == 0)
		hostname = NULL;

	/* See if we can deduce addr */
	addrbuf[0] = 0;
	if (addr == NULL || strlen(addr) == 0)
		_resolve_addr(addrbuf, hostname);
	else
		strncat(addrbuf, addr, sizeof(addrbuf)-1);

	/* Fill in exec name if needed */
	if (exename[0] == 0)
		_get_exename(exename, sizeof(exename));

	/* Fill in tty if needed */
	if (tty == NULL) 
		tty = _get_tty(ttyname, TTY_PATH);
	else if (*tty == 0)
		tty = NULL;

	_get_commname(comm, commname, sizeof(commname));

	/* Get the local name if we have a real tty */
	if (hostname == NULL && tty)
		hostname = _get_hostname(tty);

	snprintf(buf, sizeof(buf),
		"%s comm=%s exe=%s hostname=%s addr=%s terminal=%s res=%s",
		message, commname, exename,
		hostname ? hostname : "?",
		addrbuf,
		tty ? tty : "?",
		success
		);

	errno = 0;
	ret = audit_send_user_message( audit_fd, type, HIDE_IT, buf );
	if ((ret < 1) && errno == 0)
		errno = ret;
	return ret;
}


/*
 * This function will log a message to the audit system using a predefined
 * message format. It should be used for all account manipulation operations.
 * Parameter usage is as follows:
 *
 * audit_fd - The fd returned by audit_open
 * type - type of message: AUDIT_USER_CHAUTHTOK for changing any account
 *        attributes.
 * pgname - program's name
 * op  -  operation. "adding user", "changing finger info", "deleting group"
 * name - user's account or group name. If not available use NULL.
 * id  -  uid or gid that the operation is being performed on. This is used
 *        only when user is NULL.
 * host - The hostname if known
 * addr - The network address of the user
 * tty  - The tty of the user
 * result - 1 is "success" and 0 is "failed"
 *
 * It returns the sequence number which is > 0 on success or <= 0 on error.
 */
int audit_log_acct_message(int audit_fd, int type, const char *pgname,
	const char *op, const char *name, unsigned int id, 
	const char *host, const char *addr, const char *tty, int result)
{
	const char *success;
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	char addrbuf[INET6_ADDRSTRLEN];
	static char exename[PATH_MAX*2] = "";
	char ttyname[TTY_PATH];
	int ret;

	if (audit_fd < 0)
		return 0;

	if (result)
		success = "success";
	else
		success = "failed";

	/* If hostname is empty string, make it NULL ptr */
	if (host && *host == 0)
		host = NULL;

	/* See if we can deduce addr */
	addrbuf[0] = 0;
	if (addr == NULL || strlen(addr) == 0)
		_resolve_addr(addrbuf, host);
	else
		strncat(addrbuf, addr, sizeof(addrbuf)-1);

	/* Fill in exec name if needed */
        if (pgname == NULL) {
		if (exename[0] == 0)
	                _get_exename(exename, sizeof(exename));
        } else if (pgname[0] != '"')
                snprintf(exename, sizeof(exename), "\"%s\"", pgname);
        else
                snprintf(exename, sizeof(exename), "%s", pgname);

	/* Fill in tty if needed */
	if (tty == NULL) 
		tty = _get_tty(ttyname, TTY_PATH);
	else if (*tty == 0)
		tty = NULL;

	/* Get the local name if we have a real tty */
	if (host == NULL && tty)
		host = _get_hostname(tty);

	if (name && id == -1) {
		char user[MAX_USER];
		const char *format;
		size_t len;

		user[0] = 0;
		strncat(user, name, MAX_USER-1);
		len = strnlen(user, UT_NAMESIZE);
		user[len] = 0;
		if (audit_value_needs_encoding(name, len)) {
			audit_encode_value(user, name, len);
			format = 
	     "op=%s acct=%s exe=%s hostname=%s addr=%s terminal=%s res=%s";
		} else
			format = 
	 "op=%s acct=\"%s\" exe=%s hostname=%s addr=%s terminal=%s res=%s";

		snprintf(buf, sizeof(buf), format,
			op, user, exename,
			host ? host : "?",
			addrbuf,
			tty ? tty : "?",
			success
			);
	} else
		snprintf(buf, sizeof(buf),
		"op=%s id=%u exe=%s hostname=%s addr=%s terminal=%s res=%s",
			op, id, exename,
			host ? host : "?",
			addrbuf,
			tty ? tty : "?",
			success
			);

	errno = 0;
	ret = audit_send_user_message(audit_fd, type, REAL_ERR, buf);
	if ((ret < 1) && errno == 0)
		errno = ret;
	return ret;
}

/*
 * This function will log a message to the audit system using a predefined
 * message format. This function should be used by all apps that are SE Linux
 * object managers.
 *
 * audit_fd - The fd returned by audit_open
 * type - type of message, ex: AUDIT_USER, AUDIT_USYS_CONFIG, AUDIT_USER_LOGIN
 * message - the message being sent
 * hostname - the hostname if known
 * addr - The network address of the user
 * tty - The tty of the user
 * uid - The auid of the person related to the avc message
 *
 * It returns the sequence number which is > 0 on success or <= 0 on error.
 */
int audit_log_user_avc_message(int audit_fd, int type, const char *message,
	const char *hostname, const char *addr, const char *tty, uid_t uid)
{
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	char addrbuf[INET6_ADDRSTRLEN];
	static char exename[PATH_MAX*2] = "";
	char ttyname[TTY_PATH];
	int retval;

	if (audit_fd < 0)
		return 0;

	/* If hostname is empty string, make it NULL ptr */
	if (hostname && *hostname == 0)
		hostname = NULL;

	addrbuf[0] = 0;
	if (addr == NULL || strlen(addr) == 0)
		_resolve_addr(addrbuf, hostname);
	else
		strncat(addrbuf, addr, sizeof(addrbuf)-1);

	if (exename[0] == 0)
		_get_exename(exename, sizeof(exename));

	if (tty == NULL) 
		tty = _get_tty(ttyname, TTY_PATH);
	else if (*tty == 0)
		tty = NULL;

	snprintf(buf, sizeof(buf),
	    "%s exe=%s sauid=%d hostname=%s addr=%s terminal=%s",
		message, exename, uid,
		hostname ? hostname : "?",
		addrbuf,
		tty ? tty : "?"
		);

	errno = 0;
	retval = audit_send_user_message( audit_fd, type, REAL_ERR, buf );
	if (retval == -EPERM && !audit_can_write()) {
		syslog(LOG_ERR, "Can't send to audit system: %s %s",
			audit_msg_type_to_name(type), buf);
		return 0;
	}
	if ((retval < 1) && errno == 0)
		errno = retval;
	return retval;
}

/*
 * This function will log a message to the audit system using a predefined
 * message format. It should be used for all SE linux user and role 
 * manipulation operations.
 * Parameter usage is as follows:
 *
 * type - type of message: AUDIT_ROLE_ASSIGN/REMOVE for changing any SE Linux
 *        user or role attributes.
 * pgname - program's name
 * op  -  operation. "adding-user", "adding-role", "deleting-user", "deleting-role"
 * name - user's account. If not available use NULL.
 * id  -  uid that the operation is being performed on. This is used
 *        only when name is NULL.
 * new_seuser - the new seuser that the login user is getting
 * new_role - the new_role that the login user is getting
 * new_range - the new mls range that the login user is getting
 * old_seuser - the old seuser that the login usr had
 * old_role - the old role that the login user had
 * old_range - the old mls range that the login usr had
 * host - The hostname if known
 * addr - The network address of the user
 * tty  - The tty of the user
 * result - 1 is "success" and 0 is "failed"
 *
 * It returns the sequence number which is > 0 on success or <= 0 on error.
 */
int audit_log_semanage_message(int audit_fd, int type, const char *pgname,
	const char *op, const char *name, unsigned int id, 
	const char *new_seuser, const char *new_role, const char *new_range,
	const char *old_seuser, const char *old_role, const char *old_range,
	const char *host, const char *addr,
	const char *tty, int result)
{
	const char *success;
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	char addrbuf[INET6_ADDRSTRLEN];
	static char exename[PATH_MAX*2] = "";
	char ttyname[TTY_PATH];
	int ret;

	if (audit_fd < 0)
		return 0;

	if (result)
		success = "success";
	else
		success = "failed";

	/* If hostname is empty string, make it NULL ptr */
	if (host && *host == 0)
		host = NULL;
	addrbuf[0] = 0;
	if (addr == NULL || strlen(addr) == 0)
		_resolve_addr(addrbuf, host);
	else
		strncat(addrbuf, addr, sizeof(addrbuf)-1);

	if (pgname == NULL || strlen(pgname) == 0) {
		if (exename[0] == 0)
			_get_exename(exename, sizeof(exename));
		pgname = exename;
	}

	if (tty == NULL || strlen(tty) == 0) 
		tty = _get_tty(ttyname, TTY_PATH);
	else if (*tty == 0)
		tty = NULL;

	if (name && strlen(name) > 0) {
		size_t len;
		const char *format;
		char user[MAX_USER];

		user[0] = 0;
		strncat(user, name, MAX_USER-1);
		len = strnlen(user, UT_NAMESIZE);
		user[len] = 0;
		if (audit_value_needs_encoding(name, len)) {
			audit_encode_value(user, name, len);
			format = "op=%s acct=%s old-seuser=%s old-role=%s old-range=%s new-seuser=%s new-role=%s new-range=%s exe=%s hostname=%s addr=%s terminal=%s res=%s";
		} else
			format = "op=%s acct=\"%s\" old-seuser=%s old-role=%s old-range=%s new-seuser=%s new-role=%s new-range=%s exe=%s hostname=%s addr=%s terminal=%s res=%s";
		snprintf(buf, sizeof(buf), format, op, user, 
			old_seuser && strlen(old_seuser) ? old_seuser : "?",
			old_role && strlen(old_role) ? old_role : "?",
			old_range && strlen(old_range) ? old_range : "?",
			new_seuser && strlen(new_seuser) ? new_seuser : "?",
			new_role && strlen(new_role) ? new_role : "?",
			new_range && strlen(new_range) ? new_range : "?",
			pgname,
			host && strlen(host) ? host : "?",
			addrbuf,
			tty && strlen(tty) ? tty : "?",
			success
			);
	} else
		snprintf(buf, sizeof(buf),
		"op=%s id=%u old-seuser=%s old-role=%s old-range=%s new-seuser=%s new-role=%s new-range=%s exe=%s hostname=%s addr=%s terminal=%s res=%s",
			op, id,
			old_seuser && strlen(old_seuser) ? old_seuser : "?",
			old_role && strlen(old_role) ? old_role : "?",
			old_range && strlen(old_range) ? old_range : "?",
			new_seuser && strlen(new_seuser) ? new_seuser : "?",
			new_role && strlen(new_role) ? new_role : "?",
			new_range && strlen(new_range) ? new_range : "?",
			pgname,
			host && strlen(host) ? host : "?",
			addrbuf,
			tty && strlen(tty) ? tty : "?",
			success
			);

	errno = 0;
	ret = audit_send_user_message(audit_fd, type, REAL_ERR, buf);
	if ((ret < 1) && errno == 0)
		errno = ret;
	return ret;
}

/*
 * This function will log a message to the audit system using a predefined
 * message format. This function should be used by all console apps that do
 * not manipulate accounts or groups.
 *
 * audit_fd - The fd returned by audit_open
 * type - type of message, ex: AUDIT_USER_CMD
 * command - the command line being logged
 * tty - The tty of the user
 * result - 1 is "success" and 0 is "failed"
 *
 * It returns the sequence number which is > 0 on success or <= 0 on error.
 */
int audit_log_user_command(int audit_fd, int type, const char *command,
	const char *tty, int result)
{
	char *p;
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	char commname[PATH_MAX*2];
	char cwdname[PATH_MAX*2];
	char ttyname[TTY_PATH];
	char format[64];
	const char *success;
	char *cmd;
	int ret, cwdenc=0, cmdenc=0;
	unsigned int len;

	if (audit_fd < 0)
		return 0;

	if (result)
		success = "success";
	else
		success = "failed";

	if (tty == NULL) 
		tty = _get_tty(ttyname, TTY_PATH);
	else if (*tty == 0)
		tty = NULL;

	/* Trim leading spaces */
	while (*command == ' ')
		command++;

	cmd = strdup(command);
	if (cmd == NULL)
		return -1;

	// We borrow the commname buffer
	if (getcwd(commname, PATH_MAX) == NULL)
		strcpy(commname, "?");
	len = strlen(commname);
	if (audit_value_needs_encoding(commname, len)) {
		audit_encode_value(cwdname, commname, len);
		cwdenc = 1;
	} else
		strcpy(cwdname, commname);

	len = strlen(cmd);
	// Trim the trailing carriage return and spaces
	while (len && (cmd[len-1] == 0x0A || cmd[len-1] == ' ')) {
		cmd[len-1] = 0;
		len--;
	}

	if (len >= PATH_MAX) {
		cmd[PATH_MAX] = 0;
		len = PATH_MAX-1;
	}
	if (audit_value_needs_encoding(cmd, len)) {
		audit_encode_value(commname, cmd, len);
		cmdenc = 1;
	}
	if (cmdenc == 0)
		strcpy(commname, cmd);
	free(cmd);

	// Make the format string
	if (cwdenc)
		p=stpcpy(format, "cwd=%s ");
	else
		p=stpcpy(format, "cwd=\"%s\" ");

	if (cmdenc)
		p = stpcpy(p, "cmd=%s ");
	else
		p = stpcpy(p, "cmd=\"%s\" ");

	strcpy(p, "terminal=%s res=%s");

	// now use the format string to make the event
	snprintf(buf, sizeof(buf), format,
			cwdname, commname,
			tty ? tty : "?",
			success
		);

	errno = 0;
	ret = audit_send_user_message( audit_fd, type, HIDE_IT, buf );
	if ((ret < 1) && errno == 0)
		errno = ret;
	return ret;
}

