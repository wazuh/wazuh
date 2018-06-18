/*
* audispd-builtins.c - some common builtin plugins
* Copyright (c) 2007,2010,2013 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
* Boston, MA 02110-1335, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <string.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/uio.h> // writev
#include <fcntl.h>
#include "audispd-pconfig.h"
#include "audispd-builtins.h"

// Local data
static volatile int sock = -1, conn = -1;
static int syslog_started = 0, priority;
static char *path = NULL;

// Local prototypes
static void init_af_unix(const plugin_conf_t *conf);
static void init_syslog(const plugin_conf_t *conf);


void start_builtin(plugin_conf_t *conf)
{
	if (strcasecmp("builtin_af_unix", conf->path) == 0) {
		conf->type = S_AF_UNIX;
		init_af_unix(conf);
	} else if (strcasecmp("builtin_syslog", conf->path) == 0) {
		conf->type = S_SYSLOG;
		init_syslog(conf);
	} else
		syslog(LOG_ERR, "Unknown builtin %s", conf->path);
}

void stop_builtin(plugin_conf_t *conf)
{
	if (conf->type == S_AF_UNIX)
		destroy_af_unix();
	else if (conf->type == S_SYSLOG)
		destroy_syslog();
	else
		syslog(LOG_ERR, "Unknown builtin %s", conf->path);
}

static void af_unix_accept(int fd)
{
	int cmd;

	do {
		conn = accept(fd, NULL, NULL);
	} while (conn < 0 && errno == EINTR);

	// De-register since this is intended to be one listener
	if (conn >= 0)
		remove_event(fd);
	cmd = fcntl(conn, F_GETFD);
	fcntl(conn, F_SETFD, cmd|FD_CLOEXEC);
}

static int create_af_unix_socket(const char *path, int mode)
{
	struct sockaddr_un addr;
	socklen_t len;
	int rc, cmd;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog(LOG_ERR, "Couldn't open af_unix socket (%s)",
				strerror(errno));
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(&addr.sun_path[0], path);
	len = sizeof(addr);
	rc = bind(sock, (const struct sockaddr *)&addr,	len);
	if (rc < 0) {
		syslog(LOG_ERR, "Couldn't bind af_unix socket (%s)",
				strerror(errno));
		destroy_af_unix();
		return -1;
	}
	if (mode != -1) { 
		rc = chmod(path, mode);
		if (rc < 0) {
			syslog(LOG_ERR, "Couldn't chmod %s to %04o (%s)",
				path, mode, strerror(errno));
			destroy_af_unix();
			return -1;
		}
	}

	// Put socket in nonblock mode
	cmd = fcntl(sock, F_GETFL);
	fcntl(sock, F_SETFL, cmd|FNDELAY);

	// don't leak the descriptor
	cmd = fcntl(sock, F_GETFD);
	fcntl(sock, F_SETFD, cmd|FD_CLOEXEC);

	// Make socket listening...won't block
	(void)listen(sock, 5);

	// Register socket with poll
	add_event(sock, af_unix_accept);
	return 0;
}

static void init_af_unix(const plugin_conf_t *conf)
{
	int i = 1, mode = -1;
	char *base = NULL;

	// while args
	while (conf->args[i]) {
		int rc, bad = 0;

		// is all nums - do mode
		base = conf->args[i];
		while (*base) {
			if (!isdigit(*base)) {
				bad = 1;
				break;
			}
			base++;
		}
		if (!bad) {
			errno = 0;
			mode = strtoul(conf->args[i], NULL, 8);
			if (errno) {
				syslog(LOG_ERR, "Error converting %s (%s)",
					conf->args[i], strerror(errno));
				mode = -1;
				bad = 1;
			} else if (path) {
				rc = chmod(path, mode);
				if (rc < 0) {
					syslog(LOG_ERR,
					    "Couldn't chmod %s to %04o (%s)",
						conf->args[i], mode,
						strerror(errno));
					destroy_af_unix();
					return;
				}
			}
		} else {
			// else check for '/'
			base = strchr(conf->args[i], '/');
			if (base) {
				// get dirname
				DIR *d;
				char *dir = strdup(conf->args[i]);
				base = dirname(dir);
				d = opendir(base);
				if (d) {
					closedir(d);
					unlink(conf->args[i]);
					if (create_af_unix_socket(
						    conf->args[i], mode)<0) {
						free(dir);
						return;
					}
					path = strdup(conf->args[i]);
					bad = 0;
				} else
					syslog(LOG_ERR, "Couldn't open %s (%s)",
						base, strerror(errno));
				free(dir);
			} else 
				syslog(LOG_ERR, "Malformed path %s",
					conf->args[i]);
		}
		if (bad) {
			destroy_af_unix();
			return;
		}
		i++;
	}
	syslog(LOG_INFO, "af_unix plugin initialized");
}

void send_af_unix_string(const char *s, unsigned int len)
{
	if (sock < 0) 
		return;

	if (conn >= 0) {
		int rc;
		do {
			rc = write(conn, s, len);
		} while (rc < 0 && errno == EINTR);
		if (rc < 0 && errno == EPIPE) {
			close(conn);
			conn = -1;
			add_event(sock, af_unix_accept);
		}
	} 
}

void send_af_unix_binary(event_t *e)
{
	if (sock < 0) 
		return;

	if (conn >= 0) {
		int rc;
		struct iovec vec[2];

		vec[0].iov_base = &e->hdr;
		vec[0].iov_len = sizeof(struct audit_dispatcher_header);
		vec[1].iov_base = e->data;
		vec[1].iov_len = MAX_AUDIT_MESSAGE_LENGTH;
		do {
			rc = writev(conn, vec, 2);
		} while (rc < 0 && errno == EINTR);
		if (rc < 0 && errno == EPIPE) {
			close(conn);
			conn = -1;
			add_event(sock, af_unix_accept);
		}
	} 
}

void destroy_af_unix(void)
{
	if (conn >= 0) {
		close(conn);
		conn = -1;
	}
	if (sock >= 0) {
		close(sock);
		sock = -1;
	}
	if (path) {
		unlink(path);
		free(path);
		path = NULL;
	}
}

static void init_syslog(const plugin_conf_t *conf)
{
	int i, facility = LOG_USER;
	priority = LOG_INFO;

	for (i = 1; i<3; i++) {
		if (conf->args[i]) {
			if (strcasecmp(conf->args[i], "LOG_DEBUG") == 0)
				priority = LOG_DEBUG;
			else if (strcasecmp(conf->args[i], "LOG_INFO") == 0)
				priority = LOG_INFO;
			else if (strcasecmp(conf->args[i], "LOG_NOTICE") == 0)
				priority = LOG_NOTICE;
			else if (strcasecmp(conf->args[i], "LOG_WARNING") == 0)
				priority = LOG_WARNING;
			else if (strcasecmp(conf->args[i], "LOG_ERR") == 0)
				priority = LOG_ERR;
			else if (strcasecmp(conf->args[i], "LOG_CRIT") == 0)
				priority = LOG_CRIT;
			else if (strcasecmp(conf->args[i], "LOG_ALERT") == 0)
				priority = LOG_ALERT;
			else if (strcasecmp(conf->args[i], "LOG_EMERG") == 0)
				priority = LOG_EMERG;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL0") == 0)
				facility = LOG_LOCAL0;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL1") == 0)
				facility = LOG_LOCAL1;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL2") == 0)
				facility = LOG_LOCAL2;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL3") == 0)
				facility = LOG_LOCAL3;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL4") == 0)
				facility = LOG_LOCAL4;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL5") == 0)
				facility = LOG_LOCAL5;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL6") == 0)
				facility = LOG_LOCAL6;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL7") == 0)
				facility = LOG_LOCAL7;
			else if (strcasecmp(conf->args[i], "LOG_AUTH") == 0)
				facility = LOG_AUTH;
			else if (strcasecmp(conf->args[i], "LOG_AUTHPRIV") == 0)
				facility = LOG_AUTHPRIV;
			else if (strcasecmp(conf->args[i], "LOG_DAEMON") == 0)
				facility = LOG_DAEMON;
			else if (strcasecmp(conf->args[i], "LOG_SYSLOG") == 0)
				facility = LOG_SYSLOG;
			else if (strcasecmp(conf->args[i], "LOG_USER") == 0)
				facility = LOG_USER;
			else {
				syslog(LOG_ERR, 
					"Unknown log priority/facility %s",
					conf->args[i]);
				syslog_started = 0;
				return;
			}
		}
	}
	syslog(LOG_INFO, "syslog plugin initialized");
	if (facility != LOG_USER)
		openlog("audispd", 0, facility);
	syslog_started = 1;
}

void send_syslog(const char *s, uint32_t ver)
{
	if (syslog_started) {
		if (ver == AUDISP_PROTOCOL_VER2) {
			char *ptr = strdup(s);
			if (ptr) {
				char *c = strchr(ptr, AUDIT_INTERP_SEPARATOR);
				if (c)
					*c = ' ';
				syslog(priority, "%s", ptr);
				free(ptr);
				return;
			}
		}
		// Everything should fall through except success because
		// something is better than nothing.
		syslog(priority, "%s", s);
	}
}

void destroy_syslog(void)
{
	syslog_started = 0;
}

