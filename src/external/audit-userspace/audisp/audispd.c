/* audispd.c --
 * Copyright 2007-08,2013,2016-17 Red Hat Inc., Durham, North Carolina.
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
 */

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/uio.h>
#include <getopt.h>

#include "audispd-config.h"
#include "audispd-pconfig.h"
#include "audispd-llist.h"
#include "audispd-builtins.h"
#include "queue.h"
#include "libaudit.h"

/* Global Data */
volatile int stop = 0;
volatile int hup = 0;

/* Local data */
static daemon_conf_t daemon_config;
static conf_llist plugin_conf;
static int audit_fd;
static pthread_t inbound_thread;
static char *config_file = NULL;

/* Local function prototypes */
static void signal_plugins(int sig);
static int event_loop(void);
static int safe_exec(plugin_conf_t *conf);
static void *inbound_thread_main(void *arg);
static void process_inbound_event(int fd);

/*
 * Output a usage message and exit with an error.
 */
static void usage(void)
{
	fprintf(stderr, "%s",
		"Usage: audispd [options]\n"
		"-c,--config_dir <config_dir_path>: Override default "
			"configuration file path\n");
	exit(2);
}

static void release_memory_exit(int code)
{
	free(config_file);
	exit(code);
}

/*
 * SIGTERM handler
 */
static void term_handler( int sig )
{
        stop = 1;
}

/*
 * SIGCHLD handler
 */
static void child_handler( int sig )
{
	int status;
	pid_t pid;
	
	pid = waitpid(-1, &status, WNOHANG);
	if (pid > 0) {
		// Mark the child pid as 0 in the configs
		lnode *tpconf;
		plist_first(&plugin_conf);
		tpconf = plist_get_cur(&plugin_conf);
		while (tpconf) {
			if (tpconf->p && tpconf->p->pid == pid) {
				tpconf->p->pid = 0;
				break;
			}
			tpconf = plist_next(&plugin_conf);
		}
	}
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler( int sig )
{
	hup = 1;
}

/*
 * SIGALRM handler - help force exit when terminating daemon
 */
static void alarm_handler( int sig )
{
	pthread_cancel(inbound_thread);
	raise(SIGTERM);
}

static int count_dots(const char *s)
{
	const char *ptr;
	int cnt = 0;

	while ((ptr = strchr(s, '.'))) {
		cnt++;
		s = ptr + 1;
	}
	return cnt;
}

static void load_plugin_conf(conf_llist *plugin)
{
	DIR *d;

	/* init plugin list */
	plist_create(plugin);

	/* read configs */
	d = opendir(daemon_config.plugin_dir);
	if (d) {
		struct dirent *e;

		while ((e = readdir(d))) {
			plugin_conf_t config;
			char fname[PATH_MAX];

			// Don't run backup files, hidden files, or dirs
			if (e->d_name[0] == '.' || count_dots(e->d_name) > 1)
				continue;

			snprintf(fname, sizeof(fname), "%s%s",
				daemon_config.plugin_dir, e->d_name);

			clear_pconfig(&config);
			if (load_pconfig(&config, fname) == 0) {
				/* Push onto config list only if active */
				if (config.active == A_YES)
					plist_append(plugin, &config);
				else
					free_pconfig(&config);
			} else
				syslog(LOG_ERR, 
					"Skipping %s plugin due to errors",
					e->d_name);
		}
		closedir(d);
	}
}

static int start_one_plugin(lnode *conf)
{
	if (conf->p->restart_cnt > daemon_config.max_restarts)
		return 1;

	if (conf->p->type == S_BUILTIN)
		start_builtin(conf->p);
	else if (conf->p->type == S_ALWAYS) {
		if (safe_exec(conf->p)) {
			syslog(LOG_ERR,
				"Error running %s (%s) continuing without it",
				conf->p->path, strerror(errno));
			conf->p->active = A_NO;
			return 0;
		}

		/* Close the parent's read side */
		close(conf->p->plug_pipe[0]);
		conf->p->plug_pipe[0] = -1;
		/* Avoid leaking descriptor */
		fcntl(conf->p->plug_pipe[1], F_SETFD, FD_CLOEXEC);
	}
	return 1;
}

static int start_plugins(conf_llist *plugin)
{
	/* spawn children */
	lnode *conf;
	int active = 0;

	plist_first(plugin);
	conf = plist_get_cur(plugin);
	if (conf == NULL || conf->p == NULL)
		return active;

	do {
		if (conf->p && conf->p->active == A_YES) {
			if (start_one_plugin(conf))
				active++;
		}
	} while ((conf = plist_next(plugin)));
	return active;
}

static int reconfigure(void)
{
	int rc;
	daemon_conf_t tdc;
	conf_llist tmp_plugin;
	lnode *tpconf;

	/* Read new daemon config */
	rc = load_config(&tdc, config_file);
	if (rc == 0) {
		if (tdc.q_depth > daemon_config.q_depth) {
			increase_queue_depth(tdc.q_depth);
			daemon_config.q_depth = tdc.q_depth;
		}
		daemon_config.overflow_action = tdc.overflow_action;
		reset_suspended();
		/* We just fill these in because they are used by this
		 * same thread when we return
		 */
		daemon_config.node_name_format = tdc.node_name_format;
		free((char *)daemon_config.name);
		daemon_config.name = tdc.name;
	}

	/* The idea for handling SIGHUP to children goes like this:
	 * 1) load the current config in temp list
	 * 2) mark all in real list unchecked
	 * 3) for each one in tmp list, scan old list
	 * 4) if new, start it, append to list, mark done
	 * 5) else check if there was a change to active state
	 * 6) if so, copy config over and start
	 * 7) If no change, send sighup to non-builtins and mark done
	 * 8) Finally, scan real list for unchecked, terminate and deactivate
	 */
	syslog(LOG_INFO, "Starting reconfigure");
	load_plugin_conf(&tmp_plugin);
	plist_mark_all_unchecked(&plugin_conf);

	plist_first(&tmp_plugin);
	tpconf = plist_get_cur(&tmp_plugin);
	while (tpconf && tpconf->p) {
		lnode *opconf;
		
		opconf = plist_find_name(&plugin_conf, tpconf->p->name);
		if (opconf == NULL) {
			/* We have a new service */
			if (tpconf->p->active == A_YES) {
				tpconf->p->checked = 1;
				plist_last(&plugin_conf);
				plist_append(&plugin_conf, tpconf->p);
				free(tpconf->p);
				tpconf->p = NULL;
				start_one_plugin(plist_get_cur(&plugin_conf));
			}
		} else {
			if (opconf->p->active == tpconf->p->active) {
				/* If active and no state change, sighup it */
				if (opconf->p->type == S_ALWAYS && 
						opconf->p->active == A_YES) {
					if (opconf->p->inode==tpconf->p->inode)
						kill(opconf->p->pid, SIGHUP);
					else {
						/* Binary changed, restart */
						syslog(LOG_INFO,
					"Restarting %s since binary changed",
							opconf->p->path);
						kill(opconf->p->pid, SIGTERM);
						usleep(50000); // 50 msecs
						close(opconf->p->plug_pipe[1]);
						opconf->p->plug_pipe[1] = -1;
						opconf->p->pid = 0;
						start_one_plugin(opconf);
						opconf->p->inode =
							tpconf->p->inode;
					}
				}
				opconf->p->checked = 1;
			} else {
				/* A change in state */
				if (tpconf->p->active == A_YES) {
					/* starting - copy config and exec */
					free_pconfig(opconf->p);
					free(opconf->p);
					opconf->p = tpconf->p;
					opconf->p->checked = 1;
					start_one_plugin(opconf);
					tpconf->p = NULL;
				}
			}
		}

		tpconf = plist_next(&tmp_plugin);
	}

	/* Now see what's left over */
	while ( (tpconf = plist_find_unchecked(&plugin_conf)) ) {
		/* Anything not checked is something removed from the config */
		tpconf->p->active = A_NO;
		syslog(LOG_INFO, "Terminating %s because its now inactive",
				tpconf->p->path);
		if (tpconf->p->type == S_ALWAYS) {
			kill(tpconf->p->pid, SIGTERM);
			close(tpconf->p->plug_pipe[1]);
		} else
			stop_builtin(tpconf->p);
		tpconf->p->plug_pipe[1] = -1;
		tpconf->p->pid = 0;
		tpconf->p->checked = 1;
	}
	
	/* Release memory from temp config */
	plist_first(&tmp_plugin);
	tpconf = plist_get_cur(&tmp_plugin);
	while (tpconf) {
		free_pconfig(tpconf->p);
		tpconf = plist_next(&tmp_plugin);
	}
	plist_clear(&tmp_plugin);
	return plist_count_active(&plugin_conf);
}

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	static const struct option opts[] = {
		{"config_dir", required_argument, NULL, 'c'},
		{NULL, 0, NULL, 0}
	};
	lnode *conf;
	struct sigaction sa;
	int i;

	while ((i = getopt_long(argc, argv, "i:c:", opts, NULL)) != -1) {
		switch (i) {
			case 'c':
				if (asprintf(&config_file, "%s/audispd.conf",
						optarg) < 0) {
mem_out:
					printf(
					"Failed allocating memory, exiting\n");
					release_memory_exit(1);
				}
				break;
			default:
				usage();
		}
	}

	/* check for trailing command line following options */
	if (optind < argc)
		usage();

	if (config_file == NULL)
		config_file = strdup("/etc/audisp/audispd.conf");
	if (config_file == NULL)
		goto mem_out;

	set_aumessage_mode(MSG_SYSLOG, DBG_NO);

	/* Clear any procmask set by libev */
	sigfillset (&sa.sa_mask);
	sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Ignore all signals by default */
	sa.sa_handler = SIG_IGN;
	for (i=1; i<NSIG; i++)
		sigaction(i, &sa, NULL);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = alarm_handler;
	sigaction(SIGALRM, &sa, NULL);
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);
	setsid();

	audit_fd = dup(0);
	if (audit_fd < 0) {
		syslog(LOG_ERR, "Failed setting up input(%s, %d), exiting",
				strerror(errno), audit_fd);
		release_memory_exit(1);
	}

	/* Make all descriptors point to dev null */
	i = open("/dev/null", O_RDWR);
	if (i >= 0) {
		if (dup2(0, i) < 0 || dup2(1, i) < 0 || dup2(2, i) < 0) {
			syslog(LOG_ERR, "Failed duping /dev/null %s, exiting",
					strerror(errno));
			release_memory_exit(1);
		}
		close(i);
	} else {
		syslog(LOG_ERR, "Failed opening /dev/null %s, exiting",
					strerror(errno));
		close(audit_fd);
		release_memory_exit(1);
	}
	if (fcntl(audit_fd, F_SETFD, FD_CLOEXEC) < 0) {
		syslog(LOG_ERR, "Failed protecting input %s, exiting",
					strerror(errno));
		close(audit_fd);
		release_memory_exit(1);
	}

	/* init the daemon's config */
	if (load_config(&daemon_config, config_file)) {
		close(audit_fd);
		release_memory_exit(6);
	}

	load_plugin_conf(&plugin_conf);

	/* if no plugins - exit */
	if (plist_count(&plugin_conf) == 0) {
		syslog(LOG_NOTICE, "No plugins found, exiting");
		close(audit_fd);
		release_memory_exit(0);
	}

	/* Plugins are started with the auditd priority */
	i = start_plugins(&plugin_conf);

	/* Now boost priority to make sure we are getting time slices */
	if (daemon_config.priority_boost != 0) {
		int rc;

		errno = 0;
		rc = nice((int)-daemon_config.priority_boost);
		if (rc == -1 && errno) {
			syslog(LOG_ERR, "Cannot change priority (%s)",
					strerror(errno));
			/* Stay alive as this is better than stopping */
		}
	}

	/* Let the queue initialize */
	init_queue(daemon_config.q_depth);
	syslog(LOG_INFO, 
		"audispd initialized with q_depth=%d and %d active plugins",
		daemon_config.q_depth, i);

	/* Tell it to poll the audit fd */
	if (add_event(audit_fd, process_inbound_event) < 0) {
		syslog(LOG_ERR, "Cannot add event, exiting");
		close(audit_fd);
		close(i);
		release_memory_exit(1);
	}

	/* Create inbound thread */
	pthread_create(&inbound_thread, NULL, inbound_thread_main, NULL); 

	// Block these signals on main thread so poll(2) wakes up
	sigemptyset (&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

	/* Start event loop */
	while (event_loop()) {
		hup = 0;
		if (reconfigure() == 0) {
			syslog(LOG_INFO,
		"After reconfigure, there are no active plugins, exiting");
			break;
		}
	}

	/* Tell plugins we are going down */
	signal_plugins(SIGTERM);

	/* Cleanup builtin plugins */
	destroy_af_unix();
	destroy_syslog();

	/* Give it 5 seconds to clear the queue */
	alarm(5);
	pthread_join(inbound_thread, NULL);

	/* Release configs */
	plist_first(&plugin_conf);
	conf = plist_get_cur(&plugin_conf);
	while (conf) {
		free_pconfig(conf->p);
		conf = plist_next(&plugin_conf);
	}
	plist_clear(&plugin_conf);

	/* Cleanup the queue */
	destroy_queue();
	free_config(&daemon_config);
	free((void *)config_file);
	
	return 0;
}

static int safe_exec(plugin_conf_t *conf)
{
	char *argv[MAX_PLUGIN_ARGS+2];
	int pid, i;

	/* Set up IPC with child */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, conf->plug_pipe) != 0)
		return -1;

	pid = fork();
	if (pid > 0) {
		conf->pid = pid;
		return 0;	/* Parent...normal exit */
	}
	if (pid < 0) { 
		close(conf->plug_pipe[0]);
		close(conf->plug_pipe[1]);
		conf->pid = 0;
		return -1;	/* Failed to fork */
	}

	/* Set up comm with child */
	if (dup2(conf->plug_pipe[0], 0) < 0) {
		close(conf->plug_pipe[0]);
		close(conf->plug_pipe[1]);
		conf->pid = 0;
		return -1;	/* Failed to fork */
	}
	for (i=3; i<24; i++)	 /* Arbitrary number */
		close(i);

	/* Child */
	argv[0] = (char *)conf->path;
	for (i=1; i<(MAX_PLUGIN_ARGS+1); i++)
		argv[i] = conf->args[i];
	argv[i] = NULL;
	execve(conf->path, argv, NULL);
	exit(1);		/* Failed to exec */
}

static void signal_plugins(int sig)
{
	lnode *conf;

	plist_first(&plugin_conf);
	conf = plist_get_cur(&plugin_conf);
	while (conf) {
		if (conf->p && conf->p->pid && conf->p->type == S_ALWAYS)
			kill(conf->p->pid, sig);
		conf = plist_next(&plugin_conf);
	}
}

static int write_to_plugin(event_t *e, const char *string, size_t string_len,
			   lnode *conf)
{
	int rc;

	if (conf->p->format == F_STRING) {
		do {
			rc = write(conf->p->plug_pipe[1], string, string_len);
		} while (rc < 0 && errno == EINTR);
	} else {
		struct iovec vec[2];

		vec[0].iov_base = &e->hdr;
		vec[0].iov_len = sizeof(struct audit_dispatcher_header);

		vec[1].iov_base = e->data;
		vec[1].iov_len = MAX_AUDIT_MESSAGE_LENGTH;
		do {
			rc = writev(conf->p->plug_pipe[1], vec, 2);
		} while (rc < 0 && errno == EINTR);
	}
	return rc;
}

/* Returns 0 on stop, and 1 on HUP */
static int event_loop(void)
{
	char *name = NULL, tmp_name[255];

	/* Get the host name representation */
	switch (daemon_config.node_name_format)
	{
		case N_NONE:
			break;
		case N_HOSTNAME:
			if (gethostname(tmp_name, sizeof(tmp_name))) {
				syslog(LOG_ERR, "Unable to get machine name");
				name = strdup("?");
			} else
				name = strdup(tmp_name);
			break;
		case N_USER:
			if (daemon_config.name)
				name = strdup(daemon_config.name);
			else {
				syslog(LOG_ERR, "User defined name missing");
				name = strdup("?");
			}
			break;
		case N_FQD:
			if (gethostname(tmp_name, sizeof(tmp_name))) {
				syslog(LOG_ERR, "Unable to get machine name");
				name = strdup("?");
			} else {
				int rc;
				struct addrinfo *ai;
				struct addrinfo hints;

				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
				hints.ai_socktype = SOCK_STREAM;

				rc = getaddrinfo(tmp_name, NULL, &hints, &ai);
				if (rc != 0) {
					syslog(LOG_ERR,
					"Cannot resolve hostname %s (%s)",
					tmp_name, gai_strerror(rc));
					name = strdup("?");
					break;
				}
				name = strdup(ai->ai_canonname);
				freeaddrinfo(ai);
			}
			break;
		case N_NUMERIC:
			if (gethostname(tmp_name, sizeof(tmp_name))) {
				syslog(LOG_ERR, "Unable to get machine name");
				name = strdup("?");
			} else {
				int rc;
				struct addrinfo *ai;
				struct addrinfo hints;

				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
				hints.ai_socktype = SOCK_STREAM;

				rc = getaddrinfo(tmp_name, NULL, &hints, &ai);
				if (rc != 0) {
					syslog(LOG_ERR,
					"Cannot resolve hostname %s (%s)",
					tmp_name, gai_strerror(rc));
					name = strdup("?");
					break;
				}
				inet_ntop(ai->ai_family,
						ai->ai_family == AF_INET ?
		(void *) &((struct sockaddr_in *)ai->ai_addr)->sin_addr :
		(void *) &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
						tmp_name, INET6_ADDRSTRLEN);
				freeaddrinfo(ai);
				name = strdup(tmp_name);
			}
			break;
	}

	/* Figure out the format for the af_unix socket */
	while (stop == 0) {
		event_t *e;
		const char *type;
		char *v, *ptr, unknown[32];
		unsigned int len;
		lnode *conf;

		/* This is where we block until we have an event */
		e = dequeue();
		if (e == NULL) {
			if (hup) {
				free(name);
				return 1;
			}
			continue;
		}

		/* Get the event formatted */
		type = audit_msg_type_to_name(e->hdr.type);
		if (type == NULL) {
			snprintf(unknown, sizeof(unknown),
				"UNKNOWN[%u]", e->hdr.type);
			type = unknown;
		}
		// Protocol 1 is not formatted
		if (e->hdr.ver == AUDISP_PROTOCOL_VER) {
			if (daemon_config.node_name_format != N_NONE) {
			    len = asprintf(&v, "node=%s type=%s msg=%.*s\n", 
					name, type, e->hdr.size, e->data);
			} else
				len = asprintf(&v, "type=%s msg=%.*s\n", 
					type, e->hdr.size, e->data);
		// Protocol 2 events are already formatted
		} else if (e->hdr.ver == AUDISP_PROTOCOL_VER2) {
			len = asprintf(&v, "%.*s\n", e->hdr.size, e->data);
		} else
			len = 0;
		if (len <= 0) {
			v = NULL;
			free(e); /* Either corrupted event or no memory */
			continue;
		}

		/* Strip newlines from event record */
		ptr = v;
		while ((ptr = strchr(ptr, 0x0A)) != NULL) {
			if (ptr != &v[len-1])
				*ptr = ' ';
			else
				break; /* Done - exit loop */
		}

		/* Distribute event to the plugins */
		plist_first(&plugin_conf);
		conf = plist_get_cur(&plugin_conf);
		do {
			if (conf == NULL || conf->p == NULL)
				continue;
			if (conf->p->active == A_NO || stop)
				continue;

			/* Now send the event to the right child */
			if (conf->p->type == S_SYSLOG) {
				// Strip out End of event records for syslog
				if (e->hdr.type != AUDIT_EOE)
					send_syslog(v, e->hdr.ver);
			} else if (conf->p->type == S_AF_UNIX) {
				if (conf->p->format == F_STRING)
					send_af_unix_string(v, len);
				else
					send_af_unix_binary(e);
			} else if (conf->p->type == S_ALWAYS && !stop) {
				int rc;
				rc = write_to_plugin(e, v, len, conf);
				if (rc < 0 && errno == EPIPE) {
					/* Child disappeared ? */
					syslog(LOG_ERR,
					"plugin %s terminated unexpectedly", 
								conf->p->path);
					conf->p->pid = 0;
					conf->p->restart_cnt++;
					if (conf->p->restart_cnt >
						daemon_config.max_restarts) {
						syslog(LOG_ERR,
					"plugin %s has exceeded max_restarts",
								conf->p->path);
					}
					close(conf->p->plug_pipe[1]);
					conf->p->plug_pipe[1] = -1;
					conf->p->active = A_NO;
					if (!stop && start_one_plugin(conf)) {
						rc = write_to_plugin(e, v, len,
								     conf);
						syslog(LOG_NOTICE,
						"plugin %s was restarted",
							conf->p->path);
						conf->p->active = A_YES;
					} 
				}
			}
		} while (!stop && (conf = plist_next(&plugin_conf)));

		/* Done with the memory...release it */
		free(v);
		free(e);
		if (hup)
			break;
	}
	free(name);
	if (stop)
		return 0;
	else
		return 1;
}

static struct pollfd pfd[4];
static poll_callback_ptr pfd_cb[4];
static volatile int pfd_cnt=0;
int add_event(int fd, poll_callback_ptr cb)
{
	if (pfd_cnt > 3)
		return -1;

	pfd[pfd_cnt].fd = fd;
	pfd[pfd_cnt].events = POLLIN;
	pfd[pfd_cnt].revents = 0;
	pfd_cb[pfd_cnt] = cb;
	pfd_cnt++;
	return 0;
}

int remove_event(int fd)
{
	int start, i;
	if (pfd_cnt == 0)
		return -1;

	for (start=0; start < pfd_cnt; start++) {
		if (pfd[start].fd == fd)
			break;
	}
	for (i=start; i<(pfd_cnt-1); i++) {
		pfd[i].events = pfd[i+1].events;
		pfd[i].revents = pfd[i+1].revents;
		pfd[i].fd = pfd[i+1].fd;
		pfd_cb[i] = pfd_cb[i+1];
	}

	pfd_cnt--;
	return 0;
}

/* inbound thread - enqueue inbound data to intermediate table */
static void *inbound_thread_main(void *arg)
{
	while (stop == 0) {
		int rc;
		if (hup)
			nudge_queue();
		do {
			rc = poll(pfd, pfd_cnt, 20000); /* 20 sec */
		} while (rc < 0 && errno == EAGAIN && stop == 0 && hup == 0);
		if (rc == 0)
			continue;

		/* Event readable... */
		if (rc > 0) {
			/* Figure out the fd that is ready and call */
			int i = 0;
			while (i < pfd_cnt) {
				if (pfd[i].revents & POLLIN) 
					pfd_cb[i](pfd[i].fd);
				i++;
			}
		} 
	}
	/* make sure event loop wakes up */
	nudge_queue();
	return NULL;
}

static void process_inbound_event(int fd)
{
	int rc;
	struct iovec vec;
	event_t *e = malloc(sizeof(event_t));
	if (e == NULL) 
		return;
	memset(e, 0, sizeof(event_t));

	/* Get header first. It is fixed size */
	vec.iov_base = &e->hdr;
	vec.iov_len = sizeof(struct audit_dispatcher_header);
	do {
		rc = readv(fd, &vec, 1);
	} while (rc < 0 && errno == EINTR);

	if (rc <= 0) {
		if (rc == 0)
			stop = 1; // End of File
		free(e);
		return;
	}

	if (rc > 0) {
		/* Sanity check */
		if ((e->hdr.ver != AUDISP_PROTOCOL_VER &&
				e->hdr.ver != AUDISP_PROTOCOL_VER2)) {
			syslog(LOG_ERR,
				"Unknown dispatcher protocol %u, exiting",
					e->hdr.ver);
			free(e);
			exit(1);
		}
		if (e->hdr.hlen != sizeof(e->hdr)) {
			syslog(LOG_ERR,
				    "Header length mismatch %u %lu, exiting",
					e->hdr.hlen, sizeof(e->hdr));
			free(e);
			exit(1);
		}
		if (e->hdr.size > MAX_AUDIT_MESSAGE_LENGTH) {
			syslog(LOG_ERR,	"Header size mismatch %d, exiting",
					e->hdr.size);
			free(e);
			exit(1);
		}

		/* Next payload */
		vec.iov_base = e->data;
		vec.iov_len = e->hdr.size;
		do {
			rc = readv(fd, &vec, 1);
		} while (rc < 0 && errno == EINTR);

		if (rc > 0)
			enqueue(e, &daemon_config);
		else {
			if (rc == 0)
				stop = 1; // End of File
			free(e);
		}
	}
}
