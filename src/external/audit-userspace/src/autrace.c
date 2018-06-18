/* autrace.c -- 
 * Copyright 2005-09,2011,2015-16 Red Hat Inc., Durham, North Carolina.
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
 *     Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <linux/net.h>
#include "libaudit.h"
#include "private.h"

/*
 * This program will add the audit rules to trace a process similar
 * to strace. It will then execute the process.
 */
static int threat = 0;
static int count_rules(void);
static int count_em(int fd);
extern int delete_all_rules(int fd);

static void usage(void)
{
	fprintf(stderr, "usage: autrace [-r] program\n");
}

static int insert_rule(int audit_fd, const char *field)
{
	int rc;
	int flags = AUDIT_FILTER_EXIT;
	int action = AUDIT_ALWAYS;
	struct audit_rule_data *rule = malloc(sizeof(struct audit_rule_data));
	int machine = audit_detect_machine();
	char *t_field = NULL;

	if (rule == NULL)
		goto err;
	memset(rule, 0, sizeof(struct audit_rule_data));
	if (threat) {
		rc = 0;
		if (machine != MACH_AARCH64) {
			rc |= audit_rule_syscallbyname_data(rule, "open");
			rc |= audit_rule_syscallbyname_data(rule, "creat");
			rc |= audit_rule_syscallbyname_data(rule, "rename");
			rc |= audit_rule_syscallbyname_data(rule, "unlink");
			rc |= audit_rule_syscallbyname_data(rule, "mknod");
			rc |= audit_rule_syscallbyname_data(rule, "mkdir");
			rc |= audit_rule_syscallbyname_data(rule, "rmdir");
			rc |= audit_rule_syscallbyname_data(rule, "chown");
			rc |= audit_rule_syscallbyname_data(rule, "lchown");
			rc |= audit_rule_syscallbyname_data(rule, "chmod");
			rc |= audit_rule_syscallbyname_data(rule, "link");
			rc |= audit_rule_syscallbyname_data(rule, "symlink");
			rc |= audit_rule_syscallbyname_data(rule, "readlink");
		}
		rc |= audit_rule_syscallbyname_data(rule, "openat");
		rc |= audit_rule_syscallbyname_data(rule, "truncate");
		rc |= audit_rule_syscallbyname_data(rule, "renameat");
		rc |= audit_rule_syscallbyname_data(rule, "unlinkat");
		rc |= audit_rule_syscallbyname_data(rule, "mknodat");
		rc |= audit_rule_syscallbyname_data(rule, "mkdirat");
		rc |= audit_rule_syscallbyname_data(rule, "chdir");
		rc |= audit_rule_syscallbyname_data(rule, "fchownat");
		rc |= audit_rule_syscallbyname_data(rule, "fchmodat");
		rc |= audit_rule_syscallbyname_data(rule, "linkat");
		rc |= audit_rule_syscallbyname_data(rule, "symlinkat");
		rc |= audit_rule_syscallbyname_data(rule, "readlinkat");
		rc |= audit_rule_syscallbyname_data(rule, "execve");
		rc |= audit_rule_syscallbyname_data(rule, "name_to_handle_at");

		if (machine != MACH_X86 && machine != MACH_S390X && 
						machine != MACH_S390) {
			rc |= audit_rule_syscallbyname_data(rule, "connect");
			rc |= audit_rule_syscallbyname_data(rule, "bind");
			rc |= audit_rule_syscallbyname_data(rule, "accept");
			rc |= audit_rule_syscallbyname_data(rule, "sendto");
			rc |= audit_rule_syscallbyname_data(rule, "recvfrom");
			rc |= audit_rule_syscallbyname_data(rule, "accept4");
		}

		rc |= audit_rule_syscallbyname_data(rule, "sendfile");
	} else
		rc = audit_rule_syscallbyname_data(rule, "all");
	if (rc < 0)
		goto err;
	t_field = strdup(field);
	rc = audit_rule_fieldpair_data(&rule, t_field, flags);
	free(t_field);
	if (rc < 0)
		goto err;
	rc = audit_add_rule_data(audit_fd, rule, flags, action);
	if (rc < 0)
		goto err;

	// Now if i386, lets add its network rules
	if (machine == MACH_X86 || machine == MACH_S390X ||
						machine == MACH_S390) {
		int i, a0[6] = { SYS_CONNECT, SYS_BIND, SYS_ACCEPT, SYS_SENDTO,
				 SYS_RECVFROM, SYS_ACCEPT4 };
		for (i=0; i<6; i++) {
			char pair[32];

			memset(rule, 0, sizeof(struct audit_rule_data));
			rc |= audit_rule_syscallbyname_data(rule, "socketcall");
			snprintf(pair, sizeof(pair), "a0=%d", a0[i]);
			rc |= audit_rule_fieldpair_data(&rule, pair, flags);
			t_field = strdup(field);
			rc |= audit_rule_fieldpair_data(&rule, t_field, flags);
			free(t_field);
			rc |= audit_add_rule_data(audit_fd, rule, flags, action);
		}
	}
	free(rule);
	return 0;
err:
	fprintf(stderr, "Error inserting audit rule for %s\n", field);
	free(rule);
	return 1;
}

int key_match(struct audit_reply *rep)
{
	return 1;
}

/*
 * Algorithm:
 * check that user is root
 * check to see if program exists
 * if so fork, child waits for parent
 * parent clears audit rules, loads audit all syscalls with child's pid
 * parent tells child to go & waits for sigchld
 * child exec's program
 * parent deletes rules after getting sigchld
 */
int main(int argc, char *argv[])
{
	int fd[2];
	int pid,cmd=1;
	char buf[2];

	if (argc < 2) {
		usage();
		return 1;
	}
	if (strcmp(argv[cmd], "-h") == 0) {
		usage();
		return 1;
	}
	if (strcmp(argv[cmd], "-r") == 0) {
		threat = 1;
		cmd++;
	}
	if (!audit_can_control()) {
		fprintf(stderr,
		"You must be root or have capabilities to run this program.\n");
		return 1;
	}
	if (access(argv[cmd], X_OK)) {
		if (errno == ENOENT)
			fprintf(stderr, "Error - can't find: %s\n", argv[cmd]); 
		else
			fprintf(stderr, "Error checking %s (%s)\n", 
				argv[cmd], strerror(errno));
		return 1;
	}
	set_aumessage_mode(MSG_STDERR, DBG_NO);
	switch (count_rules())
	{
		case -1:
			if (errno == ECONNREFUSED)
		                fprintf(stderr,
					"The audit system is disabled\n");
			else
				fprintf(stderr,
					"Error - can't get rule count.\n");
			return 1;
		case 0:
			break;
		default:
			fprintf(stderr, 
			"autrace cannot be run with rules loaded.\n"
			"Please delete all rules using 'auditctl -D' if you "
			"really wanted to\nrun this command.\n");
			return 1;
	}
	if (pipe(fd) != 0) {
		fprintf(stderr, "Error creating pipe.\n");
		return 1;
	}
	
	switch ((pid=fork()))
	{
		case -1:
			fprintf(stderr, "Error forking.\n");
			return 1;
		case 0: /* Child */
			close(fd[1]);
			printf("Waiting to execute: %s\n", argv[cmd]);
			while (read(fd[0], buf, 1) == -1 && errno == EINTR)
				/* blank */ ;
			close(fd[0]);
			execvp(argv[cmd], &argv[cmd]);
			fprintf(stderr, "Failed to exec %s\n", argv[cmd]);
			return 1;
		default: /* Parent */
			close(fd[0]);
			fcntl(fd[1], F_SETFD, FD_CLOEXEC);
			{
				char field[16];
				int audit_fd;
  				audit_fd = audit_open();
				if (audit_fd < 0)
					exit(1);
				snprintf(field, sizeof(field), "pid=%d", pid);
				if (insert_rule(audit_fd, field)) {
					kill(pid,SIGTERM);
					(void)delete_all_rules(audit_fd);
					exit(1);
				}
				snprintf(field, sizeof(field), "ppid=%d", pid);
				if (insert_rule(audit_fd, field)) {
					kill(pid,SIGTERM);
					(void)delete_all_rules(audit_fd);
					exit(1);
				}
				sleep(1);
				if (write(fd[1],"1", 1) != 1) {
					kill(pid,SIGTERM);
					(void)delete_all_rules(audit_fd);
					exit(1);
				}
				waitpid(pid, NULL, 0);
				close(fd[1]);
				puts("Cleaning up...");
				(void)delete_all_rules(audit_fd);
				close(audit_fd);
			}
			printf("Trace complete. "
				"You can locate the records with "
				"\'ausearch -i -p %d\'\n",
				pid);
			break;
	}

	return 0;
}

static int count_rules(void)
{
	int fd, total, rc;

	fd = audit_open();
	if (fd < 0) 
		return -1;

	rc = audit_request_rules_list_data(fd);
	if (rc > 0) 
		total = count_em(fd);
	else 
		total = -1;

	close(fd); 
	return total;
}

static int count_em(int fd)
{
	int i, retval, count = 0;
	int timeout = 40; /* loop has delay of .1 - this is 4 seconds */
	struct audit_reply rep;
	fd_set read_mask;

	FD_ZERO(&read_mask);
	FD_SET(fd, &read_mask);

	for (i = 0; i < timeout; i++) {
		struct timeval t;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		retval = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
		if (retval > 0) {
			if (rep.type == NLMSG_ERROR && 
					rep.error->error == 0)
				continue;
			do {
				retval=select(fd+1, &read_mask, NULL, NULL, &t);
			} while (retval < 0 && errno == EINTR);

			switch (rep.type)
			{
				case NLMSG_DONE:
					return count;
				case AUDIT_LIST_RULES:
					i = 0;
					count++;
					break;
				case NLMSG_ERROR:
					return -1;
				default:
					break;
			}
		} else if (errno == EAGAIN)  // Take short delay
			select(fd+1, &read_mask, NULL, NULL, &t);
	}
	if (i >= timeout && count == 0)
		count = -1;
	return count;
}

