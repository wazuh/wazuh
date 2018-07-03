/* auditd-sendmail.c --
 * Copyright 2005 Red Hat Inc., Durham, North Carolina.
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
#include <unistd.h>		// for access()
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include "libaudit.h"
#include "private.h"
#include "auditd-config.h"

extern const char *email_command;
static int safe_popen(pid_t *pid, const char *mail_acct);

// returns 1 on error & 0 if OK
int sendmail(const char *subject, const char *content, const char *mail_acct)
{
	pid_t pid;

	if (access(email_command, 01) == 0)
	{	
		FILE *mail;
		int fd;

		fd = safe_popen(&pid, mail_acct);
		if (fd < 0) 
			return 1;
		mail = fdopen(fd, "w");
		if (mail == NULL) {
			kill(pid, SIGKILL);
			close(fd);
			audit_msg(LOG_ERR, "Error - starting mail"); 
			return 1;
		}

		fprintf(mail, "To: %s\n", mail_acct);
		fprintf(mail, "From: root\n");
//		fprintf(mail, "X-Sender: %s\n", mail_acct);
		fprintf(mail, "Subject: %s\n\n", subject); // End of Header
		fprintf(mail, "%s\n", content);
		fprintf(mail, ".\n\n");		// Close it up...
		fclose(mail);
		return 0;
	} else
		audit_msg(LOG_ERR, "Error - %s isn't executable",
			email_command); 
	return 1;	
}

static int safe_popen(pid_t *pid, const char *mail_acct)
{
	char *argv[4];
	char acct[256];
	int pipe_fd[2];
	struct sigaction sa;

	if (pipe(pipe_fd)) {
		audit_msg(LOG_ALERT,
		"Audit daemon failed to create pipe while sending email alert");
		return -1;
	}

	*pid = fork();
	if (*pid < 0) {
		close(pipe_fd[0]);
		close(pipe_fd[1]);
		audit_msg(LOG_ALERT,
		    "Audit daemon failed to fork while sending email alert");
		return -1;
	}
	if (*pid) {       /* Parent */
		close(pipe_fd[0]);	// adjust pipe
		return pipe_fd[1];
	}
	/* Child */
	sigfillset (&sa.sa_mask);
	sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);

	close(pipe_fd[1]);	// adjust pipe
	dup2(pipe_fd[0], 0);

	/* Make email acct param */
	snprintf(acct, sizeof(acct), "-f%s", mail_acct);

	/* Stuff arg list */
	argv[0] = (char *)email_command;
	argv[1] = (char *)"-t";
	argv[2] = acct;
	argv[3] = NULL;
	execve(email_command, argv, NULL);
	audit_msg(LOG_ALERT, "Audit daemon failed to exec %s", email_command);
	exit(1);
}

