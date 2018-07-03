/*
 * aulast.c - A last program based on audit logs 
 * Copyright (c) 2008-2009,2011,2016 Red Hat Inc., Durham, North Carolina.
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
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "libaudit.h"
#include "auparse.h"
#include "aulast-llist.h"


static	llist l;
static FILE *f = NULL;
static char *kernel = NULL;

/* command line params */
static int bad = 0, proof = 0, debug = 0;
static char *cterm = NULL, *user = NULL;

void usage(void)
{
	fprintf(stderr,
 "usage: aulast [--stdin] [--proof] [--extract] [-f file] [--user name] [--tty tty]\n");
}

/* This outputs a line of text reporting the login/out times */
static void report_session(lnode* cur)
{
	int notime = 0;

	// Don't list failed logins
	if (cur == NULL)
		return;

	if (cur->result != bad)
		return;

	if (cur->name) {
		// This is a reboot record
		printf("%-8.8s ", cur->name);
		if (cur->end == 0) {
			cur->end = time(NULL);
			notime = 1;
		}
	} else
		printf("%-8.u ", cur->auid);

	if (strncmp("/dev/", cur->term, 5) == 0)
		printf("%-12.12s ", cur->term+5);
	else
		printf("%-12.12s ", cur->term);
	printf("%-16.16s ", cur->host ? cur->host : "?");
	printf("%-16.16s ", ctime(&cur->start));
	switch(cur->status)
	{
		case SESSION_START:
			printf("  still logged in\n");
			break;
		case DOWN:
			printf("- down\n");
			break;
		case CRASH:
			printf("- crash\n");
			break;
		case GONE:
			printf("  gone - no logout\n");
			break;
		case LOG_OUT: {
			time_t secs;
			int mins, hours, days;
			if (notime)
				printf("- %-7.5s", " ");
			else
				printf("- %-7.5s", ctime(&cur->end) + 11);
			secs = cur->end - cur->start;
			mins  = (secs / 60) % 60;
			hours = (secs / 3600) % 24;
			days  = secs / 86400;
			if (days)
				printf("(%d+%02d:%02d)\n", days, hours, mins);
			else
				printf("(%02d:%02d)\n", hours, mins);
			}
			break;
		default:
			printf("\n");
			break;
	}
	if (proof) {
		char start[32], end[32];
		struct tm *btm;

		if (cur->loginuid_proof == 0 && cur->result == 1) // Bad login
			printf("    audit event proof serial number:"
			       " %lu\n", cur->user_login_proof);
		else
			printf("    audit event proof serial numbers:"
			       " %lu, %lu, %lu\n", cur->loginuid_proof,
				cur->user_login_proof, cur->user_end_proof);
		printf("    Session data can be found with this search:\n");
		btm = localtime(&cur->start);
		strftime(start, sizeof(start), "%x %T", btm);
		if (cur->end != 0) {
			btm = localtime(&cur->end);
			strftime(end, sizeof(end), "%x %T", btm);
		      printf("    ausearch --start %s --end %s",
				start, end);
		} else {
		    printf("    ausearch --start %s", start);
		}
		if (cur->name == NULL)
			printf(" --session %u", cur->session);
		if (cur->loginuid_proof == 0 && cur->result == 1) // Bad login
			printf(" -a %lu", cur->user_login_proof);
		printf("\n\n");
	}
}

static void extract_record(auparse_state_t *au)
{
	if (f == NULL)
		return;

	fprintf(f, "%s\n", auparse_get_record_text(au));
}

static void create_new_session(auparse_state_t *au)
{
	const char *tpid, *tses, *tauid, *tacct = NULL;
	int pid = -1, auid = -1, ses = -1;
	lnode *n;

	// Get pid
	tpid = auparse_find_field(au, "pid");
	if (tpid)
		pid = auparse_get_field_int(au);

	// Get second auid field
	tauid = auparse_find_field(au, "old-auid");
	if (tauid)
		tauid = auparse_find_field(au, "auid");
	else {	// kernel 3.13 or older
		auparse_first_record(au);
		auparse_find_field(au, "auid");
		auparse_next_field(au);
		tauid = auparse_find_field(au, "auid");
	}
	if (tauid) {
		auid = auparse_get_field_int(au);
		tacct = auparse_interpret_field(au);
	}

	// Get second ses field
	tses = auparse_find_field(au, "old-ses");
	if (tses)
		tses = auparse_find_field(au, "ses");
	else {	// kernel 3.13 or older
		auparse_first_record(au);
		auparse_find_field(au, "ses"); 
		auparse_next_field(au);
		tses = auparse_find_field(au, "ses");
	}
	if (tses)
		ses = auparse_get_field_int(au);

	// Check that they are valid
	if (pid == -1 || auid ==-1 || ses == -1) {
		if (debug)
			fprintf(stderr, "Bad login for event: %lu\n",
					auparse_get_serial(au));
		return;
	}

	// See if this session is already open
	//cur = list_find_auid(&l, auid, pid, ses);
	n = list_find_session(&l, ses);
	if (n) {
		// This means we have an open session close it out
		n->status = GONE;
		n->end = auparse_get_time(au);
		report_session(n);
		list_delete_cur(&l);
	}

	// If this is supposed to be limited to a specific
	// uid and we don't have that record, skip creating it
	if (user) {
		if ((tacct && strcmp(user, tacct)) || tacct == NULL) {
			if (debug)
				fprintf(stderr,
			    "login reporting limited to %s for event: %lu\n",
					user, auparse_get_serial(au));
			return;
		}
	}

	n = malloc(sizeof(lnode));
	if (n == NULL)
		return;
	n->session = ses;
	n->start = auparse_get_time(au);
	n->end = 0;
	n->auid = auid;
	n->pid = pid;
	n->result = -1;
	n->name = tacct ? strdup(tacct) : NULL;
	n->term = NULL;
	n->host = NULL;
	n->status = LOG_IN;
	n->loginuid_proof = auparse_get_serial(au);
	n->user_login_proof = 0;
	n->user_end_proof = 0;
	list_create_session_simple(&l, n);
}

static void update_session_login(auparse_state_t *au)
{
	const char *tpid, *tses, *tuid, *tacct=NULL, *host, *term, *tres;
	int pid = -1, uid = -1, ses = -1, result = -1;
	time_t start;
	lnode *cur;

	// Get pid
	tpid = auparse_find_field(au, "pid");
	if (tpid)
		pid = auparse_get_field_int(au);

	// Get ses field - skipping first uid
	tses = auparse_find_field(au, "ses");
	if (tses)
		ses = auparse_get_field_int(au);

	// Get second uid field - we should be positioned past the first one
	// gdm sends uid, everything else sends id, we try acct as last resort
	tuid = auparse_find_field(au, "uid");
	if (tuid)
		uid = auparse_get_field_int(au);
	else {
		auparse_first_record(au);
		tuid = auparse_find_field(au, "id");
		if (tuid)
			uid = auparse_get_field_int(au);
		auparse_first_record(au);
	}

	start = auparse_get_time(au);

	host = auparse_find_field(au, "hostname");
	if (host && strcmp(host, "?") == 0)
		host = auparse_find_field(au, "addr");

	term = auparse_find_field(au, "terminal");
	if (term == NULL)
		term = "?";
	tres = auparse_find_field(au, "res");
	if (tres)
		tres = auparse_interpret_field(au);
	if (tres) {
		if (strcmp(tres, "success") == 0)
			result = 0;
		else
			result = 1;
	}
	// We only get tacct when its a bad login
	if (result == 1) {
		auparse_first_record(au);
		tacct = auparse_find_field(au, "acct");
		if (tacct)
			tacct = auparse_interpret_field(au);
	} else {
		// Check that they are valid
		if (pid == -1 || uid ==-1 || ses == -1) { 
			if (debug)
				fprintf(stderr,
					"Bad user login for event: %lu\n",
					auparse_get_serial(au));
			return;
		}
	}

	// See if this session is already open
	if (result == 0)
		cur = list_find_auid(&l, uid, pid, ses);
	else
		cur = NULL;
	if (cur) {
		// If we are limited to a specific terminal and
		// we find out the session is not associated with
		// the terminal of interest, delete the current node
		if (cterm && strstr(term, cterm) == NULL) {
			list_delete_cur(&l);
			if (debug)
				fprintf(stderr,
				"User login limited to %s for event: %lu\n",
					cterm, auparse_get_serial(au));
			return;
		}

		// This means we have an open session - update it
		list_update_start(&l, host, term, result,
				auparse_get_serial(au));

		// If the results were failed, we can close it out
		/* FIXME: result cannot be true. This is dead code.
		if (result) {
			report_session(cur);
			list_delete_cur(&l);
		} */
	} else if (bad == 1 && result == 1) {
		// If it were a bad login and we are wanting bad logins
		// create the record and report it.
		lnode n;

		n.start = start;
		n.end = start;
		n.auid = uid;
		n.name = tacct;
		n.term = term;
		n.host = host;
		n.result = result;
		n.status = LOG_OUT;
		n.loginuid_proof = 0;
		n.user_login_proof = auparse_get_serial(au);
		n.user_end_proof = 0;
		report_session(&n); 
	} else if (debug)
		printf("Session not found or updated\n");
}

static void update_session_logout(auparse_state_t *au)
{
	const char *tses, *tauid, *tpid;
	int pid = -1, auid = -1, ses = -1;
	lnode *cur;

	// Get pid field
	tpid = auparse_find_field(au, "pid");
	if (tpid)
		pid = auparse_get_field_int(au);

	// Get auid field
	tauid = auparse_find_field(au, "auid");
	if (tauid)
		auid = auparse_get_field_int(au);

	// Get ses field
	tses = auparse_find_field(au, "ses");
	if (tses)
		ses = auparse_get_field_int(au);

	// Check that they are valid
	if (pid == -1 || auid ==-1 || ses == -1) {
		if (debug)
			fprintf(stderr, "Bad user logout for event: %lu\n",
					auparse_get_serial(au));
		return;
	}

	// See if this session is already open
	cur = list_find_auid(&l, auid, pid, ses);
	if (cur) {
		// if time never got updated, this must be a cron or su 
		// session...so we will just delete it.
		if (cur->start) {
			// This means we have an open session close it out
			time_t end = auparse_get_time(au);
			list_update_logout(&l, end, auparse_get_serial(au));
			report_session(cur);
		} else if (debug)
			fprintf(stderr, "start time error for event: %lu\n",
					auparse_get_serial(au));
		list_delete_cur(&l);
	}
}

static void process_bootup(auparse_state_t *au)
{
	lnode *cur;
	int start;

	// See if we have unclosed boot up and make into CRASH record
	list_first(&l);
	cur = list_get_cur(&l);
	while (cur) {
		if (cur->name) {
			cur->user_end_proof = auparse_get_serial(au);
			cur->status = CRASH;
			cur->end = auparse_get_time(au);
			report_session(cur);
		}
		cur = list_next(&l);
	}

	// Logout and process anyone still left in the machine
	list_first(&l);
	cur = list_get_cur(&l);
	while (cur) {
		if (cur->status != CRASH) {
			cur->user_end_proof = auparse_get_serial(au);
			cur->status = DOWN;
			cur->end = auparse_get_time(au);
			report_session(cur);
		}
		cur = list_next(&l);
	}

	// Since this is a boot message, all old entries should be gone
	list_clear(&l);
	list_create(&l);

	// make reboot record - user:reboot, tty:system boot, host: kernel 
	start = auparse_get_time(au);
	list_create_session(&l, 0, 0, 0, auparse_get_serial(au));
	cur = list_get_cur(&l);
	cur->start = start;
	cur->name = strdup("reboot");
	cur->term = strdup("system boot");
	if (kernel)
		cur->host = strdup(kernel);
	cur->result = 0;
}

static void process_kernel(auparse_state_t *au)
{
	const char *kernel_str = auparse_find_field(au, "kernel");
	if (kernel_str == NULL)
		return;

	free(kernel);
	kernel = strdup(kernel_str);
}

static void process_shutdown(auparse_state_t *au)
{
	lnode *cur;

	// Find reboot record
	list_first(&l);
	cur = list_get_cur(&l);
	while (cur) {
		if (cur->name) {
			// Found it - close it out and display it
			time_t end = auparse_get_time(au);
			list_update_logout(&l, end, auparse_get_serial(au));
			report_session(cur);
			list_delete_cur(&l);
			return;
		}
		cur = list_next(&l);
	}
}

int main(int argc, char *argv[])
{
	int i, use_stdin = 0;
	char *file = NULL;
        auparse_state_t *au;

	setlocale (LC_ALL, "");
	for (i=1; i<argc; i++) {
		if (strcmp(argv[i], "-f") == 0) {
			if (use_stdin == 0) {
				i++;
				file = argv[i];
			} else {
				fprintf(stderr,"stdin already given\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--bad") == 0) {
			bad = 1;
		} else if (strcmp(argv[i], "--proof") == 0) {
			proof = 1;
		} else if (strcmp(argv[i], "--extract") == 0) {
			f = fopen("aulast.log", "wt");
		} else if (strcmp(argv[i], "--stdin") == 0) {
			if (file == NULL)
				use_stdin = 1;
			else {
				fprintf(stderr, "file already given\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--user") == 0) {
			if (user == NULL) {
				i++;
				user = argv[i];
			} else {
				usage();
				return 1;
			}
		} else if (strcmp(argv[i], "--tty") == 0) {
			if (cterm == NULL) {
				i++;
				cterm = argv[i];
			} else {
				usage();
				return 1;
			}
		} else if (strcmp(argv[i], "--debug") == 0) {
			debug = 1;
		} else {
			usage();
			return 1;
		}
	}
	list_create(&l);

	// Search for successful user logins
	if (file)
		au = auparse_init(AUSOURCE_FILE, file);
	else if (use_stdin)
		au = auparse_init(AUSOURCE_FILE_POINTER, stdin);
	else {
		if (getuid()) {
			fprintf(stderr,
			  "You probably need to be root for this to work\n");
		}
		au = auparse_init(AUSOURCE_LOGS, NULL);
	}
	if (au == NULL) {
		fprintf(stderr, "Error - %s\n", strerror(errno));
		goto error_exit_1;
	}

	// The theory: iterate though events
	// 1) when LOGIN is found, create a new session node
	// 2) if that session number exists, close out the old one
	// 3) when USER_LOGIN is found, update session node
	// 4) When USER_END is found update session node and close it out
	// 5) When BOOT record found make new record and check for previous
	// 6) If previous boot found, set status to crash and logout everyone
	// 7) When SHUTDOWN found, close out reboot record

	while (auparse_next_event(au) > 0) {
		// We will take advantage of the fact that all events
		// of interest are one record long
		int type = auparse_get_type(au);
		if (type < 0)
			continue;
		switch (type)
		{
			case AUDIT_LOGIN:
				create_new_session(au);
				extract_record(au);
				break;
			case AUDIT_USER_LOGIN:
				update_session_login(au);
				extract_record(au);
				break;
			case AUDIT_USER_END:
				update_session_logout(au);
				extract_record(au);
				break;
			case AUDIT_SYSTEM_BOOT:
				process_bootup(au);
				extract_record(au);
				break;
			case AUDIT_SYSTEM_SHUTDOWN:
				process_shutdown(au);
				extract_record(au);
				break;
			case AUDIT_DAEMON_START:
				process_kernel(au);
				extract_record(au);
				break;
		}
	}
	auparse_destroy(au);

	// Now output the leftovers
	list_first(&l);
	do {
		lnode *cur = list_get_cur(&l);
		report_session(cur);
	} while (list_next(&l));

	free(kernel);
	list_clear(&l);
	if (f)
		fclose(f);
	return 0;

error_exit_1:
	list_clear(&l);
	if (f)
		fclose(f);
	return 1;
}

