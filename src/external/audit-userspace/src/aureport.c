/*
 * aureport.c - main file for aureport utility 
 * Copyright 2005-08, 2010,11,2013 Red Hat Inc., Durham, North Carolina.
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
#include <stdio_ext.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <locale.h>
#include <sys/param.h>
#include "libaudit.h"
#include "auditd-config.h"
#include "aureport-options.h"
#include "aureport-scan.h"
#include "ausearch-lol.h"
#include "ausearch-lookup.h"
#include "auparse-idata.h"


extern event very_first_event;
event very_last_event;
static FILE *log_fd = NULL;
static lol lo;
static int found = 0;
static int files_to_process = 0; // Logs left when processing multiple
static int userfile_is_dir = 0;
static int process_logs(void);
static int process_log_fd(const char *filename);
static int process_stdin(void);
static int process_file(char *filename);
static int get_event(llist **);

extern char *user_file;
extern int force_logs;


static int is_pipe(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == 0) {
		if (S_ISFIFO(st.st_mode))
			return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct rlimit limit;
	int rc;

	/* Check params and build regexpr */
	setlocale (LC_ALL, "");
	if (check_params(argc, argv))
		return 1;

	/* Raise the rlimits in case we're being started from a shell
	* with restrictions. Not a fatal error.  */
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_CPU, &limit);
	set_aumessage_mode(MSG_STDERR, DBG_NO);
	(void) umask( umask( 077 ) | 027 );
	very_first_event.sec = 0;
	reset_counters();

	print_title();
	lol_create(&lo);
	if (user_file) {
		struct stat sb;
		if (stat(user_file, &sb) == -1) {
			perror("stat");
			return 1;
		} else {
			switch (sb.st_mode & S_IFMT) {
				case S_IFDIR: 
					userfile_is_dir = 1;
					rc = process_logs();
					break;
				case S_IFREG:
				default:
					rc = process_file(user_file);
					break;
			}
		}
	} else if (force_logs)
		rc = process_logs();
	else if (is_pipe(0))
		rc = process_stdin();
	else
		rc = process_logs();
	lol_clear(&lo);
	if (rc)
		return rc;

	if (!found && report_detail == D_DETAILED && report_type != RPT_TIME) {
		printf("<no events of interest were found>\n\n");
		destroy_counters();
		aulookup_destroy_uid_list();
		return 1;
	} else 
		print_wrap_up();
	destroy_counters();
	aulookup_destroy_uid_list();
	free(user_file);
	return 0;
}

static int process_logs(void)
{
	struct daemon_conf config;
	char *filename;
	int len, num = 0;

	if (user_file && userfile_is_dir) {
		char dirname[MAXPATHLEN];
		clear_config (&config);

		strcpy(dirname, user_file);
		if (dirname[strlen(dirname)-1] != '/')
			strcat(dirname, "/");
		strcat (dirname, "audit.log");
		free((void *)config.log_file);
		config.log_file=strdup(dirname);
		fprintf(stderr, "NOTE - using logs in %s\n", config.log_file);
	} else {
		/* Load config so we know where logs are */
       		if (load_config(&config, TEST_SEARCH))
			fprintf(stderr, "NOTE - using built-in logs: %s\n",
				config.log_file);
	}

	/* for each file */
	len = strlen(config.log_file) + 16;
	filename = malloc(len);
	if (!filename) {
		fprintf(stderr, "No memory\n");
		free_config(&config);
		return 1;
	}
	/* Find oldest log file */
	snprintf(filename, len, "%s", config.log_file);
	do {
		if (access(filename, R_OK) != 0)
			break;
// FIXME: do a time check and put them on linked list for later
		num++;
		snprintf(filename, len, "%s.%d", config.log_file, num);
	} while (1);
	num--;
	/*
	 * We note how many files we need to process
	 */
	files_to_process = num;

	/* Got it, now process logs from last to first */
	if (num > 0)
		snprintf(filename, len, "%s.%d", config.log_file, num);
	else
		snprintf(filename, len, "%s", config.log_file);
	do {
		int ret;
		if ((ret = process_file(filename))) {
			free(filename);
			free_config(&config);
			return ret;
		}

		/* Get next log file */
		files_to_process--;     /* one less file to process */
		num--;
		if (num > 0)
			snprintf(filename, len, "%s.%d", config.log_file, num);
		else if (num == 0)
			snprintf(filename, len, "%s", config.log_file);
		else
			break;
	} while (1);
	free(filename);
	free_config(&config);
	return 0;
}

static void process_event(llist *entries)
{
	if (scan(entries)) {
		// If its a single event or SYSCALL load interpretations
		if ((entries->cnt == 1) || 
				(entries->head->type == AUDIT_SYSCALL))
			_auparse_load_interpretations(entries->head->interp);
		// This is the per entry action item
		if (per_event_processing(entries))
			found = 1;
		_auparse_free_interpretations();
	}
}

static int process_log_fd(const char *filename)
{
	llist *entries; // entries in a record
	int ret;
	int first = 0;
	event first_event, last_event;

	last_event.sec = 0;
	last_event.milli = 0;

	/* For each event in file */
	do {
		ret = get_event(&entries);
		if ((ret != 0)||(entries->cnt == 0)||(entries->head == NULL))
			break;
		// If report is RPT_TIME or RPT_SUMMARY, get 
		if (report_type <= RPT_SUMMARY) {
			if (first == 0) {
				list_get_event(entries, &first_event);
				first = 1;
			}
			list_get_event(entries, &last_event);
		}
		// Are we within time range?
		if (start_time == 0 || entries->e.sec >= start_time) {
			if (end_time == 0 || entries->e.sec <= end_time) {
				process_event(entries);
			}
		}
		list_clear(entries);
		free(entries);
	} while (ret == 0);
	fclose(log_fd);
	// This is the per file action items
	very_last_event.sec = last_event.sec;
	very_last_event.milli = last_event.milli;
	if (report_type == RPT_TIME) {
		if (first == 0) {
			printf("%s: no records\n", filename);
		} else {
			struct tm *btm;
			char tmp[32];

			printf("%s: ", filename);
			btm = localtime(&first_event.sec);
			if (btm)
				strftime(tmp, sizeof(tmp), "%x %T", btm);
			else
				strcpy(tmp, "?");
			printf("%s.%03u - ", tmp, first_event.milli);
			btm = localtime(&last_event.sec);
			if (btm)
				strftime(tmp, sizeof(tmp), "%x %T", btm);
			else
				strcpy(tmp, "?");
			printf("%s.%03u\n", tmp, last_event.milli);
		}
	}

	return 0;
}

static int process_stdin(void)
{
	log_fd = stdin;

	return process_log_fd("stdin");
}

static int process_file(char *filename)
{
	log_fd = fopen(filename, "rm");
	if (log_fd == NULL) {
		fprintf(stderr, "Error opening %s (%s)\n", filename, 
			strerror(errno));
		return 1;
	}

	__fsetlocking(log_fd, FSETLOCKING_BYCALLER);
	return process_log_fd(filename);
}

/*
 * This function returns a linked list of all records in an event.
 * It returns 0 on success, 1 on eof, -1 on error. 
 */
static int get_event(llist **l)
{
	char *rc;
	char *buff = NULL;

	*l = get_ready_event(&lo);
	if (*l)
		return 0;

	while (1) {
		if (!buff) {
			buff = malloc(MAX_AUDIT_MESSAGE_LENGTH);
			if (!buff)
				return -1;
		}
		rc = fgets_unlocked(buff, MAX_AUDIT_MESSAGE_LENGTH,
					log_fd);
		if (rc) {
			if (lol_add_record(&lo, buff)) {
				*l = get_ready_event(&lo);
				if (*l)
					break;
			}
		} else {
			free(buff);
			if (feof_unlocked(log_fd)) {
				// Only mark all events complete if this is
				// the last file.
				if (files_to_process == 0) {
					terminate_all_events(&lo);
				}
				*l = get_ready_event(&lo);
				if (*l)
					return 0;
				else
					return 1;
			} else 
				return -1;
		}
	}
	free(buff);
	return 0;
}

