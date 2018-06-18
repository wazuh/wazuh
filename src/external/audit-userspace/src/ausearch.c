/*
 * ausearch.c - main file for ausearch utility 
 * Copyright 2005-08,2010,2013,2014 Red Hat Inc., Durham, North Carolina.
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
#include <sys/param.h>
#include <locale.h>
#include <signal.h>
#include "libaudit.h"
#include "auditd-config.h"
#include "ausearch-options.h"
#include "ausearch-lol.h"
#include "ausearch-lookup.h"
#include "auparse.h"
#include "ausearch-checkpt.h"


static FILE *log_fd = NULL;
static lol lo;
static int found = 0;
static int input_is_pipe = 0;
static int timeout_interval = 3;	/* timeout in seconds */
static int files_to_process = 0;	/* number of log files yet to process when reading multiple */
static int process_logs(void);
static int process_log_fd(void);
static int process_stdin(void);
static int process_file(char *filename);
static int get_record(llist **);

extern const char *checkpt_filename;	/* checkpoint file name */
extern int checkpt_timeonly;	/* use timestamp from within checkpoint file */
static int have_chkpt_data = 0;		/* have checkpt need to compare wit */
extern char *user_file;
extern int force_logs;
static int userfile_is_dir = 0;
extern int match(llist *l);
extern void output_record(llist *l);
extern void ausearch_free_interpretations(void);

static int is_pipe(int fd)
{
	struct stat st;
	int pipe_mode=0;

	if (fstat(fd, &st) == 0) {
		if (S_ISFIFO(st.st_mode)) 
			pipe_mode = 1;
	}
	return pipe_mode;
}

int main(int argc, char *argv[])
{
	struct rlimit limit;
	int rc;
	struct stat sb;

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

	/* Load the checkpoint file if requested */
	if (checkpt_filename) {
		rc = load_ChkPt(checkpt_filename);
		/*
 		 * If < -1, then some load/parse error
 		 * If == -1 then no file present (OK)
		 * If == 0, then checkpoint has data
 		 */
		if (rc < -1) {
			(void)free((void *)checkpt_filename);
			free_ChkPtMemory();
			return 10;	/* bad checkpoint status file */
		} else if (rc == -1) {
			/*
 			 * No file, so no checking required. This just means
 			 * we have never checkpointed before and this is the
 			 * first time.
 			 */
			have_chkpt_data = 0;
		} else {
			/* We will need to check */
			have_chkpt_data++;
		}
	}
	
	lol_create(&lo);
	if (user_file) {
		if (stat(user_file, &sb) == -1) {
               		perror("stat");
			return 1;
		}
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
	} else if (force_logs)
		rc = process_logs();
	else if (is_pipe(0))
		rc = process_stdin();
	else
		rc = process_logs();

	/* Generate a checkpoint if required */
	if (checkpt_filename) {
		/* Providing haven't failed and have sucessfully read data records, save a checkpoint */
		if (!checkpt_failure && (rc == 0))
			save_ChkPt(checkpt_filename);
		free_ChkPtMemory();
		free((void *)checkpt_filename);
		/*
 		 * A checkpoint failure at this point means either 
 		 * - we failed in attempting to create the checkpoint file
 		 *   and so we will return 11
 		 * - we had a corrupted checkpoint file and so we will return 12
 		 */
		if (checkpt_failure) {
			rc = ((checkpt_failure & CP_CORRUPTED) ==
						 CP_CORRUPTED) ? 12 : 11;
		}
	}

	lol_clear(&lo);
	ilist_clear(event_type);
	free(event_type);
	free(user_file);
	free((char *)event_key);
	free((char *)event_tuid);
	free((char *)event_teuid);
	free((char *)event_tauid);
	auparse_destroy(NULL);
	if (rc)
		return rc;
	if (!found) {
		if (report_format != RPT_RAW)
			fprintf(stderr, "<no matches>\n");
		return 1;
	}
	return 0;
}

static int process_logs(void)
{
	struct daemon_conf config;
	char *filename;
	int len, num = 0;
	int found_chkpt_file = -1;
	int ret;

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
	}
	else {
		/* Load config so we know where logs are */
        	if (load_config(&config, TEST_SEARCH)) {
        	        fprintf(stderr,
				"NOTE - using built-in logs: %s\n",
				config.log_file);
		}
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
		
		/*
		 * If we have prior checkpoint data, we ignore files till we
		 * find the file we last checkpointed from
		 */
		if (checkpt_filename && have_chkpt_data) {
			struct stat sbuf;

			if (stat(filename, &sbuf)) {
				fprintf(stderr, "Error stat'ing %s (%s)\n",
					filename, strerror(errno));
				free(filename);
				free_config(&config);
				return 1;
			}
			/*
			 * Have we accessed the checkpointed file?
			 * If so, stop checking further files.
			 */
			if (	(sbuf.st_dev == chkpt_input_dev) &&
				(sbuf.st_ino == chkpt_input_ino) ) {
				/*
				 * If we are ignoring all but time, then we
				 * don't stop checking more files and just
				 * let this loop go to completion and hence
				 * we will find the 'oldest' file.
				 */
				if (!checkpt_timeonly) {
					found_chkpt_file = num++;
					break;
				}
			}
		}

		num++;
		snprintf(filename, len, "%s.%d", config.log_file, num);
	} while (1);

	/* If a checkpoint is loaded but can't find it's file, and we
	 * are not only just checking the timestamp from the checkpoint file,
	 * we need to error */
	if (checkpt_filename && have_chkpt_data && found_chkpt_file == -1
					&& !checkpt_timeonly) {
		free(filename);
		free_config(&config);
		return 10;
	}

	num--;

	/* We note how many files we need to process */
	files_to_process = num;

	/* Got it, now process logs from last to first */
	if (num > 0)
		snprintf(filename, len, "%s.%d", config.log_file, num);
	else
		snprintf(filename, len, "%s", config.log_file);
	do {
		if ((ret = process_file(filename))) {
			free(filename);
			free_config(&config);
			return ret;
		}
		if (just_one && found)
			break;
		files_to_process--;	/* one less file to process */

		/* Get next log file */
		num--;
		if (num > 0)
			snprintf(filename, len, "%s.%d", config.log_file, num);
		else if (num == 0)
			snprintf(filename, len, "%s", config.log_file);
		else
			break;
	} while (1);
	/*
 	 * If performing a checkpoint, set the checkpointed
	 * file details - ie remember the last file processed
	 */
	ret = 0;
	if (checkpt_filename)
		ret = set_ChkPtFileDetails(filename);

	free(filename);
	free_config(&config);
	return ret;
}

/*
 * Decide if we should start outputting events given we loaded a checkpoint.
 *
 * The previous checkpoint will have recorded the last event outputted,
 * if there was one. If nothing is to be output, either the audit.log file
 * is empty, all the events in it were incomplete, or ???
 *
 * We can return
 * 	0 	no output
 * 	1	can output
 * 	2	can output but not this event
 * 	3	we have found an event whose time is > MAX_EVENT_DELTA_SECS secs
 * 		past our checkpoint time, which means this particular event is
 * 		complete. This should not happen, for we should have found our
 * 		checkpoint event before ANY other completed event.
 *
 */
static int chkpt_output_decision(event * e)
{
	static int can_output = 0;

	/* Short cut. Once we made the decision, it's made for good */
	if (can_output)
		return 1;

	/* If there was no checkpoint file, we turn on output */
	if (have_chkpt_data == 0) {
		can_output = 1;
		return 1;	/* can output on this event */
	}

	/*
	 * If the previous checkpoint had no recorded output, then
	 * we assume everything was partial so we turn on output
	 */
	if (chkpt_input_levent.sec == 0) {
		can_output = 1;
		return 1;	/* can output on this event */
	}

	/*
	 * If we are ignoring all but event time from within the checkpoint
	 * file, then we output if the current event's time is greater than
	 * or equal to the checkpoint time.
	 */
	if (checkpt_timeonly) {
		if ( (chkpt_input_levent.sec < e->sec) ||
			( (chkpt_input_levent.sec == e->sec) &&
				(chkpt_input_levent.milli <= e->milli) ) ) {
			can_output = 1;
			return 1;   /* can output on this event */
		}
	}

	if (chkpt_input_levent.sec == e->sec &&
		chkpt_input_levent.milli == e->milli &&
		chkpt_input_levent.serial == e->serial &&
		chkpt_input_levent.type == e->type ) {

		/* So far a match, so now check the nodes */
		if (chkpt_input_levent.node == NULL && e->node == NULL) {
			can_output = 1;
			return 2;	/* output after this event */
		}
		if (chkpt_input_levent.node && e->node &&
			(strcmp(chkpt_input_levent.node, e->node) == 0) ) {
			can_output = 1;
			return 2;	/* output after this event */
		}
		/*
 		 * The nodes are different. Drop through to further checks.
 		 */
	}
	/*
	 * If the event we are looking at is more than MAX_EVENT_DELTA_SECS
	 * seconds past our checkpoint event, then by definition we should
	 * have had a complete event (ie a complete event is one where at
	 * least MAX_EVENT_DELTA_SECS seconds have passed since it's last
	 * output record).
	 * This means there is a problem, for the recorded checkpoint event was
	 * the last complete event in the file when we last processed it.
	 * Normally we see this if the checkpoint is very old and the system
	 * has used the same inode again in an audit log file.
	 */
	if ( (chkpt_input_levent.sec < e->sec) &&
		((e->sec - chkpt_input_levent.sec) > MAX_EVENT_DELTA_SECS) ) {
/*		fprintf(stderr, "%s %lu.%03u:%lu vs %s %lu.%03u:%lu\n",
			chkpt_input_levent.host ? chkpt_input_levent.host : "-",
			chkpt_input_levent.sec, chkpt_input_levent.milli,
			chkpt_input_levent.serial,
			e->host, e->sec, e->milli, e->serial); */
		return 3;
	}

	return 0;
}

static int process_log_fd(void)
{
	llist *entries; // entries in a record
	int ret;
	int do_output = 1;

	/* For each record in file */
	do {
		ret = get_record(&entries);
		if ((ret != 0)||(entries->cnt == 0)) {
			break;
		}
		/* 
 		 * We flush all events on the last log file being processed.
 		 * Thus incomplete events are 'carried forward' to be
 		 * completed from the rest of it's records we expect to find
 		 * in the next file we are about to process.
 		 */
		if (match(entries)) {
			/*
			 * If we are checkpointing, decide if we output
			 * this event
			 */
			if (checkpt_filename)
				do_output = chkpt_output_decision(&entries->e);

			if (do_output == 1) {
				found = 1;
				output_record(entries);
			} else if (do_output == 3) {
				fprintf(stderr,
			"Corrupted checkpoint file. Inode match, but newer complete event (%lu.%03u:%lu) found before loaded checkpoint %lu.%03u:%lu\n",
					entries->e.sec, entries->e.milli,
					entries->e.serial,
					chkpt_input_levent.sec,
					chkpt_input_levent.milli,
					chkpt_input_levent.serial);
				checkpt_failure |= CP_CORRUPTED;
				list_clear(entries);
				free(entries);
				fclose(log_fd);
				return 10;
			}
			if (just_one) {
				list_clear(entries);
				free(entries);
				break;
			}
			if (line_buffered)
				fflush(stdout);
		}
		/* Remember this event if checkpointing, irrespective of if we displayed it or not (do_output == 1) */
		if (checkpt_filename) {
			if (set_ChkPtLastEvent(&entries->e)) {
				list_clear(entries);
				free(entries);
				fclose(log_fd);
				return 4;	/* no memory */
			}
		}
		ausearch_free_interpretations();
		list_clear(entries);
		free(entries);
	} while (ret == 0);
	fclose(log_fd);

	return 0;
}

static void alarm_handler(int signal)
{
	/* will interrupt current syscall */
}

static int process_stdin(void)
{
	log_fd = stdin;
	input_is_pipe=1;

	if (signal(SIGALRM, alarm_handler) == SIG_ERR ||
	    siginterrupt(SIGALRM, 1) == -1)
		return -1;

	return process_log_fd();
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
	return process_log_fd();
}

/*
 * This function returns a malloc'd buffer of the next record in the audit
 * logs. It returns 0 on success, 1 on eof, -1 on error. 
 */
static int get_record(llist **l)
{
	char *rc;
	char *buff = NULL;
	int rcount = 0, timer_running = 0;

	/*
	 * If we have any events ready to print ie have all records that
	 * make up the event, we just return. If not, we read more lines
	 * from the files until we get a complete event or finish reading
	 * input
	 */
	*l = get_ready_event(&lo);
	if (*l)
		return 0;

	while (1) {
		rcount++;

		if (!buff) {
			buff = malloc(MAX_AUDIT_MESSAGE_LENGTH);
			if (!buff)
				return -1;
		}

		if (input_is_pipe && rcount > 1) {
			timer_running = 1;
			alarm(timeout_interval);
		}

		rc = fgets_unlocked(buff, MAX_AUDIT_MESSAGE_LENGTH,
					log_fd);

		if (timer_running) {
			/* timer may have fired but that's ok */
			timer_running = 0;
			alarm(0);
		}

		if (rc) {
			if (lol_add_record(&lo, buff)) {
				*l = get_ready_event(&lo);
				if (*l)
					break;
			}
		} else {
			free(buff);
			/*
			 * If we get an EINTR error or we are at EOF, we check
			 * to see if we have any events to print and return
			 * appropriately. If we are the last file being
			 * processed, we mark all incomplete events as
			 * complete so they will be printed.
			 */
			if ((ferror_unlocked(log_fd) &&
			     errno == EINTR) || feof_unlocked(log_fd)) {
				/*
				 * Only mark all events as L_COMPLETE if we are
				 * the last file being processed.
				 * We DO NOT do this if we are checkpointing.
				 */
				if (files_to_process == 0) {
					if (!checkpt_filename)
					terminate_all_events(&lo);
				}
				*l = get_ready_event(&lo);
				if (*l)
					return 0;
				else
					return 1;
			} else 
				return -1; /* all other errors are terminal */
		}
	}
	free(buff);
	return 0;
}

