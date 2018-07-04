/* ausearch-options.c - parse commandline options and configure ausearch
 * Copyright 2005-08,2010-11,2014,2016-17 Red Hat Inc., Durham, North Carolina.
 * Copyright (c) 2011 IBM Corp.
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
 *     Debora Velarde <dvelarde@us.ibm.com>
 *     Steve Grubb <sgrubb@redhat.com>
 *     Marcelo Henrique Cerri <mhcerri@br.ibm.com>
 */

#include "config.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include "ausearch-options.h"
#include "ausearch-time.h"
#include "ausearch-int.h"
#include "libaudit.h"
#include "auparse-defs.h"


/* Global vars that will be accessed by the main program */
char *user_file = NULL;
int force_logs = 0;
const char *checkpt_filename = NULL;	/* checkpoint filename if present */
report_t report_format = RPT_DEFAULT;


/* Global vars that will be accessed by the match model */
unsigned int event_id = -1;
gid_t event_gid = -1, event_egid = -1;
ilist *event_type = NULL;
pid_t event_pid = -1, event_ppid = -1;
success_t event_success = S_UNSET;
auparse_esc_t escape_mode = AUPARSE_ESC_TTY;
int event_exact_match = 0;
uid_t event_uid = -1, event_euid = -1, event_loginuid = -2;
const char *event_tuid = NULL, *event_teuid = NULL, *event_tauid = NULL;
int event_syscall = -1, event_machine = -1;
int event_ua = 0, event_ga = 0, event_se = 0;
int just_one = 0;
uint32_t event_session_id = -2;
long long event_exit = 0;
int event_exit_is_set = 0;
int line_buffered = 0;
int event_debug = 0;
int checkpt_timeonly = 0;
int extra_keys = 0, extra_labels = 0, extra_obj2 = 0, extra_time = 0;
const char *event_key = NULL;
const char *event_filename = NULL;
const char *event_exe = NULL;
const char *event_comm = NULL;
const char *event_hostname = NULL;
const char *event_terminal = NULL;
const char *event_subject = NULL;
const char *event_object = NULL;
const char *event_uuid = NULL;
const char *event_vmname = NULL;
ilist *event_type;

slist *event_node_list = NULL;

struct nv_pair {
    int        value;
    const char *name;
};


enum { S_EVENT, S_COMM, S_FILENAME, S_ALL_GID, S_EFF_GID, S_GID, S_HELP,
S_HOSTNAME, S_INTERP, S_INFILE, S_MESSAGE_TYPE, S_PID, S_SYSCALL, S_OSUCCESS,
S_TIME_END, S_TIME_START, S_TERMINAL, S_ALL_UID, S_EFF_UID, S_UID, S_LOGINID,
S_VERSION, S_EXACT_MATCH, S_EXECUTABLE, S_CONTEXT, S_SUBJECT, S_OBJECT,
S_PPID, S_KEY, S_RAW, S_NODE, S_IN_LOGS, S_JUST_ONE, S_SESSION, S_EXIT,
S_LINEBUFFERED, S_UUID, S_VMNAME, S_DEBUG, S_CHECKPOINT, S_ARCH, S_FORMAT,
S_EXTRA_TIME, S_EXTRA_LABELS, S_EXTRA_KEYS, S_EXTRA_OBJ2, S_ESCAPE };

static struct nv_pair optiontab[] = {
	{ S_EVENT, "-a" },
	{ S_ARCH, "--arch" },
	{ S_EVENT, "--event" },
	{ S_COMM, "-c" },
	{ S_COMM, "--comm" },
	{ S_CHECKPOINT, "--checkpoint" },
	{ S_DEBUG, "--debug" },
	{ S_EXIT, "-e" },
	{ S_ESCAPE, "--escape" },
	{ S_EXIT, "--exit" },
	{ S_EXTRA_KEYS, "--extra-keys" },
	{ S_EXTRA_LABELS, "--extra-labels" },
	{ S_EXTRA_OBJ2, "--extra-obj2" },
	{ S_EXTRA_TIME, "--extra-time" },
	{ S_FILENAME, "-f" },
	{ S_FILENAME, "--file" },
	{ S_FORMAT, "--format" },
	{ S_ALL_GID, "-ga" },
	{ S_ALL_GID, "--gid-all" },
	{ S_EFF_GID, "-ge" },
	{ S_EFF_GID, "--gid-effective" },
	{ S_GID, "-gi" },
	{ S_GID, "--gid" },
	{ S_HELP, "-h" },
	{ S_HELP, "--help" },
	{ S_HOSTNAME, "-hn" },
	{ S_HOSTNAME, "--host" },
	{ S_INTERP, "-i" },
	{ S_INTERP, "--interpret" },
	{ S_INFILE, "-if" },
	{ S_INFILE, "--input" },
	{ S_IN_LOGS, "--input-logs" },
	{ S_JUST_ONE, "--just-one" },
	{ S_KEY, "-k" },
	{ S_KEY, "--key" },
	{ S_LINEBUFFERED, "-l" },
	{ S_LINEBUFFERED, "--line-buffered" },
	{ S_MESSAGE_TYPE, "-m" },
	{ S_MESSAGE_TYPE, "--message" },
	{ S_NODE, "-n" },
	{ S_NODE, "--node" },
	{ S_OBJECT, "-o" },
	{ S_OBJECT, "--object" },
	{ S_PID, "-p" },
	{ S_PID, "--pid" },
	{ S_PPID, "-pp" },
	{ S_PPID, "--ppid" },
	{ S_RAW, "-r" },
	{ S_RAW, "--raw" },
	{ S_SYSCALL, "-sc" },
	{ S_SYSCALL, "--syscall" },
	{ S_CONTEXT, "-se" },
	{ S_CONTEXT, "--context" },
	{ S_SESSION, "--session" },
	{ S_SUBJECT, "-su" },
	{ S_SUBJECT, "--subject" },
	{ S_OSUCCESS, "-sv" },
	{ S_OSUCCESS, "--success" },
	{ S_TIME_END, "-te"},
	{ S_TIME_END, "--end"},
	{ S_TIME_START, "-ts" },
	{ S_TIME_START, "--start" },
	{ S_TERMINAL, "-tm" },
	{ S_TERMINAL, "--terminal" },
	{ S_ALL_UID, "-ua" },
	{ S_ALL_UID, "--uid-all" },
	{ S_EFF_UID, "-ue" },
	{ S_EFF_UID, "--uid-effective" },
	{ S_UID, "-ui" },
	{ S_UID, "--uid" },
	{ S_UUID, "-uu" },
	{ S_UUID, "--uuid" },
	{ S_LOGINID, "-ul" },
	{ S_LOGINID, "--loginuid" },
	{ S_VERSION, "-v" },
	{ S_VERSION, "--version" },
	{ S_VMNAME, "-vm" },
	{ S_VMNAME, "--vm-name" },
	{ S_EXACT_MATCH, "-w" },
	{ S_EXACT_MATCH, "--word" },
	{ S_EXECUTABLE, "-x" },
	{ S_EXECUTABLE, "--executable" }
};
#define OPTION_NAMES (sizeof(optiontab)/sizeof(optiontab[0]))


static int audit_lookup_option(const char *name)
{
        unsigned int i;

        for (i = 0; i < OPTION_NAMES; i++)
                if (!strcmp(optiontab[i].name, name))
			return optiontab[i].value;
        return -1;
}

static void usage(void)
{
	printf("usage: ausearch [options]\n"
	"\t-a,--event <Audit event id>\tsearch based on audit event id\n"
	"\t--arch <CPU>\t\t\tsearch based on the CPU architecture\n"
	"\t-c,--comm  <Comm name>\t\tsearch based on command line name\n"
	"\t--checkpoint <checkpoint file>\tsearch from last complete event\n"
	"\t--debug\t\t\tWrite malformed events that are skipped to stderr\n"
	"\t-e,--exit  <Exit code or errno>\tsearch based on syscall exit code\n"
	"\t-f,--file  <File name>\t\tsearch based on file name\n"
	"\t--format [raw|default|interpret|csv|text] results format options\n"
	"\t-ga,--gid-all <all Group id>\tsearch based on All group ids\n"
	"\t-ge,--gid-effective <effective Group id>  search based on Effective\n\t\t\t\t\tgroup id\n"
	"\t-gi,--gid <Group Id>\t\tsearch based on group id\n"
	"\t-h,--help\t\t\thelp\n"
	"\t-hn,--host <Host Name>\t\tsearch based on remote host name\n"
	"\t-i,--interpret\t\t\tInterpret results to be human readable\n"
	"\t-if,--input <Input File name>\tuse this file instead of current logs\n"
	"\t--input-logs\t\t\tUse the logs even if stdin is a pipe\n"
	"\t--just-one\t\t\tEmit just one event\n"
	"\t-k,--key  <key string>\t\tsearch based on key field\n"
	"\t-l, --line-buffered\t\tFlush output on every line\n"
	"\t-m,--message  <Message type>\tsearch based on message type\n"
	"\t-n,--node  <Node name>\t\tsearch based on machine's name\n"
	"\t-o,--object  <SE Linux Object context> search based on context of object\n"
	"\t-p,--pid  <Process id>\t\tsearch based on process id\n"
	"\t-pp,--ppid <Parent Process id>\tsearch based on parent process id\n"
	"\t-r,--raw\t\t\toutput is completely unformatted\n"
	"\t-sc,--syscall <SysCall name>\tsearch based on syscall name or number\n"
	"\t-se,--context <SE Linux context> search based on either subject or\n\t\t\t\t\t object\n"
	"\t--session <login session id>\tsearch based on login session id\n"
	"\t-su,--subject <SE Linux context> search based on context of the Subject\n"
	"\t-sv,--success <Success Value>\tsearch based on syscall or event\n\t\t\t\t\tsuccess value\n"
	"\t-te,--end [end date] [end time]\tending date & time for search\n"
	"\t-ts,--start [start date] [start time]\tstarting data & time for search\n"
	"\t-tm,--terminal <TerMinal>\tsearch based on terminal\n"
	"\t-ua,--uid-all <all User id>\tsearch based on All user id's\n"
	"\t-ue,--uid-effective <effective User id>  search based on Effective\n\t\t\t\t\tuser id\n"
	"\t-ui,--uid <User Id>\t\tsearch based on user id\n"
	"\t-ul,--loginuid <login id>\tsearch based on the User's Login id\n"
	"\t-uu,--uuid <guest UUID>\t\tsearch for events related to the virtual\n"
	"\t\t\t\t\tmachine with the given UUID.\n"
	"\t-v,--version\t\t\tversion\n"
	"\t-vm,--vm-name <guest name>\tsearch for events related to the virtual\n"
	"\t\t\t\t\tmachine with the name.\n"
	"\t-w,--word\t\t\tstring matches are whole word\n"
	"\t-x,--executable <executable name>  search based on executable name\n"
	);
}

static int convert_str_to_msg(const char *optarg)
{
	int tmp, retval = 0;

	if (isdigit(optarg[0])) {
		errno = 0;
		tmp = strtoul(optarg, NULL, 10);
		if (errno) {
	       		fprintf(stderr, 
			"Numeric message type conversion error (%s) for %s\n",
				strerror(errno), optarg);
			retval = -1;
		}
	} else {
		tmp = audit_name_to_msg_type(optarg);
		if (tmp < 0) 
		        retval = -1;
	}
	if (retval == 0) {
		if (event_type == NULL) {
			event_type = malloc(sizeof(ilist));
			if (event_type == NULL)
				return -1;
			ilist_create(event_type);
		}
		ilist_append(event_type, tmp, 1, 0);
	}
	return retval;
}

static int parse_msg(const char *optarg)
{
	int retval = 0;
	char *saved;

	if (strchr(optarg, ',')) {
		char *ptr, *tmp = strdup(optarg);
		if (tmp == NULL)
			return -1;
		ptr = strtok_r(tmp, ",", &saved);
		while (ptr) {
			retval = convert_str_to_msg(ptr);
			if (retval != 0)
				break;
			ptr = strtok_r(NULL, ",", &saved);
		}
		free(tmp);
		return retval;
	}

	return convert_str_to_msg(optarg);
}

/*
 * This function examines the commandline parameters and sets various
 * search options. It returns a 0 on success and < 0 on failure
 */
int check_params(int count, char *vars[])
{
	int c = 1;
	int retval = 0;
	const char *optarg;

	if (count < 2) {
		usage();
		return -1;
	}
	while (c < count && retval == 0) {
		// Go ahead and point to the next argument
		if (c+1 < count) {
			if (vars[c+1][0] != '-')
				optarg = vars[c+1];
			else
				optarg = NULL;
		} else
			optarg = NULL;

		switch (audit_lookup_option(vars[c])) {
		case S_EVENT:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
			if (isdigit(optarg[0])) {
				errno = 0;
				event_id = strtoul(optarg, NULL, 10);
				if (errno) {
					fprintf(stderr,
					"Illegal value for audit event ID");
					retval = -1;
				}
				c++;
			} else {
				fprintf(stderr, 
			"Audit event id must be a numeric value, was %s\n",
					optarg);
				retval = -1;
			}
			break;
		case S_EXTRA_KEYS:
			extra_keys = 1;
			if (optarg) {
				fprintf(stderr, 
					"Argument is NOT required for %s\n",
					vars[c]);
        	                retval = -1;
			}
			break;
		case S_EXTRA_LABELS:
			extra_labels = 1;
			if (optarg) {
				fprintf(stderr, 
					"Argument is NOT required for %s\n",
					vars[c]);
        	                retval = -1;
			}
			break;
		case S_EXTRA_OBJ2:
			extra_obj2 = 1;
			if (optarg) {
				fprintf(stderr, 
					"Argument is NOT required for %s\n",
					vars[c]);
        	                retval = -1;
			}
			break;
		case S_EXTRA_TIME:
			extra_time = 1;
			if (optarg) {
				fprintf(stderr, 
					"Argument is NOT required for %s\n",
					vars[c]);
        	                retval = -1;
			}
			break;
		case S_COMM:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			} else {
				event_comm = strdup(optarg);
        	                if (event_comm == NULL)
                	                retval = -1;
				c++;
			}
			break;
		case S_FILENAME:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			} else {
				if (strlen(optarg) >= PATH_MAX) {
					fprintf(stderr,
						"File name is too long %s\n",
						optarg);
					retval = -1;
					break;
				}
				event_filename = strdup(optarg);
       		                if (event_filename == NULL)
               		                retval = -1;
				c++;
			}
			break;
		case S_KEY:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				event_key = strdup(optarg);
        	                if (event_key == NULL)
                	                retval = -1;
				c++;
			}
			break;
		case S_ALL_GID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if (isdigit(optarg[0])) {
				errno = 0;
                        	event_gid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric group ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
                	} else {
				struct group *gr ;

				gr = getgrnam(optarg) ;
				if (gr == NULL) {
                        		fprintf(stderr, 
				"Group ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_gid = gr->gr_gid;
                	}
			event_egid = event_gid;
			event_ga = 1;
			c++;
			break;
		case S_EFF_GID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if (isdigit(optarg[0])) {
				errno = 0;
                        	event_egid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric group ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
                	} else {
				struct group *gr ;

				gr = getgrnam(optarg) ;
				if (gr == NULL) {
                        		fprintf(stderr, 
			"Effective group ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_egid = gr->gr_gid;
                	}
			c++;
			break;
		case S_GID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if (isdigit(optarg[0])) {
				errno = 0;
                        	event_gid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric group ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
                	} else {
				struct group *gr ;

				gr = getgrnam(optarg) ;
				if (gr == NULL) {
                        		fprintf(stderr, 
				"Group ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_gid = gr->gr_gid;
                	}
			c++;
			break;
		case S_HELP:
			usage();
			exit(0);
			break;
		case S_HOSTNAME:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				event_hostname = strdup(optarg);
				if (event_hostname == NULL)
					retval = -1;
				c++;
			}
			break;
		case S_INTERP:
			if (report_format == RPT_DEFAULT)
				report_format = RPT_INTERP;
			else {
				fprintf(stderr, 
					"Conflicting output format %s\n",
					vars[c]);
        	                retval = -1;
			}
			if (optarg) {
				fprintf(stderr, 
					"Argument is NOT required for %s\n",
					vars[c]);
        	                retval = -1;
			}
			break;
		case S_INFILE:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				user_file = strdup(optarg);
				if (user_file == NULL)
					retval = -1;
				c++;
			}
			break;
		case S_MESSAGE_TYPE:
	                if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
        	                retval = -1;
	                } else {
				if (strcasecmp(optarg, "ALL") != 0) {
					retval = parse_msg(optarg);
				}
				c++;
			}
			if (retval < 0) {
				int i;
                        	fprintf(stderr, 
					"Valid message types are: ALL ");
				for (i=AUDIT_USER;i<=AUDIT_LAST_VIRT_MSG;i++){
					const char *name;
					if (i == AUDIT_WATCH_INS) // Skip a few
						i = AUDIT_FIRST_USER_MSG;
					name = audit_msg_type_to_name(i);
					if (name)
		                        	fprintf(stderr, "%s ", name);
				}
                        	fprintf(stderr, "\n");
			}
			break;
		case S_OBJECT:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			} else {
				event_object = strdup(optarg);
        	                if (event_object == NULL)
                	                retval = -1;
				c++;
			}
			break;
		case S_PPID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
			if (isdigit(optarg[0])) {
				errno = 0;
				event_ppid = strtol(optarg,NULL,10);
				if (errno)
					retval = -1;
				c++;
			} else {
				fprintf(stderr, 
			"Parent process id must be a numeric value, was %s\n",
					optarg);
				retval = -1;
			}
			break;
		case S_PID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
			if (isdigit(optarg[0])) {
				errno = 0;
				event_pid = strtol(optarg,NULL,10);
				if (errno)
					retval = -1;
				c++;
			} else {
				fprintf(stderr, 
				"Process id must be a numeric value, was %s\n",
					optarg);
				retval = -1;
			}
			break;
		case S_RAW:
			if (report_format == RPT_DEFAULT)
				report_format = RPT_RAW;
			else {
				fprintf(stderr, 
					"Conflicting output format --raw\n");
        	                retval = -1;
			}
			if (optarg) {
				fprintf(stderr, 
					"Argument is NOT required for --raw\n");
        	                retval = -1;
			}
			break;
		case S_ESCAPE:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				if (strcmp(optarg, "raw") == 0)
					escape_mode = AUPARSE_ESC_RAW;
				else if (strcmp(optarg, "tty") == 0)
					escape_mode = AUPARSE_ESC_TTY;
				else if (strncmp(optarg, "shell", 6) == 0)
					escape_mode = AUPARSE_ESC_SHELL;
				else if (strcmp(optarg, "shell_quote") == 0)
					escape_mode = AUPARSE_ESC_SHELL_QUOTE;
				else {
					fprintf(stderr, 
						"Unknown option (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				c++;
			}
			break;
		case S_FORMAT:
			if (report_format != RPT_DEFAULT) {
				fprintf(stderr, 
					"Multiple output formats, use only 1\n");
        	                retval = -1;
				break;
			}
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				if (strcmp(optarg, "raw") == 0)
					report_format = RPT_RAW;
				else if (strcmp(optarg, "default") == 0)
					report_format = RPT_DEFAULT;
				else if (strncmp(optarg, "interp", 6) == 0)
					report_format = RPT_INTERP;
				else if (strcmp(optarg, "csv") == 0)
					report_format = RPT_CSV;
				else if (strcmp(optarg, "text") == 0)
					report_format = RPT_TEXT;
				else {
					fprintf(stderr, 
						"Unknown option (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				c++;
			}
			break;
		case S_NODE:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				snode sn;
				c++;

				if (!event_node_list) {
					event_node_list = malloc(sizeof (slist));
					if (!event_node_list) {
						retval = -1;
						break;
					}
					slist_create(event_node_list);
				}
				
				sn.str = strdup(optarg);
				sn.key = NULL;
				sn.hits=0;
				slist_append(event_node_list, &sn);
			}
			break;
		case S_SYSCALL:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
			if (isdigit(optarg[0])) {
				errno = 0;
				event_syscall = (int)strtoul(optarg, NULL, 10);
				if (errno) {
                        		fprintf(stderr, 
			"Syscall numeric conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
			} else {
				if (event_machine == -1) {
	                                int machine;
        	                        machine = audit_detect_machine();
                	                if (machine < 0) {
                        	                fprintf(stderr,
                                            "Error detecting machine type");
                                	        retval = -1;
						break;
	                                }
					event_machine = machine;
				}
				event_syscall = audit_name_to_syscall(optarg, 
					event_machine);
				if (event_syscall == -1) {
					fprintf(stderr, 
						"Syscall %s not found\n",
						optarg);
                                        retval = -1;
				}
                        }
			c++;
			break;
		case S_CONTEXT:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			} else {
				event_subject = strdup(optarg);
        	                if (event_subject == NULL)
                	                retval = -1;
				event_object = strdup(optarg);
        	                if (event_object == NULL)
                	                retval = -1;
				event_se = 1;
				c++;
			}
			break;
		case S_SUBJECT:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			} else {
				event_subject = strdup(optarg);
        	                if (event_subject == NULL)
                	                retval = -1;
				c++;
			}
			break;
		case S_OSUCCESS:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if ( (strstr(optarg, "yes")!=NULL) || 
					(strstr(optarg, "no")!=NULL) ) {
                        	if (strcmp(optarg, "yes") == 0)
					event_success = S_SUCCESS;
				else
					event_success = S_FAILED;
                	} else {
                        	fprintf(stderr, 
					"Success must be 'yes' or 'no'.\n");
                        	retval = -1;
                	}
			c++;
			break;
		case S_SESSION:
			if (!optarg) {
				if ((c+1 < count) && vars[c+1])
					optarg = vars[c+1];
				else {
					fprintf(stderr,
						"Argument is required for %s\n",
						vars[c]);
					retval = -1;
					break;
				}
			}
			{ 
			size_t len = strlen(optarg);
			if (isdigit(optarg[0])) {
				errno = 0;
				event_session_id = strtoul(optarg,NULL,10);
				if (errno)
					retval = -1;
				c++;
                        } else if (len >= 2 && *(optarg)=='-' &&
                                                (isdigit(optarg[1]))) {
				errno = 0;
                                event_session_id = strtoul(optarg, NULL, 0);
				if (errno) {
					retval = -1;
					fprintf(stderr, "Error converting %s\n",
						optarg);
				}
				c++;
			} else {
				fprintf(stderr, 
				"Session id must be a numeric value, was %s\n",
					optarg);
				retval = -1;
			}
			}
			break;
		case S_EXIT:
			if (!optarg) {
				if ((c+1 < count) && vars[c+1])
					optarg = vars[c+1];
				else {
					fprintf(stderr,
						"Argument is required for %s\n",
						vars[c]);
					retval = -1;
					break;
				}
			} 
			{
			size_t len = strlen(optarg);
                        if (isdigit(optarg[0])) {
				errno = 0;
                                event_exit = strtoll(optarg, NULL, 0);
				if (errno) {
					retval = -1;
					fprintf(stderr, "Error converting %s\n",
						optarg);
				}
                        } else if (len >= 2 && *(optarg)=='-' &&
                                                (isdigit(optarg[1]))) {
				errno = 0;
                                event_exit = strtoll(optarg, NULL, 0);
				if (errno) {
					retval = -1;
					fprintf(stderr, "Error converting %s\n",
						optarg);
				}
                        } else {
                                event_exit = audit_name_to_errno(optarg);
                                if (event_exit == 0) {
					retval = -1;
					fprintf(stderr, 
						"Unknown errno, was %s\n",
						optarg);
				}
                        }
			c++;
			if (retval != -1)
				event_exit_is_set = 1;
			}
			break;
		case S_TIME_END:
			if (optarg) {
				if ( (c+2 < count) && vars[c+2] && 
					(vars[c+2][0] != '-') ) {
				/* Have both date and time - check order*/
					if (strchr(optarg, ':')) {
						if (ausearch_time_end(vars[c+2],
								 optarg) != 0) 
							retval = -1;
					} else {
						if (ausearch_time_end(optarg, 
								vars[c+2]) != 0)
							retval = -1;
					}
					c++;			
				} else {
					// Check against recognized words
					int t = lookup_time(optarg);
					if (t >= 0) {
						if (ausearch_time_end(optarg,
								NULL) != 0)
							retval = -1;
					} else if ( (strchr(optarg, ':')) == NULL) {
						/* Only have date */
						if (ausearch_time_end(optarg,
								NULL) != 0)
							retval = -1;
					} else {
						/* Only have time */
						if (ausearch_time_end(NULL,
								optarg) != 0)
							retval = -1;
					}
				}
				c++;			
				break;
			} 
			fprintf(stderr, 
				"%s requires either date and/or time\n",
				vars[c]);
			retval = -1;
			break;
		case S_TIME_START:
			if (optarg) {
				if ( (c+2 < count) && vars[c+2] && 
					(vars[c+2][0] != '-') ) {
				/* Have both date and time - check order */
					if (strchr(optarg, ':')) {
						if (ausearch_time_start(
							vars[c+2], optarg) != 0)
							retval = -1;
					} else {
						if (ausearch_time_start(optarg, 
								vars[c+2]) != 0)
							retval = -1;
					}
					c++;
				} else {
					// Check against recognized words
					int t = lookup_time(optarg);
					if (t >= 0) {
						if (ausearch_time_start(optarg,
							"00:00:00") != 0)
							retval = -1;
					} else if (strcmp(optarg,
							"checkpoint") == 0) {
					// Only use the timestamp from within
					// the checkpoint file
						checkpt_timeonly++;
					} else if (strchr(optarg, ':') == NULL){
						/* Only have date */
						if (ausearch_time_start(optarg,
							"00:00:00") != 0)
							retval = -1;
					} else {
						/* Only have time */
						if (ausearch_time_start(NULL,
								optarg) != 0)
							retval = -1;
					}
				}
				c++;
				break;
			}
			fprintf(stderr, 
				"%s requires either date and/or time\n",
				vars[c]);
			retval = -1;
			break;
		case S_TERMINAL:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
                	} else { 
				event_terminal = strdup(optarg);
				if (event_terminal == NULL)
        	                        retval = -1;
				c++;
			}
			break;
		case S_UID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if (isdigit(optarg[0])) {
				errno = 0;
                        	event_uid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric user ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
                	} else {
				struct passwd *pw;

				pw = getpwnam(optarg);
				if (pw == NULL) {
                        		fprintf(stderr, 
			"Effective user ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_uid = pw->pw_uid;
				event_tuid = strdup(optarg);
                	}
			c++;
			break;
		case S_EFF_UID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if (isdigit(optarg[0])) {
				errno = 0;
                        	event_euid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric user ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
                	} else {
				struct passwd *pw ;

				pw = getpwnam(optarg) ;
				if (pw == NULL) {
                        		fprintf(stderr, 
				"User ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_euid = pw->pw_uid;
				event_teuid = strdup(optarg);
                	}
			c++;
			break;
		case S_ALL_UID:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
                	if (isdigit(optarg[0])) {
				errno = 0;
                        	event_uid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric user ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                	retval = -1;
				}
                	} else {
				struct passwd *pw ;

				pw = getpwnam(optarg) ;
				if (pw == NULL) {
                        		fprintf(stderr, 
				"User ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_uid = pw->pw_uid;
				event_tuid = strdup(optarg);
				event_teuid = strdup(optarg);
				event_tauid = strdup(optarg);
                	}
			event_ua = 1;
			event_euid = event_uid;
			event_loginuid = event_uid;
			c++;
			break;
		case S_LOGINID:
			if (!optarg) {
				if ((c+1 < count) && vars[c+1])
					optarg = vars[c+1];
				else {
					fprintf(stderr,
						"Argument is required for %s\n",
						vars[c]);
					retval = -1;
					break;
				}
			}
			{
			size_t len = strlen(optarg);
                        if (isdigit(optarg[0])) {
				errno = 0;
                        	event_loginuid = strtoul(optarg,NULL,10);
				if (errno) {
                        		fprintf(stderr, 
			"Numeric user ID conversion error (%s) for %s\n",
						strerror(errno), optarg);
                                        retval = -1;
				}
                        } else if (len >= 2 && *(optarg)=='-' &&
                                                (isdigit(optarg[1]))) {
				errno = 0;
                                event_loginuid = strtol(optarg, NULL, 0);
				if (errno) {
					retval = -1;
					fprintf(stderr, "Error converting %s\n",
						optarg);
				}
                        } else {
				struct passwd *pw ;

				pw = getpwnam(optarg) ;
				if (pw == NULL) {
                        		fprintf(stderr, 
			"Login user ID is non-numeric and unknown (%s)\n",
						optarg);
					retval = -1;
					break;
				}
				event_loginuid = pw->pw_uid;
				event_tauid = strdup(optarg);
                        }
			}
			c++;
			break;
		case S_UUID:
			if (!optarg) {
				fprintf(stderr,
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				event_uuid = strdup(optarg);
				if (event_uuid == NULL) {
					retval = -1;
				}
				c++;
			}
			break;
		case S_VMNAME:
			if (!optarg) {
				fprintf(stderr,
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				event_vmname= strdup(optarg);
				if (event_vmname == NULL) {
					retval = -1;
				}
				c++;
			}
			break;
		case S_VERSION:
	                printf("ausearch version %s\n", VERSION);
			exit(0);
			break;
		case S_EXACT_MATCH:
			event_exact_match=1;
			break;
		case S_IN_LOGS:
			force_logs = 1;
			break;
		case S_JUST_ONE:
			just_one = 1;
			break;
		case S_EXECUTABLE:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
	               	} else { 
				event_exe = strdup(optarg);
				if (event_exe == NULL)
       	                	        retval = -1;
				c++;
			}
			break;
		case S_LINEBUFFERED:
			line_buffered = 1;
			break;
		case S_DEBUG:
			event_debug = 1;
			break;
		case S_CHECKPOINT:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				checkpt_filename = strdup(optarg);
        	                if (checkpt_filename == NULL)
                	                retval = -1;
				c++;
			}
			break;
		case S_ARCH:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
				break;
			}
			if (event_machine != -1) {
				if (event_syscall != -1)
					fprintf(stderr, 
			"Arch needs to be defined before the syscall\n");
				else
					fprintf(stderr, 
						"Arch is already defined\n");
				retval = -1;
				break;
			} else {
				int machine = audit_determine_machine(optarg);
				if (machine < 0) {
					fprintf(stderr, "Unknown arch %s\n",
						optarg);
					retval = -1;
				}
				event_machine = machine;
			}
			c++;
			break;
		default:
			fprintf(stderr, "%s is an unsupported option\n", 
				vars[c]);
			retval = -1;
			break;
		}
		c++;
	}

	// Final config checks
	if ((extra_time || extra_labels || extra_keys) && report_format != RPT_CSV) {
		fprintf(stderr, "--extra options requires format to be csv\n");
		retval = -1;
	}

	return retval;
}

