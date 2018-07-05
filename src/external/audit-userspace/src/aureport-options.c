/* aureport-options.c - parse commandline options and configure aureport
 * Copyright 2005-08,2010-11,2014 Red Hat Inc., Durham, North Carolina.
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
#include <time.h>
#include <limits.h>
#include "aureport-options.h"
#include "ausearch-time.h"
#include "libaudit.h"
#include "auparse-defs.h"


/* Global vars that will be accessed by the main program */
char *user_file = NULL;
int force_logs = 0;
int no_config = 0;

/* These are for compatibility with parser */
unsigned int event_id = -1;
uid_t event_uid = -1, event_loginuid = -2, event_euid = -1;
const char *event_tuid = NULL, *event_teuid = NULL, *event_tauid = NULL;
gid_t event_gid = -1, event_egid = -1;
slist *event_node_list = NULL;
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
long long event_exit = 0;
int event_exit_is_set = 0;
int event_ppid = -1, event_session_id = -2;
int event_debug = 0, event_machine = -1;

/* These are used by aureport */
const char *dummy = "dummy";
report_type_t report_type = RPT_UNSET;
report_det_t report_detail = D_UNSET;
report_t report_format = RPT_DEFAULT;
failed_t event_failed = F_BOTH;
conf_act_t event_conf_act = C_NEITHER;
success_t event_success = S_SUCCESS;
int event_pid = 0;
auparse_esc_t escape_mode = AUPARSE_ESC_TTY;

struct nv_pair {
    int        value;
    const char *name;
};

enum {  R_INFILE, R_TIME_END, R_TIME_START, R_VERSION, R_SUMMARY, R_LOG_TIMES,
	R_CONFIGS, R_LOGINS, R_USERS, R_TERMINALS, R_HOSTS, R_EXES, R_FILES,
	R_AVCS, R_SYSCALLS, R_PIDS, R_EVENTS, R_ACCT_MODS,  
	R_INTERPRET, R_HELP, R_ANOMALY, R_RESPONSE, R_SUMMARY_DET, R_CRYPTO,
	R_MAC, R_FAILED, R_SUCCESS, R_ADD, R_DEL, R_AUTH, R_NODE, R_IN_LOGS,
	R_KEYS, R_TTY, R_NO_CONFIG, R_COMM, R_VIRT, R_INTEG, R_ESCAPE };

static struct nv_pair optiontab[] = {
	{ R_AUTH, "-au" },
	{ R_AUTH, "--auth" },
	{ R_AVCS, "-a" },
	{ R_AVCS, "--avc" },
	{ R_ADD, "--add" },
	{ R_CONFIGS, "-c" },
	{ R_COMM, "--comm" },
	{ R_CONFIGS, "--config" },
	{ R_CRYPTO, "-cr" },
	{ R_CRYPTO, "--crypto" },
	{ R_DEL, "--delete" },
	{ R_EVENTS, "-e" },
	{ R_EVENTS, "--event" },
	{ R_ESCAPE, "--escape" },
	{ R_FILES, "-f" },
	{ R_FILES, "--file" },
	{ R_FAILED, "--failed" },
	{ R_HOSTS, "-h" },
	{ R_HOSTS, "--host" },
	{ R_HELP, "--help" },
	{ R_INTERPRET, "-i" },
	{ R_INTERPRET, "--interpret" },
	{ R_INFILE, "-if" },
	{ R_INFILE, "--input" },
	{ R_IN_LOGS, "--input-logs" },
	{ R_INTEG, "--integrity" },
	{ R_KEYS, "-k" },
	{ R_KEYS, "--key" },
	{ R_LOGINS, "-l" },
	{ R_LOGINS, "--login" },
	{ R_ACCT_MODS, "-m" },
	{ R_ACCT_MODS, "--mods" },
	{ R_MAC, "-ma" },
	{ R_MAC, "--mac" },
	{ R_NODE, "--node" },
	{ R_NO_CONFIG, "-nc" },
	{ R_NO_CONFIG, "--no-config" },
	{ R_ANOMALY, "-n" },
	{ R_ANOMALY, "--anomaly" },
	{ R_PIDS, "-p" },
	{ R_PIDS, "--pid" },
	{ R_RESPONSE, "-r" },
	{ R_RESPONSE, "--response" },
	{ R_SYSCALLS, "-s" },
	{ R_SYSCALLS, "--syscall" },
	{ R_SUCCESS, "--success" },
	{ R_SUMMARY_DET, "--summary" },
	{ R_LOG_TIMES, "-t" },
	{ R_LOG_TIMES, "--log" },
	{ R_TIME_END, "-te"},
	{ R_TIME_END, "--end"},
	{ R_TERMINALS, "-tm"}, // don't like this
	{ R_TERMINALS, "--terminal"}, // don't like this
	{ R_TIME_START, "-ts" },
	{ R_TTY, "--tty" },
	{ R_TIME_START, "--start" },
	{ R_USERS, "-u" },
	{ R_USERS, "--user" },
	{ R_VERSION, "-v" },
	{ R_VERSION, "--version" },
	{ R_EXES, "-x" },
	{ R_EXES, "--executable" },
	{ R_VIRT, "--virt" }
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
	printf("usage: aureport [options]\n"
	"\t-a,--avc\t\t\tAvc report\n"
	"\t-au,--auth\t\t\tAuthentication report\n"
	"\t--comm\t\t\t\tCommands run report\n"
	"\t-c,--config\t\t\tConfig change report\n"
	"\t-cr,--crypto\t\t\tCrypto report\n"
	"\t-e,--event\t\t\tEvent report\n"
	"\t-f,--file\t\t\tFile name report\n"
	"\t--failed\t\t\tonly failed events in report\n"
	"\t-h,--host\t\t\tRemote Host name report\n"
	"\t--help\t\t\t\thelp\n"
	"\t-i,--interpret\t\t\tInterpretive mode\n"
	"\t-if,--input <Input File name>\tuse this file as input\n"
	"\t--input-logs\t\t\tUse the logs even if stdin is a pipe\n"
	"\t--integrity\t\t\tIntegrity event report\n"
	"\t-l,--login\t\t\tLogin report\n"
	"\t-k,--key\t\t\tKey report\n"
	"\t-m,--mods\t\t\tModification to accounts report\n"
	"\t-ma,--mac\t\t\tMandatory Access Control (MAC) report\n"
	"\t-n,--anomaly\t\t\taNomaly report\n"
	"\t-nc,--no-config\t\t\tDon't include config events\n"
	"\t--node <node name>\t\tOnly events from a specific node\n"
	"\t-p,--pid\t\t\tPid report\n"
	"\t-r,--response\t\t\tResponse to anomaly report\n"
	"\t-s,--syscall\t\t\tSyscall report\n"
	"\t--success\t\t\tonly success events in report\n"
	"\t--summary\t\t\tsorted totals for main object in report\n"
	"\t-t,--log\t\t\tLog time range report\n"
	"\t-te,--end [end date] [end time]\tending date & time for reports\n"
	"\t-tm,--terminal\t\t\tTerMinal name report\n"
	"\t-ts,--start [start date] [start time]\tstarting data & time for reports\n"
	"\t--tty\t\t\t\tReport about tty keystrokes\n"
	"\t-u,--user\t\t\tUser name report\n"
	"\t-v,--version\t\t\tVersion\n"
	"\t--virt\t\t\t\tVirtualization report\n"
	"\t-x,--executable\t\t\teXecutable name report\n"
	"\tIf no report is given, the summary report will be displayed\n"
	);
}

static int set_report(report_type_t r)
{
	if (report_type == RPT_UNSET) {
		report_type = r;
		return 0;
	} else {
		fprintf(stderr, "Error - only one report can be specified");
		return 1;
	}
}

static int set_detail(report_det_t d)
{
	if (report_detail == D_UNSET) {
		report_detail = d;
		return 0;
	} else if (d == D_SUM) {
		report_detail = d;
		return 0;
	} else {
		return 1;
	}
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
		case R_INFILE:
			if (!optarg) {
				fprintf(stderr, 
					"Argument is required for %s\n",
					vars[c]);
				retval = -1;
			} else {
				if (strlen(optarg) >= PATH_MAX) {
					fprintf(stderr, 
						"File name is too long %s\n",
						optarg);
					retval = -1;
					break;
				}
				user_file = strdup(optarg);
				if (user_file == NULL)
					retval = -1;
				c++;
			}
			break;
		case R_LOG_TIMES:
			if (set_report(RPT_TIME))
				retval = -1;
			else
				set_detail(D_DETAILED);
			break;
		case R_AVCS:
			if (set_report(RPT_AVC))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
				event_comm = dummy;
				event_subject = dummy;
				event_object = dummy;
			}
			break;
		case R_AUTH:
			if (set_report(RPT_AUTH))
				retval = -1;
			else {
				set_detail(D_DETAILED);
				event_exe = dummy;
				event_hostname = dummy;
				event_terminal = dummy;
				event_uid = 1;
			}
			break;
		case R_MAC:
			if (set_report(RPT_MAC))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
				event_loginuid = 1;
				event_tauid = dummy;
			}
			break;
		case R_INTEG:
			if (set_report(RPT_INTEG))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
				event_loginuid = 1;
				event_tauid = dummy;
			}
			break;
		case R_VIRT:
			if (set_report(RPT_VIRT))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
			}
			break;
		case R_CONFIGS:
			if (set_report(RPT_CONFIG))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
				event_loginuid = 1;
				event_tauid = dummy;
			}
			break;
		case R_CRYPTO:
			if (set_report(RPT_CRYPTO))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
				event_loginuid = 1;
				event_tauid = dummy;
			}
			break;
		case R_LOGINS:
			if (set_report(RPT_LOGIN))
				retval = -1;
			else {
				set_detail(D_DETAILED);
				event_exe = dummy;
				event_hostname = dummy;
				event_terminal = dummy;
				event_loginuid = 1;
				event_tauid = dummy;
			}
			break;
		case R_ACCT_MODS:
			if (set_report(RPT_ACCT_MOD))
				retval = -1;
			else { 
				set_detail(D_DETAILED);
				event_exe = dummy;
				event_hostname = dummy;
				event_terminal = dummy;
				event_loginuid = 1;
				event_tauid = dummy;
			}
			break;
		case R_EVENTS:
			if (set_report(RPT_EVENT))
				retval = -1;
			else {
//				if (!optarg) {
					set_detail(D_DETAILED);
					event_loginuid = 1;
					event_tauid = dummy;
//				} else {
//					UNIMPLEMENTED;
//					set_detail(D_SPECIFIC);
//					if (isdigit(optarg[0])) {
//						errno = 0;
//						event_id = strtoul(optarg,
//							NULL, 10);
//						if (errno) {
//							fprintf(stderr,
//					"Illegal value for audit event ID");
//							retval = -1;
//						}
//						c++;
//					} else {
//						fprintf(stderr,
//			"Audit event id must be a numeric value, was %s\n",
//						optarg);
//						retval = -1;
//					}
//				}
			}
			break;
		case R_FILES:
			if (set_report(RPT_FILE))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_filename = dummy;
					event_exe = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_HOSTS:
			if (set_report(RPT_HOST))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_hostname = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_INTERPRET:
			report_format = RPT_INTERP;
			if (optarg) {
				fprintf(stderr,
					"Argument is NOT required for %s\n",
					vars[c]);
				retval = -1;
			}
			break;
		case R_PIDS:
			if (set_report(RPT_PID))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_exe = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_SYSCALLS:
			if (set_report(RPT_SYSCALL))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_comm = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_TERMINALS:
			if (set_report(RPT_TERM))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_terminal = dummy;
					event_hostname = dummy;
					event_exe = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_USERS:
			if (set_report(RPT_USER))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_terminal = dummy;
					event_hostname = dummy;
					event_exe = dummy;
					event_uid = 1;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_EXES:
			if (set_report(RPT_EXE))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_terminal = dummy;
					event_hostname = dummy;
					event_exe = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_COMM:
			if (set_report(RPT_COMM))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_terminal = dummy;
					event_hostname = dummy;
					event_comm = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_ANOMALY:
			if (set_report(RPT_ANOMALY))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_terminal = dummy;
					event_hostname = dummy;
					event_exe = dummy;
					event_comm = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_RESPONSE:
			if (set_report(RPT_RESPONSE))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_KEYS:
			if (set_report(RPT_KEY))
				retval = -1;
			else {
				if (!optarg) {
					set_detail(D_DETAILED);
					event_exe = dummy;
					event_key = dummy;
					event_loginuid = 1;
					event_tauid = dummy;
				} else {
					UNIMPLEMENTED;
				}
			}
			break;
		case R_TTY:
			if (set_report(RPT_TTY))
				retval = -1;
			else {
				set_detail(D_DETAILED);
				event_session_id = 1;
				event_loginuid = 1;
				event_tauid = dummy;
				event_terminal = dummy;
				event_comm = dummy;
			}
			break;
		case R_TIME_END:
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
		case R_TIME_START:
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
					} else if ( strchr(optarg, ':') == NULL) {
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
		case R_NODE:
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
		case R_ESCAPE:
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
		case R_SUMMARY_DET:
			set_detail(D_SUM);
			break;
		case R_FAILED:
			event_failed = F_FAILED;
			break;
		case R_SUCCESS:
			event_failed = F_SUCCESS;
			break;
		case R_ADD:
			event_conf_act = C_ADD;
			break;
		case R_DEL:
			event_conf_act = C_DEL;
			break;
		case R_IN_LOGS:
			force_logs = 1;
			break;
		case R_NO_CONFIG:
			no_config = 1;
			break;
		case R_VERSION:
	                printf("aureport version %s\n", VERSION);
			exit(0);
			break;
		case R_HELP:
			usage();
			exit(0);
			break;
		default:
			fprintf(stderr, "%s is an unsupported option\n", 
				vars[c]);
			retval = -1;
			break;
		}
		c++;
	}

	if (retval >= 0) {
		if (report_type == RPT_UNSET) {
			if (set_report(RPT_SUMMARY))
				retval = -1;
			else {
				set_detail(D_SUM);
				event_filename = dummy;
				event_hostname = dummy;
				event_terminal = dummy;
				event_exe = dummy;
				event_comm = dummy;
				event_key = dummy;
				event_loginuid = 1;
				event_tauid = dummy;
			}
		}
	} else
		usage();

	return retval;
}

