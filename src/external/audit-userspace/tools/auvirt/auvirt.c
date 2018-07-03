/*
 * auvirt.c - A tool to extract data related to virtualization.
 * Copyright (c) 2011 IBM Corp.
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
 *   Marcelo Henrique Cerri <mhcerri@br.ibm.com>
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "auparse.h"
#include "libaudit.h"
#include "ausearch-time.h"
#include "auvirt-list.h"

/* Command line parameters */
static int help_flag = 0;
static int stdin_flag = 0;
static int summary_flag = 0;
static int all_events_flag = 0;
static int uuid_flag = 0;
static int proof_flag = 0;
static const char *vm = NULL;
static const char *uuid = NULL;
static const char *file = NULL;
static int debug = 0;
/*
 * The start time and end time given in the command line is stored respectively
 * in the variables start_time and end_time that are declared/defined in the
 * files ausearch-time.h and ausearch-time.c. These files are reused from the
 * ausearch tool source code:
 *
 *	time_t start_time = 0;
 *	time_t end_time = 0;
 */

/* List of events */
enum event_type {
	ET_NONE = 0, ET_START, ET_STOP, ET_MACHINE_ID, ET_AVC, ET_RES, ET_ANOM
};
struct record_id {
	time_t time;
	unsigned int milli;
	unsigned long serial;
};
struct event {
	enum event_type type;
	time_t start;
	time_t end;
	const char *user;
	char *uuid;
	char *name;
	int success;
	pid_t pid;
	/* Fields specific for resource events: */
	char *reason;
	char *res_type;
	char *res;
	/* Fields specific for cgroup resources */
	char *cgroup_class;
	char *cgroup_detail;
	char *cgroup_acl;
	/* Fields specific for machine id events: */
	char *seclevel;
	/* Fields specific for avc events: */
	char *avc_result;
	char *avc_operation;
	char *target;
	char *comm;
	char *context;
	/* Fields to print proof information: */
	struct record_id proof[4];
};
list_t *events = NULL;


/* Auxiliary functions to allocate and to free events. */
struct event *event_alloc(void)
{
	struct event *event = malloc(sizeof(struct event));
	if (event) {
		/* The new event is initialized with values that represents
		 * unset values: -1 for user and pid and 0 (or NULL) for numbers
		 * and pointers. For example, event->end = 0 represents an
		 * unfinished event.
		 */
		memset(event, 0, sizeof(struct event));
		event->pid = -1;
	}
	return event;
}

void event_free(struct event *event)
{
	if (event) {
		free((void *)event->user);
		free(event->uuid);
		free(event->name);
		free(event->reason);
		free(event->res_type);
		free(event->res);
		free(event->avc_result);
		free(event->avc_operation);
		free(event->seclevel);
		free(event->target);
		free(event->comm);
		free(event->cgroup_class);
		free(event->cgroup_detail);
		free(event->cgroup_acl);
		free(event->context);
		free(event);
	}
}

#define copy_str( str ) (str) ? strdup(str) : NULL


void usage(FILE *output)
{
	fprintf(output, "usage: auvirt [--stdin] [--all-events] [--summary] "
			"[--start start-date [start-time]] "
			"[--end end-date [end-time]] [--file file-name] "
			"[--show-uuid] [--proof] "
			"[--uuid uuid] [--vm vm-name]\n");
}

/* Parse and check command line arguments */
int parse_args(int argc, char **argv)
{
	/* Based on http://www.ietf.org/rfc/rfc4122.txt */
	const char *uuid_pattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
		"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
	int i, rc = 0;
	regex_t uuid_regex;

	if (regcomp(&uuid_regex, uuid_pattern, REG_EXTENDED)) {
		fprintf(stderr, "Failed to initialize program.\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		const char *opt = argv[i];
		if (opt[0] != '-') {
			fprintf(stderr, "Argument not expected: %s\n", opt);
			goto error;
		} else if (strcmp("--vm", opt) == 0 ||
			   strcmp("-v", opt) == 0) {
			if ((i + 1) >= argc || argv[i + 1][0] == '-') {
				fprintf(stderr, "\"%s\" option requires "
						"an argument.\n", opt);
				goto error;
			}
			vm = argv[++i];
		} else if (strcmp("--uuid", opt) == 0 ||
			   strcmp("-u", opt) == 0) {
			if ((i + 1) >= argc || argv[i + 1][0] == '-') {
				fprintf(stderr, "\"%s\" option requires "
						"an argument.\n", opt);
				goto error;
			}
			if (regexec(&uuid_regex, argv[i + 1], 0, NULL, 0)) {
				fprintf(stderr, "Invalid uuid: %s\n",
						argv[i + 1]);
				goto error;
			}
			uuid = argv[++i];
		} else if (strcmp("--all-events", opt) == 0 ||
		           strcmp("-a", opt) == 0) {
			all_events_flag = 1;
		} else if (strcmp("--summary", opt) == 0 ||
			   strcmp("-s", opt) == 0) {
			summary_flag = 1;
		} else if (strcmp("--file", opt) == 0 ||
			   strcmp("-f", opt) == 0) {
			if ((i + 1) >= argc || argv[i + 1][0] == '-') {
				fprintf(stderr, "\"%s\" option requires "
						"an argument.\n", opt);
				goto error;
			}
			file = argv[++i];
		} else if (strcmp("--show-uuid", opt) == 0) {
			uuid_flag = 1;
		} else if (strcmp("--stdin", opt) == 0) {
			stdin_flag = 1;
		} else if (strcmp("--proof", opt) == 0) {
			proof_flag = 1;
		} else if (strcmp("--help", opt) == 0 ||
			   strcmp("-h", opt) == 0) {
			help_flag = 1;
			goto exit;
		} else if (strcmp("--start", opt) == 0 ||
			   strcmp("-ts", opt) == 0) {
			const char *date, *time = NULL;
			if ((i + 1) >= argc || argv[i + 1][0] == '-') {
				fprintf(stderr, "\"%s\" option requires at "
						"least one argument.\n", opt);
				goto error;
			}
			date = argv[++i];
			if ((i + 1) < argc && argv[i + 1][0] != '-')
				time = argv[++i];
			else
				time = "00:00:00";
			/* This will set start_time */
			if (ausearch_time_start(date, time))
				goto error;
		} else if (strcmp("--end", opt) == 0 ||
			   strcmp("-te", opt) == 0) {
			const char *date, *time = NULL;
			if ((i + 1) >= argc || argv[i + 1][0] == '-') {
				fprintf(stderr, "\"%s\" option requires at "
						"least one argument.\n", opt);
				goto error;
			}
			date = argv[++i];
			if ((i + 1) < argc && argv[i + 1][0] != '-')
				time = argv[++i];
			else
				time = "00:00:00";
			/* This will set end_time */
			if (ausearch_time_end(date, time))
				goto error;
		} else if (strcmp("--debug", opt) == 0) {
			debug = 1;
		} else {
			fprintf(stderr, "Unknown option \"%s\".\n", opt);
			goto error;
		}
	}

	/* Validate conflicting options */
	if (stdin_flag && file) {
		fprintf(stderr, "\"--sdtin\" and \"--file\" options "
				"must not be specified together.\n");
		goto error;
	}

	if (debug) {
		fprintf(stderr, "help_flag='%i'\n", help_flag);
		fprintf(stderr, "stdin_flag='%i'\n", stdin_flag);
		fprintf(stderr, "all_events_flag='%i'\n", all_events_flag);
		fprintf(stderr, "summary_flag='%i'\n", summary_flag);
		fprintf(stderr, "uuid='%s'\n", uuid ? uuid : "(null)");
		fprintf(stderr, "vm='%s'\n", vm ? vm : "(null)");
		fprintf(stderr, "file='%s'\n", file ? file : "(null)");
		fprintf(stderr, "start_time='%-.16s'\n", (start_time == 0L) ?
				"" : ctime(&start_time));
		fprintf(stderr, "end_time='%-.16s'\n", (end_time == 0L) ?
				"" : ctime(&end_time));
	}

exit:
	regfree(&uuid_regex);
	return rc;
error:
	rc = 1;
	goto exit;
}

/* Initialize an auparse_state_t with the correct log source. */
auparse_state_t *init_auparse(void)
{
	auparse_state_t *au = NULL;
	if (stdin_flag) {
		au = auparse_init(AUSOURCE_FILE_POINTER, stdin);
	} else if (file) {
		au = auparse_init(AUSOURCE_FILE, file);
	} else {
		au = auparse_init(AUSOURCE_LOGS, NULL);
	}
	if (au == NULL) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
	}
	return au;
}

/* Extract the most common fields from virtualization-related records. */
int extract_virt_fields(auparse_state_t *au, const char **p_uuid,
		const char **p_user, time_t *p_time, const char **p_name,
		int *p_suc)
{
	const char *field = NULL;
	auparse_first_record(au);

	/* Order matters */
	if (p_user) {
		const char *t;
		if (!auparse_find_field(au, field = "uid"))
			goto error;
		t = auparse_interpret_field(au);
		if (t)
			*p_user = strdup(t);
	}
	if (p_name) {
		if (!auparse_find_field(au, field = "vm"))
			goto error;
		*p_name = auparse_interpret_field(au);
	}
	if (p_uuid) {
		if (!auparse_find_field(au, field = "uuid"))
			goto error;
		*p_uuid = auparse_get_field_str(au);
	}
	if (p_suc) {
		const char *res = auparse_find_field(au, field = "res");
		if (res == NULL)
			goto error;
		*p_suc = (strcmp("success", res) == 0) ? 1 : 0;
	}
	if (p_time) {
		*p_time = auparse_get_time(au);
	}
	return 0;

error:
	if (debug) {
		fprintf(stderr, "Failed to get field \"%s\" for record "
				"%ld.%03u:%lu\n", field ? field : "",
				auparse_get_time(au),
				auparse_get_milli(au),
				auparse_get_serial(au));
	}
	if (p_user)
		free((void *) *p_user);
	return 1;
}

/* Return label and categories from a security context. */
const char *get_seclevel(const char *seclabel)
{
	/*
	 * system_u:system_r:svirt_t:s0:c107,c434
	 *                           \____ _____/
	 *                                '
	 *                           level + cat
	 */
	int c = 0;
	for (;seclabel && *seclabel; seclabel++) {
		if (*seclabel == ':')
			c += 1;
		if (c == 3)
			return seclabel + 1;
	}
	return NULL;
}

int add_proof(struct event *event, auparse_state_t *au)
{
	if (!proof_flag)
		return 0;

	size_t i, proof_len = sizeof(event->proof)/sizeof(event->proof[0]);
	for (i = 0; i < proof_len; i++) {
		if (event->proof[i].time == 0)
			break;
	}
	if (i == proof_len) {
		if (debug)
			fprintf(stderr, "Failed to add proof.\n");
		return 1;
	}

	event->proof[i].time = auparse_get_time(au);
	event->proof[i].milli = auparse_get_milli(au);
	event->proof[i].serial = auparse_get_serial(au);
	return 0;
}

// This returns -1 if we don't want the event and 0 if we do
int filter_event(auparse_state_t *au)
{
	extern time_t start_time, end_time;
	time_t current = auparse_get_time(au);

	if (start_time == 0 || current >= start_time) {
		if (end_time == 0 || current <= end_time) {

			if (vm) {
				const char *v = auparse_find_field(au, "vm");
				if (v) {
					const char *v_text =
						auparse_interpret_field(au);
					if (v_text && strcmp(vm, v_text))
						return -1;
				}
			}
			if (uuid) {
				const char *u = auparse_find_field(au, "uuid");
				if (u) {
					const char *u_text =
						auparse_interpret_field(au);
					if (u_text && strcmp(uuid, u_text))
						return -1;
				}
			}
			auparse_first_record(au);
			return 0;
		}
	}
	return -1;
}

/*
 * machine_id records are used to get the selinux context associated to a
 * guest.
 */
int process_machine_id_event(auparse_state_t *au)
{
	time_t time;
	const char *seclevel, *model, *uuid, *name, *user = NULL;
	struct event *event;
	int success;

	if (filter_event(au))
		return 0;

	seclevel = get_seclevel(auparse_find_field(au, "vm-ctx"));
	if (seclevel == NULL) {
		if (debug)
			fprintf(stderr, "Security context not found for "
					"MACHINE_ID event.\n");
	}

	// We only need to collect seclevel if model is selinux	
	model = auparse_find_field(au, "model");
	if (model && strcmp(model, "dac") == 0)
		return 0;

	if (extract_virt_fields(au, &uuid, &user, &time, &name, &success))
		return 0;

	event = event_alloc();
	if (event == NULL) {
		free((void *)user);
		return 1;
	}
	event->type = ET_MACHINE_ID;
	event->uuid = copy_str(uuid);
	event->name = copy_str(name);
	event->success = success;
	event->seclevel = copy_str(seclevel);
	event->user = user;
	event->start = time;
	add_proof(event, au);
	if (list_append(events, event) == NULL) {
		event_free(event);
		return 1;
	}
	return 0;
}

int add_start_guest_event(auparse_state_t *au)
{
	struct event *start;
	time_t time;
	const char *uuid, *name, *user = NULL;
	int success;
	list_node_t *it;

	/* Just skip this record if it failed to get some of the fields */
	if (extract_virt_fields(au, &uuid, &user, &time, &name, &success))
		return 0;

	/* On failure, loop backwards to update all the resources associated to
	 * the last session of this guest. When a machine_id or a stop event is
	 * found the loop can be broken because a machine_id is created at the
	 * beginning of a session and a stop event indicates a previous
	 * session.
	 */
	if (!success) {
		for (it = events->tail; it; it = it->prev) {
			struct event *event = it->data;
			if (event->success && event->uuid &&
			    strcmp(uuid, event->uuid) == 0) {
				if (event->type == ET_STOP ||
				    event->type == ET_MACHINE_ID) {
					/* An old session found. */
					break;
				} else if (event->type == ET_RES &&
				           event->end == 0) {
					event->end = time;
					add_proof(event, au);
				}
			}
		}
	}

	start = event_alloc();
	if (start == NULL) {
		free((void *)user);
		return 1;
	}
	start->type = ET_START;
	start->uuid = copy_str(uuid);
	start->name = copy_str(name);
	start->success = success;
	start->user = user;
	start->start = time;
	auparse_first_record(au);
	if (auparse_find_field(au, "vm-pid"))
		start->pid = auparse_get_field_int(au);
	add_proof(start, au);
	if (list_append(events, start) == NULL) {
		event_free(start);
		return 1;
	}
	return 0;
}

int add_stop_guest_event(auparse_state_t *au)
{
	list_node_t *it;
	struct event *stop, *start = NULL, *event = NULL;
	time_t time;
	const char *uuid, *name, *user = NULL;
	int success;

	/* Just skip this record if it failed to get some of the fields */
	if (extract_virt_fields(au, &uuid, &user, &time, &name, &success))
		return 0;

	/* Loop backwards to find the last start event for the uuid and
	 * update all resource records related to that guest session.
	 */
	for (it = events->tail; it; it = it->prev) {
		event = it->data;
		if (event->success && event->uuid &&
		    strcmp(uuid, event->uuid) == 0) {
			if (event->type == ET_START) {
				/* If an old session is found it's no longer
				 * necessary to update the resource records.
				 */
				if (event->end || start)
					break;
				/* This is the start event related to the
				 * current session. */
				start = event;
			} else if (event->type == ET_STOP ||
				   event->type == ET_MACHINE_ID) {
				/* Old session found. */
				break;
			} else if (event->type == ET_RES && event->end == 0) {
				/* Update the resource assignments. */
				event->end = time;
				add_proof(event, au);
			}
		}
	}
	if (start == NULL) {
		if (debug) {
			fprintf(stderr, "Couldn't find the correlated start "
					"record to the stop event.\n");
		}
		free((void *)user);
		return 0;
	}

	/* Create a new stop event */
	stop = event_alloc();
	if (stop == NULL) {
		free((void *)user);
		return 1;
	}
	stop->type = ET_STOP;
	stop->uuid = copy_str(uuid);
	stop->name = copy_str(name);
	stop->success = success;
	stop->user = user;
	stop->start = time;
	auparse_first_record(au);
	if (auparse_find_field(au, "vm-pid"))
		stop->pid = auparse_get_field_int(au);
	add_proof(stop, au);
	if (list_append(events, stop) == NULL) {
		free((void *)user);
		event_free(stop);
		return 1;
	}

	/* Update the correlated start event. */
	if (success) {
		start->end = time;
		add_proof(start, au);
	}
	return 0;
}

int process_control_event(auparse_state_t *au)
{
	const char *op;

	if (filter_event(au))
		return 0;

	op = auparse_find_field(au, "op");
	if (op == NULL) {
		if (debug)
			fprintf(stderr, "Invalid op field.\n");
		return 0;
	}

	if (strcmp("start", op) == 0) {
		if (add_start_guest_event(au))
			return 1;
	} else if (strcmp("stop", op) == 0) {
		if (add_stop_guest_event(au))
			return 1;
	} else if (debug) {
		fprintf(stderr, "Unknown op: %s\n", op);
	}
	return 0;
}

static int is_resource(const char *res)
{
	if (res == NULL ||
	    res[0] == '\0' ||
	    strcmp("0", res) == 0 ||
	    strcmp("?", res) == 0)
		return 0;
	return 1;
}

int add_resource(auparse_state_t *au, const char *uuid, const char *user,
		time_t time, const char *name, int success, const char *reason,
		const char *res_type, const char *res)
{
	if (!is_resource(res)) {
		free((void *)user);
		return 0;
	}

	struct event *event = event_alloc();
	if (event == NULL)
		return 1;
	event->type = ET_RES;
	event->uuid = copy_str(uuid);
	event->name = copy_str(name);
	event->success = success;
	event->reason = copy_str(reason);
	event->res_type = copy_str(res_type);
	event->res = copy_str(res);
	event->user = user;
	event->start = time;
	add_proof(event, au);

	/* Get cgroup specific fields. */
	if (strcmp("cgroup", res_type) == 0) {
		event->cgroup_class = copy_str(auparse_find_field(au, "class"));
		if (event->cgroup_class) {
			const char *detail = NULL;
			if (strcmp("path", event->cgroup_class) == 0) {
				if (auparse_find_field(au, "path"))
					detail = auparse_interpret_field(au);
			} else if (strcmp("major", event->cgroup_class) == 0) {
				detail = auparse_find_field(au, "category");
			}
			event->cgroup_detail = copy_str(detail);
		}
		event->cgroup_acl = copy_str(auparse_find_field(au, "acl"));
	}

	if (list_append(events, event) == NULL) {
		event_free(event);
		return 1;
	}
	return 0;
}

int update_resource(auparse_state_t *au, const char *uuid, time_t time,
		int success, const char *res_type, const char *res)
{
	if (!is_resource(res) || !success)
		return 0;

	list_node_t *it;
	struct event *start = NULL;

	/* Find the last start event for the uuid */
	for (it = events->tail; it; it = it->prev) {
		start = it->data;
		if (start->type == ET_RES &&
		    start->success &&
		    start->uuid &&
		    strcmp(uuid, start->uuid) == 0 &&
		    strcmp(res_type, start->res_type) == 0 &&
		    strcmp(res, start->res) == 0)
			break;
	}
	if (it == NULL) {
		if (debug) {
			fprintf(stderr, "Couldn't find the correlated resource"
					" record to update for %s.\n", res_type);
		}
		return 0;
	}

	start->end = time;
	add_proof(start, au);
	return 0;
}

int process_resource_event(auparse_state_t *au)
{
	time_t time;
	const char *res_type, *uuid, *name, *user = NULL;
	char field[64];
	const char *reason;
	int success;

	if (filter_event(au))
		return 0;

	/* Just skip this record if it failed to get some of the fields */
	if (extract_virt_fields(au, &uuid, &user, &time, &name, &success))
		return 0;

	/* Get the resource type */
	auparse_first_record(au);
	res_type = auparse_find_field(au, "resrc");
	reason = auparse_find_field(au, "reason");
	if (res_type == NULL) {
		if (debug)
			fprintf(stderr, "Invalid resrc field.\n");
		free((void *)user);
		return 0;
	}

	/* Resource records with these types have old and new values. New
	 * values indicate resources assignments and are added to the event
	 * list. Old values are used to update the end time of a resource
	 * assignment.
	 */
	int rc = 0;
	if (strcmp("disk", res_type) == 0 ||
	    strcmp("vcpu", res_type) == 0 ||
	    strcmp("mem", res_type) == 0 ||
	    strcmp("rng", res_type) == 0 ||
	    strcmp("net", res_type) == 0) {
		const char *res = NULL;
		/* Resource removed */
		snprintf(field, sizeof(field), "old-%s", res_type);
		if(auparse_find_field(au, field))
			res = auparse_interpret_field(au);
		if (res == NULL && debug) {
			fprintf(stderr, "Failed to get %s field.\n", field);
		} else {
			rc += update_resource(au, uuid, time, 
					success, res_type, res);
		}

		/* Resource added */
		res = NULL;
		snprintf(field, sizeof(field), "new-%s", res_type);
		if (auparse_find_field(au, field))
			res = auparse_interpret_field(au);
		if (res == NULL && debug) {
			fprintf(stderr, "Failed to get %s field.\n", field);
			free((void *)user);
		} else {
			rc += add_resource(au, uuid, user, time, name, success,
					reason, res_type, res);
		}
	} else if (strcmp("cgroup", res_type) == 0) {
		auparse_first_record(au);
		const char *cgroup = NULL;
		if (auparse_find_field(au, "cgroup"))
			cgroup = auparse_interpret_field(au);
		rc += add_resource(au, uuid, user, time, name, success, reason,
				res_type, cgroup);
	} else if (debug) {
		fprintf(stderr, "Found an unknown resource: %s.\n",
				res_type);
		free((void *)user);
	} else
		free((void *)user);
	return rc;
}

/* Search for the last machine_id record with the given seclevel */
struct event *get_machine_id_by_seclevel(const char *seclevel)
{
	struct event *machine_id = NULL;
	list_node_t *it;

	for (it = events->tail; it; it = it->prev) {
		struct event *event = it->data;
		if (event->type == ET_MACHINE_ID &&
		    event->seclevel != NULL) {
			if (strcmp(event->seclevel, seclevel) == 0) {
				machine_id = event;
				break;
			}
		}
	}

	return machine_id;
}

/* AVC records are correlated to guest through the selinux context. */
int process_avc_selinux(auparse_state_t *au)
{
	const char *seclevel, *user = NULL;
	struct event *machine_id, *avc;
	time_t time;

	seclevel = get_seclevel(auparse_find_field(au, "scontext"));
	if (seclevel == NULL) {
		if (debug) {
			fprintf(stderr, "Security context not found "
					"for AVC event.\n");
		}
		return 0;
	}

	if (extract_virt_fields(au, NULL, &user, &time, NULL, NULL))
		return 0;

	machine_id = get_machine_id_by_seclevel(seclevel);
	if (machine_id == NULL) {
		if (debug) {
			fprintf(stderr, "Couldn't get the machine id "
				"based on security level in AVC event.\n");
		}
		free((void *)user);
		return 0;
	}

	avc = event_alloc();
	if (avc == NULL) {
		free((void *)user);
		return 1;
	}
	avc->type = ET_AVC;

	/* Guest info */
	avc->uuid = copy_str(machine_id->uuid);
	avc->name = copy_str(machine_id->name);
	memcpy(avc->proof, machine_id->proof, sizeof(avc->proof));

	/* AVC info */
	avc->start = time;
	avc->user = user;
	avc->seclevel = copy_str(seclevel);
	auparse_first_record(au);
	avc->avc_result = copy_str(auparse_find_field(au, "seresult"));
	avc->avc_operation = copy_str(auparse_find_field(au, "seperms"));
	if (auparse_find_field(au, "comm"))
		avc->comm = copy_str(auparse_interpret_field(au));
	if (auparse_find_field(au, "name"))
		avc->target = copy_str(auparse_interpret_field(au));

	/* get the context related to the permission that was denied. */
	if (avc->avc_operation) {
		const char *ctx = NULL;
		if (strcmp("relabelfrom", avc->avc_operation) == 0) {
			ctx = auparse_find_field(au, "scontext");
		} else if (strcmp("relabelto", avc->avc_operation) == 0) {
			ctx = auparse_find_field(au, "tcontext");
		}
		avc->context = copy_str(ctx);
	}

	add_proof(avc, au);
	if (list_append(events, avc) == NULL) {
		event_free(avc);
		return 1;
	}
	return 0;
}

#ifdef WITH_APPARMOR
int process_avc_apparmor_source(auparse_state_t *au)
{
	time_t time = 0;
	struct event *avc;
	const char *target, *user = NULL;

	/* Get the target object. */
	if (auparse_find_field(au, "name") == NULL) {
		if (debug) {
			auparse_first_record(au);
			fprintf(stderr, "Couldn't get the resource name from "
					"the AVC record: %s\n",
					auparse_get_record_text(au));
		}
		return 0;
	}
	target = auparse_interpret_field(au);

	/* Loop backwards to find a guest session with the target object
	 * assigned to. */
	struct list_node_t *it;
	struct event *res = NULL;
	for (it = events->tail; it; it = it->prev) {
		struct event *event = it->data;
		if (event->success) {
			if (event->type == ET_RES &&
			           event->end == 0 &&
			           event->res != NULL &&
		                   strcmp(target, event->res) == 0) {
				res = event;
				break;
			}
		}
	}

	/* Check if a resource event was found. */
	if (res == NULL) {
		if (debug) {
			fprintf(stderr, "Target object not found for AVC "
					"event.\n");
		}
		return 0;
	}

	if (extract_virt_fields(au, NULL, &user, &time, NULL, NULL))
		return 0;

	avc = event_alloc();
	if (avc == NULL) {
		free(user);
		return 1;
	}
	avc->type = ET_AVC;

	/* Guest info */
	avc->uuid = copy_str(res->uuid);
	avc->name = copy_str(res->name);
	memcpy(avc->proof, res->proof, sizeof(avc->proof));

	/* AVC info */
	avc->start = time;
	avc->user = user;
	auparse_first_record(au);
	if (auparse_find_field(au, "apparmor")) {
		int i;
		avc->avc_result = copy_str(auparse_interpret_field(au));
		for (i = 0; avc->avc_result && avc->avc_result[i]; i++) {
			avc->avc_result[i] = tolower(avc->avc_result[i]);
		}
	}
	if (auparse_find_field(au, "operation"))
		avc->avc_operation = copy_str(auparse_interpret_field(au));
	avc->target = copy_str(target);
	if (auparse_find_field(au, "comm"))
		avc->comm = copy_str(auparse_interpret_field(au));

	add_proof(avc, au);
	if (list_append(events, avc) == NULL) {
		event_free(avc);
		return 1;
	}
	return 0;
}

int process_avc_apparmor_target(auparse_state_t *au)
{
	const char *user = NULL;
	time_t time;
	const char *profile;
	struct event *avc;

	/* Get profile associated with the AVC record */
	if (auparse_find_field(au, "profile") == NULL) {
		if (debug) {
			auparse_first_record(au);
			fprintf(stderr, "AppArmor profile not found for AVC "
					"record: %s\n",
					auparse_get_record_text(au));
		}
		return 0;
	}
	profile = auparse_interpret_field(au);

	/* Break path to get just the basename */
	const char *basename = profile + strlen(profile);
	while (basename != profile && *basename != '/')
		basename--;
	if (*basename == '/')
		basename++;

	/* Check if it is an apparmor profile generated by libvirt and get the
	 * guest UUID from it */
	const char *prefix = "libvirt-";
	if (strncmp(prefix, basename, strlen(prefix)) != 0) {
		if (debug) {
			fprintf(stderr, "Found a profile which is not "
					"generated by libvirt: %s\n", profile);
		}
		return 0;
	}

	/* Try to find a valid guest session */
	const char *uuid = basename + strlen(prefix);
	struct list_node_t *it;
	struct event *machine_id = NULL;
	for (it = events->tail; it; it = it->prev) {
		struct event *event = it->data;
		if (event->success) {
			if (event->uuid != NULL &&
			    strcmp(event->uuid, uuid) == 0) {
				/* machine_id is used here instead of the start
				 * event because it is generated before any
				 * other event when a guest is started. So,
				 * it's possible to correlate AVC events that
				 * occurs during a guest start.
				 */
				if (event->type == ET_MACHINE_ID) {
					machine_id = event;
					break;
				} else if (event->type == ET_STOP) {
					break;
				}
			}
		}
	}
	if (machine_id == NULL) {
		if (debug) {
			fprintf(stderr, "Found an AVC record for an unknown "
					"guest.\n");
		}
		return 0;
	}

	if (extract_virt_fields(au, NULL, &user, &time, NULL, NULL))
		return 0;

	avc = event_alloc();
	if (avc == NULL) {
		free(user);
		return 1;
	}
	avc->type = ET_AVC;

	/* Guest info */
	avc->uuid = copy_str(machine_id->uuid);
	avc->name = copy_str(machine_id->name);
	memcpy(avc->proof, machine_id->proof, sizeof(avc->proof));

	/* AVC info */
	avc->start = time;
	avc->user = user;
	auparse_first_record(au);
	if (auparse_find_field(au, "apparmor")) {
		int i;
		avc->avc_result = copy_str(auparse_interpret_field(au));
		for (i = 0; avc->avc_result && avc->avc_result[i]; i++) {
			avc->avc_result[i] = tolower(avc->avc_result[i]);
		}
	}
	if (auparse_find_field(au, "operation"))
		avc->avc_operation = copy_str(auparse_interpret_field(au));
	if (auparse_find_field(au, "name"))
		avc->target = copy_str(auparse_interpret_field(au));
	if (auparse_find_field(au, "comm"))
		avc->comm = copy_str(auparse_interpret_field(au));

	add_proof(avc, au);
	if (list_append(events, avc) == NULL) {
		event_free(avc);
		return 1;
	}
	return 0;
}

/* AVC records are correlated to guest through the apparmor path name. */
int process_avc_apparmor(auparse_state_t *au)
{
	if (process_avc_apparmor_target(au))
		return 1;
	auparse_first_record(au);
	return process_avc_apparmor_source(au);
}
#endif

int process_avc(auparse_state_t *au)
{
	if (filter_event(au))
		return 0;

	/* Check if it is a SELinux AVC record */
	if (auparse_find_field(au, "scontext")) {
		return process_avc_selinux(au);
	}

#ifdef WITH_APPARMOR
	/* Check if it is an AppArmor AVC record */
	auparse_first_record(au);
	if (auparse_find_field(au, "apparmor")) {
		auparse_first_record(au);
		return process_avc_apparmor(au);
	}
#endif
	return 0;
}

/* This function tries to correlate an anomaly record to a guest using the qemu
 * pid or the selinux context. */
int process_anom(auparse_state_t *au)
{
	const char *user = NULL;
	time_t time;
	pid_t pid = -1;
	list_node_t *it;
	struct event *anom, *start = NULL;

	if (filter_event(au))
		return 0;

	/* An anomaly record is correlated to a guest by the process id */
	if (auparse_find_field(au, "pid")) {
		pid = auparse_get_field_int(au);
	} else {
		if (debug) {
			fprintf(stderr, "Found an anomaly record "
					"without pid.\n");
		}
	}

	/* Loop backwards to find a running guest with the same pid. */
	if (pid >= 0) {
		for (it = events->tail; it; it = it->next) {
			struct event *event = it->data;
			if (event->pid == pid && event->success) {
				if (event->type == ET_STOP) {
					break;
				} else if (event->type == ET_START) {
					if (event->end == 0)
						start = event;
					break;
				}
			}
		}
	}

	/* Try to match using selinux context */
	if (start == NULL) {
		const char *seclevel;
		struct event *machine_id;

		seclevel = get_seclevel(auparse_find_field(au, "subj"));
		if (seclevel == NULL) {
			if (debug) {
				auparse_first_record(au);
				const char *text = auparse_get_record_text(au);
				fprintf(stderr, "Security context not found "
						"for anomaly event: %s\n",
						text ? text : "");
			}
			return 0;
		}
		machine_id = get_machine_id_by_seclevel(seclevel);
		if (machine_id == NULL) {
			if (debug) {
				fprintf(stderr, "Couldn't get the security "
					"level from the anomaly event.\n");
			}
			return 0;
		}

		for (it = events->tail; it; it = it->next) {
			struct event *event = it->data;
			if (event->success && machine_id->uuid && event->uuid &&
			    strcmp(machine_id->uuid, event->uuid) == 0) {
				if (event->type == ET_STOP) {
					break;
				} else if (event->type == ET_START) {
					if (event->end == 0)
						start = event;
					break;
				}
			}
		}
	}

	if (start == NULL) {
		if (debug) {
			const char *text = auparse_get_record_text(au);
			fprintf(stderr, "Guest not found for "
					"anomaly record: %s.\n",
					text ? text : "");
		}
		return 0;
	}

	if (extract_virt_fields(au, NULL, &user, &time, NULL, NULL))
		return 0;

	anom = event_alloc();
	if (anom == NULL) {
		free((void *)user);
		return 1;
	}
	anom->type = ET_ANOM;
	anom->uuid = copy_str(start->uuid);
	anom->name = copy_str(start->name);
	anom->user = user;
	anom->start = time;
	anom->pid = pid;
	memcpy(anom->proof, start->proof, sizeof(anom->proof));
	add_proof(anom, au);
	if (list_append(events, anom) == NULL) {
		event_free(anom);
		return 1;
	}
	return 0;
}

/* Convert record type to a string */
const char *get_rec_type(struct event *e)
{
	static char buf[16];
	if (e == NULL)
		return "";

	switch (e->type) {
	case ET_START:
		return "start";
	case ET_STOP:
		return "stop";
	case ET_RES:
		return "resrc";
	case ET_AVC:
		return "avc";
	case ET_ANOM:
		return "anom";
	default:
		break;
	}

	snprintf(buf, sizeof(buf), "%d", e->type);
	return buf;
}

/* Convert a time period to string */
const char *get_time_period(struct event *event)
{
	size_t i = 0;
	static char buf[128];

	i += sprintf(buf + i, "%-16.16s", ctime(&event->start));
	if (event->end) {
		time_t secs = event->end - event->start;
		int mins, hours, days;
		i += sprintf(buf + i, " - %-7.5s", ctime(&event->end) + 11);
		mins  = (secs / 60) % 60;
		hours = (secs / 3600) % 24;
		days  = secs / 86400;
		if (days) {
			i += sprintf(buf + i, "(%d+%02d:%02d)", days, hours,
					mins);
		} else {
			i += sprintf(buf + i, "(%02d:%02d)", hours, mins);
		}
	} else {
		if (!event->success &&
		    event->type != ET_AVC &&
		    event->type != ET_ANOM) {
			i += sprintf(buf + i, " - failed");
		}
	}
	return buf;
}

void print_event(struct event *event)
{
	/* Auxiliary macro to convert NULL to "" */
	#define N(str) ((str) ? str : "")

	/* machine id records are used just to get information about
	 * the guests. */
	if (event->type == ET_MACHINE_ID)
		return;
	/* If "--all-events" is not given, only the start event is shown. */
	if (!all_events_flag && event->type != ET_START)
		return;
	/* The type of event is shown only when all records are shown */
	if (all_events_flag)
		printf("%-6.5s ", get_rec_type(event));

	/* Print common fields */
	printf("%-22.22s", N(event->name));
	if (uuid_flag)
		printf("\t%-36.36s", N(event->uuid));
	printf("\t%-11.11s\t%-32.32s", N(event->user),
			get_time_period(event));

	/* Print type specific fields */
	if (event->type == ET_RES) {
		printf("\t%-12.12s", N(event->res_type));
		printf("\t%-10.10s", N(event->reason));
		if (strcmp("cgroup", event->res_type) != 0) {
			printf("\t%s", N(event->res));
		} else {
			printf("\t%s\t%s\t%s", N(event->cgroup_class),
					N(event->cgroup_acl),
					N(event->cgroup_detail));
		}
	} else if (event->type == ET_MACHINE_ID) {
		printf("\t%s", N(event->seclevel));
	} else if (event->type == ET_AVC) {
		printf("\t%-12.12s", N(event->avc_operation));
		printf("\t%-10.10s", N(event->avc_result));
		printf("\t%s\t%s\t%s", N(event->comm), N(event->target),
				N(event->context));
	}
	printf("\n");

	/* Print proof */
	if (proof_flag) {
		int first = 1;
		int i, len = sizeof(event->proof)/sizeof(event->proof[0]);
		printf("    Proof:");
		for (i = 0; i < len; i++) {
			if (event->proof[i].time) {
				//printf("%s %ld.%03u:%lu",
				printf("%s%lu",
					(first) ? "" : ",",
//					event->proof[i].time,
//					event->proof[i].milli,
					event->proof[i].serial);
				first = 0;
			}
		}
		printf("\n\n");
	}
}

/* Print all events */
void print_events(void)
{
	list_node_t *it;
	for (it = events->head; it; it = it->next) {
		struct event *event = it->data;
		if (event)
			print_event(event);
	}
}

/* Count and print summary */
void print_summary(void)
{
	/* Summary numbers */
	time_t stime = 0, etime = 0;
	long start = 0, stop = 0, res = 0, avc = 0, anom = 0, failure = 0;
	char start_buf[32], end_buf[32];

	/* Calculate summary */
	list_node_t *it;
	for (it = events->head; it; it = it->next) {
		struct event *event = it->data;
		if (event->success == 0 &&
		    (event->type == ET_START ||
		     event->type == ET_STOP  ||
		     event->type == ET_RES)) {
			failure++;
		} else {
			switch (event->type) {
			case ET_START:
				start++;
				break;
			case ET_STOP:
				stop++;
				break;
			case ET_RES:
				res++;
				break;
			case ET_AVC:
				avc++;
				break;
			case ET_ANOM:
				anom++;
				break;
			default:
				break;
			}
		}

		/* Calculate time range */
		if (event->start) {
			if (stime == 0 || event->start < stime) {
				stime = event->start;
			}
			if (etime == 0 || event->start > etime) {
				etime = event->start;
			}
		}
		if (event->end) {
			if (stime == 0 || event->end < stime) {
				stime = event->end;
			}
			if (etime == 0 || event->end > etime) {
				etime = event->end;
			}
		}

	}

	if (stime)
		ctime_r(&stime, start_buf);
	else
		strcpy(start_buf, "undef");
	if (etime)
		ctime_r(&etime, end_buf);
	else
		strcpy(end_buf, "undef");

	/* Print summary */
	printf("Range of time for report:       %-.16s - %-.16s\n",
			start_buf, end_buf);
	printf("Number of guest starts:         %ld\n", start);
	printf("Number of guest stops:          %ld\n", stop);
	printf("Number of resource assignments: %ld\n", res);
	printf("Number of related AVCs:         %ld\n", avc);
	printf("Number of related anomalies:    %ld\n", anom);
	printf("Number of failed operations:    %ld\n", failure);
}

int main(int argc, char **argv)
{
	int rc = 0;
	auparse_state_t *au = NULL;

	setlocale(LC_ALL, "");
	if (parse_args(argc, argv))
		goto error;
	if (help_flag) {
		usage(stdout);
		goto exit;
	}

	/* Initialize event list*/
	events = list_new((list_free_data_fn*) event_free);
	if (events == NULL)
		goto unexpected_error;

	/* Initialize auparse */
	au = init_auparse();
	if (au == NULL)
		goto error;

	while (auparse_next_event(au) > 0) {
		int err = 0;

		switch(auparse_get_type(au)) {
		case AUDIT_VIRT_MACHINE_ID:
			err = process_machine_id_event(au);
			break;
		case AUDIT_VIRT_CONTROL:
			err = process_control_event(au);
			break;
		case AUDIT_VIRT_RESOURCE:
			err = process_resource_event(au);
			break;
		case AUDIT_AVC:
			if (all_events_flag || summary_flag)
				err = process_avc(au);
			break;
		case AUDIT_FIRST_ANOM_MSG ... AUDIT_LAST_ANOM_MSG:
		case AUDIT_FIRST_KERN_ANOM_MSG ... AUDIT_LAST_KERN_ANOM_MSG:
			if (all_events_flag || summary_flag)
				err = process_anom(au);
			break;
		default:
			break;
		}
		if (err) {
			goto unexpected_error;
		}
	}

	/* Show results */
	if (summary_flag) {
		print_summary();
	} else {
		print_events();
	}

	/* success */
	goto exit;

unexpected_error:
	fprintf(stderr, "Unexpected error\n");
error:
	rc = 1;
exit:
	if (au)
		auparse_destroy(au);
	list_free(events);
	if (debug)
		fprintf(stdout, "Exit code: %d\n", rc);
	return rc;
}

