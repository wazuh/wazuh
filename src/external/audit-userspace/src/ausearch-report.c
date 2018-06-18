/*
* ausearch-report.c - Format and output events
* Copyright (c) 2005-09,2011-13,2016-17 Red Hat Inc., Durham, North Carolina.
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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "libaudit.h"
#include "ausearch-options.h"
#include "ausearch-parse.h"
#include "ausearch-lookup.h"
#include "auparse.h"
#include "auparse-idata.h"
#include "auditd-config.h"

/* Local functions */
static void output_raw(llist *l);
static void output_default(llist *l);
static void output_interpreted(llist *l);
static void output_interpreted_record(const lnode *n, const event *e);
static void feed_auparse(llist *l, auparse_callback_ptr callback);
static void interpret(char *name, char *val, int comma, int rtype);
static void csv_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);
static void text_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

/* The machine based on elf type */
static unsigned long machine = -1;
static int cur_syscall = -1;

/* The first syscall argument */
static unsigned long long a0, a1;

/* tracks state of interpretations */
static int loaded = 0;

void ausearch_load_interpretations(const lnode *n)
{
	if (loaded == 0) {
		_auparse_load_interpretations(n->interp);
		loaded = 1;
	}
}

void ausearch_free_interpretations(void)
{
	if (loaded) {
		_auparse_free_interpretations();
		loaded = 0;
	}
}

/* This function branches to the correct output format */
void output_record(llist *l)
{
	switch (report_format) {
		case RPT_RAW:
			output_raw(l);
			break;
		case RPT_DEFAULT:
			output_default(l);
			break;
		case RPT_INTERP:
			output_interpreted(l);
			break;
		case RPT_PRETTY:
			break;
		case RPT_CSV:
			feed_auparse(l, csv_event);
			break;
		case RPT_TEXT:
			feed_auparse(l, text_event);
			break;
		default:
			fprintf(stderr, "Report format error");
			exit(1);
	}
}

/* This function will output the record as is */
static void output_raw(llist *l)
{
	const lnode *n;

	list_first(l);
	n = list_get_cur(l);
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	do {
		// Only add the separator for enriched events.
		if (l->fmt == LF_ENRICHED)
			n->message[n->mlen] = AUDIT_INTERP_SEPARATOR;
		puts(n->message);
	} while ((n=list_next(l)));
}

/*
 * This function will take the linked list and format it for output. No
 * interpretation is performed. The output order is lifo for everything.
 */
static void output_default(llist *l)
{
	const lnode *n;

	list_last(l);
	n = list_get_cur(l);
	printf("----\ntime->%s", ctime(&l->e.sec));
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	if (n->type >= AUDIT_DAEMON_START && n->type < AUDIT_SYSCALL)
		puts(n->message); // No injection possible
	else {
		do {
			safe_print_string_n(n->message, n->mlen, 1);
		} while ((n=list_prev(l)));
	}
}

/*
 * This function will take the linked list and format it for output. 
 * Interpretation is performed to aid understanding of records. The output
 * order is lifo for everything.
 */
static void output_interpreted(llist *l)
{
	const lnode *n;

	list_last(l);
	n = list_get_cur(l);
	printf("----\n");
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	if (n->type >= AUDIT_DAEMON_START && n->type < AUDIT_SYSCALL) 
		output_interpreted_record(n, &(l->e));
	else {
		do {
			output_interpreted_record(n, &(l->e));
		} while ((n=list_prev(l)));
	}
}

/*
 * This function will cycle through a single record and lookup each field's
 * value that it finds. 
 */
static void output_interpreted_record(const lnode *n, const event *e)
{
	char *ptr, *str = n->message;
	int found, comma = 0;
	int num = n->type;
	struct tm *btm;
	char tmp[32];

	// Reset these because each record could be different
	machine = -1;
	cur_syscall = -1;

	/* Check and see if we start with a node
 	 * If we do, and there is a space in the line
 	 * move the pointer to the first character past
 	 * the space
  	 */
	if (e->node) {
		if ((ptr=strchr(str, ' ')) != NULL) {
			str = ptr+1;
		}
	}

	// First locate time stamp.
	ptr = strchr(str, '(');
	if (ptr == NULL) {
		fprintf(stderr, "can't find time stamp\n");
		return;
	}

	*ptr++ = 0;	/* move to the start of the timestamp */

	// print everything up to it.
	if (num >= 0) {
		const char	* bptr;
		bptr = audit_msg_type_to_name(num);
		if (bptr) {
			if (e->node)
				printf("node=%s ", e->node);
			printf("type=%s msg=audit(", bptr);
			goto no_print;
		}
	} 
	if (e->node)
		printf("node=%s ", e->node);
	printf("%s(", str);
no_print:

	str = strchr(ptr, ')');
	if(str == NULL)
		return;
	*str++ = 0;
	btm = localtime(&e->sec);
	if (btm)
		strftime(tmp, sizeof(tmp), "%x %T", btm);
	else
		strcpy(tmp, "?");
	printf("%s", tmp);
	printf(".%03u:%lu) ", e->milli, e->serial);

	if (n->type == AUDIT_SYSCALL) { 
		a0 = n->a0;
		a1 = n->a1;
	}

	// for each item.
	ausearch_load_interpretations(n);
	found = 0;
	while (str && *str && (ptr = strchr(str, '='))) {
		char *name, *val;
		comma = 0;
		found = 1;

		// look back to last space - this is name
		name = ptr;
		while (*name != ' ' && name > str)
			--name;
		*ptr++ = 0;

		// print everything up to the '='
		printf("%s=", str);

		// Some user messages have msg='uid=500   in this case
		// skip the msg= piece since the real stuff is the uid=
		if (strcmp(name, "msg") == 0) {
			str = ptr;
			continue;
		}

		// In the above case, after msg= we need to trim the ' from uid
		if (*name == '\'')
			name++;

		// get string after = to the next space or end - this is value
		if (*ptr == '\'' || *ptr == '"') {
			str = strchr(ptr+1, *ptr);
			if (str) {
				str++;
				if (*str)
					*str++ = 0;
			}
		} else {
			str = strchr(ptr, ',');
			val = strchr(ptr, ' ');
			if (str && val && (str < val)) {
			// Value side  has commas and another field exists
			// Known: LABEL_LEVEL_CHANGE banners=none,none
			// Known: ROLL_ASSIGN new-role=r,r
			// Known: any MAC LABEL can potentially have commas
				int ftype = auparse_interp_adjust_type(n->type,
								name, val);
				if (ftype == AUPARSE_TYPE_MAC_LABEL) {
					str = val;
					*str++ = 0;
				} else {
					*str++ = 0;
					comma = 1;
				}
			} else if (str && (val == NULL)) {
			// Goes all the way to the end. Done parsing
			// Known: MCS context in PATH rec obj=u:r:t:s0:c2,c7
				int ftype = auparse_interp_adjust_type(n->type,
								name, ptr);
				if (ftype == AUPARSE_TYPE_MAC_LABEL)
					str = NULL;
				else {
					*str++ = 0;
					comma = 1;
				}
			} else if (val) {
			// There is another field, point to next (normal path)
				str = val;
				*str++ = 0;
			}
		}
		// val points to begin & str 1 past end
		val = ptr;
		
		// print interpreted string
		interpret(name, val, comma, n->type);
	}
	ausearch_free_interpretations();

	// If nothing found, just print out as is
	if (!found && ptr == NULL && str)
		safe_print_string(str, 1);

	// If last field had comma, output the rest
	else if (comma)
		safe_print_string(str, 1);
	printf("\n");
}

static void interpret(char *name, char *val, int comma, int rtype)
{
	int type;
	idata id;

	while (*name == ' '||*name == '(')
		name++;

	if (*name == 'a' && strcmp(name, "acct") == 0) {
		// Remove trailing punctuation
		int len = strlen(val);
		if (val[len-1] == ':')
			val[len-1] = 0;
	}
	type = auparse_interp_adjust_type(rtype, name, val);

	if (rtype == AUDIT_SYSCALL || rtype == AUDIT_SECCOMP) {
		if (machine == (unsigned long)-1) 
			machine = audit_detect_machine();
		if (*name == 'a' && strcmp(name, "arch") == 0) {
			unsigned long ival;
			errno = 0;
			ival = strtoul(val, NULL, 16);
			if (errno) {
				printf("arch conversion error(%s) ", val);
				return;
			}
			machine = audit_elf_to_machine(ival);
		}
		if (cur_syscall < 0 && *name == 's' &&
				strcmp(name, "syscall") == 0) {
			unsigned long ival;
			errno = 0;
			ival = strtoul(val, NULL, 10);
			if (errno) {
				printf("syscall conversion error(%s) ", val);
				return;
			}
			cur_syscall = ival;
		}
		id.syscall = cur_syscall;
	} else
		id.syscall = 0;
	id.machine = machine;
	id.a0 = a0;
	id.a1 = a1;
	id.name = name;
	id.val = val;
	id.cwd = NULL;

	char *out = auparse_do_interpretation(type, &id, escape_mode);
	if (type == AUPARSE_TYPE_UNCLASSIFIED)
		printf("%s%c", val, comma ? ',' : ' ');
	else if (name[0] == 'k' && strcmp(name, "key") == 0) {
		char *str, *ptr = out;
		int count = 0;
		while ((str = strchr(ptr, AUDIT_KEY_SEPARATOR))) {
			*str = 0;
			if (count == 0) {
				printf("%s", ptr);
				count++;
			} else
				printf(" key=%s", ptr);
			ptr = str+1;
		}
		if (count == 0)
			printf("%s ", out);
		else
			printf(" key=%s ", ptr);
	} else if (type == AUPARSE_TYPE_TTY_DATA)
		printf("%s", out);
	else
		printf("%s ", out);

	free(out);
}

/* This function will output a normalized line of audit
 * fields one line per event in csv format */
static int csv_header_done = 0;
extern int extra_keys, extra_labels, extra_obj2, extra_time;
static void csv_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	if (csv_header_done == 0) {
		csv_header_done = 1;
		printf( "NODE,EVENT,DATE,TIME,%sSERIAL_NUM,EVENT_KIND,"
			"SESSION,SUBJ_PRIME,SUBJ_SEC,SUBJ_KIND,%sACTION,"
			"RESULT,OBJ_PRIME,OBJ_SEC,%s%sOBJ_KIND,HOW%s\n",
		    extra_time ? "YEAR,MONTH,DAY,WEEKDAY,HOUR,GMT_OFFSET," : "",
			extra_labels ? "SUBJ_LABEL," : "",
			extra_obj2 ? "OBJ2," : "",
			extra_labels ? "OBJ_LABEL," : "",
			extra_keys ? ",KEY" : "");
	}

	char tmp[20];
	const char *item, *type, *evkind, *subj_kind, *action, *str, *how;
	int rc;
	time_t t = auparse_get_time(au);
	struct tm *tv = localtime(&t);

	// NODE
	item = auparse_get_node(au);
	if (item) {
		printf("%s", auparse_interpret_field(au));
		free((void *)item);
	}
	putchar(',');

	// Event
	type = auparse_get_type_name(au);
	if (type)
		printf("%s", type);
	putchar(',');

	// Normalize
	rc = auparse_normalize(au,
			extra_labels ? NORM_OPT_ALL : NORM_OPT_NO_ATTRS);

	//DATE
	if (tv) {
		strftime(tmp, sizeof(tmp), "%x", tv);
		printf("%s", tmp);
	}
	putchar(',');

	// TIME
	if (tv) {
		strftime(tmp, sizeof(tmp), "%T", tv);
		printf("%s", tmp);
	}
	putchar(',');

	if (extra_time) {
		// YEAR
		if (tv) {
			strftime(tmp, sizeof(tmp), "%Y", tv);
			printf("%s", tmp);
		}
		putchar(',');

		// MONTH
		if (tv) {
			strftime(tmp, sizeof(tmp), "%m", tv);
			printf("%s", tmp);
		}
		putchar(',');

		// DAY
		if (tv) {
			strftime(tmp, sizeof(tmp), "%d", tv);
			printf("%s", tmp);
		}
		putchar(',');

		// WEEKDAY
		if (tv) {
			strftime(tmp, sizeof(tmp), "%u", tv);
			printf("%s", tmp);
		}
		putchar(',');

		// HOUR
		if (tv) {
			strftime(tmp, sizeof(tmp), "%k", tv);
			printf("%s", tmp);
		}
		putchar(',');
		if (tv) {
			char sign = tv->tm_gmtoff >= 0 ? '+' : '-';
			unsigned long total = labs(tv->tm_gmtoff);
			unsigned long hour = total/3600;
			unsigned long min = (total - (hour * 3600))%60;
			printf("%c%02lu:%02lu", sign, hour, min);
		}
		putchar(',');
	}

	// SERIAL_NUMBER
	printf("%lu,", auparse_get_serial(au));

	if (rc) {
		fprintf(stderr, "error normalizing %s\n", type);

		// Just dump an empty frame
		printf(",,,,,,,,,%s%s\n", extra_labels ? ",," : "",
			extra_keys ? "," : "");
		return;
	}

	// EVENT_KIND
	evkind = auparse_normalize_get_event_kind(au);
	printf("%s", evkind ? evkind : "unknown");
	putchar(',');

	// SESSION
	rc = auparse_normalize_session(au);
	if (rc == 1)
		printf("%s", auparse_interpret_field(au));
	putchar(',');

	// SUBJ_PRIME
	rc = auparse_normalize_subject_primary(au);
	if (rc == 1) {
		const char *subj = auparse_interpret_field(au);
		if (strcmp(subj, "unset") == 0)
			subj = "system";
		printf("%s", subj);
	}
	putchar(',');

	// SUBJ_SEC
	rc = auparse_normalize_subject_secondary(au);
	if (rc == 1)
		printf("%s", auparse_interpret_field(au));
	putchar(',');

	// SUBJ_KIND
	subj_kind = auparse_normalize_subject_kind(au);
	if (subj_kind)
		printf("%s", subj_kind);
	putchar(',');

	// SUBJ_LABEL
	if (extra_labels) {
		rc = auparse_normalize_subject_first_attribute(au);
		do {
			if (rc == 1) {
				const char *name = auparse_get_field_name(au);
				if (strcmp(name, "subj") == 0) {
					printf("%s",
						auparse_interpret_field(au));
					break;
				}
			}
		} while (auparse_normalize_subject_next_attribute(au) == 1);
		putchar(',');
	}

	// ACTION
	action = auparse_normalize_get_action(au);
	printf("%s", action ? action : "did-unknown");
	putchar(',');

	// RESULT
	rc = auparse_normalize_get_results(au);
	if (rc == 1) {
		int i = 0;
		const char *res[] = { "failed", "success" };
		item = auparse_interpret_field(au);
		if (strcmp(item, "yes") == 0)
			i = 1;
		else if (strncmp(item, "suc", 3) == 0)
			i = 1;
		else if (auparse_get_field_type(au) == AUPARSE_TYPE_SECCOMP &&
				strcmp(item, "allow") == 0)
			i = 1;
		printf("%s", res[i]);
	}
	putchar(',');

	// OBJ_PRIME
	rc = auparse_normalize_object_primary(au);
	if (rc == 1) {
		const char *val;

		if (auparse_get_field_type(au) == AUPARSE_TYPE_ESCAPED_FILE)
			val = auparse_interpret_realpath(au);
		else
			val = auparse_interpret_field(au);
		printf("%s", val);
	}
	putchar(',');

	// OBJ_SEC
	rc = auparse_normalize_object_secondary(au);
	if (rc == 1)
		printf("%s", auparse_interpret_field(au));
	putchar(',');

	// OBJECT 2
	if (extra_obj2) {
		rc = auparse_normalize_object_primary2(au);
		if (rc == 1) {
			const char *val;

			if (auparse_get_field_type(au) ==
						AUPARSE_TYPE_ESCAPED_FILE)
				val = auparse_interpret_realpath(au);
			else
				val = auparse_interpret_field(au);
			printf("%s", val);
		}
		putchar(',');
	}

	// OBJ_LABEL
	if (extra_labels) {
		rc = auparse_normalize_object_first_attribute(au);
		do {
			if (rc == 1) {
				const char *name = auparse_get_field_name(au);
				if (strcmp(name, "obj") == 0) {
					printf("%s",
						auparse_interpret_field(au));
					break;
				}
			}
		} while (auparse_normalize_object_next_attribute(au) == 1);
		putchar(',');
	}

	// OBJ_KIND
	str = auparse_normalize_object_kind(au);
	printf("%s,", str);

	// HOW
	how = auparse_normalize_how(au);
	if (how)
		printf("%s", how);

	// KEY
	if (extra_keys) {
		putchar(','); // This is to close out HOW
		rc = auparse_normalize_key(au);
		if (rc == 1)
			printf("%s", auparse_interpret_field(au));
	}
	printf("\n");
}


/* This function will output a normalized line of audit
 * fields one line per event as an english sentence */
static void text_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	char tmp[20];
        const char *item, *action, *how;
        int rc, type, id = -2;
        time_t t = auparse_get_time(au);
        struct tm *tv = localtime(&t);

	if (tv)
		strftime(tmp, sizeof(tmp), "%T %x", tv);
	else
		strcpy(tmp, "?");
	type = auparse_get_type(au);
	auparse_normalize(au, NORM_OPT_NO_ATTRS);
	item = auparse_get_node(au);
	if (item) {
		printf("On %s at %s ", auparse_interpret_field(au), tmp);
		free((void *)item);
	} else
		printf("At %s ", tmp);

	rc = auparse_normalize_subject_primary(au);
	if (rc == 1) {
		const char *subj = auparse_interpret_field(au);
		id = auparse_get_field_int(au);
		if (strcmp(subj, "unset") == 0)
			subj = "system";
		printf("%s", subj);
	}

	// Need to compare auid and uid before doing this
	rc = auparse_normalize_subject_secondary(au);
	if (rc == 1) {
		int uid = auparse_get_field_int(au);
		if (uid != id && id != -2)
			printf(", acting as %s,", auparse_interpret_field(au));
	}

	rc = auparse_normalize_get_results(au);
	if (rc == 1) {
		int i = 0;
		const char *res[] = { "unsuccessfully", "successfully" };
		item = auparse_interpret_field(au);
		if (strcmp(item, "yes") == 0)
			i = 1;
		else if (strncmp(item, "suc", 3) == 0)
			i = 1;
		else if (auparse_get_field_type(au) == AUPARSE_TYPE_SECCOMP &&
				strcmp(item, "allow") == 0)
			i = 1;
		printf(" %s ", res[i]);
	} else
		putchar(' ');

	action = auparse_normalize_get_action(au);

	if (event_debug) {
		if (action == NULL)
			printf("error on type:%d\n", type);
	}
	printf("%s ", action ? action : "did-unknown");

	rc = auparse_normalize_object_primary(au);
	if (rc == 1) {
		const char *val = NULL;
		int ftype;

		// If we have an object and this is an AVC, add some words
		if (action && strstr(action, "violated"))
			val = "accessing ";

		ftype = auparse_get_field_type(au);
		if (ftype == AUPARSE_TYPE_ESCAPED_FILE)
			val = auparse_interpret_realpath(au);
		else if (ftype == AUPARSE_TYPE_SOCKADDR) {
			val = auparse_interpret_sock_address(au);
			if (val == NULL)
				val = auparse_interpret_sock_family(au);
		}

		if (val == NULL)
			val = auparse_interpret_field(au);

		printf("%s ", val);
	}

	rc = auparse_normalize_object_primary2(au);
	if (rc == 1) {
		const char *val;

		if (auparse_get_field_type(au) == AUPARSE_TYPE_ESCAPED_FILE)
			val = auparse_interpret_realpath(au);
		else
			val = auparse_interpret_field(au);
		printf("to %s ", val);
	}

	how = auparse_normalize_how(au);
	if (how && action && *action != 'e')   // Don't print for ended-session
		printf("using %s", how);

	printf("\n");
}

/* This function will push an event into auparse. The callback arg will
 * perform all formatting for the intended report option. */
static auparse_state_t *au; 
static void feed_auparse(llist *l, auparse_callback_ptr callback)
{
	const lnode *n;

	list_first(l);
	n = list_get_cur(l);
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	au = auparse_init(AUSOURCE_FEED, 0);
	auparse_set_escape_mode(au, escape_mode);
	auparse_add_callback(au, callback, NULL, NULL);
	do {
		// Records need to be terminated by a newline
		// Temporarily replace it.
		if (l->fmt == LF_ENRICHED)
			n->message[n->mlen] = AUDIT_INTERP_SEPARATOR;
		n->message[n->tlen] = 0x0a;
		auparse_feed(au, n->message, n->tlen+1);
		if (l->fmt == LF_ENRICHED)
			n->message[n->mlen] = 0;
		n->message[n->tlen] = 0;
	} while ((n=list_next(l)));

	auparse_flush_feed(au);
	auparse_destroy(au);
}

