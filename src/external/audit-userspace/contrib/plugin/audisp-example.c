/* audisp-example.c --
 * Copyright 2012 Red Hat Inc., Durham, North Carolina.
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
 * This is a sample program to demonstrate several concepts of how to
 * write an audispd plugin using libauparse. It can be tested by using a
 * file of raw audit records. You can generate the test file like:
 *
 * ausearch --start today --raw > test.log.
 *
 * Then you can test this app by: cat test.log | ./audisp-example
 *
 * It will print things to stdout. In a real program, you wouldn't
 * do anything with stdout since that is likely to be pointing to /dev/null.
 *
 * Excluding some init/destroy items you might need to add to main, the 
 * event_handler function is the main place that you would modify to do
 * things specific to your plugin. 
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include "libaudit.h"
#include "auparse.h"

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static auparse_state_t *au = NULL;

/* Local declarations */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

/*
 * SIGTERM handler
 */
static void term_handler( int sig )
{
        stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler( int sig )
{
        hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

	/* Initialize the auparse library */
	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		printf("audisp-example is exiting due to auparse init errors");
		return -1;
	}
	auparse_add_callback(au, handle_event, NULL, NULL);
	do {
		fd_set read_mask;
		struct timeval tv;
		int retval = -1;

		/* Load configuration */
		if (hup) {
			reload_config();
		}
		do {
			/* If we timed out & have events, shake them loose */
			if (retval == 0 && auparse_feed_has_data(au))
				auparse_feed_age_events(au);

			tv.tv_sec = 3;
			tv.tv_usec = 0;
			FD_ZERO(&read_mask);
			FD_SET(0, &read_mask);
			if (auparse_feed_has_data(au))
				retval= select(1, &read_mask, NULL, NULL, &tv);
			else
				retval= select(1, &read_mask, NULL, NULL, NULL);
		} while (retval == -1 && errno == EINTR && !hup && !stop);

		/* Now the event loop */
		 if (!stop && !hup && retval > 0) {
			if (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH,
				stdin)) {
				auparse_feed(au, tmp, strnlen(tmp,
						MAX_AUDIT_MESSAGE_LENGTH));
			}
		}
		if (feof(stdin))
			break;
	} while (stop == 0);

	/* Flush any accumulated events from queue */
	auparse_flush_feed(au);
	auparse_destroy(au);
	if (stop)
		printf("audisp-example is exiting on stop request\n");
	else
		printf("audisp-example is exiting on stdin EOF\n");

	return 0;
}

/* This function shows how to dump a whole event by iterating over records */
static void dump_whole_event(auparse_state_t *au)
{
	auparse_first_record(au);
	do {
		printf("%s\n", auparse_get_record_text(au));
	} while (auparse_next_record(au) > 0);
	printf("\n");
}

/* This function shows how to dump a whole record's text */
static void dump_whole_record(auparse_state_t *au)
{
	printf("%s: %s\n", audit_msg_type_to_name(auparse_get_type(au)),
		auparse_get_record_text(au));
	printf("\n");
}

/* This function shows how to iterate through the fields of a record
 * and print its name and raw value and interpretted value. */
static void dump_fields_of_record(auparse_state_t *au)
{
	printf("record type %d(%s) has %d fields\n", auparse_get_type(au),
		audit_msg_type_to_name(auparse_get_type(au)),
		auparse_get_num_fields(au));

	printf("line=%d file=%s\n", auparse_get_line_number(au),
		auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");

	const au_event_t *e = auparse_get_timestamp(au);
	if (e == NULL) {
		printf("Error getting timestamp - aborting\n");
		return;
	}
	/* Note that e->sec can be treated as time_t data if you want
	 * something a little more readable */
	printf("event time: %u.%u:%lu, host=%s\n", (unsigned)e->sec,
		e->milli, e->serial, e->host ? e->host : "?");
		auparse_first_field(au);

	do {
		printf("field: %s=%s (%s)\n",
		auparse_get_field_name(au),
		auparse_get_field_str(au),
		auparse_interpret_field(au));
	} while (auparse_next_field(au) > 0);
	printf("\n");
}

/* This function receives a single complete event at a time from the auparse
 * library. This is where the main analysis code would be added. */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, num=0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	/* Loop through the records in the event looking for one to process.
	   We use physical record number because we may search around and
	   move the cursor accidentally skipping a record. */
	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		/* Now we can branch based on what record type we find.
		   This is just a few suggestions, but it could be anything. */
		switch (type) {
			case AUDIT_AVC:
				dump_fields_of_record(au);
				break;
			case AUDIT_SYSCALL:
				dump_whole_record(au); 
				break;
			case AUDIT_USER_LOGIN:
				break;
			case AUDIT_ANOM_ABEND:
				break;
			case AUDIT_MAC_STATUS:
				dump_whole_event(au); 
				break;
			default:
				break;
		}
		num++;
	}
}

