/* internal.h -- 
 * Copyright 2006-07,2013-17 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 * Authors:
 *	Steve Grubb <sgrubb@redhat.com>
 */
#ifndef AUPARSE_INTERNAL_HEADER
#define AUPARSE_INTERNAL_HEADER

#include "auparse-defs.h"
#include "ellist.h"
#include "auditd-config.h"
#include "data_buf.h"
#include "normalize-llist.h"
#include "dso.h"
#include <stdio.h>

/* This is what state the parser is in */
typedef enum { EVENT_EMPTY, EVENT_ACCUMULATING, EVENT_EMITTED } auparser_state_t;

/*
 * NOTES:
 * Auditd events are made up of one or more records. The auditd system cannot
 * guarantee that the set of records that make up an event will occur
 * atomically, that is the stream will have interleaved records of different
 * events. IE
 *      ...
 *      event0_record0
 *      event1_record0
 *      event1_record1
 *      event2_record0
 *      event1_record3
 *      event2_record1
 *      event1_record4
 *      event3_record0
 *      ...
 *      
 * The auditd system does guarantee that the records that make up an event will
 * appear in order. Thus, when processing event streams, we need to maintain
 * a list of events with their own list of records hence List of List (LOL)
 * event processing.
 *
 * When processing an event stream we define the end of an event via
 *      record type = AUDIT_EOE (audit end of event type record), or
 *      record type = AUDIT_PROCTITLE   (we note the AUDIT_PROCTITLE is always
 *                                      the last record), or
 *      record type < AUDIT_FIRST_EVENT (only single record events appear
 *                                      before this type), or
 *      record type >= AUDIT_FIRST_ANOM_MSG (only single record events appear
 *                                      after this type), or
 *      for the stream being processed, the time of the event is over 2 seconds
 *      old
 *
 * So, under LOL_EVENT processing, a event node (au_lolnode) can be either
 *
 * EBS_EMPTY: node is scheduled for emptying (freeing)
 * EBS_BUILDING: node is still building (awaiting more records and/or awaiting
 *               an End of Event action)
 * EBS_COMPLETE: node is complete and avaiable for use
 *
 * The old auparse() library processed events as they appeared and hence failed
 * to deal with interleaved records. The old library kept a 'current' event
 * which it would parse. This new LOL_EVENT code maintains the concept of a
 * 'current' event, but it now points to an event within the list of list 
 * events structure.
 */
typedef enum { EBS_EMPTY, EBS_BUILDING, EBS_COMPLETE } au_lol_t;

/*
 * Structure to hold an event and it's list of constituent records
 */
typedef struct _au_lolnode {
	event_list_t  *l;	/* the list of this event's records */
	au_lol_t      status;	/* this event's build state */
} au_lolnode;

/*
 * List of events being processed at any one time
 */
typedef struct {
	au_lolnode *array;	/* array of events */
	int         maxi;	/* largest index in array used */
	int         limit;	/* number of events in array */
} au_lol;

/*
 * The list is a dynamically growable list. We initally hold ARRAY_LIMIT
 * events and grow by ARRAY_LIMIT if we need to maintain more events at
 * any one time
 */

#define ARRAY_LIMIT     80

/* This is the name/value pair used by search tables */
struct nv_pair {
	int        value;
	const char *name;
};

typedef uint32_t value_t;

typedef struct subj
{
	value_t primary;        // typically auid
	value_t secondary;      // typically uid
	cllist attr;            // List of attributes
	const char *what;	// What the subject is
} subject;

typedef struct obj
{
	value_t primary;
	value_t secondary;
	value_t two;		// Sometimes we have a second e.g. rename/mount
	cllist attr;            // List of attributes
	unsigned int what;      // What the primary object is
} object;

typedef struct data
{
	const char *evkind;
	value_t session;
	subject actor;
	const char *action;
	object thing;
	value_t results;
	const char *how;
	normalize_option_t opt;
	value_t key;
} normalize_data;

struct opaque
{
	ausource_t source;		// Source type
	char **source_list;		// Array of buffers, or array of
					//	 file names
	int list_idx;			// The index into the source list
	FILE *in;			// If source is file, this is the fd
	unsigned int line_number;	// line number of current file, zero
					//	 if invalid
	char *next_buf;			// The current buffer being broken down
	unsigned int off;		// The current offset into next_buf
	char *cur_buf;			// The current buffer being parsed
	int line_pushed;		// True if retrieve_next_line() 
					//	returns same input
	event_list_t *le;		// Linked list of record in same event
	struct expr *expr;		// Search expression or NULL
	char *find_field;		// Used to store field name when
					//	 searching
	austop_t search_where;		// Where to put the cursors on a match
	auparser_state_t parse_state;	// parsing state
	DataBuf databuf;		// input data

	// function to call to notify user of parsing changes
	void (*callback)(struct opaque *au, auparse_cb_event_t cb_event_type,
			void *user_data);

	void *callback_user_data;	// user data supplied to callback

	// function to call when user_data is destroyed
	void (*callback_user_data_destroy)(void *user_data);
	
	au_lol *au_lo;		// List of events
	int au_ready;		// For speed, we note how many EBS_COMPLETE
				// events we hold at any point in time. Thus
				// we don't have to scan the list
	auparse_esc_t escape_mode;
	message_t message_mode;		// Where to send error messages
	debug_message_t debug_message;	// Whether or not messages are debug or not
	const char *tmp_translation;	// Pointer to manage mem for field translation
	normalize_data norm_data;
};

AUDIT_HIDDEN_START

// auditd-config.c
void clear_config(struct daemon_conf *config);
int aup_load_config(auparse_state_t *au, struct daemon_conf *config, log_test_t lt);
void free_config(struct daemon_conf *config);

// normalize.c
void init_normalizer(normalize_data *d);
void clear_normalizer(normalize_data *d);

AUDIT_HIDDEN_END

#endif

