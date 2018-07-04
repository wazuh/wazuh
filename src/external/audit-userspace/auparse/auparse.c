/* auparse.c --
 * Copyright 2006-08,2012-17 Red Hat Inc., Durham, North Carolina.
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
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include "expression.h"
#include "internal.h"
#include "auparse.h"
#include "interpret.h"
#include "auparse-idata.h"
#include "libaudit.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio_ext.h>

//#define LOL_EVENTS_DEBUG01	1	// add debug for list of list event
					// processing

#ifdef LOL_EVENTS_DEBUG01
static int debug = 0;
#endif

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
	init_interpretation_list();
}

/* like strchr except string is delimited by length, not null byte */
static char *strnchr(const char *s, int c, size_t n)
{
    char *p_char;
    const char *p_end = s + n;

    for (p_char = (char *)s; p_char < p_end && *p_char != c; p_char++);
    if (p_char == p_end) return NULL;
    return p_char;
}

static int setup_log_file_array(auparse_state_t *au)
{
        struct daemon_conf config;
        char *filename, **tmp;
        int len, num = 0, i = 0;

        /* Load config so we know where logs are */
	set_aumessage_mode(au, MSG_STDERR, DBG_NO);
	aup_load_config(au, &config, TEST_SEARCH);

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
		num++;
		snprintf(filename, len, "%s.%d", config.log_file, num);
	} while (1);

	if (num == 0) {
		fprintf(stderr, "No log file\n");
		free_config(&config);
		free(filename);
		return 1;
	}
	num--;
	tmp = malloc((num+2)*sizeof(char *));

        /* Got it, now process logs from last to first */
	if (num > 0)
		snprintf(filename, len, "%s.%d", config.log_file, num);
	else
		snprintf(filename, len, "%s", config.log_file);
	do {
		tmp[i++] = strdup(filename);

		/* Get next log file */
		num--;
		if (num > 0)
			snprintf(filename, len, "%s.%d", config.log_file, num);
		else if (num == 0)
			snprintf(filename, len, "%s", config.log_file);
		else
			break;
	} while (1);
	free_config(&config);
	free(filename);

	// Terminate the list
	tmp[i] = NULL; 
	au->source_list = tmp;
	return 0;
}


/*
 * au_lol_create - Create and initialise the base List of List event structure
 * Args:
 *   lol  - pointer to memory holding structure (eg the static au_lo variable)
 * Rtns:
 *   NULL - no memory
 *   ptr  - pointer to array of event nodes (au_lolnode)
 */
static au_lolnode *au_lol_create(au_lol *lol)
{
	int sz = ARRAY_LIMIT * sizeof(au_lolnode);

	lol->maxi = -1;
	lol->limit = ARRAY_LIMIT;
	if ((lol->array = (au_lolnode *)malloc(sz)) == NULL) {
		lol->maxi = -1;
		return NULL;
	}
	memset(lol->array, 0x00, sz);

	return lol->array;
}

/*
 * au_lol_clear - Free or rest the base List of List event structure
 *
 * Args:
 *  lol	- pointer to memory holding structure (eg the static au_lo variable)
 *  reset - flag to indicate a reset of the structure, or the complete
 *          freeing of memory
 * Rtns:
 *	void
 */
static void au_lol_clear(au_lol *lol, int reset)
{
	int i;

	if (lol->array) {
		for (i = 0; i <= lol->maxi; i++) {
			if (lol->array[i].l) {
				aup_list_clear(lol->array[i].l);
				free(lol->array[i].l);
			}
		}
	}
	if (reset) {
		/* If resetting, we just zero fields */
		if (lol->array)
			memset(lol->array, 0x00,
					lol->limit * sizeof(au_lolnode));
		lol->maxi = -1;
	} else {
		/* If not resetting, we free everything */
		if (lol->array) free(lol->array);
		lol->array = NULL;
		lol->maxi = -1;
	}
}

/*
 * au_lol_append - Add a new event to our base List of List structure
 *
 * Args:
 *  lol	- pointer to memory holding structure (eg the static au_lo variable)
 *  l	- event list structure (which contains an event's constituent records)
 * Rtns:
 *   ptr  - pointer to au_lolnode which holds the event list structure
 *   NULL - failed to reallocate memory
 */
static au_lolnode *au_lol_append(au_lol *lol, event_list_t *l)
{
	int i;
	size_t new_size;
	au_lolnode *ptr;

	for (i = 0; i < lol->limit; i++) {
		au_lolnode *cur = &lol->array[i];
		if (cur->status == EBS_EMPTY) {
			cur->l = l;
			cur->status = EBS_BUILDING;
			if (i > lol->maxi)
				lol->maxi = i;
			return cur;
		}
	}
	/* Over ran the array, make it bigger */
	new_size = sizeof(au_lolnode) * (lol->limit + ARRAY_LIMIT);
	ptr = realloc(lol->array, new_size);
	if (ptr) {
		lol->array = ptr;
		memset(&lol->array[lol->limit], 0x00,
				sizeof(au_lolnode) * ARRAY_LIMIT);
		lol->array[i].l = l;
		lol->array[i].status = EBS_BUILDING;
		lol->maxi = i;
		lol->limit += ARRAY_LIMIT;
	}
	return ptr;
}

/*
 * au_get_ready_event - Find the next COMPLETE event in our list and mark EMPTY
 *
 * Args:
 *  lol	- pointer to memory holding structure (eg the static au_lo variable)
 *  is_test - do not mark the node EMPTY
 * Rtns:
 *  ptr	- pointer to complete node (possibly just marked empty)
 *  NULL - no complete nodes exist
 */
static event_list_t *au_get_ready_event(auparse_state_t *au, int is_test)
{
        int i;
	au_lol *lol = au->au_lo;
	
	if (au->au_ready == 0) {
		//if (debug) printf("No events ready\n");
		return NULL;
	}

        for (i=0; i<=lol->maxi; i++) {
                au_lolnode *cur = &(lol->array[i]);
                if (cur->status == EBS_COMPLETE) {
			/*
			 * If we are just testing for a complete event, return
			 */
			if (is_test)
				return cur->l;
			/*
			 * Otherwise set it status to empty and accept the
			 * caller will take custody of the memory
			 */
                        cur->status = EBS_EMPTY;
			au->au_ready--;
                        return cur->l;
                }
        }

        return NULL;
}

/*
 * au_check_events  - Run though all events marking those we can mark COMPLETE
 *
 * Args:
 *  lol	- pointer to memory holding structure (eg the static au_lo variable)
 *  sec	- time of current event from stream being processed. We use this to see
 *        how old the events are we have in our list
 * Rtns:
 *	void
 */
static void au_check_events(auparse_state_t *au, time_t sec)
{
	rnode *r;
        int i;
	au_lol *lol = au->au_lo;

        for(i=0; i<=lol->maxi; i++) {
                au_lolnode *cur = &lol->array[i];
                if (cur->status == EBS_BUILDING) {
                        if ((r = aup_list_get_cur(cur->l)) == NULL)
				continue;
                        // If 2 seconds have elapsed, we are done
                        if (cur->l->e.sec + 2 < sec) {
                                cur->status = EBS_COMPLETE;
				au->au_ready++;
                        } else if ( // FIXME: Check this v remains true
				r->type == AUDIT_PROCTITLE ||
				r->type == AUDIT_EOE || 
				r->type < AUDIT_FIRST_EVENT ||
				r->type >= AUDIT_FIRST_ANOM_MSG ||
				r->type == AUDIT_KERNEL) {
                                // If known to be 1 record event, we are done
				cur->status = EBS_COMPLETE;
				au->au_ready++;
                        }
                }
        }
}

/*
 * au_terminate_all_events - Mark all events in 'BUILD' state to be COMPLETE
 *
 * Args:
 *  lol	- pointer to memory holding structure (eg the static au_lo variable)
 * Rtns:
 *  void
 */
static void au_terminate_all_events(auparse_state_t *au)
{
        int i;
	au_lol *lol = au->au_lo;

        for (i=0; i<=lol->maxi; i++) {
                au_lolnode *cur = &lol->array[i];
                if (cur->status == EBS_BUILDING) {
                        cur->status = EBS_COMPLETE;
			au->au_ready++;
			//if (debug) printf("%d events complete\n", au->au_ready);
                }
        }
}

#ifdef	LOL_EVENTS_DEBUG01
/*
 * print_list_t	- Print summary of event's records
 * Args:
 * 	l	- event_list to print
 * Rtns:
 *	void
 */
void print_list_t(event_list_t *l)
{
	rnode *r;

	if (l == NULL) {
		printf("\n");
		return;
	}
	printf("0x%X: %ld.%3.3u:%lu %s", l, l->e.sec, l->e.milli,
			l->e.serial, l->e.host ? l->e.host : "");
	printf(" cnt=%u", l->cnt);
	for (r = l->head; r != NULL; r = r->next) {
		printf(" {%d %d %u}", r->type, r->list_idx, r->line_number);
	}
	printf("\n");
}

/*
 * lol_status - return type of event state as a character
 * Args:
 *	s	- event state
 * Rtns:
 *	char	- E, B or C for EMPTY, BUILDING or COMPLETE, or '*' for unknown
 */
static char lol_status(au_lol_t s)
{
	switch(s) {
	case EBS_EMPTY: return 'E'; break;
	case EBS_BUILDING: return 'B'; break;
	case EBS_COMPLETE: return 'C'; break;
	}
	return '*';
}

/*
 * print_lol - Print a list of list events and their records
 * Args:
 *   label - String to act as label when printing
 *   lol   - pointer to memory holding structure (eg the static au_lo variable)
 * Rtns:
 *	void
 */
void print_lol(char *label, au_lol *lol)
{
	int  i;

	printf("%s 0x%X: a: 0x%X, %d, %d\n", label, lol, lol->array,
					lol->maxi, lol->limit);
	if (debug > 1) for (i = 0; i <= lol->maxi; i++) {
		printf("{%2d 0x%X %c } ", i, (&lol->array[i]),
					lol_status(lol->array[i].status));
		print_list_t(lol->array[i].l);
	}
	if (lol->maxi >= 0)
		printf("\n");
}
#endif	/* LOL_EVENTS_DEBUG01 */


/* General functions that affect operation of the library */
auparse_state_t *auparse_init(ausource_t source, const void *b)
{
	char **tmp, **bb = (char **)b, *buf = (char *)b;
	int n, i;
	size_t size, len;

	auparse_state_t *au = malloc(sizeof(auparse_state_t));
	if (au == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	au->le = NULL;

	/*
	 * Set up the List of List events base structure
	 */
	au->au_lo = calloc(sizeof(au_lol), 1);
	if (au->au_lo == NULL) {
		free(au);
		errno = ENOMEM;
		return NULL;
	}

	au_lol_clear(au->au_lo, 0);	// python doesn't call auparse_destroy
	if (au_lol_create(au->au_lo) == NULL) {
		free(au->au_lo);
		free(au);
		errno = ENOMEM;
		return NULL;
	}
	au->au_ready = 0;

	au->in = NULL;
	au->source_list = NULL;
	databuf_init(&au->databuf, 0, 0);
	au->callback = NULL;
	au->callback_user_data = NULL;
	au->callback_user_data_destroy = NULL;
	switch (source)
	{
		case AUSOURCE_LOGS:
			if (setup_log_file_array(au))
				goto bad_exit;
			break;
		case AUSOURCE_FILE:
			if (b == NULL)
				goto bad_exit;
			if (access(b, R_OK))
				goto bad_exit;
			tmp = malloc(2*sizeof(char *));
			tmp[0] = strdup(b);
			tmp[1] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_FILE_ARRAY:
			if (bb == NULL)
				goto bad_exit;
			n = 0;
			while (bb[n]) {
				if (access(bb[n], R_OK))
					goto bad_exit;
				n++;
			}
			tmp = malloc((n+1)*sizeof(char *));
			for (i=0; i<n; i++)
				tmp[i] = strdup(bb[i]);
			tmp[n] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_BUFFER:
			if (buf == NULL)
				goto bad_exit;
			len = strlen(buf);
			if (databuf_init(&au->databuf, len,
					 DATABUF_FLAG_PRESERVE_HEAD) < 0)
				goto bad_exit;
			if (databuf_append(&au->databuf, buf, len) < 0)
				goto bad_exit;
			break;
		case AUSOURCE_BUFFER_ARRAY:
			if (bb == NULL)
				goto bad_exit;
			size = 0;
			for (n = 0; (buf = bb[n]); n++) {
				len = strlen(bb[n]);
				if (bb[n][len-1] != '\n') {
					size += len + 1;
				} else {
					size += len;
				}
			}
			if (databuf_init(&au->databuf, size,
					DATABUF_FLAG_PRESERVE_HEAD) < 0)
				goto bad_exit;
			for (n = 0; (buf = bb[n]); n++) {
				len = strlen(buf);
				if (databuf_append(&au->databuf, buf, len) < 0)
					goto bad_exit;
			}
			break;
		case AUSOURCE_DESCRIPTOR:
			n = (long)b;
			au->in = fdopen(n, "rm");
			break;
		case AUSOURCE_FILE_POINTER:
			au->in = (FILE *)b;
			break;
		case AUSOURCE_FEED:
                    if (databuf_init(&au->databuf, 0, 0) < 0) goto bad_exit;
			break;
		default:
			errno = EINVAL;
			goto bad_exit;
			break;
	}
	au->source = source;
	au->list_idx = 0;
        au->line_number = 0;
	au->next_buf = NULL;
	au->off = 0;
	au->cur_buf = NULL;
	au->line_pushed = 0;
	au->parse_state = EVENT_EMPTY;
	au->expr = NULL;
	au->find_field = NULL;
	au->search_where = AUSEARCH_STOP_EVENT;
	au->escape_mode = AUPARSE_ESC_TTY;
	au->message_mode = MSG_QUIET;
	au->debug_message = DBG_NO;
	au->tmp_translation = NULL;
	init_normalizer(&au->norm_data);

	return au;
bad_exit:
	databuf_free(&au->databuf);
	/* Free list of events list (au_lo) structure */
	au_lol_clear(au->au_lo, 0);
	free(au->au_lo);
	free(au);
	return NULL;
}


void auparse_add_callback(auparse_state_t *au, auparse_callback_ptr callback,
			  void *user_data, user_destroy user_destroy_func)
{
	if (au == NULL) {
		errno = EINVAL;
		return;
	}

	if (au->callback_user_data_destroy) {
		(*au->callback_user_data_destroy)(au->callback_user_data);
		au->callback_user_data = NULL;
	}

	au->callback = callback;
	au->callback_user_data = user_data;
	au->callback_user_data_destroy = user_destroy_func;
}

static void consume_feed(auparse_state_t *au, int flush)
{
	//if (debug) printf("consume feed, flush %d\n", flush);
	while (auparse_next_event(au) > 0) {
		if (au->callback) {
			(*au->callback)(au, AUPARSE_CB_EVENT_READY,
					au->callback_user_data);
		}
	}
	if (flush) {
		// FIXME: might need a call here to force auparse_next_event()
		// to consume any partial data not fully consumed.

		/* Terminate all outstanding events, as we are at end of input
		 * (ie mark BUILDING events as COMPLETE events) then if we
		 * have a callback execute the callback on each event
		 * FIXME: Should we implement a 'checkpoint' concept as per
		 * ausearch or accept these 'partial' events?
		 */
		event_list_t	*l;

		//if (debug) printf("terminate all events in flush\n");
		au_terminate_all_events(au);
		while ((l = au_get_ready_event(au, 0)) != NULL) {
			rnode *r;
			au->le = l;  // make this current the event of interest
			aup_list_first(l);
			r = aup_list_get_cur(l);
			free_interpretation_list();
			load_interpretation_list(r->interp);
			aup_list_first_field(l);

			if (au->callback) {
				(*au->callback)(au, AUPARSE_CB_EVENT_READY,
					au->callback_user_data);
			}
		}
	}
}

int auparse_feed(auparse_state_t *au, const char *data, size_t data_len)
{
	if (databuf_append(&au->databuf, data, data_len) < 0)
		return -1;
	consume_feed(au, 0);
	return 0;
}

int auparse_flush_feed(auparse_state_t *au)
{
	consume_feed(au, 1);
	return 0;
}

// If there is data in the state machine, return 1
// Otherwise return 0 to indicate its empty
int auparse_feed_has_data(auparse_state_t *au)
{
	if (au_get_ready_event(au, 1) != NULL)
		return 1;

	return 0;
}

void auparse_feed_age_events(auparse_state_t *au)
{
	time_t t = time(NULL);
	au_check_events(au, t);
	consume_feed(au, 0);
}

void auparse_set_escape_mode(auparse_state_t *au, auparse_esc_t mode)
{
	if (au == NULL)
		return;
	au->escape_mode = mode;
}

/*
 * Non-public function. Subject to change.
 * buf is a string of name value pairs to be used for interpreting.
 * Calling this function automatically releases the previous list.
 */
void _auparse_load_interpretations(const char *buf)
{
	free_interpretation_list();

	if (buf == NULL)
		return;

	load_interpretation_list(buf);
}

/*
 * Non-public function. Subject to change.
 */
void _auparse_free_interpretations(void)
{
	free_interpretation_list();
}

int auparse_reset(auparse_state_t *au)
{
	if (au == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* Create or Free list of events list (au_lo) structure */
	if (au->au_lo->array == NULL)
		au_lol_create(au->au_lo);
	else
		au_lol_clear(au->au_lo, 1);

	au->parse_state = EVENT_EMPTY;
	switch (au->source)
	{
		case AUSOURCE_LOGS:
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			if (au->in) {
				fclose(au->in);
				au->in = NULL;
			}
		/* Fall through */
		case AUSOURCE_DESCRIPTOR:
		case AUSOURCE_FILE_POINTER:
			if (au->in) 
				rewind(au->in);
		/* Fall through */
		case AUSOURCE_BUFFER:
		case AUSOURCE_BUFFER_ARRAY:
			au->list_idx = 0;
			au->line_number = 0;
			au->off = 0;
			databuf_reset(&au->databuf);
			break;
		default:
			return -1;
	}
	free_interpretation_list();
	return 0;
}


/* Add EXPR to AU, using HOW to select the combining operator.
   On success, return 0.
   On error, free EXPR set errno and return -1.
   NOTE: EXPR is freed on error! */
static int add_expr(auparse_state_t *au, struct expr *expr, ausearch_rule_t how)
{
	if (au->expr == NULL)
		au->expr = expr;
	else if (how == AUSEARCH_RULE_CLEAR) {
		expr_free(au->expr);
		au->expr = expr;
	} else {
		struct expr *e;

		e = expr_create_binary(how == AUSEARCH_RULE_OR ? EO_OR : EO_AND,
				       au->expr, expr);
		if (e == NULL) {
			int err;

			err = errno;
			expr_free(expr);
			errno = err;
			return -1;
		}
		au->expr = e;
	}
	au->expr->started = 0;
	return 0;
}

static int ausearch_add_item_internal(auparse_state_t *au, const char *field,
	const char *op, const char *value, ausearch_rule_t how, unsigned op_eq,
	unsigned op_ne)
{
	struct expr *expr;

	// Make sure there's a field
	if (field == NULL)
		goto err_out;

	// Make sure how is within range
	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_out;

	// All pre-checks are done, build a rule
	if (strcmp(op, "exists") == 0)
		expr = expr_create_field_exists(field);
	else {
		unsigned t_op;

		if (strcmp(op, "=") == 0)
			t_op = op_eq;
		else if (strcmp(op, "!=") == 0)
			t_op = op_ne;
		else
			goto err_out;
		if (value == NULL)
			goto err_out;
		expr = expr_create_comparison(field, t_op, value);
	}
	if (expr == NULL)
		return -1;
	if (add_expr(au, expr, how) != 0)
		return -1; /* expr is freed by add_expr() */
	return 0;

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_add_item(auparse_state_t *au, const char *field, const char *op,
	const char *value, ausearch_rule_t how)
{
	return ausearch_add_item_internal(au, field, op, value, how, EO_RAW_EQ,
					  EO_RAW_NE);
}

int ausearch_add_interpreted_item(auparse_state_t *au, const char *field,
	const char *op, const char *value, ausearch_rule_t how)
{
	return ausearch_add_item_internal(au, field, op, value, how,
					  EO_INTERPRETED_EQ, EO_INTERPRETED_NE);
}

int ausearch_add_timestamp_item_ex(auparse_state_t *au, const char *op,
	time_t sec, unsigned milli, unsigned serial, ausearch_rule_t how)
{
	static const struct {
		unsigned value;
		const char name[3];
	} ts_tab[] = {
		{EO_VALUE_LT, "<"},
		{EO_VALUE_LE, "<="},
		{EO_VALUE_GE, ">="},
		{EO_VALUE_GT, ">"},
		{EO_VALUE_EQ, "="},
	};

	struct expr *expr;
        size_t i;
	unsigned t_op;

        for (i = 0; i < sizeof(ts_tab) / sizeof(*ts_tab); i++) {
                if (strcmp(ts_tab[i].name, op) == 0)
			goto found_op;
	}
	goto err_out;
found_op:
	t_op = ts_tab[i].value;

	if (milli >= 1000)
		goto err_out;

	// Make sure how is within range
	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_out;

	// All pre-checks are done, build a rule
	expr = expr_create_timestamp_comparison_ex(t_op, sec, milli, serial);
	if (expr == NULL)
		return -1;
	if (add_expr(au, expr, how) != 0)
		return -1; /* expr is freed by add_expr() */
	return 0;

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_add_timestamp_item(auparse_state_t *au, const char *op, time_t sec,
				unsigned milli, ausearch_rule_t how)
{
	return ausearch_add_timestamp_item_ex(au, op, sec, milli, 0, how);
}

int ausearch_add_expression(auparse_state_t *au, const char *expression,
			    char **error, ausearch_rule_t how)
{
	struct expr *expr;

	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_einval;

	expr = expr_parse(expression, error);
	if (expr == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (add_expr(au, expr, how) != 0)
		goto err; /* expr is freed by add_expr() */
	return 0;

err_einval:
	errno = EINVAL;
err:
	*error = NULL;
	return -1;
}

int ausearch_add_regex(auparse_state_t *au, const char *regexp)
{
	struct expr *expr;

	// Make sure there's an expression
	if (regexp == NULL)
		goto err_out;

	expr = expr_create_regexp_expression(regexp);
	if (expr == NULL)
		return -1;
	if (add_expr(au, expr, AUSEARCH_RULE_AND) != 0)
		return -1; /* expr is freed by add_expr() */
	return 0;

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_set_stop(auparse_state_t *au, austop_t where)
{
	if (where < AUSEARCH_STOP_EVENT || where > AUSEARCH_STOP_FIELD) {
		errno = EINVAL;
		return -1;
	}

	au->search_where = where;
	return 0;
}

void ausearch_clear(auparse_state_t *au)
{
	if (au->expr != NULL) {
		expr_free(au->expr);
		au->expr = NULL;
	}
	au->search_where = AUSEARCH_STOP_EVENT;
}

static void auparse_destroy_common(auparse_state_t *au)
{
	if (au == NULL)
		return;

	if (au->source_list) {
		int n = 0;
		while (au->source_list[n]) 
			free(au->source_list[n++]);
		free(au->source_list);
		au->source_list = NULL;
	}

	au->next_buf = NULL;
        free(au->cur_buf);
	au->cur_buf = NULL;
	au->le = NULL;
	au->parse_state = EVENT_EMPTY;
        free(au->find_field);
	au->find_field = NULL;
	ausearch_clear(au);
	databuf_free(&au->databuf);
	if (au->callback_user_data_destroy) {
		(*au->callback_user_data_destroy)(au->callback_user_data);
		au->callback_user_data = NULL;
	}
	if (au->in) {
		fclose(au->in);
		au->in = NULL;
	}
	free_interpretation_list();
	clear_normalizer(&au->norm_data);
	au_lol_clear(au->au_lo, 0);
	free((void *)au->tmp_translation);
	free(au->au_lo);
	free(au);
}

void auparse_destroy(auparse_state_t *au)
{
	aulookup_destroy_uid_list();
	aulookup_destroy_gid_list();

	auparse_destroy_common(au);
}

void auparse_destroy_ext(auparse_state_t *au, auparse_destroy_what_t what)
{
	if (what == AUPARSE_DESTROY_COMMON)
		auparse_destroy_common(au);
	else if (what == AUPARSE_DESTROY_ALL)
		auparse_destroy(au);
	return;
}

/* alloc a new buffer, cur_buf which contains a null terminated line
 * without a newline (note, this implies the line may be empty (strlen == 0)) if
 * successfully read a blank line (e.g. containing only a single newline).
 * cur_buf will have been newly allocated with malloc.
 * 
 * Note: cur_buf will be freed the next time this routine is called if
 * cur_buf is not NULL, callers who retain a reference to the cur_buf
 * pointer will need to set cur_buf to NULL to cause the previous cur_buf
 * allocation to persist.
 *
 * Returns:
 *     1 if successful (errno == 0)
 *     0 if non-blocking input unavailable (errno == 0)
 *    -1 if error (errno contains non-zero error code)
 *    -2 if EOF  (errno == 0)
 */

static int readline_file(auparse_state_t *au)
{
	ssize_t rc;
	char *p_last_char;
	size_t n = 0;

	if (au->cur_buf != NULL) {
		free(au->cur_buf);
		au->cur_buf = NULL;
	}
	if (au->in == NULL) {
		errno = EBADF;
		return -1;
	}
	if ((rc = getline(&au->cur_buf, &n, au->in)) <= 0) {
		// Note: getline always malloc's if lineptr==NULL or n==0,
		// on failure malloc'ed memory is left uninitialized,
		// caller must free it.
		free(au->cur_buf);
		au->cur_buf = NULL;

		// Note: feof() does not set errno
		if (feof(au->in)) {
			// return EOF condition
			errno = 0;
			return -2;
		}
		// return error condition, error code in errno
		return -1;
	}
	p_last_char = au->cur_buf + (rc-1);
	if (*p_last_char == '\n') {	/* nuke newline */
		*p_last_char = 0;
	}
	// return success
	errno = 0;
	return 1;
}


/* malloc & copy a line into cur_buf from the internal buffer,
 * next_buf.  cur_buf will contain a null terminated line without a
 * newline (note, this implies the line may be empty (strlen == 0)) if
 * successfully read a blank line (e.g. containing only a single
 * newline).
 * 
 * Note: cur_buf will be freed the next time this routine is called if
 * cur_buf is not NULL, callers who retain a reference to the cur_buf
 * pointer will need to set cur_buf to NULL to cause the previous cur_buf
 * allocation to persist.
 *
 * Returns:
 *     1 if successful (errno == 0)
 *     0 if non-blocking input unavailable (errno == 0)
 *    -1 if error (errno contains non-zero error code)
 *    -2 if EOF  (errno == 0)
 */

static int readline_buf(auparse_state_t *au)
{
	char *p_newline=NULL;
	size_t line_len;

	if (au->cur_buf != NULL) {
		free(au->cur_buf);
		au->cur_buf = NULL;
	}

	//if (debug) databuf_print(&au->databuf, 1, "readline_buf");
	if (au->databuf.len == 0) {
		// return EOF condition
		errno = 0;
		return -2;
	}

	if ((p_newline = strnchr(databuf_beg(&au->databuf), '\n',
						au->databuf.len)) != NULL) {
		line_len = p_newline - databuf_beg(&au->databuf);
		
		/* dup the line */
		au->cur_buf = malloc(line_len+1);   // +1 for null terminator
		if (au->cur_buf == NULL)
			return -1; // return error condition, errno set
		strncpy(au->cur_buf, databuf_beg(&au->databuf), line_len);
		au->cur_buf[line_len] = 0;

		if (databuf_advance(&au->databuf, line_len+1) < 0)
			return -1;
		// return success
		errno = 0;
		return 1;
	
	} else {
		// return no data available
		errno = 0;
		return 0;
	}
}

static int str2event(char *s, au_event_t *e)
{
	char *ptr;

	errno = 0;
	e->sec = strtoul(s, NULL, 10);
	if (errno)
		return -1;
	ptr = strchr(s, '.');
	if (ptr) {
		ptr++;
		e->milli = strtoul(ptr, NULL, 10);
		if (errno)
			return -1;
		s = ptr;
	} else
		e->milli = 0;
	
	ptr = strchr(s, ':');
	if (ptr) {
		ptr++;
		e->serial = strtoul(ptr, NULL, 10);
		if (errno)
			return -1;
	} else
		e->serial = 0;
	return 0;
}

/* Returns 0 on success and 1 on error */
static int extract_timestamp(const char *b, au_event_t *e)
{
	char *ptr, *tmp;
	int rc = 1;

        e->host = NULL;
	if (*b == 'n')
		tmp = strndupa(b, 340);
	else
		tmp = strndupa(b, 80);
	ptr = audit_strsplit(tmp);
	if (ptr) {
		// Optionally grab the node - may or may not be included
		if (*ptr == 'n') {
			e->host = strdup(ptr+5);
			(void)audit_strsplit(NULL);// Bump along to next one
		}
		// at this point we have type=
		ptr = audit_strsplit(NULL);
		if (ptr) {
			if (*(ptr+9) == '(')
				ptr+=9;
			else
				ptr = strchr(ptr, '(');
			if (ptr) {
				// now we should be pointed at the timestamp
				char *eptr;
				ptr++;
				eptr = strchr(ptr, ')');
				if (eptr)
					*eptr = 0;

				if (str2event(ptr, e) == 0)
					rc = 0;
			}
			// else we have a bad line
		}
		// else we have a bad line
	}
	if (rc)
		free((void *)e->host);

	// else we have a bad line
	return rc;
}

static int events_are_equal(au_event_t *e1, au_event_t *e2)
{
	// Check time & serial first since its most likely way
	// to spot 2 different events
	if (!(e1->serial == e2->serial && e1->milli == e2->milli &&
					e1->sec == e2->sec))
		return 0;
	// Hmm...same so far, check if both have a host, only a string
	// compare can tell if they are the same. Otherwise, if only one
	// of them have a host, they are definitely not the same. Its
	// a boundary on daemon config.
	if (e1->host && e2->host) {
		if (strcmp(e1->host, e2->host))
			return 0;
	} else if (e1->host || e2->host)
		return 0;
	return 1;
}

/* This function will figure out how to get the next line of input.
 * storing it cur_buf. cur_buf will be NULL terminated but will not
 * contain a trailing newline. This implies a successful read 
 * (result == 1) may result in a zero length cur_buf if a blank line
 * was read.
 *
 * cur_buf will have been allocated with malloc. The next time this
 * routine is called if cur_buf is non-NULL cur_buf will be freed,
 * thus if the caller wishes to retain a reference to malloc'ed
 * cur_buf data it should copy the cur_buf pointer and set cur_buf to
 * NULL.
 *
 * Returns:
 *     1 if successful (errno == 0)
 *     0 if non-blocking input unavailable (errno == 0)
 *    -1 if error (errno contains non-zero error code)
 *    -2 if EOF  (errno == 0)
 */

static int retrieve_next_line(auparse_state_t *au)
{
	int rc;

	// If line was pushed back for re-reading return that
	if (au->line_pushed) {
		// Starting new event, clear previous event data,
		// previous line is returned again for new parsing
		au->line_pushed = 0;
		au->line_number++;
		return 1;
	}

	switch (au->source)
	{
		case AUSOURCE_DESCRIPTOR:
		case AUSOURCE_FILE_POINTER:
			rc = readline_file(au);
			if (rc > 0) au->line_number++;
			return rc;
		case AUSOURCE_LOGS:
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			// if the first time through, open file
			if (au->list_idx == 0 && au->in == NULL &&
						au->source_list != NULL) {
				if (au->source_list[au->list_idx] == NULL) {
					errno = 0;
					return -2;
				}
				au->line_number = 0;
				au->in = fopen(au->source_list[au->list_idx],
									"rm");
				if (au->in == NULL)
					return -1;
				__fsetlocking(au->in, FSETLOCKING_BYCALLER);
			}

			// loop reading lines from a file
			while (au->in) {
				if ((rc = readline_file(au)) == -2) {
					// end of file, open next file,
					// try readline again
					fclose(au->in);
					au->in = NULL;
					au->list_idx++;
					au->line_number = 0;
					if (au->source_list[au->list_idx]) {
						au->in = fopen(
						  au->source_list[au->list_idx],
						  "rm");
						if (au->in == NULL)
							return -1;
						__fsetlocking(au->in,
							FSETLOCKING_BYCALLER);
					}
				} else {
					if (rc > 0)
						au->line_number++;
					return rc;
				}
			}
			return -2;	// return EOF
		case AUSOURCE_BUFFER:
		case AUSOURCE_BUFFER_ARRAY:
			rc = readline_buf(au);
			if (rc > 0)
				au->line_number++;
			return rc;
		case AUSOURCE_FEED:
			rc = readline_buf(au);
			// No such thing as EOF for feed, translate EOF
			// to data not available
			if (rc == -2)
				return 0;
			else
				if (rc > 0)
					au->line_number++;
			return rc;
		default:
			return -1;
	}
	return -1;		/* should never reach here */
}

/*******
* Functions that traverse events.
********/
static int ausearch_reposition_cursors(auparse_state_t *au)
{
	int rc = 0;

	switch (au->search_where)
	{
		case AUSEARCH_STOP_EVENT:
			aup_list_first(au->le);
			aup_list_first_field(au->le);
			break;
		case AUSEARCH_STOP_RECORD:
			aup_list_first_field(au->le);
			break;
		case AUSEARCH_STOP_FIELD:
			// do nothing - this is the normal stopping point
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

/* This is called during search once per each record. It walks the list
 * of nvpairs and decides if a field matches. */
static int ausearch_compare(auparse_state_t *au)
{
	rnode *r;

	if (au->le == NULL)
		return 0;

	r = aup_list_get_cur(au->le);
	if (r) {
		int res = expr_eval(au, r, au->expr);
		return res;
	}

	return 0;
}

// Returns < 0 on error, 0 no data, > 0 success
int ausearch_next_event(auparse_state_t *au)
{
	int rc;

	if (au->expr == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (au->expr->started == 0) {
		if ((rc = auparse_first_record(au)) <= 0)
			return rc;
		au->expr->started = 1;
	} else {
		if ((rc = auparse_next_event(au)) <= 0)
			return rc;
	}
        do {
		do {
			if ((rc = ausearch_compare(au)) > 0) {
				ausearch_reposition_cursors(au);
				return 1;
			} else if (rc < 0)
				return rc;
               	} while ((rc = auparse_next_record(au)) > 0);
		if (rc < 0)
			return rc;
        } while ((rc = auparse_next_event(au)) > 0);
	if (rc < 0)
		return rc;
	
	return 0;
}

/*
 * au_auparse_next_event - Get the next complete event
 * Args:
 * 	au - the parser state machine
 * Rtns:
 *	< 0	- error
 *	== 0	- no data
 *	> 0	- we have an event and it's set to the 'current event' au->le
 */
static int au_auparse_next_event(auparse_state_t *au)
{
	int rc, i, built;
	event_list_t *l;
	au_event_t e;

	/*
	 * Deal with Python memory management issues where it issues a
	 * auparse_destroy() call after an auparse_init() call but then wants
	 * to still work with auparse data. Basically, we assume if the user
	 * wants to parse for events (calling auparse_next_event()) we accept
	 * that they expect the memory structures to exist. This is a bit
	 * 'disconcerting' but the au_lol capability is a patch trying to
	 * redress a singleton approach to event processing.
	 */
	if (au->au_lo->array == NULL && au->au_lo->maxi == -1) {
#ifdef	LOL_EVENTS_DEBUG01
		if (debug) printf("Creating lol array\n");
#endif	/* LOL_EVENTS_DEBUG01 */
		au_lol_create(au->au_lo);
	}	

	/*
	 * First see if we have any empty events but with an allocated event
	 * list. These would have just been processed, so we can free them
	 */
	for (i = 0; i <= au->au_lo->maxi; i++) {
		au_lolnode *cur = &au->au_lo->array[i];
		if (cur->status == EBS_EMPTY && cur->l) {
#ifdef	LOL_EVENTS_DEBUG01
			if (debug) {printf("Freeing at start "); print_list_t(cur->l);}
#endif	/* LOL_EVENTS_DEBUG01 */
			aup_list_clear(cur->l);
			free(cur->l);
			au->le = NULL;	// this should crash any usage
					// of au->le until reset
			cur->l = NULL;
		}
	}
	/*
	 * Now see if we have completed events queued, and if so grab the
	 * first one and set it to be the 'current' event of interest
	 */
	if ((l = au_get_ready_event(au, 0)) != NULL) {
		rnode *r;

		aup_list_first(l);
		r = aup_list_get_cur(l);
		free_interpretation_list();
		load_interpretation_list(r->interp);
		aup_list_first_field(l);
		au->le = l;
#ifdef	LOL_EVENTS_DEBUG01
		if (debug) print_lol("upfront", au->au_lo);
#endif	/* LOL_EVENTS_DEBUG01 */
		return 1;
	}
	/*
	 * If no complete events are available, lets ingest
	 */
	while (1) {
		for (i = 0; i <= au->au_lo->maxi; i++) {
			au_lolnode *cur = &au->au_lo->array[i];
			if (cur->status == EBS_EMPTY && cur->l) {
#ifdef	LOL_EVENTS_DEBUG01
				if (debug) {printf("Freeing at loop"); print_list_t(cur->l);}
#endif	/* LOL_EVENTS_DEBUG01 */
				aup_list_clear(cur->l);
				free(cur->l);
				au->le = NULL;	/* this should crash any usage of au->le until reset */
				cur->l = NULL;
			}
		}
		rc = retrieve_next_line(au);
#ifdef	LOL_EVENTS_DEBUG01
		if (debug) printf("next_line(%d) '%s'\n", rc, au->cur_buf);
#endif	/* LOL_EVENTS_DEBUG01 */
		if (rc == 0) {
#ifdef	LOL_EVENTS_DEBUG01
			if (debug) printf("Empty line\n");
#endif	/* LOL_EVENTS_DEBUG01 */
			return 0;	/* NO data now */
		}
		if (rc == -2) {
			/*
			 * We are at EOF, so see if we have any accumulated
			 * events.
			 */
#ifdef	LOL_EVENTS_DEBUG01
			if (debug) printf("EOF\n");
#endif	/* LOL_EVENTS_DEBUG01 */
			au_terminate_all_events(au);
			if ((l = au_get_ready_event(au, 0)) != NULL) {
				rnode *r;

				aup_list_first(l);
				r = aup_list_get_cur(l);
				free_interpretation_list();
				load_interpretation_list(r->interp);
				aup_list_first_field(l);
				au->le = l;
#ifdef	LOL_EVENTS_DEBUG01
				if (debug) print_lol("eof termination",au->au_lo);
#endif	/* LOL_EVENTS_DEBUG01 */
				return 1;
			}
			return 0;
		} else if (rc < 0) {
#ifdef	LOL_EVENTS_DEBUG01
			/* Straight error */
			if (debug) printf("Error %d\n", rc);
#endif	/* LOL_EVENTS_DEBUG01 */
			return -1;
		}
		/* So we got a successful read ie rc > 0 */
		if (extract_timestamp(au->cur_buf, &e)) {
#ifdef	LOL_EVENTS_DEBUG01
			if (debug) printf("Malformed line:%s\n", au->cur_buf);
#endif	/* LOL_EVENTS_DEBUG01 */
			continue;
		}

		/*
		 * Is this an event we have already been building?
		 */
		built = 0;
		for (i = 0; i <= au->au_lo->maxi; i++) {
			au_lolnode *cur = &au->au_lo->array[i];
			if (cur->status == EBS_BUILDING) {
				if (events_are_equal(&cur->l->e, &e)) {
#ifdef	LOL_EVENTS_DEBUG01
					if (debug) printf("Adding event to building event\n");
#endif	/* LOL_EVENTS_DEBUG01 */
					aup_list_append(cur->l, au->cur_buf,
						au->list_idx, au->line_number);
					au->cur_buf = NULL;
					free((char *)e.host);
					au_check_events(au,  e.sec);
#ifdef	LOL_EVENTS_DEBUG01
					if (debug) print_lol("building",au->au_lo);
#endif	/* LOL_EVENTS_DEBUG01 */
					/* we built something, so break out */
					built++;
					break;
				}
			}
		}
		if (built)
			continue;

		/* So create one */
#ifdef	LOL_EVENTS_DEBUG01
		if (debug) printf("First record in new event, initialize event\n");
#endif	/* LOL_EVENTS_DEBUG01 */
		if ((l=(event_list_t *)malloc(sizeof(event_list_t))) == NULL) {
			free((char *)e.host);
			return -1;
		}
		aup_list_create(l);
		aup_list_set_event(l, &e);
		aup_list_append(l, au->cur_buf, au->list_idx, au->line_number);
		if (au_lol_append(au->au_lo, l) == NULL) {
			free((char *)e.host);
#ifdef	LOL_EVENTS_DEBUG01
			if (debug) printf("error appending to lol\n");
#endif	/* LOL_EVENTS_DEBUG01 */
			return -1;
		}
		au->cur_buf = NULL;
		free((char *)e.host);
		au_check_events(au,  e.sec);
		if ((l = au_get_ready_event(au, 0)) != NULL) {
			rnode *r;

			aup_list_first(l);
			r = aup_list_get_cur(l);
			free_interpretation_list();
			load_interpretation_list(r->interp);
			aup_list_first_field(l);
			au->le = l;
#ifdef	LOL_EVENTS_DEBUG01
			if (debug) print_lol("basic", au->au_lo);
#endif	/* LOL_EVENTS_DEBUG01 */
			return 1;
		}
	}
}

// Brute force go to next event. Returns < 0 on error, 0 no data, > 0 success
int auparse_next_event(auparse_state_t *au)
{
	clear_normalizer(&au->norm_data);
	return au_auparse_next_event(au);
}

/* Accessors to event data */
const au_event_t *auparse_get_timestamp(auparse_state_t *au)
{
	if (au && au->le && au->le->e.sec != 0)
		return &au->le->e;
	else
		return NULL;
}


time_t auparse_get_time(auparse_state_t *au)
{
	if (au && au->le)
		return au->le->e.sec;
	else
		return 0;
}


unsigned int auparse_get_milli(auparse_state_t *au)
{
	if (au && au->le)
		return au->le->e.milli;
	else
		return 0;
}


unsigned long auparse_get_serial(auparse_state_t *au)
{
	if (au && au->le)
		return au->le->e.serial;
	else
		return 0;
}


// Gets the machine node name
const char *auparse_get_node(auparse_state_t *au)
{
	if (au && au->le && au->le->e.host != NULL)
		return strdup(au->le->e.host);
	else
		return NULL;
}


int auparse_node_compare(au_event_t *e1, au_event_t *e2)
{
	// If both have a host, only a string compare can tell if they
	// are the same. Otherwise, if only one of them have a host, they
	// are definitely not the same. Its a boundary on daemon config.
	if (e1->host && e2->host) 
		return strcmp(e1->host, e2->host);
	else if (e1->host)
		return 1;
	else if (e2->host)
		return -1;

	return 0;
}


int auparse_timestamp_compare(au_event_t *e1, au_event_t *e2)
{
	if (e1->sec > e2->sec)
		return 1;
	if (e1->sec < e2->sec)
		return -1;

	if (e1->milli > e2->milli)
		return 1;
	if (e1->milli < e2->milli)
		return -1;

	if (e1->serial > e2->serial)
		return 1;
	if (e1->serial < e2->serial)
		return -1;

	return 0;
}

unsigned int auparse_get_num_records(auparse_state_t *au)
{
	// Its OK if au->le == NULL because get_cnt handles it
	return aup_list_get_cnt(au->le);
}

unsigned int auparse_get_record_num(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r) 
		return r->item;

	return 0;
}


/* Functions that traverse records in the same event */
int auparse_first_record(auparse_state_t *au)
{
	int rc;
	rnode *r;

	// Its OK if au->le == NULL because get_cnt handles it
	if (aup_list_get_cnt(au->le) == 0) {
		// This function loads interpretations
		rc = auparse_next_event(au);
		if (rc <= 0)
			return rc;
	}
	aup_list_first(au->le);
	r = aup_list_get_cur(au->le);
	free_interpretation_list();
	load_interpretation_list(r->interp);
	aup_list_first_field(au->le);
	
	return 1;
}

/*
 * Returns:	-1 if an error occurs,
 * 		0 if no more records in  current  event,
 *		1 for success.
 */
int auparse_next_record(auparse_state_t *au)
{
	rnode *r;

	free_interpretation_list();
	// Its OK if au->le == NULL because get_cnt handles it
	if (aup_list_get_cnt(au->le) == 0) { 
		int rc = auparse_first_record(au);
		if (rc <= 0)
			return rc;
	}
	r = aup_list_next(au->le);
	if (r) {
		load_interpretation_list(r->interp);
		return 1;
	} else
		return 0;
}


int auparse_goto_record_num(auparse_state_t *au, unsigned int num)
{
	rnode *r;

	/* Check if a request is out of range */
	free_interpretation_list();
	// Its OK if au->le == NULL because get_cnt handles it
	if (num >= aup_list_get_cnt(au->le))
		return 0;

	r = aup_list_goto_rec(au->le, num);
	if (r != NULL) {
		load_interpretation_list(r->interp);
		aup_list_first_field(au->le);
		return 1;
	} else
		return 0;
}


/* Accessors to record data */
int auparse_get_type(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r) 
		return r->type;
	else
		return 0;
}


const char *auparse_get_type_name(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	rnode *r = aup_list_get_cur(au->le);
	if (r)
		return audit_msg_type_to_name(r->type);
	else
		return NULL;
}


unsigned int auparse_get_line_number(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r) 
		return r->line_number;
	else
		return 0;
}


const char *auparse_get_filename(auparse_state_t *au)
{
	switch (au->source)
	{
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			break;
		default:
			return NULL;
	}

	if (au->le == NULL)
		return NULL;

	rnode *r = aup_list_get_cur(au->le);
	if (r) {
		if (r->list_idx < 0) return NULL;
		return au->source_list[r->list_idx];
	} else {
		return NULL;
	}
}


int auparse_first_field(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	return aup_list_first_field(au->le);
}


int auparse_next_field(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r) {
		if (nvlist_next(&r->nv))
			return 1;
		else
			return 0;
	}
	return 0;
}


unsigned int auparse_get_num_fields(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r)
		return nvlist_get_cnt(&r->nv);
	else
		return 0;
}

const char *auparse_get_record_text(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	rnode *r = aup_list_get_cur(au->le);
	if (r) 
		return r->record;
	else
		return NULL;
}

const char *auparse_get_record_interpretations(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	rnode *r = aup_list_get_cur(au->le);
	if (r) 
		return r->interp;
	else
		return NULL;
}


/* scan from current location to end of event */
const char *auparse_find_field(auparse_state_t *au, const char *name)
{
	if (au->le == NULL)
		return NULL;

	free(au->find_field);
	au->find_field = strdup(name);

	if (au->le->e.sec) {
		const char *cur_name;
		rnode *r;

		// look at current record before moving
		r = aup_list_get_cur(au->le);
		if (r == NULL)
			return NULL;
		cur_name = nvlist_get_cur_name(&r->nv);
		if (cur_name && strcmp(cur_name, name) == 0)
			return nvlist_get_cur_val(&r->nv);

		return auparse_find_field_next(au);
	}
	return NULL;
}

/* Increment 1 location and then scan for next field */
const char *auparse_find_field_next(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	if (au->find_field == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (au->le->e.sec) {
		int moved = 0;

		rnode *r = aup_list_get_cur(au->le);
		while (r) {	// For each record in the event...
			if (!moved) {
				nvlist_next(&r->nv);
				moved=1;
			}
			if (nvlist_find_name(&r->nv, au->find_field))
				return nvlist_get_cur_val(&r->nv);
			r = aup_list_next(au->le);
			if (r) {
				aup_list_first_field(au->le);
				load_interpretation_list(r->interp);
			}
		}
	}
	return NULL;
}


/* Accessors to field data */
unsigned int auparse_get_field_num(auparse_state_t *au)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r) {
		nvnode *n = nvlist_get_cur(&r->nv);
		if (n)
			return n->item;
	}
	return 0;
}

int auparse_goto_field_num(auparse_state_t *au, unsigned int num)
{
	if (au->le == NULL)
		return 0;

	rnode *r = aup_list_get_cur(au->le);
	if (r) {
		if (num >= r->nv.cnt)
			return 0;

		if ((nvlist_goto_rec(&r->nv, num)))
			return 1;
	}
	return 0;
}

const char *auparse_get_field_name(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	if (au->le->e.sec) {
		rnode *r = aup_list_get_cur(au->le);
		if (r) 
			return nvlist_get_cur_name(&r->nv);
	}
	return NULL;
}


const char *auparse_get_field_str(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	if (au->le->e.sec) {
		rnode *r = aup_list_get_cur(au->le);
		if (r) 
			return nvlist_get_cur_val(&r->nv);
	}
	return NULL;
}

int auparse_get_field_type(auparse_state_t *au)
{
	if (au->le == NULL)
		return AUPARSE_TYPE_UNCLASSIFIED;

        if (au->le->e.sec) {
                rnode *r = aup_list_get_cur(au->le);
                if (r)
                        return nvlist_get_cur_type(r);
        }
	return AUPARSE_TYPE_UNCLASSIFIED;
}

int auparse_get_field_int(auparse_state_t *au)
{
	const char *v = auparse_get_field_str(au);
	if (v) {
		int val;

		errno = 0;
		val = strtol(v, NULL, 10);
		if (errno == 0)
			return val;
	} else
		errno = ENODATA;
	return -1;
}

const char *auparse_interpret_field(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

	if (au->le->e.sec) {
		rnode *r = aup_list_get_cur(au->le);
		if (r) {
			r->cwd = NULL;
			return nvlist_interp_cur_val(r, au->escape_mode);
		}
	}
	return NULL;
}


const char *auparse_interpret_realpath(auparse_state_t *au)
{
	if (au->le == NULL)
		return NULL;

        if (au->le->e.sec) {
                rnode *r = aup_list_get_cur(au->le);
                if (r) {
			if (nvlist_get_cur_type(r) != AUPARSE_TYPE_ESCAPED_FILE)
				return NULL;

			// Tell it to make a realpath
			r->cwd = au->le->cwd;
                        return nvlist_interp_cur_val(r, au->escape_mode);
		}
        }
	return NULL;
}

static const char *auparse_interpret_sock_parts(auparse_state_t *au,
	const char *field)
{
	if (au->le == NULL)
		return NULL;

        if (au->le->e.sec) {
        	rnode *r = aup_list_get_cur(au->le);
		if (r == NULL)
			return NULL;
		// This is limited to socket address fields
		if (nvlist_get_cur_type(r) != AUPARSE_TYPE_SOCKADDR)
			return NULL;
		// Get interpretation
		const char *val = nvlist_interp_cur_val(r, au->escape_mode);
		if (val == NULL)
			return NULL;
		// make a copy since we modify it
		char *tmp = strdup(val);
		if (tmp == NULL)
			return NULL;
		// Locate the address part
		val = strstr(tmp, field);
		if (val) {
			// Get past the =
			val += strlen(field);
			// find other side
			char *ptr = strchr(val, ' ');
			if (ptr) {
				// terminate, copy, and return it
				*ptr = 0;
				const char *final = strdup(val);
				free(tmp);
				free((void *)au->tmp_translation);
				au->tmp_translation = final;
				return final;
			}
		}
		free(tmp);
        }
	return NULL;
}

const char *auparse_interpret_sock_family(auparse_state_t *au)
{
	return auparse_interpret_sock_parts(au, "fam=");
}

const char *auparse_interpret_sock_port(auparse_state_t *au)
{
	return auparse_interpret_sock_parts(au, "lport=");
}

const char *auparse_interpret_sock_address(auparse_state_t *au)
{
	return auparse_interpret_sock_parts(au, "laddr=");
}

