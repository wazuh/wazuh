/*
* expression.h - Expression parsing and handling
* Copyright (C) 2008,2014 Red Hat Inc., Durham, North Carolina.
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
*   Miloslav Trmač <mitr@redhat.com>
*   Steve Grubb <sgrubb@redhat.com>  extended timestamp
*/

#ifndef EXPRESSION_H__
#define EXPRESSION_H__

#include <regex.h>
#include <sys/types.h>

#include "internal.h"

enum {
	EO_NOT,			/* Uses v.sub[0] */
	EO_AND, EO_OR,		/* Uses v.sub[0] and v.sub[1] */
	/* All of the following use v.p */
	EO_RAW_EQ, EO_RAW_NE, EO_INTERPRETED_EQ, EO_INTERPRETED_NE,
	EO_VALUE_EQ, EO_VALUE_NE, EO_VALUE_LT, EO_VALUE_LE, EO_VALUE_GT,
	EO_VALUE_GE,
	/* Uses v.p.field.  Cannot be specified by an expression. */
	EO_FIELD_EXISTS,
	EO_REGEXP_MATCHES,	/* Uses v.regexp */
	NUM_EO_VALUES,
};

enum field_id {
	EF_TIMESTAMP, EF_RECORD_TYPE, EF_TIMESTAMP_EX
};

struct expr {
	unsigned op : 8;	/* EO_* */
	unsigned virtual_field : 1;
	/* Can be non-zero only if virtual_field != 0 */
	unsigned precomputed_value : 1;
	/* Decides if >= > < <= applies to field */
	unsigned numeric_field : 1;
	unsigned started : 1;
	union {
		struct expr *sub[2];
		struct {
			union {
				char *name;
				enum field_id id; /* If virtual_field != 0 */
			} field;
			union {
				char *string;
				/* A member from the following is selected
				   implicitly by field.id. */
				struct {
					time_t sec;
					unsigned int milli;
				} timestamp; /* EF_TIMESTAMP */
				struct {
					time_t sec;
					unsigned milli;
					unsigned serial;
				} timestamp_ex; /* EF_TIMESTAMP_EX */
				int int_value; /* EF_RECORD_TYPE */
			} value;
			uint32_t unsigned_val; /* UID & GID */
		} p;
		regex_t *regexp;
	} v;
};

AUDIT_HIDDEN_START

/* Free EXPR and all its subexpressions. */
void expr_free(struct expr *expr);

/* Parse STRING.
   On success, return the parsed expression tree.
   On error, set *ERROR to an error string (for free()) or NULL, and return
   NULL.  (*ERROR == NULL is allowed to handle out-of-memory errors) */
struct expr *expr_parse(const char *string, char **error);

/* Create a comparison-expression for FIELD, OP and VALUE.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *expr_create_comparison(const char *field, unsigned op,
				    const char *value);

/* Create a timestamp comparison-expression for with OP, SEC, MILLI.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *expr_create_timestamp_comparison(unsigned op, time_t sec,
					      unsigned milli);

/* Create an extended timestamp comparison-expression for with OP, SEC, 
   MILLI, and SERIAL.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *expr_create_timestamp_comparison_ex(unsigned op, time_t sec,
				      unsigned milli, unsigned serial);

/* Create an EO_FIELD_EXISTS-expression for FIELD.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *expr_create_field_exists(const char *field);

/* Create a \regexp expression for regexp comparison.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *expr_create_regexp_expression(const char *regexp);

/* Create a binary expresion for OP and subexpressions E1 and E2.
   On success, return the created expresion.
   On error, set errno and return NULL. */
struct expr *expr_create_binary(unsigned op, struct expr *e1, struct expr *e2);

/* Evaluate EXPR on RECORD in AU->le.
   Return 1 if EXPR is true, 0 if it false or if it fails.
   (No error reporting facility is provided; an invalid term is considered to
   be false; e.g. !invalid is true.) */
int expr_eval(auparse_state_t *au, rnode *record, const struct expr *expr);

AUDIT_HIDDEN_END

#endif
