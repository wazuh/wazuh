/*
* expression.c - Expression parsing and handling
* Copyright (C) 2008,2014,2016 Red Hat Inc., Durham, North Carolina.
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "expression.h"
#include "interpret.h"

/* Utilities */

/* Free EXPR and all its subexpressions. */
void
expr_free(struct expr *expr)
{
	switch (expr->op) {
	case EO_NOT:
		expr_free(expr->v.sub[0]);
		break;

	case EO_AND: case EO_OR:
		expr_free(expr->v.sub[0]);
		expr_free(expr->v.sub[1]);
		break;

	case EO_RAW_EQ: case EO_RAW_NE: case EO_INTERPRETED_EQ:
	case EO_INTERPRETED_NE: case EO_VALUE_EQ: case EO_VALUE_NE:
	case EO_VALUE_LT: case EO_VALUE_LE: case EO_VALUE_GT: case EO_VALUE_GE:
		if (expr->virtual_field == 0)
			free(expr->v.p.field.name);
		if (expr->precomputed_value == 0)
			free(expr->v.p.value.string);
		break;

	case EO_FIELD_EXISTS:
		assert(expr->virtual_field == 0);
		free(expr->v.p.field.name);
		break;

	case EO_REGEXP_MATCHES:
		regfree(expr->v.regexp);
		free(expr->v.regexp);
		break;

	default:
		abort();
	}
	free(expr);
}

/* Expression parsing. */

/* The formal grammar:

   start: or-expression

   or-expression: and-expression
   or-expression: or-expression || and-expression

   and-expression: primary-expression
   and-expression: and-expression && primary-expression

   primary-expression: ! primary-expression
   primary-expression: ( or-expression )
   primary-expression: comparison-expression

   comparison-expression: field op value
   comparison-expression: field-escape "regexp" regexp-value
   field: string
   field: field-escape string
   value: string
   regexp-value: string
   regexp-value: regexp */

/* Token types */
enum token_type {
	/* EO_* */
	T_LEFT_PAREN = NUM_EO_VALUES, T_RIGHT_PAREN, T_STRING, T_REGEXP,
	T_FIELD_ESCAPE, T_UNKNOWN, T_EOF
};

/* Expression parsing status */
struct parsing {
	char **error;		/* Error message destination. */
	enum token_type token;
	const char *token_start; /* Original "src" value */
	int token_len;		/* int because it must be usable in %.*s */
	char *token_value;	/* Non-NULL only for T_STRING, until used */
	const char *src;	/* Expression source, after the current token */
};

static struct expr *parse_or(struct parsing *p);

/* Allocate SIZE bytes.
   On error, return NULL and try to set *P->ERROR. */
static void *
parser_malloc(struct parsing *p, size_t size)
{
	void *res;

	res = malloc(size);
	if (res)
		return res;
	*p->error = strdup("Out of memory");
	return NULL;
}

/* Reallocate PTR to SIZE bytes.
   On error, free(PTR), return NULL and try to set *P->ERROR.
   NOTE: realloc() does not free(PTR), this function does. */
static void *
parser_realloc(struct parsing *p, void *ptr, size_t size)
{
	void *res;

	res = realloc(ptr, size);
	if (res != NULL || size == 0)
		return res;
	free(ptr);
	*p->error = strdup("Out of memory");
	return NULL;
}

/* Discard P->token_value, if any, and parse the next token in P->src.
   On success, return 0.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   -1. */
static int
lex(struct parsing *p)
{
	free(p->token_value);
	p->token_value = NULL;
	while (*p->src == ' ' || *p->src == '\t' || *p->src == '\n')
		p->src++;
	p->token_start = p->src;
	switch (*p->src) {
	case '\0':
		p->token = T_EOF;
		break;

	case '!':
		p->src++;
		if (*p->src == '=' && p->src[1] == '=') {
			p->src += 2;
			p->token = EO_VALUE_NE;
			break;
		}
		p->token = EO_NOT;
		break;

	case '"': case '/': {
		char *buf, delimiter;
		size_t dest, buf_size;

		delimiter = *p->src;
		buf_size = 8;
		buf = parser_malloc(p, buf_size);
		if (buf == NULL)
			return -1;
		p->src++;
		dest = 0;
		while (*p->src != delimiter) {
			if (*p->src == '\0') {
				*p->error = strdup("Terminating delimiter "
						   "missing");
				free(buf);
				return -1;
			}
			if (*p->src == '\\') {
				p->src++;
				if (*p->src != '\\' && *p->src != delimiter) {
					if (asprintf(p->error, "Unknown escape "
						     "sequence ``\\%c''",
						     *p->src) < 0)
						*p->error = NULL;
					free(buf);
					return -1;
				}
			}
			/* +1: make sure there is space for the terminating
			   NUL. */
			if (dest + 1 >= buf_size) {
				if (buf_size > SIZE_MAX / 2) {
					*p->error = strdup("Delimited string "
							   "too long");
					free(buf);
					return -1;
				}
				buf_size *= 2;
				buf = parser_realloc(p, buf, buf_size);
				if (buf == NULL) {
					*p->error = strdup("Out of memory");
					return -1;
				}
			}
			buf[dest] = *p->src;
			dest++;
			p->src++;
		}
		p->src++;
		buf[dest] = '\0';
		p->token_value = parser_realloc(p, buf, dest + 1);
		if (p->token_value == NULL)
			return -1;
		p->token = delimiter == '/' ? T_REGEXP : T_STRING;
		break;
	}

	case '&':
		p->src++;
		if (*p->src == '&') {
			p->src++;
			p->token = EO_AND;
			break;
		}
		p->token = T_UNKNOWN;
		break;

	case '(':
		p->src++;
		p->token = T_LEFT_PAREN;
		break;

	case ')':
		p->src++;
		p->token = T_RIGHT_PAREN;
		break;

	case '<':
		p->src++;
		if (*p->src == '=') {
			p->src++;
			p->token = EO_VALUE_LE;
			break;
		}
		p->token = EO_VALUE_LT;
		break;

	case '=':
		p->src++;
		if (*p->src == '=') {
			p->src++;
			p->token = EO_VALUE_EQ;
			break;
		}
		p->token = T_UNKNOWN;
		break;

	case '>':
		p->src++;
		if (*p->src == '=') {
			p->src++;
			p->token = EO_VALUE_GE;
			break;
		}
		p->token = EO_VALUE_GT;
		break;

	case '\\':
		p->src++;
		p->token = T_FIELD_ESCAPE;
		break;

	case '|':
		p->src++;
		if (*p->src == '|') {
			p->src++;
			p->token = EO_OR;
			break;
		}
		p->token = T_UNKNOWN;
		break;

	case 'i':
		if (p->src[1] == '=') {
			p->src += 2;
			p->token = EO_INTERPRETED_EQ;
			break;
		} else if (p->src[1] == '!' && p->src[2] == '=') {
			p->src += 3;
			p->token = EO_INTERPRETED_NE;
			break;
		}
		goto unquoted_string;

	case 'r':
		if (p->src[1] == '=') {
			p->src += 2;
			p->token = EO_RAW_EQ;
			break;
		} else if (p->src[1] == '!' && p->src[2] == '=') {
			p->src += 3;
			p->token = EO_RAW_NE;
			break;
		}
		goto unquoted_string;

	default:
		/* This assumes ASCII */
		assert ('Z' == 'A' + 25 && 'z' == 'a' + 25);
#define IS_UNQUOTED_STRING_CHAR(C)			\
			(((C) >= 'a' && (C) <= 'z')	\
			 || ((C) >= 'A' && (C) <= 'Z')	\
			 || ((C) >= '0' && (C) <= '9')	\
			 || (C) == '_' || (C) == '-')
		if (IS_UNQUOTED_STRING_CHAR(*p->src)) {
			size_t len;

		unquoted_string:
			do
				p->src++;
			while (IS_UNQUOTED_STRING_CHAR(*p->src));
			len = p->src - p->token_start;
			p->token_value = parser_malloc(p, len + 1);
			if (p->token_value == NULL)
				return -1;
			memcpy(p->token_value, p->token_start, len);
			p->token_value[len] = '\0';
			p->token = T_STRING;
			break;
		}
		p->src++;
		p->token = T_UNKNOWN;
		break;
	}
	if (p->src - p->token_start > INT_MAX) {
		*p->error = strdup("Token too long");
		return -1;
	}
	p->token_len = p->src - p->token_start;
	return 0;
}

/* Parse an escaped field NAME to DEST.
   Return 0 on success, -1 if NAME is unknown. */
static int
parse_escaped_field_name(enum field_id *dest, const char *name)
{
	if (strcmp(name, "timestamp") == 0)
		*dest = EF_TIMESTAMP;
	else if (strcmp(name, "record_type") == 0)
		*dest = EF_RECORD_TYPE;
	else if (strcmp(name, "timestamp_ex") == 0)
		*dest = EF_TIMESTAMP_EX;
	else 
		return -1;

	return 0;
}

/* Parse a \timestamp field value in P->token_value to DEST.
   On success, return 0.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   -1. */
static int
parse_timestamp_value(struct expr *dest, struct parsing *p)
{
	intmax_t sec;

	assert(p->token == T_STRING);
	/*
	 * On a timestamp field we will do all the parsing ourselves
	 * rather than use lex(). At the end we will move the internal cursor.
	 */
	if (sscanf(p->token_start, "ts:%jd.%u:%u", &sec,
		   &dest->v.p.value.timestamp_ex.milli,
		   &dest->v.p.value.timestamp_ex.serial) != 3) {
		if (sscanf(p->token_start, "ts:%jd.%u", &sec,
			   &dest->v.p.value.timestamp.milli) != 2) {
			if (asprintf(p->error, "Invalid timestamp value `%.*s'",
				     p->token_len, p->token_start) < 0)
				*p->error = NULL;
			return -1;
		}
	}

	/* Move the cursor past what we parsed. */
	size_t num = strspn(p->token_start, "ts:0123456789.");
	p->src = p->token_start + num;

	/* FIXME: validate milli */
	dest->v.p.value.timestamp.sec = sec;
	if (dest->v.p.value.timestamp.sec != sec) {
		if (asprintf(p->error, "Timestamp overflow in `%.*s'",
			     p->token_len, p->token_start) < 0)
			*p->error = NULL;
		return -1;
	}
	dest->precomputed_value = 1;
	return 0;
}

/* Parse a \record_type field value in P->token_value to DEST.
   On success, return 0.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   -1. */
static int
parse_record_type_value(struct expr *dest, struct parsing *p)
{
	int type;

	assert(p->token == T_STRING);
	type = audit_name_to_msg_type(p->token_value);
	if (type < 0) {
		if (asprintf(p->error, "Invalid record type `%.*s'",
			     p->token_len, p->token_start) < 0)
			*p->error = NULL;
		return -1;
	}
	dest->v.p.value.int_value = type;
	dest->precomputed_value = 1;
	return 0;
}

/* Parse a uid/gid field value in P->token_value to DEST.
   On success, return 0.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   -1. */
static int
parse_unsigned_value(struct expr *dest, struct parsing *p)
{
	uint32_t val;

	assert(p->token == T_STRING);
	errno = 0;
	val = strtoul(p->token_value, NULL, 10);
	if (errno) {
		if (asprintf(p->error, "Error converting number `%.*s'",
			     p->token_len, p->token_start) < 0)
			*p->error = NULL;
		return -1;
	}
	dest->v.p.unsigned_val = val;
	dest->precomputed_value = 1;
	return 0;
}

/* Parse a virtual field value in P->token_value to DEST.
   On success, return 0.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   NULL. */
static int
parse_virtual_field_value(struct expr *dest, struct parsing *p)
{
	switch (dest->v.p.field.id) {
	case EF_TIMESTAMP:
		return parse_timestamp_value(dest, p);

	case EF_RECORD_TYPE:
		return parse_record_type_value(dest, p);

	case EF_TIMESTAMP_EX:
		return parse_timestamp_value(dest, p);

	default:
		abort();
	}
}

/* Parse a \regexp comparison-expression string in *P, with \regexp parsed.
   Use or free EXPR.
   On success, return the parsed comparison-expression.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   NULL. */
static struct expr *
parse_comparison_regexp(struct parsing *p, struct expr *res)
{
	int err;

	if (lex(p) != 0)
		goto err_res;
	if (p->token != T_STRING && p->token != T_REGEXP) {
		if (asprintf(p->error, "Regexp expected, got `%.*s'",
			     p->token_len, p->token_start) < 0)
			*p->error = NULL;
		goto err_res;
	}
	res->v.regexp = parser_malloc(p, sizeof(*res->v.regexp));
	if (res->v.regexp == NULL)
		goto err_res;
	err = regcomp(res->v.regexp, p->token_value, REG_EXTENDED | REG_NOSUB);
	if (err != 0) {
		size_t err_size;
		char *err_msg;

		err_size = regerror(err, res->v.regexp, NULL, 0);
		err_msg = parser_malloc(p, err_size);
		if (err_msg == NULL)
			goto err_res_regexp;
		regerror(err, res->v.regexp, err_msg, err_size);
		if (asprintf(p->error, "Invalid regexp: %s", err_msg) < 0)
			*p->error = NULL;
		free(err_msg);
		goto err_res_regexp;
	}
	res->op = EO_REGEXP_MATCHES;
	if (lex(p) != 0) {
		expr_free(res);
		return NULL;
	}
	return res;

err_res_regexp:
	free(res->v.regexp);
err_res:
	free(res);
	return NULL;
}

/* Parse a comparison-expression string in *P.
   On success, return the parsed comparison-expression.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   NULL. */
static struct expr *
parse_comparison(struct parsing *p)
{
	struct expr *res;

	res = parser_malloc(p, sizeof(*res));
	if (res == NULL)
		return NULL;
	res->numeric_field = 0;
	if (p->token == T_FIELD_ESCAPE) {
		if (lex(p) != 0)
			goto err_res;
		if (p->token != T_STRING) {
			*p->error = strdup("Field name expected after field "
					   "escape");
			goto err_res;
		}
		if (strcmp(p->token_value, "regexp") == 0)
			return parse_comparison_regexp(p, res);
		res->virtual_field = 1;
		res->numeric_field = 1;
		if (parse_escaped_field_name(&res->v.p.field.id, p->token_value)
		    != 0) {
			if (asprintf(p->error,
				     "Unknown escaped field name `%.*s'",
				     p->token_len, p->token_start) < 0)
				*p->error = NULL;
			goto err_res;
		}
	} else {
		assert(p->token == T_STRING);
		res->virtual_field = 0;
		res->v.p.field.name = p->token_value;
		int type = lookup_type(p->token_value);
		if (type == AUPARSE_TYPE_UID || type == AUPARSE_TYPE_GID)
			res->numeric_field = 1;
		p->token_value = NULL;
	}
	if (lex(p) != 0)
		goto err_field;
	switch (p->token) {
	case EO_RAW_EQ: case EO_RAW_NE: case EO_INTERPRETED_EQ:
	case EO_INTERPRETED_NE:
		res->op = p->token;
		if (lex(p) != 0)
			goto err_field;
		if (p->token != T_STRING) {
			if (asprintf(p->error, "Value expected, got `%.*s'",
				     p->token_len, p->token_start) < 0)
				*p->error = NULL;
			goto err_field;
		}
		res->precomputed_value = 0;
		res->v.p.value.string = p->token_value;
		p->token_value = NULL;
		if (lex(p) != 0) {
			expr_free(res);
			return NULL;
		}
		break;

	case EO_VALUE_EQ: case EO_VALUE_NE: case EO_VALUE_LT: case EO_VALUE_LE:
	case EO_VALUE_GT: case EO_VALUE_GE:
		res->op = p->token;
		if (lex(p) != 0)
			goto err_field;
		if (p->token != T_STRING) {
			if (asprintf(p->error, "Value expected, got `%.*s'",
				     p->token_len, p->token_start) < 0)
				*p->error = NULL;
			goto err_field;
		}
		if (res->numeric_field == 0) {
			if (asprintf(p->error, "Field `%s' does not support "
				     "value comparison",
				     res->v.p.field.name) < 0)
				*p->error = NULL;
			goto err_field;
		} else {
			if (res->virtual_field) {
				if (parse_virtual_field_value(res, p) != 0)
					goto err_field;
			} else {
				if (parse_unsigned_value(res, p) != 0)
					goto err_field;
			}
		}
		if (lex(p) != 0) {
			expr_free(res);
			return NULL;
		}
		break;

	default:
		if (asprintf(p->error, "Operator expected, got `%.*s'",
			     p->token_len, p->token_start) < 0)
			*p->error = NULL;
		goto err_field;
	}
	return res;

err_field:
	if (res->virtual_field == 0)
		free(res->v.p.field.name);
err_res:
	free(res);
	return NULL;
}

/* Parse a primary-expression string in *P.
   On success, return the parsed primary-expression.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   NULL. */
static struct expr *
parse_primary(struct parsing *p)
{
	struct expr *e;

	switch (p->token) {
	case EO_NOT: {
		struct expr *res;

		if (lex(p) != 0)
			return NULL;
		e = parse_primary(p);
		if (e == NULL)
			return NULL;
		res = parser_malloc(p, sizeof(*res));
		if (res == NULL)
			goto err_e;
		res->op = EO_NOT;
		res->v.sub[0] = e;
		return res;
	}

	case T_LEFT_PAREN: {
		if (lex(p) != 0)
			return NULL;
		e = parse_or(p);
		if (e == NULL)
			return NULL;
		if (p->token != T_RIGHT_PAREN) {
			if (asprintf(p->error,
				     "Right paren expected, got `%.*s'",
				     p->token_len, p->token_start) < 0)
				*p->error = NULL;
			goto err_e;
		}
		if (lex(p) != 0)
			goto err_e;
		return e;
	}

	case T_FIELD_ESCAPE: case T_STRING:
		return parse_comparison(p);

	default:
		if (asprintf(p->error, "Unexpected token `%.*s'", p->token_len,
			     p->token_start) < 0)
			*p->error = NULL;
		return NULL;
	}
err_e:
	expr_free(e);
	return NULL;
}

/* Parse an and-expression string in *P.
   On success, return the parsed and-expression.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   NULL. */
static struct expr *
parse_and(struct parsing *p)
{
	struct expr *res;

	res = parse_primary(p);
	if (res == NULL)
		return NULL;
	while (p->token == EO_AND) {
		struct expr *e2, *e;

		if (lex(p) != 0)
			goto err_res;
		e2 = parse_primary(p);
		if (e2 == NULL)
			goto err_res;
		e = parser_malloc(p, sizeof(*e));
		if (e == NULL) {
			expr_free(e2);
			goto err_res;
		}
		e->op = EO_AND;
		e->v.sub[0] = res;
		e->v.sub[1] = e2;
		res = e;
	}
	return res;

err_res:
	expr_free(res);
	return NULL;
}

/* Parse an or-expression string in *P.
   On success, return the parsed or-expression.
   On error, set *P->ERROR to an error string (for free()) or NULL, and return
   NULL. */
static struct expr *
parse_or(struct parsing *p)
{
	struct expr *res;

	res = parse_and(p);
	if (res == NULL)
		return NULL;
	while (p->token == EO_OR) {
		struct expr *e2, *e;

		if (lex(p) != 0)
			goto err_res;
		e2 = parse_and(p);
		if (e2 == NULL)
			goto err_res;
		e = parser_malloc(p, sizeof(*e));
		if (e == NULL) {
			expr_free(e2);
			goto err_res;
		}
		e->op = EO_OR;
		e->v.sub[0] = res;
		e->v.sub[1] = e2;
		res = e;
	}
	return res;

err_res:
	expr_free(res);
	return NULL;
}

/* Parse STRING.
   On success, return the parsed expression tree.
   On error, set *ERROR to an error string (for free()) or NULL, and return
   NULL.  (*ERROR == NULL is allowed to handle out-of-memory errors) */
struct expr *
expr_parse(const char *string, char **error)
{
	struct parsing p;
	struct expr *res;

	p.error = error;
	p.token_value = NULL;
	p.src = string;
	if (lex(&p) != 0)
		goto err;
	if (p.token == T_EOF) {
		*error = strdup("Empty expression");
		goto err;
	}
	res = parse_or(&p);
	if (res != NULL && p.token != T_EOF) {
		expr_free(res);
		if (asprintf(error, "Unexpected trailing token `%.*s'",
			     p.token_len, p.token_start) < 0)
			*error = NULL;
		goto err;
	}
	free(p.token_value);
	return res;

err:
	free(p.token_value);
	return NULL;
}

 /* Manual expression creation */

/* Create a comparison-expression for FIELD, OP and VALUE.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *
expr_create_comparison(const char *field, unsigned op, const char *value)
{
	struct expr *res;

	res = calloc(sizeof(struct expr), 1);
	if (res == NULL)
		goto err;
	assert(op == EO_RAW_EQ || op == EO_RAW_NE || op == EO_INTERPRETED_EQ
	       || op == EO_INTERPRETED_NE);
	res->op = op;
	res->virtual_field = 0;
	res->precomputed_value = 0;
	res->v.p.field.name = strdup(field);
	if (res->v.p.field.name == NULL)
		goto err_res;
	res->v.p.value.string = strdup(value);
	if (res->v.p.value.string == NULL)
		goto err_field;
	return res;

err_field:
	free(res->v.p.field.name);
err_res:
	free(res);
err:
	return NULL;
}

/* Create an extended timestamp comparison-expression for with OP, SEC, 
   MILLI, and SERIAL.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *
expr_create_timestamp_comparison_ex(unsigned op, time_t sec, unsigned milli,
	unsigned serial)
{
	struct expr *res;

	res = calloc(sizeof(struct expr), 1);
	if (res == NULL)
		return NULL;
	assert(op == EO_VALUE_EQ || op == EO_VALUE_NE || op == EO_VALUE_LT
	       || op == EO_VALUE_LE || op == EO_VALUE_GT || op == EO_VALUE_GE);
	res->op = op;
	res->virtual_field = 1;
	res->numeric_field = 1;
	res->v.p.field.id = EF_TIMESTAMP_EX;
	res->precomputed_value = 1;
	res->v.p.value.timestamp_ex.sec = sec;
	assert(milli < 1000);
	res->v.p.value.timestamp_ex.milli = milli;
	res->v.p.value.timestamp_ex.serial = serial;
	return res;
}

/* Create a timestamp comparison-expression for with OP, SEC, MILLI.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *
expr_create_timestamp_comparison(unsigned op, time_t sec, unsigned milli)
{
	return expr_create_timestamp_comparison_ex(op, sec, milli, 0);
}

/* Create an EO_FIELD_EXISTS-expression for FIELD.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *
expr_create_field_exists(const char *field)
{
	struct expr *res;

	res = calloc(sizeof(struct expr), 1);
	if (res == NULL)
		goto err;
	res->op = EO_FIELD_EXISTS;
	res->virtual_field = 0;
	res->v.p.field.name = strdup(field);
	if (res->v.p.field.name == NULL)
		goto err_res;
	return res;

err_res:
	free(res);
err:
	return NULL;
}

/* Create a \regexp expression for regexp comparison.
   On success, return the created expression.
   On error, set errno and return NULL. */
struct expr *
expr_create_regexp_expression(const char *regexp)
{
	struct expr *res;

	res = calloc(sizeof(struct expr), 1);
	if (res == NULL)
		goto err;
	res->v.regexp = malloc(sizeof(*res->v.regexp));
	if (res->v.regexp == NULL)
		goto err_res;
	if (regcomp(res->v.regexp, regexp, REG_EXTENDED | REG_NOSUB) != 0) {
		errno = EINVAL;
		goto err_res_regexp;
	}
	res->op = EO_REGEXP_MATCHES;
	return res;

err_res_regexp:
	free(res->v.regexp);
err_res:
	free(res);
err:
	return NULL;
}

/* Create a binary expresion for OP and subexpressions E1 and E2.
   On success, return the created expresion.
   On error, set errno and return NULL. */
struct expr *
expr_create_binary(unsigned op, struct expr *e1, struct expr *e2)
{
	struct expr *res;

	res = calloc(sizeof(struct expr), 1);
	if (res == NULL)
		return NULL;
	assert(op == EO_AND || op ==EO_OR);
	res->op = op;
	res->v.sub[0] = e1;
	res->v.sub[1] = e2;
	return res;
}

/* Expression evaluation */

/* Return the "raw" value of the field in EXPR for RECORD in AU->le.  Set
   *FREE_IT to 1 if the return value should free()'d.
   Return NULL on error.  */
static char *
eval_raw_value(rnode *record, const struct expr *expr, int *free_it)
{
	if (expr->virtual_field == 0) {
		nvlist_first(&record->nv);
		if (nvlist_find_name(&record->nv, expr->v.p.field.name) == 0)
			return NULL;
		*free_it = 0;
		return (char *)nvlist_get_cur_val(&record->nv);
	}
	switch (expr->v.p.field.id) {
	case EF_TIMESTAMP:
	case EF_RECORD_TYPE:
	case EF_TIMESTAMP_EX:
		return NULL;

	default:
		abort();
	}
}

/* Return the "int" value of the field in EXPR for RECORD in AU->le.  Set
   valid to 1 if the return value is valid. Valid is set to 0 on error. */
static uint32_t
eval_unsigned_value(rnode *record, const struct expr *expr, int *valid)
{
	*valid = 0;
	if (expr->virtual_field == 0) {
		nvlist_first(&record->nv);
		if (nvlist_find_name(&record->nv, expr->v.p.field.name) == 0)
			return 0;
		const char *val = nvlist_get_cur_val(&record->nv);
		if (val) {
			uint32_t v = strtoul(val, NULL, 10);
			*valid = 1;
			return v;
		}
	} else
		abort();
	return 0;
}

/* Return the "interpreted" value of the field in EXPR for RECORD in AU->le.
   Set *FREE_IT to 1 if the return value should free()'d.
   Return NULL on *error.  */
static char *
eval_interpreted_value(auparse_state_t *au, rnode *record,
		       const struct expr *expr, int *free_it)
{
	if (expr->virtual_field == 0) {
		const char *res;

		nvlist_first(&record->nv);
		if (nvlist_find_name(&record->nv, expr->v.p.field.name) == 0)
			return NULL;
		*free_it = 0;
		res = nvlist_interp_cur_val(record, au->escape_mode);
		if (res == NULL)
			res = nvlist_get_cur_val(&record->nv);
		return (char *)res;
	}
	switch (expr->v.p.field.id) {
	case EF_TIMESTAMP:
	case EF_RECORD_TYPE:
	case EF_TIMESTAMP_EX:
		return NULL;

	default:
		abort();
	}
}

static int
compare_unsigned_values(uint32_t one, uint32_t two)
{
	if (one < two)
		return -1;
	else if (one > two)
		return 1;
	return 0;
}

/* Return -1, 0, 1 depending on comparing the field in EXPR with RECORD in AU.
   Set *ERROR to 0 if OK, non-zero otherwise. */
static int
compare_values(auparse_state_t *au, rnode *record, const struct expr *expr,
	       int *error)
{
	int res;
	if (expr->numeric_field == 0) {
		*error = 1;
		return 0;
	}
	switch (expr->v.p.field.id) {
	case EF_TIMESTAMP:
		if (au->le->e.sec < expr->v.p.value.timestamp.sec)
			res = -1;
		else if (au->le->e.sec > expr->v.p.value.timestamp.sec)
			res = 1;
		else if (au->le->e.milli < expr->v.p.value.timestamp.milli)
			res = -1;
		else if (au->le->e.milli > expr->v.p.value.timestamp.milli)
			res = 1;
		else
			res = 0;
		break;

	case EF_RECORD_TYPE:
		if (record->type < expr->v.p.value.int_value)
			res = -1;
		else if (record->type > expr->v.p.value.int_value)
			res = 1;
		else
			res = 0;
		break;

	case EF_TIMESTAMP_EX:
		if (au->le->e.sec < expr->v.p.value.timestamp.sec)
			res = -1;
		else if (au->le->e.sec > expr->v.p.value.timestamp.sec)
			res = 1;
		else if (au->le->e.milli < expr->v.p.value.timestamp.milli)
			res = -1;
		else if (au->le->e.milli > expr->v.p.value.timestamp.milli)
			res = 1;
		else if (au->le->e.serial < expr->v.p.value.timestamp_ex.serial)
			res = -1;
		else if (au->le->e.serial > expr->v.p.value.timestamp_ex.serial)
			res = 1;
		else
			res = 0;
		break;

	default:
		abort();
	}
	*error = 0;
	return res;
}

/* Evaluate EXPR on RECORD in AU->le.
   Return 1 if EXPR is true, 0 if it false or if it fails.
   (No error reporting facility is provided; an invalid term is considered to
   be false; e.g. !invalid is true.) */
int
expr_eval(auparse_state_t *au, rnode *record, const struct expr *expr)
{
	int res;

	switch (expr->op) {
	case EO_NOT:
		res = !expr_eval(au, record, expr->v.sub[0]);
		break;

	case EO_AND:
		res = (expr_eval(au, record, expr->v.sub[0])
			&& expr_eval(au, record, expr->v.sub[1]));
		break;

	case EO_OR:
		res = (expr_eval(au, record, expr->v.sub[0])
			|| expr_eval(au, record, expr->v.sub[1]));
		break;

	case EO_RAW_EQ: case EO_RAW_NE: {
		int free_it, ne;
		char *value;

		value = eval_raw_value(record, expr, &free_it);
		if (value == NULL)
			return 0;
		assert(expr->precomputed_value == 0);
		ne = strcmp(expr->v.p.value.string, value);
		if (free_it != 0)
			free(value);
		res = expr->op == EO_RAW_EQ ? ne == 0 : ne != 0;
		break;
	}

	case EO_INTERPRETED_EQ: case EO_INTERPRETED_NE: {
		int free_it, ne;
		char *value;

		value = eval_interpreted_value(au, record, expr, &free_it);
		if (value == NULL)
			return 0;
		assert(expr->precomputed_value == 0);
		ne = strcmp(expr->v.p.value.string, value);
		if (free_it != 0)
			free(value);
		res = expr->op == EO_INTERPRETED_EQ ? ne == 0 : ne != 0;
		break;
	}

	case EO_VALUE_EQ: case EO_VALUE_NE: case EO_VALUE_LT: case EO_VALUE_LE:
	case EO_VALUE_GT: case EO_VALUE_GE: {
		int err = 0, cmp;

		if (expr->virtual_field == 0) {
			// UID & GID here
			int valid;
			uint32_t val = eval_unsigned_value(record,expr,&valid);
			if (valid == 0)
				return 0;
			cmp = compare_unsigned_values(val,
					expr->v.p.unsigned_val);
		} else	// virtual fields here
			cmp = compare_values(au, record, expr, &err);
		if (err != 0)
			return 0;
		switch (expr->op) {
		case EO_VALUE_EQ:
			res = cmp == 0;
			break;

		case EO_VALUE_NE:
			res = cmp != 0;
			break;

		case EO_VALUE_LT:
			res = cmp < 0;
			break;

		case EO_VALUE_LE:
			res = cmp <= 0;
			break;

		case EO_VALUE_GT:
			res = cmp > 0;
			break;

		case EO_VALUE_GE:
			res = cmp >= 0;
			break;
		default:
			abort();
		}
	}
		break;

	case EO_FIELD_EXISTS:
		assert(expr->virtual_field == 0);
		nvlist_first(&record->nv);
		res = nvlist_find_name(&record->nv, expr->v.p.field.name) != 0;
		break;

	case EO_REGEXP_MATCHES:
		res = regexec(expr->v.regexp, record->record, 0, NULL, 0) == 0;
		break;

	default:
		abort();
	}
	return res;
}
