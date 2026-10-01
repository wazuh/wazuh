/** \ingroup rpmbuild
 * \file build/expression.c
 *  Simple logical expression parser.
 * This module implements a basic expression parser with support for
 * integer and string datatypes. For ease of programming, we use the
 * top-down "recursive descent" method of parsing. While a
 * table-driven bottom-up parser might be faster, it does not really
 * matter for the expressions we will be parsing.
 *
 * Copyright (C) 1998 Tom Dyas <tdyas@eden.rutgers.edu>
 * This work is provided under the GPL or LGPL at your choice.
 */

#include "system.h"

#include <string.h>

#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmver.h>
#include "rpmmacro_internal.h"
#include "rpmhook.h"
#include "rpmlua.h"
#include "debug.h"

/* #define DEBUG_PARSER 1 */

#ifdef DEBUG_PARSER
#include <stdio.h>
#define DEBUG(x) do { x ; } while (0)
#else
#define DEBUG(x)
#endif

typedef enum { 
    VALUE_TYPE_INTEGER,
    VALUE_TYPE_STRING,
    VALUE_TYPE_VERSION,
} valueType;

/**
 * Encapsulation of a "value"
 */
typedef struct _value {
  valueType type;
  union {
    char *s;
    int i;
    rpmver v;
  } data;
} *Value;

typedef int (*valueCmp)(Value v1, Value v2);

static int valueCmpInteger(Value v1, Value v2)
{
    return v1->data.i - v2->data.i;
}

static int valueCmpString(Value v1, Value v2)
{
    return strcmp(v1->data.s, v2->data.s);
}

static int valueCmpVersion(Value v1, Value v2)
{
    return rpmverCmp(v1->data.v, v2->data.v);
}

static void valueReset(Value v)
{
  if (v->type == VALUE_TYPE_STRING)
    v->data.s = _free(v->data.s);
  else if (v->type == VALUE_TYPE_VERSION)
    v->data.v = rpmverFree(v->data.v);
}

/**
 */
static Value valueMakeInteger(int i)
{
  Value v;

  v = (Value) xmalloc(sizeof(*v));
  v->type = VALUE_TYPE_INTEGER;
  v->data.i = i;
  return v;
}

/**
 */
static Value valueMakeString(char *s)
{
  Value v;

  v = (Value) xmalloc(sizeof(*v));
  v->type = VALUE_TYPE_STRING;
  v->data.s = s;
  return v;
}

static Value valueMakeVersion(const char *s)
{
  Value v = NULL;
  rpmver rv = rpmverParse(s);

  if (rv) {
    v = (Value) xmalloc(sizeof(*v));
    v->type = VALUE_TYPE_VERSION;
    v->data.v = rv;
  }
  return v;
}
/**
 */
static void valueSetInteger(Value v, int i)
{
  valueReset(v);
  v->type = VALUE_TYPE_INTEGER;
  v->data.i = i;
}

/**
 */
static void valueSetString(Value v, char *s)
{
  valueReset(v);
  v->type = VALUE_TYPE_STRING;
  v->data.s = s;
}

/**
 */
static void valueFree( Value v)
{
  if (v) {
    valueReset(v);
    free(v);
  }
}

/**
 */
static int boolifyValue(Value v)
{
  if (v && v->type == VALUE_TYPE_INTEGER)
    return v->data.i != 0;
  if (v && v->type == VALUE_TYPE_STRING)
    return v->data.s[0] != '\0';
  return 0;
}

#ifdef DEBUG_PARSER
static void valueDump(const char *msg, Value v, FILE *fp)
{
  if (msg)
    fprintf(fp, "%s ", msg);
  if (v) {
    if (v->type == VALUE_TYPE_INTEGER)
      fprintf(fp, "INTEGER %d\n", v->data.i);
    else if (v->type == VALUE_TYPE_VERSION) {
      char *evr = rpmverEVR(v->data.v);
      fprintf(fp, "VERSION %s\n", evr);
      free(evr);
    } else
      fprintf(fp, "STRING '%s'\n", v->data.s);
  } else
    fprintf(fp, "NULL\n");
}
#endif

#define valueIsInteger(v) ((v)->type == VALUE_TYPE_INTEGER)
#define valueIsString(v) ((v)->type == VALUE_TYPE_STRING)
#define valueIsVersion(v) ((v)->type == VALUE_TYPE_VERSION)
#define valueSameType(v1,v2) ((v1)->type == (v2)->type)


/**
 * Parser state.
 */
typedef struct _parseState {
    char *str;		/*!< expression string */
    const char *p;	/*!< current position in expression string */
    int nextToken;	/*!< current lookahead token */
    Value tokenValue;	/*!< valid when TOK_INTEGER or TOK_STRING */
    int flags;		/*!< parser flags */
} *ParseState;

static void exprErr(const struct _parseState *state, const char *msg,
		    const char *p)
{
    const char *newLine = strchr(state->str,'\n');

    if (newLine && (*(newLine+1) != '\0'))
	p = NULL;

    rpmlog(RPMLOG_ERR, "%s: %s\n", msg, state->str);
    if (p) {
	int l = p - state->str + strlen(msg) + 2;
	rpmlog(RPMLOG_ERR, "%*s\n", l, "^");
    }
}

/**
 * \name Parser tokens
 */
#define TOK_EOF          1
#define TOK_INTEGER      2
#define TOK_STRING       3
#define TOK_ADD          4
#define TOK_MINUS        5
#define TOK_MULTIPLY     6
#define TOK_DIVIDE       7
#define TOK_OPEN_P       8
#define TOK_CLOSE_P      9
#define TOK_EQ          10
#define TOK_NEQ         11
#define TOK_LT          12
#define TOK_LE          13
#define TOK_GT          14
#define TOK_GE          15
#define TOK_NOT         16
#define TOK_LOGICAL_AND 17
#define TOK_LOGICAL_OR  18
#define TOK_TERNARY_COND 19
#define TOK_TERNARY_ALT 20
#define TOK_VERSION	21
#define TOK_COMMA	22
#define TOK_FUNCTION	23

#if defined(DEBUG_PARSER)
typedef struct exprTokTableEntry {
    const char *name;
    int val;
} ETTE_t;

ETTE_t exprTokTable[] = {
    { "EOF",	TOK_EOF },
    { "I",	TOK_INTEGER },
    { "S",	TOK_STRING },
    { "+",	TOK_ADD },
    { "-",	TOK_MINUS },
    { "*",	TOK_MULTIPLY },
    { "/",	TOK_DIVIDE },
    { "( ",	TOK_OPEN_P },
    { " )",	TOK_CLOSE_P },
    { "==",	TOK_EQ },
    { "!=",	TOK_NEQ },
    { "<",	TOK_LT },
    { "<=",	TOK_LE },
    { ">",	TOK_GT },
    { ">=",	TOK_GE },
    { "!",	TOK_NOT },
    { "&&",	TOK_LOGICAL_AND },
    { "||",	TOK_LOGICAL_OR },
    { "?",	TOK_TERNARY_COND },
    { ":",	TOK_TERNARY_ALT},
    { "V",	TOK_VERSION},
    { ",",	TOK_COMMA},
    { "f( ",	TOK_FUNCTION},
    { NULL, 0 }
};

static const char *prToken(int val)
{
    ETTE_t *et;
    
    for (et = exprTokTable; et->name != NULL; et++) {
	if (val == et->val)
	    return et->name;
    }
    return "???";
}
#endif	/* DEBUG_PARSER */

#define RPMEXPR_DISCARD	((unsigned)1 << 31)	/* internal, discard result */

static char *getValuebuf(ParseState state, const char *p, size_t size)
{
    char *temp;
    if ((state->flags & RPMEXPR_DISCARD) != 0)
	size = 0;
    temp = (char *)xmalloc(size + 1);
    memcpy(temp, p, size);
    temp[size] = '\0';
    if (size && (state->flags & RPMEXPR_EXPAND) != 0) {
	char *temp2 = NULL;
	rpmExpandMacros(NULL, temp, &temp2, 0);
	free(temp);
	temp = temp2;
    }
    return temp;
}

static size_t skipMacro(const char *p, size_t ts)
{
    const char *pe;
    if (p[ts] == '%')
	return ts + 1;	/* %% is special */
    pe = findMacroEnd(p + ts);
    return pe ? pe - p : strlen(p);
}

static int wellformedInteger(const char *p)
{
  if (*p == '-')
    p++;
  for (; *p; p++)
    if (!risdigit(*p))
      return 0;
  return 1;
}

static const char *
isFunctionCall(const char *p)
{
    if (!risalpha(*p++) && *p != '_')
	return NULL;
    while (risalpha(*p) || risdigit(*p) || *p == '_' || *p == '.' || *p == ':')
	p++;
    return *p == '(' ? p : NULL;
}


/**
 * @param state		expression parser state
 */
static int rdToken(ParseState state)
{
  int token;
  Value v = NULL;
  const char *p = state->p;
  int expand = (state->flags & RPMEXPR_EXPAND) != 0;

  /* Skip whitespace before the next token. */
  while (*p && risspace(*p)) p++;

  switch (*p) {
  case '\0':
    token = TOK_EOF;
    p--;
    break;
  case '+':
    token = TOK_ADD;
    break;
  case '-':
    token = TOK_MINUS;
    break;
  case '*':
    token = TOK_MULTIPLY;
    break;
  case '/':
    token = TOK_DIVIDE;
    break;
  case '(':
    token = TOK_OPEN_P;
    break;
  case ')':
    token = TOK_CLOSE_P;
    break;
  case '=':
    if (p[1] == '=') {
      token = TOK_EQ;
      p++;
    } else {
      exprErr(state, _("syntax error while parsing =="), p+2);
      goto err;
    }
    break;
  case '!':
    if (p[1] == '=') {
      token = TOK_NEQ;
      p++;
    } else
      token = TOK_NOT;
    break;
  case '<':
    if (p[1] == '=') {
      token = TOK_LE;
      p++;
    } else
      token = TOK_LT;
    break;
  case '>':
    if (p[1] == '=') {
      token = TOK_GE;
      p++;
    } else
      token = TOK_GT;
    break;
  case '&':
    if (p[1] == '&') {
      token = TOK_LOGICAL_AND;
      p++;
    } else {
      exprErr(state, _("syntax error while parsing &&"), p+2);
      goto err;
    }
    break;
  case '|':
    if (p[1] == '|') {
      token = TOK_LOGICAL_OR;
      p++;
    } else {
      exprErr(state, _("syntax error while parsing ||"), p+2);
      goto err;
    }
    break;
  case '?':
    token = TOK_TERNARY_COND;
    break;
  case ':':
    token = TOK_TERNARY_ALT;
    break;
  case ',':
    token = TOK_COMMA;
    break;

  default:
    if (risdigit(*p) || (*p == '%' && expand)) {
      char *temp;
      size_t ts;

      for (ts=0; p[ts]; ts++) {
	if (p[ts] == '%' && expand)
	  ts = skipMacro(p, ts + 1) - 1;
	else if (!risdigit(p[ts]))
	  break;
      }
      temp = getValuebuf(state, p, ts);
      if (!temp)
	goto err;
      /* make sure that the expanded buffer only contains digits */
      if (expand && !wellformedInteger(temp)) {
	if (risalpha(*temp))
	  exprErr(state, _("macro expansion returned a bare word, please use \"...\""), p + 1);
	else
	  exprErr(state, _("macro expansion did not return an integer"), p + 1);
	rpmlog(RPMLOG_ERR, _("expanded string: %s\n"), temp);
	free(temp);
	goto err;
      }
      p += ts-1;
      token = TOK_INTEGER;
      v = valueMakeInteger(atoi(temp));
      free(temp);

    } else if (*p == '\"' || (*p == 'v' && *(p+1) == '\"')) {
      char *temp;
      size_t ts;
      int qtok;

      if (*p == 'v') {
	qtok = TOK_VERSION;
	p += 2;
      } else {
	qtok = TOK_STRING;
	p++;
      }

      for (ts=0; p[ts]; ts++) {
	if (p[ts] == '%' && expand)
	  ts = skipMacro(p, ts + 1) - 1;
	else if (p[ts] == '\"')
	  break;
      }
      if (p[ts] != '\"') {
        exprErr(state, _("unterminated string in expression"), p + ts + 1);
        goto err;
      }
      temp = getValuebuf(state, p, ts);
      if (!temp)
	goto err;
      p += ts;
      token = TOK_STRING;
      if (qtok == TOK_STRING) {
	v = valueMakeString(temp);
      } else {
	v = valueMakeVersion(state->flags & RPMEXPR_DISCARD ? "0" : temp);
        free(temp); /* version doesn't take ownership of the string */
        if (v == 0) {
	  exprErr(state, _("invalid version"), p+1);
	  goto err;
	}
      }
    } else if (risalpha(*p)) {
      const char *pe = isFunctionCall(p);
      if (pe && *pe == '(') {
	v = valueMakeString(rstrndup(p, pe - p));
	p = pe;
	token = TOK_FUNCTION;
	break;
      } 
      exprErr(state, _("bare words are no longer supported, please use \"...\""), p+1);
      goto err;

    } else {
      exprErr(state, _("parse error in expression"), p+1);
      goto err;
    }
    break;
  }

  state->p = p + 1;
  state->nextToken = token;
  state->tokenValue = v;

  DEBUG(printf("rdToken: \"%s\" (%d)\n", prToken(token), token));
  DEBUG(valueDump("rdToken:", state->tokenValue, stdout));

  return 0;

err:
  valueFree(v);
  return -1;
}

static Value doTernary(ParseState state);

/* always returns a string for now */
static Value doLuaFunction(ParseState state, const char *name, int argc, Value *argv)
{
    rpmlua lua = NULL; /* Global state. */
    rpmhookArgs args = NULL;
    Value v = NULL;
    char *result = NULL;
    char *argt = NULL;
    int i;
    
    if (state->flags & RPMEXPR_DISCARD)
	return valueMakeString(xstrdup(""));
    args = rpmhookArgsNew(argc);
    argt = (char *)xmalloc(argc + 1);
    for (i = 0; i < argc; i++) {
	switch (argv[i]->type) {
	    case VALUE_TYPE_INTEGER:
		argt[i] = 'i';
		args->argv[i].i = argv[i]->data.i;
		break;
	    case VALUE_TYPE_STRING:
		argt[i] = 's';
		args->argv[i].s = argv[i]->data.s;
		break;
	    default:
		exprErr(state, _("unsupported function argument type"), state->p);
		goto exit;
	}
    }
    argt[argc] = 0;
    args->argt = argt;
    result = rpmluaCallStringFunction(lua, name, args);
    if (result)
	v = valueMakeString(result);
exit:
    rpmhookArgsFree(args);
    free(argt);
    return v;
}

static Value doFunction(ParseState state)
{
  Value vname = state->tokenValue;
  Value v = NULL, *varg = NULL;
  int i, narg = 0;
  if (rdToken(state))
    goto exit;
  /* gather args */
  while (state->nextToken != TOK_CLOSE_P) {
      varg = xrealloc(varg, (narg + 1) * sizeof(Value));
      varg[narg] = doTernary(state);
      if (!varg[narg])
	goto exit;
      narg++;
      if (state->nextToken == TOK_CLOSE_P)
	break;
      if (state->nextToken != TOK_COMMA) {
	exprErr(state, _("syntax error in expression"), state->p);
	goto exit;
      }
      if (rdToken(state)) {
	goto exit;
      }
      if (state->nextToken == TOK_CLOSE_P) {
	exprErr(state, _("syntax error in expression"), state->p);
	goto exit;
      }
  }
  if (rdToken(state))
    goto exit;

  /* do the call... */
  if (!strncmp(vname->data.s, "lua:", 4))
    v = doLuaFunction(state, vname->data.s + 4, narg, varg);
  else
    exprErr(state, _("unsupported function"), state->p);

exit:
  for (i = 0; i < narg; i++)
    valueFree(varg[i]);
  free(varg);
  valueFree(vname);
  return v;
}

/**
 * @param state		expression parser state
 */
static Value doPrimary(ParseState state)
{
  Value v = NULL;
  const char *p = state->p;

  DEBUG(printf("doPrimary()\n"));

  switch (state->nextToken) {
  case TOK_FUNCTION:
    v = doFunction(state);
    if (v == NULL)
      goto err;
    break;

  case TOK_OPEN_P:
    if (rdToken(state))
      goto err;
    v = doTernary(state);
    if (state->nextToken != TOK_CLOSE_P) {
      exprErr(state, _("unmatched ("), p);
      goto err;
    }
    if (rdToken(state))
      goto err;
    break;

  case TOK_INTEGER:
  case TOK_STRING:
    v = state->tokenValue;
    if (rdToken(state))
      goto err;
    break;

  case TOK_MINUS:
    if (rdToken(state))
      goto err;

    v = doPrimary(state);
    if (v == NULL)
      goto err;

    if (! valueIsInteger(v)) {
      exprErr(state, _("- only on numbers"), p);
      goto err;
    }

    valueSetInteger(v, - v->data.i);
    break;

  case TOK_NOT:
    if (rdToken(state))
      goto err;

    v = doPrimary(state);
    if (v == NULL)
      goto err;

    valueSetInteger(v, ! boolifyValue(v));
    break;

  case TOK_EOF:
    exprErr(state, _("unexpected end of expression"), state->p);
    goto err;

  default:
    exprErr(state, _("syntax error in expression"), state->p);
    goto err;
    break;
  }

  DEBUG(valueDump("doPrimary:", v, stdout));
  return v;

err:
  valueFree(v);
  return NULL;
}

/**
 * @param state		expression parser state
 */
static Value doMultiplyDivide(ParseState state)
{
  Value v1 = NULL, v2 = NULL;

  DEBUG(printf("doMultiplyDivide()\n"));

  v1 = doPrimary(state);
  if (v1 == NULL)
    goto err;

  while (state->nextToken == TOK_MULTIPLY
	 || state->nextToken == TOK_DIVIDE) {
    int op = state->nextToken;
    const char *p = state->p;

    if (rdToken(state))
      goto err;

    if (v2) valueFree(v2);

    v2 = doPrimary(state);
    if (v2 == NULL)
      goto err;

    if (! valueSameType(v1, v2)) {
      exprErr(state, _("types must match"), NULL);
      goto err;
    }

    if (valueIsInteger(v1)) {
      int i1 = v1->data.i, i2 = v2->data.i;

      if ((state->flags & RPMEXPR_DISCARD) != 0)
        continue;	/* just use v1 in discard mode */
      if ((i2 == 0) && (op == TOK_DIVIDE)) {
	    exprErr(state, _("division by zero"), p);
	    goto err;
      }
      if (op == TOK_MULTIPLY)
	valueSetInteger(v1, i1 * i2);
      else
	valueSetInteger(v1, i1 / i2);
    } else if (valueIsVersion(v1)) {
      exprErr(state, _("* and / not supported for versions"), p);
      goto err;
    } else {
      exprErr(state, _("* and / not supported for strings"), p);
      goto err;
    }
  }

  if (v2) valueFree(v2);
  return v1;

err:
  valueFree(v1);
  valueFree(v2);
  return NULL;
}

/**
 * @param state		expression parser state
 */
static Value doAddSubtract(ParseState state)
{
  Value v1 = NULL, v2 = NULL;

  DEBUG(printf("doAddSubtract()\n"));

  v1 = doMultiplyDivide(state);
  if (v1 == NULL)
    goto err;

  while (state->nextToken == TOK_ADD || state->nextToken == TOK_MINUS) {
    int op = state->nextToken;
    const char *p = state->p;

    if (rdToken(state))
      goto err;

    if (v2) valueFree(v2);

    v2 = doMultiplyDivide(state);
    if (v2 == NULL)
      goto err;

    if (! valueSameType(v1, v2)) {
      exprErr(state, _("types must match"), NULL);
      goto err;
    }

    if (valueIsInteger(v1)) {
      int i1 = v1->data.i, i2 = v2->data.i;

      if (op == TOK_ADD)
	valueSetInteger(v1, i1 + i2);
      else
	valueSetInteger(v1, i1 - i2);
    } else if (valueIsVersion(v1)) {
      exprErr(state, _("+ and - not supported for versions"), p);
      goto err;
    } else {
      char *copy;

      if (op == TOK_MINUS) {
        exprErr(state, _("- not supported for strings"), p);
        goto err;
      }

      copy = (char *)xmalloc(strlen(v1->data.s) + strlen(v2->data.s) + 1);
      (void) stpcpy( stpcpy(copy, v1->data.s), v2->data.s);

      valueSetString(v1, copy);
    }
  }

  if (v2) valueFree(v2);
  return v1;

err:
  valueFree(v1);
  valueFree(v2);
  return NULL;
}

/**
 * @param state		expression parser state
 */
static Value doRelational(ParseState state)
{
  Value v1 = NULL, v2 = NULL;

  DEBUG(printf("doRelational()\n"));

  v1 = doAddSubtract(state);
  if (v1 == NULL)
    goto err;

  while (state->nextToken >= TOK_EQ && state->nextToken <= TOK_GE) {
    int op = state->nextToken;
    int r = 0;
    valueCmp cmp;

    if (rdToken(state))
      goto err;

    if (v2) valueFree(v2);

    v2 = doAddSubtract(state);
    if (v2 == NULL)
      goto err;

    if (! valueSameType(v1, v2)) {
      exprErr(state, _("types must match"), NULL);
      goto err;
    }

    if (valueIsInteger(v1))
      cmp = valueCmpInteger;
    else if (valueIsVersion(v1))
      cmp = valueCmpVersion;
    else
      cmp = valueCmpString;

    switch (op) {
    case TOK_EQ:
      r = (cmp(v1,v2) == 0);
      break;
    case TOK_NEQ:
      r = (cmp(v1,v2) != 0);
      break;
    case TOK_LT:
      r = (cmp(v1,v2) < 0);
      break;
    case TOK_LE:
      r = (cmp(v1,v2) <= 0);
      break;
    case TOK_GT:
      r = (cmp(v1,v2) > 0);
      break;
    case TOK_GE:
      r = (cmp(v1,v2) >= 0);
      break;
    default:
      break;
    }
    valueSetInteger(v1, r);
  }

  if (v2) valueFree(v2);
  return v1;

err:
  valueFree(v1);
  valueFree(v2);
  return NULL;
}

/**
 * @param state		expression parser state
 */
static Value doLogical(ParseState state)
{
  Value v1 = NULL, v2 = NULL;
  int oldflags = state->flags;

  DEBUG(printf("doLogical()\n"));

  v1 = doRelational(state);
  if (v1 == NULL)
    goto err;

  while (state->nextToken == TOK_LOGICAL_AND
	 || state->nextToken == TOK_LOGICAL_OR) {
    int op = state->nextToken;
    int b1 = boolifyValue(v1);

    if ((op == TOK_LOGICAL_AND && !b1) || (op == TOK_LOGICAL_OR && b1))
      state->flags |= RPMEXPR_DISCARD;		/* short-circuit */

    if (rdToken(state))
      goto err;

    if (v2) valueFree(v2);

    v2 = doRelational(state);
    if (v2 == NULL)
      goto err;

    if (! valueSameType(v1, v2)) {
      exprErr(state, _("types must match"), NULL);
      goto err;
    }

    if ((op == TOK_LOGICAL_AND && b1) || (op == TOK_LOGICAL_OR && !b1)) {
      Value vtmp = v1;
      v1 = v2;
      v2 = vtmp;
    }
    state->flags = oldflags;
  }

  if (v2) valueFree(v2);
  return v1;

err:
  valueFree(v1);
  valueFree(v2);
  state->flags = oldflags;
  return NULL;
}

static Value doTernary(ParseState state)
{
  Value v1 = NULL, v2 = NULL;
  int oldflags = state->flags;

  DEBUG(printf("doTernary()\n"));

  v1 = doLogical(state);
  if (v1 == NULL)
    goto err;
  if (state->nextToken == TOK_TERNARY_COND) {
    int cond = boolifyValue(v1);;

    if (!cond)
	state->flags |= RPMEXPR_DISCARD;	/* short-circuit */
    if (rdToken(state))
      goto err;
    valueFree(v1);
    v1 = doTernary(state);
    if (v1 == NULL)
      goto err;
    if (state->nextToken != TOK_TERNARY_ALT) {
      exprErr(state, _("syntax error in expression"), state->p);
      goto err;
    }
    state->flags = oldflags;

    if (cond)
	state->flags |= RPMEXPR_DISCARD;	/* short-circuit */
    if (rdToken(state))
      goto err;
    v2 = doTernary(state);
    if (v2 == NULL)
      goto err;
    state->flags = oldflags;

    if (! valueSameType(v1, v2)) {
      exprErr(state, _("types must match"), NULL);
      goto err;
    }

    valueFree(cond ? v2 : v1);
    return cond ? v1 : v2;
  }
  return v1;

err:
  valueFree(v1);
  valueFree(v2);
  state->flags = oldflags;
  return NULL;
}

int rpmExprBoolFlags(const char *expr, int flags)
{
  struct _parseState state;
  int result = -1;
  Value v = NULL;

  DEBUG(printf("parseExprBoolean(?, '%s')\n", expr));

  /* Initialize the expression parser state. */
  state.p = state.str = xstrdup(expr);
  state.nextToken = 0;
  state.tokenValue = NULL;
  state.flags = flags;
  if (rdToken(&state))
    goto exit;

  /* Parse the expression. */
  v = doTernary(&state);
  if (!v)
    goto exit;

  /* If the next token is not TOK_EOF, we have a syntax error. */
  if (state.nextToken != TOK_EOF) {
    exprErr(&state, _("syntax error in expression"), state.p);
    goto exit;
  }

  DEBUG(valueDump("parseExprBoolean:", v, stdout));

  result = boolifyValue(v);

exit:
  state.str = _free(state.str);
  valueFree(v);
  return result;
}

char *rpmExprStrFlags(const char *expr, int flags)
{
  struct _parseState state;
  char *result = NULL;
  Value v = NULL;

  DEBUG(printf("parseExprString(?, '%s')\n", expr));

  /* Initialize the expression parser state. */
  state.p = state.str = xstrdup(expr);
  state.nextToken = 0;
  state.tokenValue = NULL;
  state.flags = flags;
  if (rdToken(&state))
    goto exit;

  /* Parse the expression. */
  v = doTernary(&state);
  if (!v)
    goto exit;

  /* If the next token is not TOK_EOF, we have a syntax error. */
  if (state.nextToken != TOK_EOF) {
    exprErr(&state, _("syntax error in expression"), state.p);
    goto exit;
  }

  DEBUG(valueDump("parseExprString:", v, stdout));

  switch (v->type) {
  case VALUE_TYPE_INTEGER: {
    rasprintf(&result, "%d", v->data.i);
  } break;
  case VALUE_TYPE_STRING:
    result = xstrdup(v->data.s);
    break;
  case VALUE_TYPE_VERSION:
    result = rpmverEVR(v->data.v);
    break;
  default:
    break;
  }

exit:
  state.str = _free(state.str);
  valueFree(v);
  return result;
}

int rpmExprBool(const char *expr)
{
    return rpmExprBoolFlags(expr, 0);
}

char *rpmExprStr(const char *expr)
{
    return rpmExprStrFlags(expr, 0);
}
