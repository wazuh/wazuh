/** \ingroup header
 * \file lib/headerfmt.c
 */

#include "system.h"

#include <stdarg.h>
#include <rpm/header.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmstring.h>
#include "misc.h"		/* format function protos */

#include "debug.h"

#define PARSER_BEGIN 	0
#define PARSER_IN_ARRAY 1
#define PARSER_IN_EXPR  2

/** \ingroup header
 */
typedef struct sprintfTag_s * sprintfTag;
struct sprintfTag_s {
    headerFmt fmt;
    rpmTagVal tag;
    int justOne;
    char * format;
    const char * type;
};

typedef enum {
    PTOK_NONE = 0,
    PTOK_TAG,
    PTOK_ARRAY,
    PTOK_STRING,
    PTOK_COND
} ptokType;

/** \ingroup header
 */
typedef struct sprintfToken_s * sprintfToken;
struct sprintfToken_s {
    ptokType type;
    union {
	struct sprintfTag_s tag;	/*!< PTOK_TAG */
	struct {
	    sprintfToken format;
	    int i;
	    int numTokens;
	} array;			/*!< PTOK_ARRAY */
	struct {
	    char * string;
	    int len;
	} string;			/*!< PTOK_STRING */
	struct {
	    sprintfToken ifFormat;
	    int numIfTokens;
	    sprintfToken elseFormat;
	    int numElseTokens;
	    struct sprintfTag_s tag;
	} cond;				/*!< PTOK_COND */
    } u;
};

#define HASHTYPE tagCache
#define HTKEYTYPE rpmTagVal
#define HTDATATYPE rpmtd
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

typedef struct headerSprintfArgs_s *headerSprintfArgs;

struct xformat_s {
    void (*xHeader)(headerSprintfArgs hsa);
    void (*xFooter)(headerSprintfArgs hsa);
    void (*xTagHeader)(headerSprintfArgs hsa, rpmTagVal tag, int nelem);
    void (*xTagFooter)(headerSprintfArgs hsa, rpmTagVal tag, int nelem);
    void (*xItemHeader)(headerSprintfArgs hsa, rpmTagVal tag, int n, int nelem);
    void (*xItemFooter)(headerSprintfArgs hsa, rpmTagVal tag, int n, int nelem);
};

/**
 */
struct headerSprintfArgs_s {
    Header h;
    char * fmt;
    const char * errmsg;
    tagCache cache;
    sprintfToken format;
    HeaderIterator hi;
    char * val;
    size_t vallen;
    size_t alloced;
    int numTokens;
    int i;
    headerGetFlags hgflags;
    struct xformat_s xfmt;
};

static char escapedChar(const char ch)	
{
    switch (ch) {
    case 'a': 	return '\a';
    case 'b': 	return '\b';
    case 'f': 	return '\f';
    case 'n': 	return '\n';
    case 'r': 	return '\r';
    case 't': 	return '\t';
    case 'v': 	return '\v';
    default:	return ch;
    }
}

/**
 * Destroy headerSprintf format array.
 * @param format	sprintf format array
 * @param num		number of elements
 * @return		NULL always
 */
static sprintfToken
freeFormat( sprintfToken format, int num)
{
    int i;

    if (format == NULL) return NULL;

    for (i = 0; i < num; i++) {
	switch (format[i].type) {
	case PTOK_ARRAY:
	    format[i].u.array.format =
		freeFormat(format[i].u.array.format,
			format[i].u.array.numTokens);
	    break;
	case PTOK_COND:
	    format[i].u.cond.ifFormat =
		freeFormat(format[i].u.cond.ifFormat, 
			format[i].u.cond.numIfTokens);
	    format[i].u.cond.elseFormat =
		freeFormat(format[i].u.cond.elseFormat, 
			format[i].u.cond.numElseTokens);
	    break;
	case PTOK_NONE:
	case PTOK_TAG:
	case PTOK_STRING:
	default:
	    break;
	}
    }
    free(format);
    return NULL;
}

/**
 * Initialize an hsa iteration.
 * @param hsa		headerSprintf args
 */
static void hsaInit(headerSprintfArgs hsa)
{
    sprintfTag tag =
	(hsa->format->type == PTOK_TAG
	    ? &hsa->format->u.tag :
	(hsa->format->type == PTOK_ARRAY
	    ? &hsa->format->u.array.format->u.tag :
	NULL));

    hsa->i = 0;
    if (tag != NULL && tag->tag == -2)
	hsa->hi = headerInitIterator(hsa->h);
    /* Normally with bells and whistles enabled, but raw dump on iteration. */
    hsa->hgflags = (hsa->hi == NULL) ? HEADERGET_EXT : HEADERGET_RAW;
}

/**
 * Return next hsa iteration item.
 * @param hsa		headerSprintf args
 * @return		next sprintfToken (or NULL)
 */
static sprintfToken hsaNext(headerSprintfArgs hsa)
{
    sprintfToken fmt = NULL;
    sprintfTag tag =
	(hsa->format->type == PTOK_TAG
	    ? &hsa->format->u.tag :
	(hsa->format->type == PTOK_ARRAY
	    ? &hsa->format->u.array.format->u.tag :
	NULL));

    if (hsa->i >= 0 && hsa->i < hsa->numTokens) {
	fmt = hsa->format + hsa->i;
	if (hsa->hi == NULL) {
	    hsa->i++;
	} else {
	    tag->tag = headerNextTag(hsa->hi);
	    if (tag->tag == RPMTAG_NOT_FOUND)
		fmt = NULL;
	}
    }

    return fmt;
}

/**
 * Finish an hsa iteration.
 * @param hsa		headerSprintf args
 */
static void hsaFini(headerSprintfArgs hsa)
{
    hsa->hi = headerFreeIterator(hsa->hi);
    hsa->i = 0;
}

/**
 * Reserve sufficient buffer space for next output value.
 * @param hsa		headerSprintf args
 * @param need		no. of bytes to reserve
 * @return		pointer to reserved space
 */
static char * hsaReserve(headerSprintfArgs hsa, size_t need)
{
    if ((hsa->vallen + need) >= hsa->alloced) {
	if (hsa->alloced <= need)
	    hsa->alloced += need;
	hsa->alloced <<= 1;
	hsa->val = xrealloc(hsa->val, hsa->alloced+1);	
    }
    return hsa->val + hsa->vallen;
}

static void hsaAppend(headerSprintfArgs hsa, const char *str)
{
    size_t len = strlen(str);
    if (len > 0) {
	char *t = hsaReserve(hsa, len);
	stpcpy(t, str);
	hsa->vallen += len;
    }
}

RPM_GNUC_PRINTF(2, 3)
static void hsaError(headerSprintfArgs hsa, const char *fmt, ...)
{
    /* Use thread local buffer as headerFormat() errmsg arg is const */
    static __thread char *errbuf = NULL;

    if (fmt == NULL) {
	hsa->errmsg = NULL;
    } else {
	va_list ap;

	free(errbuf);
	va_start(ap, fmt);
	rvasprintf(&errbuf, fmt, ap);
	va_end(ap);
	hsa->errmsg = errbuf;
    }
}

static char *tagName(rpmTagVal tag)
{
    const char * tagN = rpmTagGetName(tag);
    char *tagval = NULL;

    if (rstreq(tagN, "(unknown)")) {
	rasprintf(&tagval, "[%u]", tag);
    } else {
	tagval = xstrdup(tagN);
    }
    return tagval;
}

static void xmlHeader(headerSprintfArgs hsa)
{
    hsaAppend(hsa, "<rpmHeader>\n");
}

static void xmlFooter(headerSprintfArgs hsa)
{
    hsaAppend(hsa, "</rpmHeader>\n");
}

static void xmlTagHeader(headerSprintfArgs hsa, rpmTagVal tag, int nelem)
{
    char *tagname = tagName(tag);
    hsaAppend(hsa, "  <rpmTag name=\"");
    hsaAppend(hsa, tagname);
    hsaAppend(hsa, "\">\n");
    free(tagname);
}

static void xmlTagFooter(headerSprintfArgs hsa, rpmTagVal tag, int nelem)
{
    hsaAppend(hsa, "  </rpmTag>\n");
}

static struct xformat_s xformat_xml = {
    .xHeader = xmlHeader,
    .xFooter = xmlFooter,
    .xTagHeader = xmlTagHeader,
    .xTagFooter = xmlTagFooter,
};

static void jsonHeader(headerSprintfArgs hsa)
{
    hsaAppend(hsa, "{\n");
}

static void jsonFooter(headerSprintfArgs hsa)
{
    /*
     * XXX HACK: when iterating through the header tags, we don't know
     * which element will be the last one. We have to emit ',' for each
     * tag we process and then delete the last one here.
     */
    hsa->vallen -= 2;
    hsaAppend(hsa, "\n}\n");
}

static void jsonTagHeader(headerSprintfArgs hsa, rpmTagVal tag, int nelem)
{
    char *tagname = tagName(tag);
    hsaAppend(hsa, "    \"");
    hsaAppend(hsa, tagname);
    hsaAppend(hsa, "\": ");
    if (nelem > 1)
	hsaAppend(hsa, "[\n");
    free(tagname);
}

static void jsonTagFooter(headerSprintfArgs hsa, rpmTagVal tag, int nelem)
{
    if (nelem > 1)
	hsaAppend(hsa, "    ]");
    hsaAppend(hsa, ",");
    hsaAppend(hsa, "\n");
}

static void jsonItemHeader(headerSprintfArgs hsa, rpmTagVal tag,
				int n, int nelem)
{
    hsaAppend(hsa, "\t");
}

static void jsonItemFooter(headerSprintfArgs hsa, rpmTagVal tag,
				int n, int nelem)
{
    if (nelem > 1) {
	if (n < nelem-1)
	    hsaAppend(hsa, ",");
	hsaAppend(hsa, "\n");
    }
}

static struct xformat_s xformat_json = {
    .xHeader = jsonHeader,
    .xFooter = jsonFooter,
    .xTagHeader = jsonTagHeader,
    .xTagFooter = jsonTagFooter,
    .xItemHeader = jsonItemHeader,
    .xItemFooter = jsonItemFooter,
};

/**
 * Search tags for a name.
 * @param hsa		headerSprintf args
 * @param token		parsed fields
 * @param name		name to find
 * @return		0 on success, 1 on not found
 */
static int findTag(headerSprintfArgs hsa, sprintfToken token, const char * name)
{
    const char *tagname = name;
    sprintfTag stag = (token->type == PTOK_COND
	? &token->u.cond.tag : &token->u.tag);

    stag->fmt = NULL;
    stag->tag = RPMTAG_NOT_FOUND;

    if (!rstreq(tagname, "*")) {
	if (rstreqn("RPMTAG_", tagname, sizeof("RPMTAG_")-1)) {
	    tagname += sizeof("RPMTAG");
	}

	/* Search tag names. */
	stag->tag = rpmTagGetValue(tagname);
	if (stag->tag == RPMTAG_NOT_FOUND) return 1;

    } else stag->tag = -2;

    /* Search extensions for specific format. */
    if (stag->type != NULL)
	stag->fmt = rpmHeaderFormatByName(stag->type);

    return stag->fmt ? 0 : 1;
}

/* forward ref */
/**
 * Parse an expression.
 * @param hsa		headerSprintf args
 * @param token		token
 * @param str		string
 * @param[out] *endPtr
 * @return		0 on success
 */
static int parseExpression(headerSprintfArgs hsa, sprintfToken token,
		char * str,char ** endPtr);

/**
 * Parse a headerSprintf term.
 * @param hsa		headerSprintf args
 * @param str
 * @param[out] *formatPtr
 * @param[out] *numTokensPtr
 * @param[out] *endPtr
 * @param state
 * @return		0 on success
 */
static int parseFormat(headerSprintfArgs hsa, char * str,
	sprintfToken * formatPtr,int * numTokensPtr,
	char ** endPtr, int state)
{
    char * chptr, * start, * next, * dst;
    sprintfToken format;
    sprintfToken token;
    int numTokens;
    int done = 0;

    /* upper limit on number of individual formats */
    numTokens = 0;
    if (str != NULL)
    for (chptr = str; *chptr != '\0'; chptr++)
	if (*chptr == '%' || *chptr == '[') numTokens++;
    numTokens = numTokens * 2 + 1;

    format = (sprintfToken)xcalloc(numTokens, sizeof(*format));
    if (endPtr) *endPtr = NULL;

    dst = start = str;
    numTokens = 0;
    token = NULL;
    if (start != NULL)
    while (*start != '\0') {
	switch (*start) {
	case '%':
	    /* handle %% */
	    if (*(start + 1) == '%') {
		if (token == NULL || token->type != PTOK_STRING) {
		    token = format + numTokens++;
		    token->type = PTOK_STRING;
		    dst = token->u.string.string = start;
		}
		start++;
		*dst++ = *start++;
		break;
	    } 

	    token = format + numTokens++;
	    *dst++ = '\0';
	    start++;

	    if (*start == '|') {
		char * newEnd;

		start++;
		if (parseExpression(hsa, token, start, &newEnd)) {
		    goto errxit;
		}
		start = newEnd;
		break;
	    }

	    token->u.tag.format = start;
	    token->u.tag.justOne = 0;

	    chptr = start;
	    while (*chptr && *chptr != '{' && *chptr != '%') {
		if (!risdigit(*chptr) && *chptr != '-') {
		    hsaError(hsa, _("invalid field width"));
		    goto errxit;
		}
		chptr++;
	    }
	    if (!*chptr || *chptr == '%') {
		hsaError(hsa, _("missing { after %%"));
		goto errxit;
	    }

	    *chptr++ = '\0';

	    while (start < chptr) {
		start++;
	    }

	    if (*start == '=') {
		token->u.tag.justOne = 1;
		start++;
	    } else if (*start == '#') {
		token->u.tag.justOne = 1;
		token->u.tag.type = "arraysize";
		start++;
	    }

	    dst = next = start;
	    while (*next && *next != '}') next++;
	    if (!*next) {
		hsaError(hsa, _("missing } after %%{"));
		goto errxit;
	    }
	    *next++ = '\0';

	    chptr = start;
	    while (*chptr && *chptr != ':') chptr++;

	    if (*chptr != '\0') {
		*chptr++ = '\0';
		if (!*chptr) {
		    hsaError(hsa, _("empty tag format"));
		    goto errxit;
		}
		token->u.tag.type = chptr;
	    } 
	    /* default to string conversion if no formats found by now */
	    if (!token->u.tag.type) {
		token->u.tag.type = "string";
	    }
	    
	    if (!*start) {
		hsaError(hsa, _("empty tag name"));
		goto errxit;
	    }

	    token->type = PTOK_TAG;

	    if (findTag(hsa, token, start)) {
		hsaError(hsa, _("unknown tag: \"%s\""), start);
		goto errxit;
	    }

	    start = next;
	    break;

	case '[':
	    *dst++ = '\0';
	    *start++ = '\0';
	    token = format + numTokens++;

	    if (parseFormat(hsa, start,
			    &token->u.array.format,
			    &token->u.array.numTokens,
			    &start, PARSER_IN_ARRAY)) {
		goto errxit;
	    }

	    if (!start) {
		hsaError(hsa, _("] expected at end of array"));
		goto errxit;
	    }

	    dst = start;

	    token->type = PTOK_ARRAY;

	    break;

	case ']':
	    if (state != PARSER_IN_ARRAY) {
		hsaError(hsa, _("unexpected ]"));
		goto errxit;
	    }
	    *start++ = '\0';
	    if (endPtr) *endPtr = start;
	    done = 1;
	    break;

	case '}':
	    if (state != PARSER_IN_EXPR) {
		hsaError(hsa, _("unexpected }"));
		goto errxit;
	    }
	    *start++ = '\0';
	    if (endPtr) *endPtr = start;
	    done = 1;
	    break;

	default:
	    if (token == NULL || token->type != PTOK_STRING) {
		token = format + numTokens++;
		token->type = PTOK_STRING;
		dst = token->u.string.string = start;
	    }

	    if (*start == '\\') {
		start++;
		if (*start == '\0') {
		    hsaError(hsa, _("escaped char expected after \\"));
		    goto errxit;
		}
		*dst++ = escapedChar(*start++);
	    } else {
		*dst++ = *start++;
	    }
	    break;
	}
	if (done)
	    break;
    }

    if (dst != NULL)
        *dst = '\0';

    for (int i = 0; i < numTokens; i++) {
	token = format + i;
	if (token->type == PTOK_STRING)
	    token->u.string.len = strlen(token->u.string.string);
    }

    *numTokensPtr = numTokens;
    *formatPtr = format;
    return 0;

errxit:
    freeFormat(format, numTokens);
    return 1;
}

static int parseExpression(headerSprintfArgs hsa, sprintfToken token,
		char * str, char ** endPtr)
{
    char * chptr;
    char * end;

    hsaError(hsa, NULL);
    chptr = str;
    while (*chptr && *chptr != '?') chptr++;

    if (*chptr != '?') {
	hsaError(hsa, _("? expected in expression"));
	return 1;
    }

    *chptr++ = '\0';;

    if (*chptr != '{') {
	hsaError(hsa, _("{ expected after ? in expression"));
	return 1;
    }

    chptr++;

    if (parseFormat(hsa, chptr, &token->u.cond.ifFormat, 
		    &token->u.cond.numIfTokens, &end, PARSER_IN_EXPR)) 
	return 1;

    /* XXX fix segfault on "rpm -q rpm --qf='%|NAME?{%}:{NAME}|\n'"*/
    if (!(end && *end)) {
	hsaError(hsa, _("} expected in expression"));
	token->u.cond.ifFormat =
		freeFormat(token->u.cond.ifFormat, token->u.cond.numIfTokens);
	return 1;
    }

    chptr = end;
    if (*chptr != ':' && *chptr != '|') {
	hsaError(hsa, _(": expected following ? subexpression"));
	token->u.cond.ifFormat =
		freeFormat(token->u.cond.ifFormat, token->u.cond.numIfTokens);
	return 1;
    }

    if (*chptr == '|') {
	if (parseFormat(hsa, NULL, &token->u.cond.elseFormat, 
		&token->u.cond.numElseTokens, &end, PARSER_IN_EXPR))
	{
	    token->u.cond.ifFormat =
		freeFormat(token->u.cond.ifFormat, token->u.cond.numIfTokens);
	    return 1;
	}
    } else {
	chptr++;

	if (*chptr != '{') {
	    hsaError(hsa, _("{ expected after : in expression"));
	    token->u.cond.ifFormat =
		freeFormat(token->u.cond.ifFormat, token->u.cond.numIfTokens);
	    return 1;
	}

	chptr++;

	if (parseFormat(hsa, chptr, &token->u.cond.elseFormat, 
			&token->u.cond.numElseTokens, &end, PARSER_IN_EXPR)) 
	    return 1;

	/* XXX fix segfault on "rpm -q rpm --qf='%|NAME?{a}:{%}|{NAME}\n'" */
	if (!(end && *end)) {
	    hsaError(hsa, _("} expected in expression"));
	    token->u.cond.ifFormat =
		freeFormat(token->u.cond.ifFormat, token->u.cond.numIfTokens);
	    return 1;
	}

	chptr = end;
	if (*chptr != '|') {
	    hsaError(hsa, _("| expected at end of expression"));
	    token->u.cond.ifFormat =
		freeFormat(token->u.cond.ifFormat, token->u.cond.numIfTokens);
	    token->u.cond.elseFormat =
		freeFormat(token->u.cond.elseFormat, token->u.cond.numElseTokens);
	    return 1;
	}
    }
	
    chptr++;

    *endPtr = chptr;

    token->type = PTOK_COND;

    (void) findTag(hsa, token, str);

    return 0;
}

static rpmtd getCached(tagCache cache, rpmTagVal tag)
{
    rpmtd *res = NULL;
    return tagCacheGetEntry(cache, tag, &res, NULL, NULL) ? res[0] : NULL;
}

/**
 * Do headerGet() just once for given tag, cache results.
 * @param hsa		headerSprintf args
 * @param tag
 * @param[out] *typeptr
 * @param[out] *data
 * @param[out] *countptr
 * @return		1 on success, 0 on failure
 */
static rpmtd getData(headerSprintfArgs hsa, rpmTagVal tag)
{
    rpmtd td = NULL;

    if (!(td = getCached(hsa->cache, tag))) {
	td = rpmtdNew();
	if (!headerGet(hsa->h, tag, td, hsa->hgflags)) {
	    rpmtdFree(td);
	    return NULL;
	}
	tagCacheAddEntry(hsa->cache, tag, td);
    }

    return td;
}

/**
 * formatValue
 * @param hsa		headerSprintf args
 * @param tag
 * @param element
 * @return		end of formatted string (NULL on error)
 */
static char * formatValue(headerSprintfArgs hsa, sprintfTag tag, int element)
{
    char * val = NULL;
    rpmtd td;

    if ((td = getData(hsa, tag->tag)) && td->count > element) {
	td->ix = element; /* Ick, use iterators instead */
	val = rpmHeaderFormatCall(tag->fmt, td);
    } else {
	val = xstrdup("(none)");
    }

    /* Handle field width + justification formatting if specified */
    if (tag->format && *tag->format) {
	char *tval = NULL;
	/* user string + extra for '%', format char and trailing '\0' */
	char fmtbuf[strlen(tag->format) + 3];

	sprintf(fmtbuf, "%%%ss", tag->format);
	rasprintf(&tval, fmtbuf, val);
	free(val);
	val = tval;
    }
	
    if (val) {
	hsaAppend(hsa, val);
    }
    free(val);

    return (hsa->val + hsa->vallen);
}

/**
 * Format a single headerSprintf item.
 * @param hsa		headerSprintf args
 * @param token
 * @param element
 * @return		end of formatted string (NULL on error)
 */
static char * singleSprintf(headerSprintfArgs hsa, sprintfToken token,
		int element)
{
    char * te;
    int i, j, found;
    rpm_count_t count, numElements;
    sprintfToken spft;
    int condNumFormats;
    size_t need;

    /* we assume the token and header have been validated already! */

    switch (token->type) {
    case PTOK_NONE:
	break;

    case PTOK_STRING:
	need = token->u.string.len;
	if (need == 0) break;
	hsaAppend(hsa, token->u.string.string);
	break;

    case PTOK_TAG:
	te = formatValue(hsa, &token->u.tag,
			(token->u.tag.justOne ? 0 : element));
	if (te == NULL)
	    return NULL;
	break;

    case PTOK_COND:
	if (getData(hsa, token->u.cond.tag.tag) ||
		      headerIsEntry(hsa->h, token->u.cond.tag.tag)) {
	    spft = token->u.cond.ifFormat;
	    condNumFormats = token->u.cond.numIfTokens;
	} else {
	    spft = token->u.cond.elseFormat;
	    condNumFormats = token->u.cond.numElseTokens;
	}

	need = condNumFormats * 20;
	if (spft == NULL || need == 0) break;

	for (i = 0; i < condNumFormats; i++, spft++) {
	    if (singleSprintf(hsa, spft, element) == NULL)
		return NULL;
	}
	break;

    case PTOK_ARRAY:
	numElements = 0;
	found = 0;
	spft = token->u.array.format;
	for (i = 0; i < token->u.array.numTokens; i++, spft++)
	{
	    rpmtd td = NULL;
	    if (spft->type != PTOK_TAG ||
		spft->u.tag.justOne) continue;

	    if (!(td = getData(hsa, spft->u.tag.tag))) {
		continue;
	    }

	    found = 1;
	    count = rpmtdCount(td);

	    if (numElements > 0 && count != numElements) {
		hsaError(hsa,
			_("array iterator used with different sized arrays"));
		return NULL;
	    }
	    if (count > numElements)
		numElements = count;
	}

	if (found) {
	    need = numElements * token->u.array.numTokens * 10;
	    if (need == 0) break;

	    spft = token->u.array.format;

	    if (hsa->xfmt.xTagHeader)
		hsa->xfmt.xTagHeader(hsa, spft->u.tag.tag, numElements);

	    for (j = 0; j < numElements; j++) {
		spft = token->u.array.format;
		for (i = 0; i < token->u.array.numTokens; i++, spft++) {
		    if (hsa->xfmt.xItemHeader) {
			hsa->xfmt.xItemHeader(hsa, spft->u.tag.tag,
						j, numElements);
		    }
		    te = singleSprintf(hsa, spft, j);
		    if (hsa->xfmt.xItemFooter) {
			hsa->xfmt.xItemFooter(hsa, spft->u.tag.tag,
						j, numElements);
		    }
		    if (te == NULL)
			return NULL;
		}
	    }

	    if (hsa->xfmt.xTagFooter)
		hsa->xfmt.xTagFooter(hsa, spft->u.tag.tag, numElements);

	}
	break;
    }

    return (hsa->val + hsa->vallen);
}

static int tagCmp(rpmTagVal a, rpmTagVal b)
{
    return (a != b);
}

static unsigned int tagId(rpmTagVal tag)
{
    return tag;
}

char * headerFormat(Header h, const char * fmt, errmsg_t * errmsg) 
{
    struct headerSprintfArgs_s hsa;
    sprintfToken nextfmt;
    sprintfTag tag;
 
    memset(&hsa, 0, sizeof(hsa));
    hsa.h = headerLink(h);
    hsa.fmt = xstrdup(fmt);
    hsa.errmsg = NULL;

    if (parseFormat(&hsa, hsa.fmt, &hsa.format, &hsa.numTokens, NULL, PARSER_BEGIN))
	goto exit;

    hsa.cache = tagCacheCreate(128, tagId, tagCmp, NULL, rpmtdFree);
    hsa.val = xstrdup("");

    tag =
	(hsa.format->type == PTOK_TAG
	    ? &hsa.format->u.tag :
	(hsa.format->type == PTOK_ARRAY
	    ? &hsa.format->u.array.format->u.tag :
	NULL));
    if (tag != NULL && tag->tag == -2 && tag->type != NULL) {
	if (rstreq(tag->type, "xml"))
	    hsa.xfmt = xformat_xml; /* struct assignment */
	else if (rstreq(tag->type, "json"))
	    hsa.xfmt = xformat_json; /* struct assignment */
    }

    if (hsa.xfmt.xHeader)
	hsa.xfmt.xHeader(&hsa);

    hsaInit(&hsa);
    while ((nextfmt = hsaNext(&hsa)) != NULL) {
	if (singleSprintf(&hsa, nextfmt, 0) == NULL) {
	    hsa.val = _free(hsa.val);
	    break;
	}
    }
    hsaFini(&hsa);

    if (hsa.xfmt.xFooter)
	hsa.xfmt.xFooter(&hsa);

    if (hsa.val != NULL && hsa.vallen < hsa.alloced)
	hsa.val = xrealloc(hsa.val, hsa.vallen+1);	

    hsa.cache = tagCacheFree(hsa.cache);
    hsa.format = freeFormat(hsa.format, hsa.numTokens);

exit:
    if (errmsg)
	*errmsg = hsa.errmsg;
    hsa.h = headerFree(hsa.h);
    hsa.fmt = _free(hsa.fmt);
    return hsa.val;
}

