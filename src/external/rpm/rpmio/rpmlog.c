/** \ingroup rpmio
 * \file rpmio/rpmlog.c
 */

#include "system.h"
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmstring.h>
#include "debug.h"

typedef struct rpmlogCtx_s * rpmlogCtx;
struct rpmlogCtx_s {
    pthread_rwlock_t lock;
    unsigned mask;
    int nrecs;
    int nrecsPri[RPMLOG_NPRIS];
    rpmlogRec recs;
    rpmlogCallback cbfunc;
    rpmlogCallbackData cbdata;
    FILE *stdlog;
};

struct rpmlogRec_s {
    int		code;		/* unused */
    rpmlogLvl	pri;		/* priority */ 
    char * message;		/* log message string */
};

/* Force log context acquisition through a function */
static rpmlogCtx rpmlogCtxAcquire(int write)
{
    static struct rpmlogCtx_s _globalCtx = { PTHREAD_RWLOCK_INITIALIZER,
					     RPMLOG_UPTO(RPMLOG_NOTICE),
					     0, {0}, NULL, NULL, NULL, NULL };
    rpmlogCtx ctx = &_globalCtx;
    int xx;

    /* XXX Silently failing is bad, but we can't very well use log here... */
    if (write)
	xx = pthread_rwlock_wrlock(&ctx->lock);
    else
	xx = pthread_rwlock_rdlock(&ctx->lock);

    return (xx == 0) ? ctx : NULL;
}

/* Release log context */
static rpmlogCtx rpmlogCtxRelease(rpmlogCtx ctx)
{
    if (ctx)
	pthread_rwlock_unlock(&ctx->lock);
    return NULL;
}

int rpmlogGetNrecsByMask(unsigned mask)
{
    rpmlogCtx ctx = rpmlogCtxAcquire(0);
    int nrecs = 0;

    if (ctx == NULL)
	return -1;

    if (mask) {
	for (int i = 0; i < RPMLOG_NPRIS; i++, mask >>= 1)
	    if (mask & 1)
	        nrecs += ctx->nrecsPri[i];
    } else
	nrecs = ctx->nrecs;

    rpmlogCtxRelease(ctx);
    return nrecs;
}

int rpmlogGetNrecs(void)
{
    return rpmlogGetNrecsByMask(0);
}

int rpmlogCode(void)
{
    int code = -1;
    rpmlogCtx ctx = rpmlogCtxAcquire(0);
    
    if (ctx && ctx->recs != NULL && ctx->nrecs > 0)
	code = ctx->recs[ctx->nrecs-1].code;

    rpmlogCtxRelease(ctx);
    return code;
}

const char * rpmlogMessage(void)
{
    const char *msg = _("(no error)");
    rpmlogCtx ctx = rpmlogCtxAcquire(0);

    if (ctx && ctx->recs != NULL && ctx->nrecs > 0)
	msg = ctx->recs[ctx->nrecs-1].message;

    rpmlogCtxRelease(ctx);
    return msg;
}

const char * rpmlogRecMessage(rpmlogRec rec)
{
    return (rec != NULL) ? rec->message : NULL;
}

rpmlogLvl rpmlogRecPriority(rpmlogRec rec)
{
    return (rec != NULL) ? rec->pri : (rpmlogLvl)-1;
}

void rpmlogPrintByMask(FILE *f, unsigned mask)
{
    rpmlogCtx ctx = rpmlogCtxAcquire(0);

    if (ctx == NULL)
	return;

    if (f == NULL)
	f = stderr;

    for (int i = 0; i < ctx->nrecs; i++) {
	rpmlogRec rec = ctx->recs + i;
	if (mask && ((RPMLOG_MASK(rec->pri) & mask) == 0))
	    continue;
	if (rec->message && *rec->message)
	    fprintf(f, "    %s", rec->message);
    }

    rpmlogCtxRelease(ctx);
}

void rpmlogPrint(FILE *f)
{
    rpmlogPrintByMask(f, 0);
}

void rpmlogClose (void)
{
    rpmlogCtx ctx = rpmlogCtxAcquire(1);

    if (ctx == NULL)
	return;

    for (int i = 0; i < ctx->nrecs; i++) {
	rpmlogRec rec = ctx->recs + i;
	rec->message = _free(rec->message);
    }
    ctx->recs = _free(ctx->recs);
    ctx->nrecs = 0;
    memset(ctx->nrecsPri, 0, sizeof(ctx->nrecsPri));

    rpmlogCtxRelease(ctx);
}

void rpmlogOpen (const char *ident, int option,
		int facility)
{
}

int rpmlogSetMask (int mask)
{
    rpmlogCtx ctx = rpmlogCtxAcquire(mask ? 1 : 0);

    int omask = -1;
    if (ctx) {
	omask = ctx->mask;
	if (mask)
	    ctx->mask = mask;
    }

    rpmlogCtxRelease(ctx);
    return omask;
}

rpmlogCallback rpmlogSetCallback(rpmlogCallback cb, rpmlogCallbackData data)
{
    rpmlogCtx ctx = rpmlogCtxAcquire(1);

    rpmlogCallback ocb = NULL;
    if (ctx) {
	ocb = ctx->cbfunc;
	ctx->cbfunc = cb;
	ctx->cbdata = data;
    }

    rpmlogCtxRelease(ctx);
    return ocb;
}

FILE * rpmlogSetFile(FILE * fp)
{
    rpmlogCtx ctx = rpmlogCtxAcquire(1);

    FILE * ofp = NULL;
    if (ctx) {
	ofp = ctx->stdlog;
	ctx->stdlog = fp;
    }

    rpmlogCtxRelease(ctx);
    return ofp;
}

static const char * const rpmlogMsgPrefix[] = {
    N_("fatal error: "),/*!< RPMLOG_EMERG */
    N_("fatal error: "),/*!< RPMLOG_ALERT */
    N_("fatal error: "),/*!< RPMLOG_CRIT */
    N_("error: "),	/*!< RPMLOG_ERR */
    N_("warning: "),	/*!< RPMLOG_WARNING */
    "",			/*!< RPMLOG_NOTICE */
    "",			/*!< RPMLOG_INFO */
    "D: ",		/*!< RPMLOG_DEBUG */
};

#define ANSI_COLOR_BLACK	"\x1b[30m"
#define ANSI_COLOR_RED		"\x1b[31m"
#define ANSI_COLOR_GREEN	"\x1b[32m"
#define ANSI_COLOR_YELLOW	"\x1b[33m"
#define ANSI_COLOR_BLUE		"\x1b[34m"
#define ANSI_COLOR_MAGENTA	"\x1b[35m"
#define ANSI_COLOR_CYAN		"\x1b[36m"
#define ANSI_COLOR_WHITE	"\x1b[37m"

#define ANSI_BRIGHT_BLACK	"\x1b[30;1m"
#define ANSI_BRIGHT_RED		"\x1b[31;1m"
#define ANSI_BRIGHT_GREEN	"\x1b[32;1m"
#define ANSI_BRIGHT_YELLOW	"\x1b[33;1m"
#define ANSI_BRIGHT_BLUE	"\x1b[34;1m"
#define ANSI_BRIGHT_MAGENTA	"\x1b[35;1m"
#define ANSI_BRIGHT_CYAN	"\x1b[36;1m"
#define ANSI_BRIGHT_WHITE	"\x1b[37;1m"

#define ANSI_COLOR_BOLD		"\x1b[1m"
#define ANSI_COLOR_RESET	"\x1b[0m"

static const char *rpmlogMsgPrefixColor[] = {
    ANSI_BRIGHT_RED,	/*!< RPMLOG_EMERG */
    ANSI_BRIGHT_RED,	/*!< RPMLOG_ALERT */
    ANSI_BRIGHT_RED,	/*!< RPMLOG_CRIT */
    ANSI_BRIGHT_RED,	/*!< RPMLOG_ERR */
    ANSI_BRIGHT_MAGENTA,/*!< RPMLOG_WARNING */
    "",			/*!< RPMLOG_NOTICE */
    "",			/*!< RPMLOG_INFO */
    ANSI_BRIGHT_BLUE,	/*!< RPMLOG_DEBUG */
};

const char * rpmlogLevelPrefix(rpmlogLvl pri)
{
    const char * prefix = "";
    if (rpmlogMsgPrefix[pri] && *rpmlogMsgPrefix[pri]) 
	prefix = _(rpmlogMsgPrefix[pri]);
    return prefix;
}

static const char * rpmlogLevelColor(rpmlogLvl pri)
{
    return rpmlogMsgPrefixColor[pri&0x7];
}

enum {
    COLOR_NO = 0,
    COLOR_AUTO = 1,
    COLOR_ALWAYS = 2,
};

static int getColorConfig(void)
{
    int rc = COLOR_NO;
    char * color = rpmExpand("%{?_color_output}%{!?_color_output:auto}", NULL);
    if (rstreq(color, "auto"))
	rc = COLOR_AUTO;
    else if (rstreq(color, "always"))
	rc = COLOR_ALWAYS;
    free(color);
    return rc;
}

static void logerror(void)
{
    static __thread int lasterr = 0;
    if (errno != EPIPE && errno != lasterr) {
	lasterr = errno;
	perror(_("Error writing to log"));
    }
}

static int rpmlogDefault(FILE *stdlog, rpmlogRec rec)
{
    FILE *msgout = (stdlog ? stdlog : stderr);
    static __thread int color = -1;
    const char * colorOn = NULL;

    if (color < 0)
	color = getColorConfig();

    if (color == COLOR_ALWAYS ||
	    (color == COLOR_AUTO && isatty(fileno(msgout))))
	colorOn = rpmlogLevelColor(rec->pri);

    switch (rec->pri) {
    case RPMLOG_INFO:
    case RPMLOG_NOTICE:
	msgout = (stdlog ? stdlog : stdout);
	break;
    case RPMLOG_EMERG:
    case RPMLOG_ALERT:
    case RPMLOG_CRIT:
    case RPMLOG_ERR:
    case RPMLOG_WARNING:
    case RPMLOG_DEBUG:
	if (colorOn && *colorOn)
	    if (fputs(rpmlogLevelColor(rec->pri), msgout) == EOF)
		logerror();
	break;
    default:
	break;
    }

    if (fputs(rpmlogLevelPrefix(rec->pri), msgout) == EOF)
	logerror();

    switch (rec->pri) {
    case RPMLOG_INFO:
    case RPMLOG_NOTICE:
	break;
    case RPMLOG_EMERG:
    case RPMLOG_ALERT:
    case RPMLOG_CRIT:
    case RPMLOG_ERR:
    case RPMLOG_WARNING:
	if (colorOn && *colorOn) {
	    if (fputs(ANSI_COLOR_RESET, msgout) == EOF)
		logerror();
	    if (fputs(ANSI_COLOR_BOLD, msgout) == EOF)
		logerror();
	}
    case RPMLOG_DEBUG:
    default:
	break;
    }

    if (rec->message)
	if (fputs(rec->message, msgout) == EOF)
	    logerror();

    switch (rec->pri) {
    case RPMLOG_INFO:
    case RPMLOG_NOTICE:
	break;
    case RPMLOG_EMERG:
    case RPMLOG_ALERT:
    case RPMLOG_CRIT:
    case RPMLOG_ERR:
    case RPMLOG_WARNING:
    case RPMLOG_DEBUG:
	if (colorOn && *colorOn)
	    if (fputs(ANSI_COLOR_RESET, msgout) == EOF)
		logerror();
	break;
    default:
	break;
    }

    if (fflush(msgout) == EOF)
	logerror();

    return (rec->pri <= RPMLOG_CRIT ? RPMLOG_EXIT : 0);
}

/* FIX: rpmlogMsgPrefix[] dependent, not unqualified */
/* FIX: rpmlogMsgPrefix[] may be NULL */
static void dolog(struct rpmlogRec_s *rec, int saverec)
{
    static pthread_mutex_t serialize = PTHREAD_MUTEX_INITIALIZER;

    int cbrc = RPMLOG_DEFAULT;
    int needexit = 0;
    FILE *clog = NULL;
    rpmlogCallbackData cbdata = NULL;
    rpmlogCallback cbfunc = NULL;
    rpmlogCtx ctx = rpmlogCtxAcquire(saverec);

    if (ctx == NULL)
	return;

    /* Save copy of all messages at warning (or below == "more important"). */
    if (saverec) {
	ctx->recs = xrealloc(ctx->recs, (ctx->nrecs+2) * sizeof(*ctx->recs));
	ctx->recs[ctx->nrecs].code = rec->code;
	ctx->recs[ctx->nrecs].pri = rec->pri;
	ctx->recs[ctx->nrecs].message = xstrdup(rec->message);
	ctx->recs[ctx->nrecs+1].code = 0;
	ctx->recs[ctx->nrecs+1].message = NULL;
	ctx->nrecs++;
	ctx->nrecsPri[rec->pri]++;
    }
    cbfunc = ctx->cbfunc;
    cbdata = ctx->cbdata;
    clog = ctx->stdlog;

    /* Free the context for callback and actual log output */
    ctx = rpmlogCtxRelease(ctx);

    /* Always serialize callback and output to avoid interleaved messages. */
    if (pthread_mutex_lock(&serialize) == 0) {
	if (cbfunc) {
	    cbrc = cbfunc(rec, cbdata);
	    needexit += cbrc & RPMLOG_EXIT;
	}

	if (cbrc & RPMLOG_DEFAULT) {
	    cbrc = rpmlogDefault(clog, rec);
	    needexit += cbrc & RPMLOG_EXIT;
	}
	pthread_mutex_unlock(&serialize);
    }
    
    if (needexit)
	exit(EXIT_FAILURE);

}

void rpmlog (int code, const char *fmt, ...)
{
    int saved_errno = errno;
    unsigned pri = RPMLOG_PRI(code);
    unsigned mask = RPMLOG_MASK(pri);
    int saverec = (pri <= RPMLOG_WARNING);
    va_list ap;
    char *msg = NULL;

    if ((mask & rpmlogSetMask(0)) == 0)
	goto exit;

    va_start(ap, fmt);
    if (rvasprintf(&msg, fmt, ap) >= 0) {
	struct rpmlogRec_s rec;

	rec.code = code;
	rec.pri = (rpmlogLvl)pri;
	rec.message = msg;

	dolog(&rec, saverec);

	free(msg);
    }
    va_end(ap);
exit:
    errno = saved_errno;
}
