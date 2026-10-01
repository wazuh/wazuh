/** \ingroup rpmcli
 * \file lib/poptALL.c
 *  Popt tables for all rpm modes.
 */

#include "system.h"

#include <rpm/rpmcli.h>
#include <rpm/rpmlib.h>		/* rpmEVR, rpmReadConfigFiles etc */
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmfileutil.h>

#include "debug.h"

#define POPT_SHOWVERSION	-999
#define POPT_SHOWRC		-998
#define POPT_QUERYTAGS		-997
#define POPT_PREDEFINE		-996
#define POPT_DBPATH		-995
#define POPT_UNDEFINE		-994
#define POPT_PIPE		-993
#define POPT_LOAD		-992

static int _debug = 0;

extern int _fsm_debug;

extern int _print_pkts;

extern int _psm_debug;

/* XXX avoid -lrpmbuild linkage. */
       int _rpmfc_debug;

extern int _rpmts_stats;

const char * rpmcliPipeOutput = NULL;

const char * rpmcliRcfile = NULL;

const char * rpmcliRootDir = "/";

rpmQueryFlags rpmcliQueryFlags;

rpmVSFlags rpmcliVSFlags;

int rpmcliVfyLevelMask;

extern int _rpmio_debug;

static int rpmcliInitialized = -1;

/**
 * Display rpm version.
 */
static void printVersion(FILE * fp)
{
    fprintf(fp, _("RPM version %s\n"), rpmEVR);
}

/**
 * Make sure that config files have been read.
 * @warning Options like --rcfile and --verbose must precede callers option.
 */
void rpmcliConfigured(void)
{

    if (rpmcliInitialized < 0)
	rpmcliInitialized = rpmReadConfigFiles(rpmcliRcfile, NULL);
    if (rpmcliInitialized)
	exit(EXIT_FAILURE);
}

static int cliDefine(const char *arg, int predefine)
{
    int rc;
    char *s, *t;
    /* XXX Convert '-' in macro name to underscore, skip leading %. */
    s = t = xstrdup(arg);
    while (*t && !risspace(*t) && (*t != '(')) {
	if (*t == '-') *t = '_';
	t++;
    }
    t = s;
    if (*t == '%') t++;

    rc = rpmDefineMacro(NULL, t, RMIL_CMDLINE);
    if (!predefine && rc == 0)
	(void) rpmDefineMacro(rpmCLIMacroContext, t, RMIL_CMDLINE);

    free(s);
    return rc;
}

/**
 */
static void rpmcliAllArgCallback( poptContext con,
                enum poptCallbackReason reason,
                const struct poptOption * opt, const char * arg,
                const void * data)
{

    /* XXX avoid accidental collisions with POPT_BIT_SET for flags */
    if (opt->arg == NULL)
    switch (opt->val) {
    case 'q':
	rpmSetVerbosity(RPMLOG_WARNING);
	break;
    case 'v':
	rpmIncreaseVerbosity();
	break;
    case POPT_PREDEFINE:
	if (cliDefine(arg, 1))
	    exit(EXIT_FAILURE);
	break;
    case 'D':
	rpmcliConfigured();
	if (cliDefine(arg, 0))
	    exit(EXIT_FAILURE);
	break;
    case POPT_UNDEFINE:
	rpmcliConfigured();
	if (*arg == '%')
	    arg++;
	rpmPopMacro(NULL, arg);
	break;
    case 'E':
	rpmcliConfigured();
	{   char *val = NULL;
	    if (rpmExpandMacros(NULL, arg, &val, 0) < 0)
		exit(EXIT_FAILURE);
	    if (fprintf(stdout, "%s\n", val) < 0 ||
		fflush(stdout) == EOF ||
		ferror(stdout)) {
	        perror(_("Error writing to stdout"));
		free(val);
	        exit(EXIT_FAILURE);
	    }
	    free(val);
	}
	break;
    case POPT_LOAD:
	rpmcliConfigured();
	if (rpmLoadMacroFile(NULL, arg)) {
	    fprintf(stderr, _("failed to load macro file %s\n"), arg);
	    exit(EXIT_FAILURE);
	}
	break;
    case POPT_DBPATH:
	rpmcliConfigured();
	if (arg && arg[0] != '/') {
	    fprintf(stderr, _("arguments to --dbpath must begin with '/'\n"));
	    exit(EXIT_FAILURE);
	}
	rpmPushMacro(NULL, "_dbpath", NULL, arg, RMIL_CMDLINE);
	break;
    case POPT_SHOWVERSION:
	printVersion(stdout);
	exit(EXIT_SUCCESS);
	break;
    case POPT_SHOWRC:
	rpmcliConfigured();
	(void) rpmShowRC(stdout);
	/* EXIT_FAILURE on any errors (during rpmcliConfigured()) */
	exit(rpmlogGetNrecsByMask(RPMLOG_UPTO(RPMLOG_ERR)) ?
	     EXIT_FAILURE : EXIT_SUCCESS);
	break;
    case POPT_QUERYTAGS:
	rpmDisplayQueryTags(stdout);
	exit(EXIT_SUCCESS);
	break;
    case POPT_PIPE:
	if (rpmcliPipeOutput) {
	    fprintf(stderr,
		    _("%s: error: more than one --pipe specified "
		      "(incompatible popt aliases?)\n"), xgetprogname());
	    exit(EXIT_FAILURE);
	}
	rpmcliPipeOutput = xstrdup(arg);
	break;
    case RPMCLI_POPT_NODIGEST:
	rpmcliVSFlags |= RPMVSF_MASK_NODIGESTS;
	rpmcliVfyLevelMask |= RPMSIG_DIGEST_TYPE;
	break;
    case RPMCLI_POPT_NOSIGNATURE:
	rpmcliVSFlags |= RPMVSF_MASK_NOSIGNATURES;
	rpmcliVfyLevelMask |= RPMSIG_SIGNATURE_TYPE;
	break;
    case RPMCLI_POPT_NOHDRCHK:
	rpmcliVSFlags |= RPMVSF_NOHDRCHK;
	break;
	
    case RPMCLI_POPT_TARGETPLATFORM:
	rpmcliInitialized = rpmReadConfigFiles(rpmcliRcfile, arg);
	break;
    }
}

struct poptOption rpmcliAllPoptTable[] = {
/* FIX: cast? */
 { NULL, '\0', POPT_ARG_CALLBACK | POPT_CBFLAG_INC_DATA | POPT_CBFLAG_CONTINUE,
        (void *)rpmcliAllArgCallback, 0, NULL, NULL },

 { "debug", 'd', POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN, &_debug, -1,
        NULL, NULL },

 { "predefine", '\0', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN, 0, POPT_PREDEFINE,
	N_("predefine MACRO with value EXPR"),
	N_("'MACRO EXPR'") },
 { "define", 'D', POPT_ARG_STRING, 0, 'D',
	N_("define MACRO with value EXPR"),
	N_("'MACRO EXPR'") },
 { "undefine", '\0', POPT_ARG_STRING, 0, POPT_UNDEFINE,
	N_("undefine MACRO"),
	N_("MACRO") },
 { "eval", 'E', POPT_ARG_STRING, 0, 'E',
	N_("print macro expansion of EXPR"),
	N_("'EXPR'") },
 { "target", '\0', POPT_ARG_STRING, NULL,  RPMCLI_POPT_TARGETPLATFORM,
        N_("Specify target platform"), N_("CPU-VENDOR-OS") },
 { "macros", '\0', POPT_ARG_STRING, &macrofiles, 0,
	N_("read <FILE:...> instead of default file(s)"),
	N_("<FILE:...>") },
 { "load", '\0', POPT_ARG_STRING, 0, POPT_LOAD,
	N_("load a single macro file"),
	N_("<FILE>") },

 /* XXX this is a bit out of place here but kinda unavoidable... */
 { "noplugins", '\0', POPT_BIT_SET,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOPLUGINS,
	N_("don't enable any plugins"), NULL },

 { "nodigest", '\0', 0, 0, RPMCLI_POPT_NODIGEST,
        N_("don't verify package digest(s)"), NULL },
 { "nohdrchk", '\0', POPT_ARGFLAG_DOC_HIDDEN, 0, RPMCLI_POPT_NOHDRCHK,
        N_("don't verify database header(s) when retrieved"), NULL },
 { "nosignature", '\0', 0, 0, RPMCLI_POPT_NOSIGNATURE,
        N_("don't verify package signature(s)"), NULL },

 { "pipe", '\0', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN, 0, POPT_PIPE,
	N_("send stdout to CMD"),
	N_("CMD") },
 { "rcfile", '\0', POPT_ARG_STRING, &rpmcliRcfile, 0,
	N_("read <FILE:...> instead of default file(s)"),
	N_("<FILE:...>") },
 { "root", 'r', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT, &rpmcliRootDir, 0,
	N_("use ROOT as top level directory"),
	N_("ROOT") },
 { "dbpath", '\0', POPT_ARG_STRING, 0, POPT_DBPATH,
	N_("use database in DIRECTORY"),
	N_("DIRECTORY") },

 { "querytags", '\0', 0, 0, POPT_QUERYTAGS,
        N_("display known query tags"), NULL },
 { "showrc", '\0', 0, NULL, POPT_SHOWRC,
	N_("display final rpmrc and macro configuration"), NULL },
 { "quiet", '\0', 0, NULL, 'q',
	N_("provide less detailed output"), NULL},
 { "verbose", 'v', 0, NULL, 'v',
	N_("provide more detailed output"), NULL},
 { "version", '\0', 0, NULL, POPT_SHOWVERSION,
	N_("print the version of rpm being used"), NULL },

 { "fsmdebug", '\0', POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN, &_fsm_debug, -1,
	N_("debug payload file state machine"), NULL},
 { "prtpkts", '\0', POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN, &_print_pkts, -1,
	NULL, NULL},
 { "rpmfcdebug", '\0', POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN, &_rpmfc_debug, -1,
	NULL, NULL},
 { "rpmiodebug", '\0', POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN, &_rpmio_debug, -1,
	N_("debug rpmio I/O"), NULL},
 { "stats", '\0', POPT_ARG_VAL|POPT_ARGFLAG_DOC_HIDDEN, &_rpmts_stats, -1,
	NULL, NULL},

   POPT_TABLEEND
};

poptContext
rpmcliFini(poptContext optCon)
{
    poptFreeContext(optCon);
    rpmFreeMacros(NULL);
    rpmFreeMacros(rpmCLIMacroContext);
    rpmFreeRpmrc();
    rpmlogClose();
    rpmcliInitialized = -1;

    return NULL;
}

poptContext
rpmcliInit(int argc, char *const argv[], struct poptOption * optionsTable)
{
    poptContext optCon = NULL;
    int rc;
    const char *ctx, *execPath;

    xsetprogname(argv[0]);

#if defined(ENABLE_NLS)
    (void) setlocale(LC_ALL, "" );

    (void) bindtextdomain(PACKAGE, LOCALEDIR);
    (void) textdomain(PACKAGE);
#endif

    rpmSetVerbosity(RPMLOG_NOTICE);

    if (optionsTable == NULL) {
	/* Read rpm configuration (if not already read). */
	rpmcliConfigured();
	return NULL;
    }

    /* XXX hack to get popt working from build tree wrt lt-foo names */
    ctx = rstreqn(xgetprogname(), "lt-", 3) ? xgetprogname() + 3 : xgetprogname();

    optCon = poptGetContext(ctx, argc, (const char **)argv, optionsTable, 0);
    {
	char *poptfile = rpmGenPath(rpmConfigDir(), LIBRPMALIAS_FILENAME, NULL);
	(void) poptReadConfigFile(optCon, poptfile);
	free(poptfile);
    }
    (void) poptReadDefaultConfig(optCon, 1);

    if ((execPath = getenv("RPM_POPTEXEC_PATH")) == NULL)
	execPath = LIBRPMALIAS_EXECPATH;
    poptSetExecPath(optCon, execPath, 1);

    /* Process all options, whine if unknown. */
    while ((rc = poptGetNextOpt(optCon)) > 0) {
	fprintf(stderr, _("%s: option table misconfigured (%d)\n"),
		xgetprogname(), rc);
	goto err;
    }

    if (rc < -1) {
	fprintf(stderr, "%s: %s: %s\n", xgetprogname(),
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
		poptStrerror(rc));
	goto err;
    }

    /* Read rpm configuration (if not already read). */
    rpmcliConfigured();

    if (_debug) {
	rpmIncreaseVerbosity();
	rpmIncreaseVerbosity();
    }

    return optCon;

err:
    poptFreeContext(optCon);
    exit(EXIT_FAILURE);
    return NULL; /* not reached */
}
