/** \ingroup rpmcli
 * \file lib/poptI.c
 *  Popt tables for install modes.
 */

#include "system.h"

#include <string.h>

#include <rpm/rpmcli.h>

#include "debug.h"

struct rpmInstallArguments_s rpmIArgs = {
    0,			/* transFlags */
    0,			/* probFilter */
    0,			/* installInterfaceFlags */
    0,			/* numRelocations */
    0,			/* noDeps */
    0,			/* incldocs */
    NULL,		/* relocations */
    NULL,		/* prefix */
};

#define	POPT_RELOCATE		-1021
#define	POPT_EXCLUDEPATH	-1022

RPM_GNUC_NORETURN
static void argerror(const char * desc)
{
    fprintf(stderr, "%s: %s\n", xgetprogname(), desc);
    exit(EXIT_FAILURE);
}

/**
 */
static void installArgCallback( poptContext con,
		enum poptCallbackReason reason,
		const struct poptOption * opt, const char * arg,
		const void * data)
{
    struct rpmInstallArguments_s * ia = &rpmIArgs;

    /* XXX avoid accidental collisions with POPT_BIT_SET for flags */
    if (opt->arg == NULL)
    switch (opt->val) {

    case 'i':
	ia->installInterfaceFlags |= INSTALL_INSTALL;
	break;

    case POPT_EXCLUDEPATH:
	if (arg == NULL || *arg != '/') 
	    argerror(_("exclude paths must begin with a /"));
	ia->relocations = xrealloc(ia->relocations, 
			sizeof(*ia->relocations) * (ia->numRelocations + 1));
	ia->relocations[ia->numRelocations].oldPath = xstrdup(arg);
	ia->relocations[ia->numRelocations].newPath = NULL;
	ia->numRelocations++;
	break;
    case POPT_RELOCATE:
      { char * oldPath = NULL;
	char * newPath = NULL;
	
	if (arg == NULL || *arg != '/') 
	    argerror(_("relocations must begin with a /"));
	oldPath = xstrdup(arg);
	if (!(newPath = strchr(oldPath, '=')))
	    argerror(_("relocations must contain a ="));
	*newPath++ = '\0';
	if (*newPath != '/') 
	    argerror(_("relocations must have a / following the ="));
	ia->relocations = xrealloc(ia->relocations, 
			sizeof(*ia->relocations) * (ia->numRelocations + 1));
	ia->relocations[ia->numRelocations].oldPath = oldPath;
	ia->relocations[ia->numRelocations].newPath = newPath;
	ia->numRelocations++;
      }	break;

    case RPMCLI_POPT_NODEPS:
	ia->noDeps = 1;
	break;

    case RPMCLI_POPT_NOFILEDIGEST:
	ia->transFlags |= RPMTRANS_FLAG_NOFILEDIGEST;
	break;

    case RPMCLI_POPT_NOCONTEXTS:
	ia->transFlags |= RPMTRANS_FLAG_NOCONTEXTS;
	break;

    case RPMCLI_POPT_NOCAPS:
	ia->transFlags |= RPMTRANS_FLAG_NOCAPS;
	break;

    case RPMCLI_POPT_FORCE:
	ia->probFilter |=
		( RPMPROB_FILTER_REPLACEPKG
		| RPMPROB_FILTER_REPLACEOLDFILES
		| RPMPROB_FILTER_REPLACENEWFILES
		| RPMPROB_FILTER_OLDPACKAGE );
	break;

    case RPMCLI_POPT_NOSCRIPTS:
	ia->transFlags |= (_noTransScripts | _noTransTriggers);
	break;

    }
}

/**
 */
struct poptOption rpmInstallPoptTable[] = {
/* FIX: cast? */
 { NULL, '\0', POPT_ARG_CALLBACK | POPT_CBFLAG_INC_DATA | POPT_CBFLAG_CONTINUE,
	(void *)installArgCallback, 0, NULL, NULL },

 { "allfiles", '\0', POPT_BIT_SET,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_ALLFILES,
  N_("install all files, even configurations which might otherwise be skipped"),
	NULL},
 { "allmatches", '\0', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, UNINSTALL_ALLMATCHES,
	N_("remove all packages which match <package> (normally an error is generated if <package> specified multiple packages)"),
	NULL},

 { "badreloc", '\0', POPT_BIT_SET,
	&rpmIArgs.probFilter, RPMPROB_FILTER_FORCERELOCATE,
	N_("relocate files in non-relocatable package"), NULL},

 { "deploops", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
 	&rpmIArgs.transFlags, RPMTRANS_FLAG_DEPLOOPS,
	N_("print dependency loops as warning"), NULL},

 { "erase", 'e', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, INSTALL_ERASE,
	N_("erase (uninstall) package"), N_("<package>+") },
 { "excludeartifacts", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOARTIFACTS,
	N_("do not install artifacts"), NULL},
 { "excludeconfigs", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOCONFIGS,
	N_("do not install configuration files"), NULL},
 { "excludedocs", '\0', POPT_BIT_SET,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NODOCS,
	N_("do not install documentation"), NULL},
 { "excludepath", '\0', POPT_ARG_STRING, 0, POPT_EXCLUDEPATH,
	N_("skip files with leading component <path> "),
	N_("<path>") },

 { "force", '\0', 0, NULL, RPMCLI_POPT_FORCE,
	N_("short hand for --replacepkgs --replacefiles"), NULL},

 { "freshen", 'F', POPT_BIT_SET, &rpmIArgs.installInterfaceFlags,
	(INSTALL_UPGRADE|INSTALL_FRESHEN|INSTALL_INSTALL),
	N_("upgrade package(s) if already installed"),
	N_("<packagefile>+") },
 { "hash", 'h', POPT_BIT_SET, &rpmIArgs.installInterfaceFlags, INSTALL_HASH,
	N_("print hash marks as package installs (good with -v)"), NULL},
 { "ignorearch", '\0', POPT_BIT_SET,
	&rpmIArgs.probFilter, RPMPROB_FILTER_IGNOREARCH,
	N_("don't verify package architecture"), NULL},
 { "ignoreos", '\0', POPT_BIT_SET,
	&rpmIArgs.probFilter, RPMPROB_FILTER_IGNOREOS,
	N_("don't verify package operating system"), NULL},
 { "ignoresize", '\0', POPT_BIT_SET, &rpmIArgs.probFilter,
	(RPMPROB_FILTER_DISKSPACE|RPMPROB_FILTER_DISKNODES),
	N_("don't check disk space before installing"), NULL},
 { "noverify", '\0', POPT_BIT_SET, &rpmIArgs.probFilter,
	(RPMPROB_FILTER_VERIFY),
	N_("short hand for --ignorepayload --ignoresignature"), NULL},
 { "includedocs", '\0', POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.incldocs, 0,
	N_("install documentation"), NULL},

 { "install", 'i', 0, NULL, 'i',
	N_("install package(s)"), N_("<packagefile>+") },

 { "justdb", '\0', POPT_BIT_SET, &rpmIArgs.transFlags, RPMTRANS_FLAG_JUSTDB,
	N_("update the database, but do not modify the filesystem"), NULL},
 { "nodb", '\0', POPT_BIT_SET, &rpmIArgs.transFlags, RPMTRANS_FLAG_NODB,
	N_("do not update the database, but modify the filesystem"), NULL},

 { "noconfigs", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOCONFIGS,
	N_("do not install configuration files"), NULL},
 { "nodeps", '\0', 0, NULL, RPMCLI_POPT_NODEPS,
	N_("do not verify package dependencies"), NULL },
 { "nodocs", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NODOCS,
	N_("do not install documentation"), NULL},

 { "nofiledigest", '\0', 0, NULL, RPMCLI_POPT_NOFILEDIGEST,
	N_("don't verify digest of files"), NULL },
 { "nomd5", '\0', POPT_ARGFLAG_DOC_HIDDEN, NULL, RPMCLI_POPT_NOFILEDIGEST,
	N_("don't verify digest of files (obsolete)"), NULL },
 { "nocontexts", '\0',0,  NULL, RPMCLI_POPT_NOCONTEXTS,
	N_("don't install file security contexts"), NULL},
 { "nocaps", '\0',0,  NULL, RPMCLI_POPT_NOCAPS,
	N_("don't install file capabilities"), NULL},

 { "noorder", '\0', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, INSTALL_NOORDER,
	N_("do not reorder package installation to satisfy dependencies"),
	NULL},

 { "noscripts", '\0', 0, NULL, RPMCLI_POPT_NOSCRIPTS,
	N_("do not execute package scriptlet(s)"), NULL },

 { "nopre", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPRE,
	N_("do not execute %%pre scriptlet (if any)"), NULL },
 { "nopost", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPOST,
	N_("do not execute %%post scriptlet (if any)"), NULL },
 { "nopreun", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPREUN,
	N_("do not execute %%preun scriptlet (if any)"), NULL },
 { "nopostun", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPOSTUN,
	N_("do not execute %%postun scriptlet (if any)"), NULL },
 { "nopretrans", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPRETRANS,
	N_("do not execute %%pretrans scriptlet (if any)"), NULL },
 { "noposttrans", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPOSTTRANS,
	N_("do not execute %%posttrans scriptlet (if any)"), NULL },
 { "nopreuntrans", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPREUNTRANS,
	N_("do not execute %%preuntrans scriptlet (if any)"), NULL },
 { "nopostuntrans", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN, &rpmIArgs.transFlags,
	RPMTRANS_FLAG_NOPOSTUNTRANS,
	N_("do not execute %%postuntrans scriptlet (if any)"), NULL },

 { "notriggers", '\0', POPT_BIT_SET, &rpmIArgs.transFlags, _noTransTriggers,
	N_("do not execute any scriptlet(s) triggered by this package"), NULL},
 { "notriggerprein", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOTRIGGERPREIN,
	N_("do not execute any %%triggerprein scriptlet(s)"), NULL},
 { "notriggerin", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOTRIGGERIN,
	N_("do not execute any %%triggerin scriptlet(s)"), NULL},
 { "notriggerun", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOTRIGGERUN,
	N_("do not execute any %%triggerun scriptlet(s)"), NULL},
 { "notriggerpostun", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOTRIGGERPOSTUN,
	N_("do not execute any %%triggerpostun scriptlet(s)"), NULL},

 { "nosysusers", '\0', POPT_BIT_SET|POPT_ARGFLAG_DOC_HIDDEN,
	&rpmIArgs.transFlags, RPMTRANS_FLAG_NOSYSUSERS,
	N_("do not create %%sysusers users and groups"), NULL },

 { "oldpackage", '\0', POPT_BIT_SET,
	&rpmIArgs.probFilter, RPMPROB_FILTER_OLDPACKAGE,
	N_("upgrade to an old version of the package (--force on upgrades does this automatically)"),
	NULL},
 { "percent", '\0', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, INSTALL_PERCENT,
	N_("print percentages as package installs"), NULL},
 { "prefix", '\0', POPT_ARG_STRING, &rpmIArgs.prefix, 0,
	N_("relocate the package to <dir>, if relocatable"),
	N_("<dir>") },
 { "relocate", '\0', POPT_ARG_STRING, 0, POPT_RELOCATE,
	N_("relocate files from path <old> to <new>"),
	N_("<old>=<new>") },
 { "replacefiles", '\0', POPT_BIT_SET, &rpmIArgs.probFilter,
	(RPMPROB_FILTER_REPLACEOLDFILES | RPMPROB_FILTER_REPLACENEWFILES),
	N_("ignore file conflicts between packages"), NULL},
 { "replacepkgs", '\0', POPT_BIT_SET,
	&rpmIArgs.probFilter, RPMPROB_FILTER_REPLACEPKG,
	N_("reinstall if the package is already present"), NULL},
 { "test", '\0', POPT_BIT_SET, &rpmIArgs.transFlags, RPMTRANS_FLAG_TEST,
	N_("don't install, but tell if it would work or not"), NULL},
 { "upgrade", 'U', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, (INSTALL_UPGRADE|INSTALL_INSTALL),
	N_("upgrade package(s)"),
	N_("<packagefile>+") },
 { "reinstall", '\0', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, (INSTALL_REINSTALL|INSTALL_INSTALL),
	N_("reinstall package(s)"),
	N_("<packagefile>+") },
 { "restore", '\0', POPT_BIT_SET,
	&rpmIArgs.installInterfaceFlags, (INSTALL_RESTORE),
	N_("restore package(s)"),
	N_("<packagefile>+") },

   POPT_TABLEEND
};
