/** \ingroup rpmio
 * \file lib/rpmgi.c
 */
#include "system.h"

#include <errno.h>
#include <string.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>		/* rpmReadPackageFile */
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>		/* XXX rpmExpand */
#include <rpm/rpmfileutil.h>
#include <rpm/rpmlog.h>

#include "rpmgi.h"
#include "manifest.h"

#include "debug.h"

#define MANIFEST_RECURSIONS 1000 /* Max. number of allowed manifest recursions */

RPM_GNUC_INTERNAL
rpmgiFlags giFlags = RPMGI_NONE;

/** \ingroup rpmgi
 */
struct rpmgi_s {
    rpmts ts;			/*!< Iterator transaction set. */

    rpmgiFlags flags;		/*!< Iterator control bits. */
    int i;			/*!< Element index. */
    int errors;

    ARGV_t argv;
    int argc;

    int curLvl;			/*!< Current recursion level */
    int	recLvls[MANIFEST_RECURSIONS]; /*!< Reversed end index for given level */

};

/**
 * Open a file after macro expanding path.
 * @todo There are two error messages printed on header, then manifest failures.
 * @param path		file path
 * @param fmode		open mode
 * @return		file handle
 */
static FD_t rpmgiOpen(const char * path, const char * fmode)
{
    char * fn = rpmExpand(path, NULL);
    FD_t fd = Fopen(fn, fmode);

    if (fd == NULL || Ferror(fd)) {
	rpmlog(RPMLOG_ERR, _("open of %s failed: %s\n"), fn, Fstrerror(fd));
	if (fd != NULL) (void) Fclose(fd);
	fd = NULL;
    }
    free(fn);

    return fd;
}

/**
 * Load manifest into iterator arg list.
 * @param gi		generalized iterator
 * @param path		file path
 * @return		RPMRC_OK on success
 */
static rpmRC rpmgiLoadManifest(rpmgi gi, const char * path)
{
    FD_t fd = rpmgiOpen(path, "r.ufdio");
    rpmRC rpmrc = RPMRC_FAIL;

    if (fd != NULL) {
	rpmrc = rpmReadPackageManifest(fd, &gi->argc, &gi->argv);
	(void) Fclose(fd);
    }
    return rpmrc;
}

/**
 * Return header from package.
 * @param gi		generalized iterator
 * @param path		file path
 * @param[out] hdrp		header (NULL on failure)
 * @return		1 if path could be opened, 0 if not
 */
static int rpmgiReadHeader(rpmgi gi, const char * path, Header * hdrp)
{
    FD_t fd = rpmgiOpen(path, "r.ufdio");
    Header h = NULL;

    if (fd != NULL) {
	/* XXX what if path needs expansion? */
	rpmRC rpmrc = rpmReadPackageFile(gi->ts, fd, path, &h);

	(void) Fclose(fd);

	switch (rpmrc) {
	case RPMRC_NOTFOUND:
	    /* XXX Read a package manifest. Restart ftswalk on success. */
	case RPMRC_FAIL:
	default:
	    h = headerFree(h);
	    break;
	case RPMRC_NOTTRUSTED:
	case RPMRC_NOKEY:
	case RPMRC_OK:
	    break;
	}
    }

    *hdrp = h;
    return (fd != NULL);
}

/**
 * Read next header from package, lazily expanding manifests as found.
 * @todo An empty file read as manifest truncates argv returning RPMRC_NOTFOUND.
 * @todo Chained manifests lose an arg someplace.
 * @param gi		generalized iterator
 * @return		header on success
 */
static Header rpmgiLoadReadHeader(rpmgi gi)
{
    Header h = NULL;

    if (gi->argv != NULL && gi->argv[gi->i] != NULL)
    do {
	char * fn = gi->argv[gi->i];
	int rc;

	while (gi->recLvls[gi->curLvl] > gi->argc - gi->i)
	    gi->curLvl--;

	rc = rpmgiReadHeader(gi, fn, &h);

	if (h != NULL || (gi->flags & RPMGI_NOMANIFEST) || rc == 0)
	    break;

	if (gi->curLvl == MANIFEST_RECURSIONS - 1) {
	    rpmlog(RPMLOG_ERR,
		   _("Max level of manifest recursion exceeded: %s\n"), fn);
	    break;
	}
	gi->curLvl++;
	gi->recLvls[gi->curLvl] = gi->argc - gi->i;

	/* Not a header, so try for a manifest. */
	gi->argv[gi->i] = NULL;		/* Mark the insertion point */
	if (rpmgiLoadManifest(gi, fn) != RPMRC_OK) {
	    gi->argv[gi->i] = fn;	/* Manifest failed, restore fn */
	    rpmlog(RPMLOG_ERR, 
		   _("%s: not an rpm package (or package manifest)\n"), fn);
	    break;
	}
	fn = _free(fn);
    } while (1);

    return h;
}


/**
 * Append globbed arg list to iterator.
 * @param gi		generalized iterator
 * @param argv		arg list to be globbed (or NULL)
 */
static void rpmgiGlobArgv(rpmgi gi, ARGV_const_t argv)
{
    if (argv == NULL) return;

    /* XXX Expand globs only if requested */
    if ((gi->flags & RPMGI_NOGLOB)) {
	argvAppend(&gi->argv, argv);
    } else {
	const char * arg;
	while ((arg = *argv++) != NULL) {
	    char ** av = NULL;

	    if (rpmGlobPath(arg, RPMGLOB_NOCHECK, NULL, &av) == 0) {
		argvAppend(&gi->argv, av);
		argvFree(av);
	    }
	}
    }
    gi->argc = argvCount(gi->argv);

    return;
}

rpmgi rpmgiFree(rpmgi gi)
{
    if (gi != NULL) {
	rpmtsFree(gi->ts);
	argvFree(gi->argv);

	memset(gi, 0, sizeof(*gi)); /* XXX trash and burn */
	free(gi);
    }
    return NULL;
}

rpmgi rpmgiNew(rpmts ts, rpmgiFlags flags, ARGV_const_t argv)
{
    rpmgi gi = (rpmgi)xcalloc(1, sizeof(*gi));

    gi->ts = rpmtsLink(ts);

    gi->flags = flags;
    gi->i = -1;
    gi->errors = 0;

    gi->argv = argvNew();
    gi->argc = 0;
    rpmgiGlobArgv(gi, argv);

    gi->curLvl = 0;
    gi->recLvls[gi->curLvl] = 1;

    return gi;
}

Header rpmgiNext(rpmgi gi)
{
    Header h = NULL;

    if (gi != NULL && ++gi->i >= 0) {
	/* 
 	 * Read next header, lazily expanding manifests as found,
 	 * count + skip errors.
 	 */
	while (gi->i < gi->argc) {
	    if ((h = rpmgiLoadReadHeader(gi)) != NULL) 
		break;
	    gi->errors++;
	    gi->i++;
        }

	/* Out of things to try, end of iteration */
	if (h == NULL)
	    gi->i = -1;
    }

    return h;
}

int rpmgiNumErrors(rpmgi gi)
{
    return (gi != NULL ? gi->errors : -1);
}
