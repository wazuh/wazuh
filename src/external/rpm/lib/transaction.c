/** \ingroup rpmts
 * \file lib/transaction.c
 */

#include "system.h"

#include <inttypes.h>
#include <libgen.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <fcntl.h>

/* duplicated from cpio.c */
#if defined(MAJOR_IN_MKDEV)
#include <sys/mkdev.h>
#elif defined(MAJOR_IN_SYSMACROS)
#include <sys/sysmacros.h>
#else
#include <sys/types.h> /* already included from system.h */
#endif

#include <rpm/rpmlib.h>		/* rpmMachineScore, rpmReadPackageFile */
#include <rpm/rpmmacro.h>	/* XXX for rpmExpand */
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmsq.h>
#include <rpm/rpmkeyring.h>

#include "fprint.h"
#include "misc.h"
#include "rpmchroot.h"
#include "rpmlock.h"
#include "rpmds_internal.h"
#include "rpmfi_internal.h"	/* only internal apis */
#include "rpmte_internal.h"	/* only internal apis */
#include "rpmts_internal.h"
#include "rpmvs.h"
#include "rpmhook.h"
#include "rpmtriggers.h"

#include "rpmplugins.h"

#include "debug.h"

struct diskspaceInfo_s {
    char * mntPoint;	/*!< File system mount point */
    dev_t dev;		/*!< File system device number. */
    int64_t bneeded;	/*!< No. of blocks needed. */
    int64_t ineeded;	/*!< No. of inodes needed. */
    int64_t bsize;	/*!< File system block size. */
    int64_t bavail;	/*!< No. of blocks available. */
    int64_t iavail;	/*!< No. of inodes available. */
    int64_t obneeded;	/*!< Bookkeeping to avoid duplicate reports */
    int64_t oineeded;	/*!< Bookkeeping to avoid duplicate reports */
    int64_t bdelta;	/*!< Delta for temporary space need on updates */
    int64_t idelta;	/*!< Delta for temporary inode need on updates */

    int rotational;	/*!< Rotational media? */
};

/* Adjust for root only reserved space. On linux e2fs, this is 5%. */
#define	adj_fs_blocks(_nb)	(((_nb) * 21) / 20)
#define BLOCK_ROUND(size, block) (((size) + (block) - 1) / (block))

static char *getMntPoint(const char *dirName, dev_t dev)
{
    char *mntPoint = realpath(dirName, NULL);
    char *end = NULL;
    struct stat sb;
    char *res = NULL;

    if (!mntPoint)
	mntPoint = xstrdup(dirName);

    while (end != mntPoint) {
	end = strrchr(mntPoint, '/');
	if (end == mntPoint) { /* reached "/" */
	    stat("/", &sb);
	    if (dev != sb.st_dev) {
		res = xstrdup(mntPoint);
	    } else {
		res = xstrdup("/");
	    }
	    break;
	} else if (end) {
	    *end = '\0';
	} else { /* dirName doesn't start with / - should not happen */
	    res = xstrdup(dirName);
	    break;
	}
	stat(mntPoint, &sb);
	if (dev != sb.st_dev) {
	    *end = '/';
	    res = xstrdup(mntPoint);
	    break;
	}
    }
    free(mntPoint);
    return res;
}

static int getRotational(const char *dirName, dev_t dev)
{
    int rotational = 1;	/* Be a good pessimist, assume the worst */
#if defined(__linux__)
    char *devpath = NULL;
    FILE *f = NULL;

    rasprintf(&devpath, "/sys/dev/block/%d:%d/queue/rotational",
			major(dev), minor(dev));
    if ((f = fopen(devpath, "r")) != NULL) {
	int v;
	if (fscanf(f, "%d", &v) == 1)
	    rotational = (v == 1);
	fclose(f);
    }
    free(devpath);
#endif

    return rotational;
}

static int rpmtsInitDSI(const rpmts ts)
{
    ts->dsi = _free(ts->dsi);
    ts->dsi = (rpmDiskSpaceInfo)xcalloc(1, sizeof(*ts->dsi));
    return 0;
}

static rpmDiskSpaceInfo rpmtsCreateDSI(const rpmts ts, dev_t dev,
				       const char * dirName, int count)
{
    rpmDiskSpaceInfo dsi;
    struct stat sb;
    int rc;
    struct statvfs sfb;

    memset(&sfb, 0, sizeof(sfb));
    rc = statvfs(dirName, &sfb);
    if (rc)
	return NULL;

    rc = stat(dirName, &sb);
    if (rc)
	return NULL;
    if (sb.st_dev != dev)
	return NULL;

    ts->dsi = xrealloc(ts->dsi, (count + 2) * sizeof(*ts->dsi));
    dsi = ts->dsi + count;
    memset(dsi, 0, 2 * sizeof(*dsi));

    dsi->dev = sb.st_dev;
    dsi->bsize = sfb.f_bsize;
    if (!dsi->bsize)
	dsi->bsize = 512;       /* we need a bsize */
    dsi->bneeded = 0;
    dsi->ineeded = 0;
    dsi->bavail = (sfb.f_flag & ST_RDONLY) ? 0 : sfb.f_bavail;

    /* XXX Avoid FAT and other file systems that have not inodes. */
    /* XXX assigning negative value to unsigned type */
    dsi->iavail = !(sfb.f_ffree == 0 && sfb.f_files == 0)
	? sfb.f_ffree : -1;

    /* Find mount point belonging to this device number */
    dsi->mntPoint = getMntPoint(dirName, dsi->dev);

    /* Initialized on demand */
    dsi->rotational = -1;

    /* normalize block size to 4096 bytes if it is too big. */
    if (dsi->bsize > 4096) {
	uint64_t old_size = dsi->bavail * dsi->bsize;
	rpmlog(RPMLOG_DEBUG,
		"dubious blocksize % " PRId64 " on %s, normalizing to 4096\n",
		dsi->bsize, dsi->mntPoint);
	dsi->bsize = 4096; /* Assume 4k block size */
	dsi->bavail = old_size / dsi->bsize;
    }

    rpmlog(RPMLOG_DEBUG,
	   "0x%08x %8" PRId64 " %12" PRId64 " %12" PRId64" rotational:%d %s\n",
	   (unsigned) dsi->dev, dsi->bsize,
	   dsi->bavail, dsi->iavail, dsi->rotational,
	   dsi->mntPoint);
    return dsi;
}

static rpmDiskSpaceInfo rpmtsGetDSI(const rpmts ts, dev_t dev,
				    const char *dirName) {
    rpmDiskSpaceInfo dsi;
    dsi = ts->dsi;
    if (dsi) {
	while (dsi->bsize && dsi->dev != dev)
	    dsi++;
	if (dsi->bsize == 0) {
	    /* create new entry */
	    dsi = rpmtsCreateDSI(ts, dev, dirName, dsi - ts->dsi);
	}
    }
    return dsi;
}

static int rpmtsGetDSIRotational(rpmts ts)
{
    int rc = 1;
    int nrot = 0;
    rpmDiskSpaceInfo dsi = ts->dsi;
    while (dsi && dsi->bsize != 0) {
	if (dsi->rotational < 0)
	    dsi->rotational = getRotational(dsi->mntPoint, dsi->dev);
	nrot += dsi->rotational;
	dsi++;
    }
    if (dsi != ts->dsi && nrot == 0)
	rc = 0;
    return rc;
}

static void rpmtsUpdateDSI(const rpmts ts, dev_t dev, const char *dirName,
		rpm_loff_t fileSize, rpm_loff_t prevSize, rpm_loff_t fixupSize,
		rpmFileAction action)
{
    int64_t bneeded;
    rpmDiskSpaceInfo dsi = rpmtsGetDSI(ts, dev, dirName);
    if (dsi == NULL)
	return;

    bneeded = BLOCK_ROUND(fileSize, dsi->bsize);

    switch (action) {
    case FA_BACKUP:
    case FA_SAVE:
    case FA_ALTNAME:
	dsi->ineeded++;
	dsi->bneeded += bneeded;
	break;

    case FA_CREATE:
	dsi->bneeded += bneeded;
	dsi->ineeded++;
	if (prevSize) {
	    dsi->bdelta += BLOCK_ROUND(prevSize - 1, dsi->bsize);
	    dsi->idelta++;
	}
	if (fixupSize) {
	    dsi->bdelta += BLOCK_ROUND(fixupSize - 1, dsi->bsize);
	    dsi->idelta++;
	}

	break;

    case FA_ERASE:
	dsi->ineeded--;
	dsi->bneeded -= bneeded;
	break;

    default:
	break;
    }

    /* adjust bookkeeping when requirements shrink */
    if (dsi->bneeded < dsi->obneeded) dsi->obneeded = dsi->bneeded;
    if (dsi->ineeded < dsi->oineeded) dsi->oineeded = dsi->ineeded;
}

static void rpmtsCheckDSIProblems(const rpmts ts, const rpmte te)
{
    rpmDiskSpaceInfo dsi = ts->dsi;

    if (dsi == NULL || !dsi->bsize)
	return;

    for (; dsi->bsize; dsi++) {

	if (dsi->bavail >= 0 && adj_fs_blocks(dsi->bneeded) > dsi->bavail) {
	    if (dsi->bneeded > dsi->obneeded) {
		rpmteAddProblem(te, RPMPROB_DISKSPACE, NULL, dsi->mntPoint,
		   (adj_fs_blocks(dsi->bneeded) - dsi->bavail) * dsi->bsize);
		dsi->obneeded = dsi->bneeded;
	    }
	}

	if (dsi->iavail >= 0 && adj_fs_blocks(dsi->ineeded) > dsi->iavail) {
	    if (dsi->ineeded > dsi->oineeded) {
		rpmteAddProblem(te, RPMPROB_DISKNODES, NULL, dsi->mntPoint,
			(adj_fs_blocks(dsi->ineeded) - dsi->iavail));
		dsi->oineeded = dsi->ineeded;
	    }
	}

	/* Adjust for temporary -> final disk consumption */
	dsi->bneeded -= dsi->bdelta;
	dsi->bdelta = 0;
	dsi->ineeded -= dsi->idelta;
	dsi->idelta = 0;
    }
}

static void rpmtsFreeDSI(rpmts ts)
{
    rpmDiskSpaceInfo dsi;
    if (ts == NULL)
	return;
    dsi = ts->dsi;
    while (dsi && dsi->bsize != 0) {
	dsi->mntPoint = _free(dsi->mntPoint);
	dsi++;
    }

    ts->dsi = _free(ts->dsi);
}


/* Calculate total number of files involved in transaction */
static uint64_t countFiles(rpmts ts)
{
    uint64_t fc = 0;
    rpmtsi pi = rpmtsiInit(ts);
    rpmte p;
    rpmfiles files;
    while ((p = rpmtsiNext(pi, 0)) != NULL) {
	files = rpmteFiles(p);
	fc += rpmfilesFC(files);
	rpmfilesFree(files);
    }
    rpmtsiFree(pi);
    return fc;
}

static int handleRemovalConflict(rpmfiles fi, int fx, rpmfiles ofi, int ofx)
{
    int rConflicts = 0; /* Removed files don't conflict, normally */
    rpmFileTypes ft = rpmfiWhatis(rpmfilesFMode(fi, fx));
    rpmFileTypes oft = rpmfiWhatis(rpmfilesFMode(ofi, ofx));
    struct stat sb;
    char *fn = NULL;

    if (oft == XDIR) {
	/* We can't handle directory changing to anything else */
	if (ft != XDIR)
	    rConflicts = 1;
    } else if (oft == LINK) {
	/* We can't correctly handle directory symlink changing to directory */
	if (ft == XDIR) {
	    fn = rpmfilesFN(fi, fx);
	    if (stat(fn, &sb) == 0 && S_ISDIR(sb.st_mode))
		rConflicts = 1;
	}
    }

    /*
     * ...but if the conflicting item is either not on disk, or has
     * already been changed to the new type, we should be ok afterall.
     */
    if (rConflicts) {
	if (fn == NULL)
	    fn = rpmfilesFN(fi, fx);
	if (lstat(fn, &sb) || rpmfiWhatis(sb.st_mode) == ft)
	    rConflicts = 0;
    }

    free(fn);
    return rConflicts;
}

/*
 * Elf files can be "colored", and if enabled in the transaction, the
 * color can be used to resolve conflicts between elf-64bit and elf-32bit
 * files to the hosts preferred type, by default 64bit. The non-preferred
 * type is overwritten or never installed at all and thus the conflict
 * magically disappears. This is infamously nasty "rpm magic" and entirely
 * unnecessary with careful packaging.
 */
static int handleColorConflict(rpmts ts,
			       rpmfs fs, rpmfiles fi, int fx,
			       rpmfs ofs, rpmfiles ofi, int ofx)
{
    int rConflicts = 1;
    rpm_color_t tscolor = rpmtsColor(ts);

    if (tscolor != 0) {
	rpm_color_t fcolor = rpmfilesFColor(fi, fx) & tscolor;
	rpm_color_t ofcolor = rpmfilesFColor(ofi, ofx) & tscolor;

	if (fcolor != 0 && ofcolor != 0 && fcolor != ofcolor) {
	    rpm_color_t prefcolor = rpmtsPrefColor(ts);

	    if (fcolor & prefcolor) {
		if (ofs && !XFA_SKIPPING(rpmfsGetAction(fs, fx)))
		    rpmfsSetAction(ofs, ofx, FA_SKIPCOLOR);
		rpmfsSetAction(fs, fx, FA_CREATE);
		rConflicts = 0;
	    } else if (ofcolor & prefcolor) {
		if (ofs && XFA_SKIPPING(rpmfsGetAction(fs, fx)))
		    rpmfsSetAction(ofs, ofx, FA_CREATE);
		rpmfsSetAction(fs, fx, FA_SKIPCOLOR);
		rConflicts = 0;
	    }
	}
    }

    return rConflicts;
}

/**
 * handleInstInstalledFiles.
 * @param ts		transaction set
 * @param p		current transaction element
 * @param fi		file info set
 * @param fx		file index
 * @param otherHeader	header containing the matching file
 * @param otherFi	matching file info set
 * @param ofx		matching file index
 * @param beingRemoved  file being removed (installed otherwise)
 */
/* XXX only ts->{probs,rpmdb} modified */
static void handleInstInstalledFile(const rpmts ts, rpmte p, rpmfiles fi, int fx,
				   Header otherHeader, rpmfiles otherFi, int ofx,
				   int beingRemoved)
{
    rpmfs fs = rpmteGetFileStates(p);
    int isCfgFile = ((rpmfilesFFlags(otherFi, ofx) | rpmfilesFFlags(fi, fx)) & RPMFILE_CONFIG);
    rpm_loff_t otherFileSize;
    int nlink;
    const int *links;

    if (XFA_SKIPPING(rpmfsGetAction(fs, fx)))
	return;

    if (rpmfilesFState(otherFi, ofx) == RPMFILE_STATE_NOTINSTALLED)
	return;

    if (rpmfilesCompare(otherFi, ofx, fi, fx)) {
	int rConflicts = 1;
	char rState = RPMFILE_STATE_REPLACED;

	/*
	 * There are some removal conflicts we can't handle. However
	 * if the package has a %pretrans scriptlet, it might be able to
	 * fix the conflict. Let it through on test-transaction to allow
	 * eg yum to get past it, if the conflict is present on the actual
	 * transaction we'll abort. Behaving differently on test is nasty,
	 * but its still better than barfing in middle of large transaction.
	 */
	if (beingRemoved) {
	    rConflicts = handleRemovalConflict(fi, fx, otherFi, ofx);
	    if (rConflicts && rpmteHaveTransScript(p, RPMTAG_PRETRANS)) {
		if (rpmtsFlags(ts) & RPMTRANS_FLAG_TEST)
		    rConflicts = 0;
	    }
	}

	if (rConflicts) {
	    /* If enabled, resolve colored conflicts to preferred type */
	    rConflicts = handleColorConflict(ts, fs, fi, fx,
					     NULL, otherFi, ofx);
	    /* If resolved, we need to adjust in-rpmdb state too */
	    if (rConflicts == 0 && rpmfsGetAction(fs, fx) == FA_CREATE)
		rState = RPMFILE_STATE_WRONGCOLOR;
	}

	/* Somebody used The Force, lets shut up... */
	if (rpmtsFilterFlags(ts) & RPMPROB_FILTER_REPLACEOLDFILES)
	    rConflicts = 0;

	if (rConflicts) {
	    char *altNEVR = headerGetAsString(otherHeader, RPMTAG_NEVRA);
	    char *fn = rpmfilesFN(fi, fx);
	    rpmteAddProblem(p, RPMPROB_FILE_CONFLICT, altNEVR, fn,
			    headerGetInstance(otherHeader));
	    free(fn);
	    free(altNEVR);
	}

	/* Save file identifier to mark as state REPLACED. */
	if ( !(isCfgFile || XFA_SKIPPING(rpmfsGetAction(fs, fx))) ) {
	    if (!beingRemoved)
		rpmfsAddReplaced(rpmteGetFileStates(p), fx, rState,
				 headerGetInstance(otherHeader), ofx);
	}
    }

    /* Determine config file disposition, skipping missing files (if any). */
    if (isCfgFile) {
	int skipMissing = ((rpmtsFlags(ts) & RPMTRANS_FLAG_ALLFILES) ? 0 : 1);
	rpmFileAction action;
	action = rpmfilesDecideFate(otherFi, ofx, fi, fx, skipMissing);
	rpmfsSetAction(fs, fx, action);
    }

    otherFileSize = rpmfilesFSize(otherFi, ofx);

    /* Only account for the last file of a hardlink set */
    nlink = rpmfilesFLinks(otherFi, ofx, &links);
    if (nlink > 1 && links[nlink - 1] != ofx)
	otherFileSize = 0;

    /* Add one to make sure the size is not zero */
    rpmfilesSetFReplacedSize(fi, fx, otherFileSize + 1);

    /* Just touch already existing files if minimize_writes is enabled */
    if (ts->min_writes) {
	if ((!isCfgFile) && (rpmfsGetAction(fs, fx) == FA_UNKNOWN)) {
	    /* XXX fsm can't handle FA_TOUCH of hardlinked files */
	    int nolinks = (nlink == 1 && rpmfilesFNlink(fi, fx) == 1);
	    if (nolinks && rpmfileContentsEqual(otherFi, ofx, fi, fx))
	       rpmfsSetAction(fs, fx, FA_TOUCH);
	}
    }
}

/**
 * Update disk space needs on each partition for this package's files.
 */
/* XXX only ts->{probs,di} modified */
static void handleOverlappedFiles(rpmts ts, fingerPrintCache fpc, rpmte p, rpmfiles fi)
{
    rpm_loff_t fixupSize = 0;
    int i, j;
    rpmfs fs = rpmteGetFileStates(p);
    rpmfs otherFs;
    rpm_count_t fc = rpmfilesFC(fi);
    int reportConflicts = !(rpmtsFilterFlags(ts) & RPMPROB_FILTER_REPLACENEWFILES);
    fingerPrint * fpList = rpmfilesFps(fi);

    for (i = 0; i < fc; i++) {
	struct fingerPrint_s * fiFps;
	int otherPkgNum, otherFileNum;
	rpmfiles otherFi;
	rpmte otherTe;
	rpmfileAttrs FFlags;
	struct rpmffi_s * recs;
	int numRecs;
	rpm_loff_t fileSize;
	int nlink;
	const int *links;

	if (XFA_SKIPPING(rpmfsGetAction(fs, i)))
	    continue;

	FFlags = rpmfilesFFlags(fi, i);

	fixupSize = 0;

	/*
	 * Retrieve all records that apply to this file. Note that the
	 * file info records were built in the same order as the packages
	 * will be installed and removed so the records for an overlapped
	 * files will be sorted in exactly the same order.
	 */
	fiFps = fpCacheGetByFp(fpc, fpList, i, &recs, &numRecs);

	/*
	 * If this package is being added, look only at other packages
	 * being added -- removed packages dance to a different tune.
	 *
	 * If both this and the other package are being added, overlapped
	 * files must be identical (or marked as a conflict). The
	 * disposition of already installed config files leads to
	 * a small amount of extra complexity.
	 *
	 * If this package is being removed, then there are two cases that
	 * need to be worried about:
	 * If the other package is being added, then skip any overlapped files
	 * so that this package removal doesn't nuke the overlapped files
	 * that were just installed.
	 * If both this and the other package are being removed, then each
	 * file removal from preceding packages needs to be skipped so that
	 * the file removal occurs only on the last occurrence of an overlapped
	 * file in the transaction set.
	 *
	 */

	/*
	 * Locate this overlapped file in the set of added/removed packages,
	 * including the package owning it: a package can have self-conflicting
	 * files when directory symlinks are present. Don't compare a file
	 * with itself though...
	 */
	for (j = 0; j < numRecs && !(recs[j].p == p && recs[j].fileno == i); j++)
	    {};

	/* Find what the previous disposition of this file was. */
	otherFileNum = -1;			/* keep gcc quiet */
	otherFi = NULL;
	otherTe = NULL;
	otherFs = NULL;

	for (otherPkgNum = j - 1; otherPkgNum >= 0; otherPkgNum--) {
	    otherTe = recs[otherPkgNum].p;
	    otherFileNum = recs[otherPkgNum].fileno;
	    otherFs = rpmteGetFileStates(otherTe);

	    /* Added packages need only look at other added packages. */
	    if (rpmteType(p) == TR_ADDED && rpmteType(otherTe) != TR_ADDED)
		continue;

	    /* XXX Happens iff fingerprint for incomplete package install. */
	    if (rpmfsGetAction(otherFs, otherFileNum) != FA_UNKNOWN) {
		otherFi = rpmteFiles(otherTe);
		break;
	    }
	}

	switch (rpmteType(p)) {
	case TR_ADDED:
	    if (otherPkgNum < 0) {
		/* XXX is this test still necessary? */
		rpmFileAction action;
		if (rpmfsGetAction(fs, i) != FA_UNKNOWN)
		    break;
		if (rpmfilesConfigConflict(fi, i)) {
		    /* Here is a non-overlapped pre-existing config file. */
		    action = (FFlags & RPMFILE_NOREPLACE) ?
			      FA_ALTNAME : FA_BACKUP;
		} else {
		    action = FA_CREATE;
		}
		rpmfsSetAction(fs, i, action);
		break;
	    }

assert(otherFi != NULL);
	    /* Mark added overlapped non-identical files as a conflict. */
	    if (rpmfilesCompare(otherFi, otherFileNum, fi, i)) {
		int rConflicts;

		/* If enabled, resolve colored conflicts to preferred type */
		rConflicts = handleColorConflict(ts, fs, fi, i,
						otherFs, otherFi, otherFileNum);

		if (rConflicts && reportConflicts) {
		    char *fn = rpmfilesFN(fi, i);
		    rpmteAddProblem(p, RPMPROB_NEW_FILE_CONFLICT,
				    rpmteNEVRA(otherTe), fn, 0);
		    free(fn);
		}
	    } else {
		/* Skip create on all but the first instance of a shared file */
		rpmFileAction oaction = rpmfsGetAction(otherFs, otherFileNum);
		if (oaction != FA_UNKNOWN && !XFA_SKIPPING(oaction)) {
		    rpmfileAttrs oflags;
		    /* ...but ghosts aren't really created so... */
		    oflags = rpmfilesFFlags(otherFi, otherFileNum);
		    if (!(oflags & RPMFILE_GHOST)) {
			rpmfsSetAction(fs, i, FA_SKIP);
		    }
		/* if the other file is color skipped then skip this file too */
		} else if (oaction == FA_SKIPCOLOR) {
		    rpmfsSetAction(fs, i, FA_SKIPCOLOR);
		}
	    }

	    /* Skipped files dont need fixup size or backups, %config or not */
	    if (XFA_SKIPPING(rpmfsGetAction(fs, i)))
		break;

	    /* Try to get the disk accounting correct even if a conflict. */
	    /* Add one to make sure the size is not zero */
	    fixupSize = rpmfilesFSize(otherFi, otherFileNum) + 1;

	    if (rpmfilesConfigConflict(fi, i)) {
		/* Here is an overlapped  pre-existing config file. */
		rpmFileAction action;
		action = (FFlags & RPMFILE_NOREPLACE) ? FA_ALTNAME : FA_SKIP;
		rpmfsSetAction(fs, i, action);
	    } else {
		/* If not decided yet, create it */
		if (rpmfsGetAction(fs, i) == FA_UNKNOWN)
		    rpmfsSetAction(fs, i, FA_CREATE);
	    }
	    break;

	case TR_REMOVED:
	    if (otherPkgNum >= 0) {
		assert(otherFi != NULL);
                /* Here is an overlapped added file we don't want to nuke. */
		if (rpmfsGetAction(otherFs, otherFileNum) != FA_ERASE) {
		    /* On updates, don't remove files. */
		    rpmfsSetAction(fs, i, FA_SKIP);
		    break;
		}
		/* Here is an overlapped removed file: skip in previous. */
		rpmfsSetAction(otherFs, otherFileNum, FA_SKIP);
	    }
	    if (XFA_SKIPPING(rpmfsGetAction(fs, i)))
		break;
	    if (rpmfilesFState(fi, i) != RPMFILE_STATE_NORMAL) {
		rpmfsSetAction(fs, i, FA_SKIP);
		break;
	    }
		
	    /* Pre-existing modified config files need to be saved. */
	    if (rpmfilesConfigConflict(fi, i)) {
		rpmfsSetAction(fs, i, FA_SAVE);
		break;
	    }
	
	    /* Otherwise, we can just erase. */
	    rpmfsSetAction(fs, i, FA_ERASE);
	    break;
	case TR_RESTORED:
	    if (XFA_SKIPPING(rpmfsGetAction(fs, i)))
		break;
	    if (rpmfilesFState(fi, i) != RPMFILE_STATE_NORMAL) {
		rpmfsSetAction(fs, i, FA_SKIP);
		break;
	    }
	    rpmfsSetAction(fs, i, FA_TOUCH);
	    break;
	default:
	    break;
	}
	rpmfilesFree(otherFi);

	fileSize = rpmfilesFSize(fi, i);
	nlink = rpmfilesFLinks(fi, i, &links);
	if (nlink > 1 && links[nlink - 1] != i) {
	    /* Only account for the last file of a hardlink set */
	    fileSize = 0;
	    fixupSize = fixupSize ? 1 : 0;
	}
	/* Update disk space info for a file. */
	rpmtsUpdateDSI(ts, fpEntryDev(fpc, fiFps), fpEntryDir(fpc, fiFps),
		       fileSize, rpmfilesFReplacedSize(fi, i),
		       fixupSize, rpmfsGetAction(fs, i));

    }
}

/**
 * Ensure that current package is newer than installed package.
 * @param tspool	transaction string pool
 * @param p		current transaction element
 * @param h		installed header
 */
static void ensureOlder(rpmstrPool tspool, const rpmte p, const Header h)
{
    rpmsenseFlags reqFlags = (RPMSENSE_LESS | RPMSENSE_EQUAL);
    rpmds req;

    req = rpmdsSinglePool(tspool, RPMTAG_REQUIRENAME,
			  rpmteN(p), rpmteEVR(p), reqFlags);
    if (rpmdsMatches(tspool, h, -1, req, 1) == 0) {
	char * altNEVR = headerGetAsString(h, RPMTAG_NEVRA);
	rpmteAddProblem(p, RPMPROB_OLDPACKAGE, altNEVR, NULL,
			headerGetInstance(h));
	free(altNEVR);
    }
    rpmdsFree(req);
}

/**
 * Check if the curent file in the file iterator is in the
 * netshardpath and though should be excluded.
 * @param ts            transaction set
 * @param fi            file info set
 * @returns 1 if path is net shared path, otherwise 0
 */
static int matchNetsharedpath(const rpmts ts, rpmfi fi)
{
    char ** nsp;
    const char * dn, * bn;
    size_t dnlen, bnlen;
    char * s;
    bn = rpmfiBN(fi);
    bnlen = strlen(bn);
    dn = rpmfiDN(fi);
    dnlen = strlen(dn);
    for (nsp = ts->netsharedPaths; nsp && *nsp; nsp++) {
	size_t len;

	len = strlen(*nsp);
	if (dnlen >= len) {
	    if (!rstreqn(dn, *nsp, len))
		continue;
	    /* Only directories or complete file paths can be net shared */
	    if (!(dn[len] == '/' || dn[len] == '\0'))
		continue;
	} else {
	    if (len < (dnlen + bnlen))
		continue;
	    if (!rstreqn(dn, *nsp, dnlen))
		continue;
	    /* Insure that only the netsharedpath basename is compared. */
	    if ((s = strchr((*nsp) + dnlen, '/')) != NULL && s[1] != '\0')
		continue;
	    if (!rstreqn(bn, (*nsp) + dnlen, bnlen))
		continue;
	    len = dnlen + bnlen;
	    /* Only directories or complete file paths can be net shared */
	    if (!((*nsp)[len] == '/' || (*nsp)[len] == '\0'))
		continue;
	}

	break;
    }
    return (nsp != NULL && *nsp != NULL);
}

static void skipEraseFiles(const rpmts ts, rpmfiles files, rpmfs fs)
{
    int i;
    /*
     * Skip net shared paths.
     * Net shared paths are not relative to the current root (though
     * they do need to take package relocations into account).
     */
    if (ts->netsharedPaths) {
	rpmfi fi = rpmfilesIter(files, RPMFI_ITER_FWD);
	while ((i = rpmfiNext(fi)) >= 0)
	{
	    if (matchNetsharedpath(ts, fi))
		rpmfsSetAction(fs, i, FA_SKIPNETSHARED);
	}
	rpmfiFree(fi);
    }
}


/**
 * Skip any files that do not match install policies.
 * @param ts		transaction set
 * @param files		file info set
 * @param fs		file states
 */
static void skipInstallFiles(const rpmts ts, rpmfiles files, rpmfs fs)
{
    rpm_color_t tscolor = rpmtsColor(ts);
    rpm_color_t FColor;
    int noConfigs = (rpmtsFlags(ts) & RPMTRANS_FLAG_NOCONFIGS);
    int noDocs = (rpmtsFlags(ts) & RPMTRANS_FLAG_NODOCS);
    int noArtifacts = (rpmtsFlags(ts) & RPMTRANS_FLAG_NOARTIFACTS);
    int * drc;
    uint8_t * dff;
    int dc;
    int i, j, ix;
    rpmfi fi = rpmfilesIter(files, RPMFI_ITER_FWD);

    if (!noDocs)
	noDocs = rpmExpandNumeric("%{_excludedocs}");

    /* Compute directory refcount, skip directory if now empty. */
    dc = rpmfiDC(fi);
    drc = (int *)xcalloc(dc, sizeof(*drc));
    dff = (uint8_t *)xcalloc(dc, sizeof(*dff));

    fi = rpmfiInit(fi, 0);
    while ((i = rpmfiNext(fi)) >= 0) {
	const char *flangs;

	ix = rpmfiDX(fi);
	drc[ix]++;

	/* Don't bother with skipped files */
	/* XXX FIXME: --excludepath on %license should not be permitted */
	if (XFA_SKIPPING(rpmfsGetAction(fs, i))) {
	    drc[ix]--; dff[ix] = 1;
	    continue;
	}

	/* Ignore colored files not in our rainbow. */
	FColor = rpmfiFColor(fi);
	if (tscolor && FColor && !(tscolor & FColor)) {
	    drc[ix]--;	dff[ix] = 1;
	    rpmfsSetAction(fs, i, FA_SKIPCOLOR);
	    continue;
	}

	/*
	 * Skip net shared paths.
	 * Net shared paths are not relative to the current root (though
	 * they do need to take package relocations into account).
	 */
	if (ts->netsharedPaths) {
	    if (matchNetsharedpath(ts, fi)) {
		drc[ix]--;	dff[ix] = 1;
		rpmfsSetAction(fs, i, FA_SKIPNETSHARED);
		continue;
	    }
	}

	/*
	 * In general, excluding license files is not permitted. In case
	 * of SKIPNETSHARED and SKIPCOLOR the file is expected to be
	 * there via other means however so that is ok.
	 */
	if (rpmfiFFlags(fi) & RPMFILE_LICENSE)
	    continue;

	/*
	 * Skip i18n language specific files.
	 */
	flangs = (ts->installLangs != NULL) ? rpmfiFLangs(fi) : NULL;
	if (flangs != NULL && *flangs != '\0') {
	    const char *l, *le;
	    char **lang;
	    for (lang = ts->installLangs; *lang != NULL; lang++) {
		for (l = flangs; *l != '\0'; l = le) {
		    for (le = l; *le != '\0' && *le != '|'; le++)
			{};
		    if ((le-l) > 0 && rstreqn(*lang, l, (le-l)))
			break;
		    if (*le == '|') le++;	/* skip over | */
		}
		if (*l != '\0')
		    break;
	    }
	    if (*lang == NULL) {
		drc[ix]--;	dff[ix] = 1;
		rpmfsSetAction(fs, i, FA_SKIPNSTATE);
		continue;
	    }
	}

	/*
	 * Skip config files if requested.
	 */
	if (noConfigs && (rpmfiFFlags(fi) & RPMFILE_CONFIG)) {
	    drc[ix]--;	dff[ix] = 1;
	    rpmfsSetAction(fs, i, FA_SKIPNSTATE);
	    continue;
	}

	/*
	 * Skip documentation if requested.
	 */
	if (noDocs && (rpmfiFFlags(fi) & RPMFILE_DOC)) {
	    drc[ix]--;	dff[ix] = 1;
	    rpmfsSetAction(fs, i, FA_SKIPNSTATE);
	    continue;
	}

	/* Skip artifacts if requested. */
	if (noArtifacts && (rpmfiFFlags(fi) & RPMFILE_ARTIFACT)) {
	    drc[ix]--;	dff[ix] = 1;
	    rpmfsSetAction(fs, i, FA_SKIPNSTATE);
	    continue;
	}
    }

    /* Skip (now empty) directories that had skipped files. */
    /* Iterate over dirs in reversed order to solve subdirs at first */
    for (j = dc - 1; j >= 0; j--) {
	const char * dn, * bn;
	size_t dnlen, bnlen;

	if (drc[j]) continue;	/* dir still has files. */
	if (!dff[j]) continue;	/* dir was not emptied here. */
	
	/* Find parent directory and basename. */
	dn = rpmfilesDN(files, j); dnlen = strlen(dn) - 1;
	bn = dn + dnlen;	bnlen = 0;
	while (bn > dn && bn[-1] != '/') {
		bnlen++;
		dnlen--;
		bn--;
	}

	/* If explicitly included in the package, skip the directory. */
	fi = rpmfiInit(fi, 0);
	while ((i = rpmfiNext(fi)) >= 0) {
	    const char * fdn, * fbn;
	    rpm_mode_t fFMode;

	    if (XFA_SKIPPING(rpmfsGetAction(fs, i)))
		continue;

	    fFMode = rpmfiFMode(fi);

	    if (rpmfiWhatis(fFMode) != XDIR)
		continue;
	    fdn = rpmfiDN(fi);
	    if (strlen(fdn) != dnlen)
		continue;
	    if (!rstreqn(fdn, dn, dnlen))
		continue;
	    fbn = rpmfiBN(fi);
	    if (strlen(fbn) != bnlen)
		continue;
	    if (!rstreqn(fbn, bn, bnlen))
		continue;
	    rpmlog(RPMLOG_DEBUG, "excluding directory %s\n", dn);
	    rpmfsSetAction(fs, i, FA_SKIPNSTATE);
	    ix = rpmfiDX(fi);
	    /* Decrease count of files for parent directory */
	    drc[ix]--;
	    /* Mark directory because something was removed from them */
	    dff[ix] = 1;
	    break;
	}
    }

    free(drc);
    free(dff);
    rpmfiFree(fi);
}

#define HASHTYPE rpmStringSet
#define HTKEYTYPE rpmsid
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE

static unsigned int sidHash(rpmsid sid)
{
    return sid;
}

static int sidCmp(rpmsid a, rpmsid b)
{
    return (a != b);
}

/* Get a rpmdbMatchIterator containing all files in
 * the rpmdb that share the basename with one from
 * the transaction.
 * @param ts		transaction set
 * @return		rpmdbMatchIterator sorted
			by (package, fileNum)
 */
static
rpmdbMatchIterator rpmFindBaseNamesInDB(rpmts ts, uint64_t fileCount)
{
    tsMembers tsmem = rpmtsMembers(ts);
    rpmstrPool tspool = rpmtsPool(ts);
    rpmtsi pi;  rpmte p;
    rpmfiles files;
    rpmfi fi;
    rpmdbMatchIterator mi;
    int oc = 0;
    const char * baseName;
    rpmsid baseNameId;

    rpmStringSet baseNames = rpmStringSetCreate(fileCount, 
					sidHash, sidCmp, NULL);

    mi = rpmdbNewIterator(rpmtsGetRdb(ts), RPMDBI_BASENAMES);

    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, 0)) != NULL) {
	rpmtsNotify(ts, NULL, RPMCALLBACK_TRANS_PROGRESS, oc++, tsmem->orderCount);

	/* Gather all installed headers with matching basename's. */
	files = rpmteFiles(p);
	fi = rpmfilesIter(files, RPMFI_ITER_FWD);
	while (rpmfiNext(fi) >= 0) {
	    size_t keylen;

	    baseNameId = rpmfiBNId(fi);

	    if (rpmStringSetHasEntry(baseNames, baseNameId))
		continue;

	    keylen = rpmstrPoolStrlen(tspool, baseNameId);
	    baseName = rpmstrPoolStr(tspool, baseNameId);
	    if (keylen == 0)
		keylen++;	/* XXX "/" fixup. */
	    rpmdbExtendIterator(mi, baseName, keylen);
	    rpmStringSetAddEntry(baseNames, baseNameId);
	}
	rpmfiFree(fi);
	rpmfilesFree(files);
    }
    rpmtsiFree(pi);
    rpmStringSetFree(baseNames);

    rpmdbSortIterator(mi);
    /* iterator is now sorted by (recnum, filenum) */
    return mi;
}

/* Check files in the transactions against the rpmdb
 * Lookup all files with the same basename in the rpmdb
 * and then check for matching finger prints
 * @param ts		transaction set
 * @param fpc		global finger print cache
 */
static
void checkInstalledFiles(rpmts ts, uint64_t fileCount, fingerPrintCache fpc)
{
    tsMembers tsmem = rpmtsMembers(ts);
    rpmte p;
    rpmfiles fi;
    rpmfs fs;
    int j;
    unsigned int fileNum;

    rpmdbMatchIterator mi;
    Header h, newheader;

    rpmlog(RPMLOG_DEBUG, "computing file dispositions\n");

    mi = rpmFindBaseNamesInDB(ts, fileCount);

    /* For all installed headers with matching basename's ... */
    if (mi == NULL)
	 return;

    if (rpmdbGetIteratorCount(mi) == 0) {
	mi = rpmdbFreeIterator(mi);
	return;
    }

    /* Loop over all packages from the rpmdb */
    h = newheader = rpmdbNextIterator(mi);
    while (h != NULL) {
	headerGetFlags hgflags = HEADERGET_MINMEM;
	struct rpmtd_s bnames, dnames, dindexes, ostates;
	fingerPrint *fpp = NULL;
	unsigned int installedPkg;
	int beingRemoved = 0;
	rpmfiles otherFi = NULL;
	rpmte *removedPkg = NULL;

	/* Is this package being removed? */
	installedPkg = rpmdbGetIteratorOffset(mi);
	if (packageHashGetEntry(tsmem->removedPackages, installedPkg,
				&removedPkg, NULL, NULL)) {
	    beingRemoved = 1;
	    otherFi = rpmteFiles(removedPkg[0]);
	}

	h = headerLink(h);
	/* For packages being removed we can use its rpmfi to avoid all this */
	if (!beingRemoved) {
	    headerGet(h, RPMTAG_BASENAMES, &bnames, hgflags);
	    headerGet(h, RPMTAG_DIRNAMES, &dnames, hgflags);
	    headerGet(h, RPMTAG_DIRINDEXES, &dindexes, hgflags);
	    headerGet(h, RPMTAG_FILESTATES, &ostates, hgflags);
	}

	/* loop over all interesting files in that package */
	do {
	    int fpIx;
	    struct rpmffi_s * recs;
	    int numRecs;
	    const char * dirName;
	    const char * baseName;

	    /* lookup finger print for this file */
	    fileNum = rpmdbGetIteratorFileNum(mi);
	    if (!beingRemoved) {
		rpmtdSetIndex(&bnames, fileNum);
		rpmtdSetIndex(&dindexes, fileNum);
		rpmtdSetIndex(&dnames, *rpmtdGetUint32(&dindexes));
		rpmtdSetIndex(&ostates, fileNum);

		dirName = rpmtdGetString(&dnames);
		baseName = rpmtdGetString(&bnames);

		fpLookup(fpc, dirName, baseName, &fpp);
		fpIx = 0;
	    } else {
		fpp = rpmfilesFps(otherFi);
		fpIx = fileNum;
	    }

	    /* search for files in the transaction with same finger print */
	    fpCacheGetByFp(fpc, fpp, fpIx, &recs, &numRecs);

	    for (j = 0; j < numRecs; j++) {
	        p = recs[j].p;
		fi = rpmteFiles(p);
		fs = rpmteGetFileStates(p);

		/* Determine the fate of each file. */
		switch (rpmteType(p)) {
		case TR_ADDED:
		    if (!otherFi) {
			/* XXX What to do if this fails? */
		        otherFi = rpmfilesNew(NULL, h, RPMTAG_BASENAMES, RPMFI_KEEPHEADER);
		    }
		    handleInstInstalledFile(ts, p, fi, recs[j].fileno,
					    h, otherFi, fileNum, beingRemoved);
		    break;
		case TR_REMOVED:
		    if (!beingRemoved) {
			if (*rpmtdGetChar(&ostates) == RPMFILE_STATE_NORMAL)
			    rpmfsSetAction(fs, recs[j].fileno, FA_SKIP);
		    }
		    break;
		default:
		    break;
		}
		rpmfilesFree(fi);
	    }

	    newheader = rpmdbNextIterator(mi);

	} while (newheader==h);

	otherFi = rpmfilesFree(otherFi);
	if (!beingRemoved) {
	    rpmtdFreeData(&ostates);
	    rpmtdFreeData(&bnames);
	    rpmtdFreeData(&dnames);
	    rpmtdFreeData(&dindexes);
	    free(fpp);
	}
	headerFree(h);
	h = newheader;
    }

    rpmdbFreeIterator(mi);
}

#define badArch(_a) (rpmMachineScore(RPM_MACHTABLE_INSTARCH, (_a)) == 0)
#define badOs(_a) (rpmMachineScore(RPM_MACHTABLE_INSTOS, (_a)) == 0)

static rpm_loff_t countPkgs(rpmts ts, rpmElementTypes types)
{
    rpm_loff_t npkgs = 0;
    rpmtsi pi = rpmtsiInit(ts);
    rpmte p;
    while ((p = rpmtsiNext(pi, types)))
	npkgs++;
    pi = rpmtsiFree(pi);
    return npkgs;
}

struct vfydata_s {
    char *msg;
    int type[3];
    int vfylevel;
};

static int vfyCb(struct rpmsinfo_s *sinfo, void *cbdata)
{
    struct vfydata_s *vd = (struct vfydata_s *)cbdata;

    if (sinfo->type & RPMSIG_VERIFIABLE_TYPE && sinfo->rc != RPMRC_NOTFOUND) {
	int res = (sinfo->rc != RPMRC_OK);
	/* Take care not to override a previous failure with success */
	if (res > vd->type[sinfo->type])
	    vd->type[sinfo->type] = res;
    }

    switch (sinfo->rc) {
    case RPMRC_OK:
	break;
    case RPMRC_NOTFOUND:
	vd->msg = xstrdup((sinfo->type == RPMSIG_SIGNATURE_TYPE) ?
			  _("no signature") : _("no digest"));
	break;
    case RPMRC_NOKEY:
	/*
	 * Legacy compat: if signatures are not required, install must
	 * succeed despite missing key.
	 */
	if (!(vd->vfylevel & RPMSIG_SIGNATURE_TYPE))
	    sinfo->rc = RPMRC_OK;
	/* fallthrough */
    default:
	if (sinfo->rc)
	    vd->msg = rpmsinfoMsg(sinfo);
	break;
    }
    return (sinfo->rc == 0);
}

static int verifyPackageFiles(rpmts ts, rpm_loff_t total)
{
    int rc = 0;
    rpmKeyring keyring = rpmtsGetKeyring(ts, 0);
    rpmtsi pi = NULL;
    rpmte p;
    rpm_loff_t oc = 0;
    rpmVSFlags vsflags = rpmtsVfyFlags(ts);
    int vfylevel = rpmtsVfyLevel(ts);

    rpmtsNotify(ts, NULL, RPMCALLBACK_VERIFY_START, 0, total);

    (void) rpmswEnter(rpmtsOp(ts, RPMTS_OP_VERIFY), 0);

    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, TR_ADDED))) {
	struct rpmvs_s *vs = rpmvsCreate(vfylevel, vsflags, keyring);
	struct vfydata_s vd = {
	    .msg = NULL,
	    .type = { -1, -1, -1, },
	    .vfylevel = vfylevel,
	};
	int verified = 0;
	int prc = RPMRC_FAIL;

	rpmtsNotify(ts, p, RPMCALLBACK_VERIFY_PROGRESS, oc++, total);
	FD_t fd = (FD_t)rpmtsNotify(ts, p, RPMCALLBACK_INST_OPEN_FILE, 0, 0);
	if (fd != NULL) {
	    prc = rpmpkgRead(vs, fd, NULL, NULL, &vd.msg);
	    rpmtsNotify(ts, p, RPMCALLBACK_INST_CLOSE_FILE, 0, 0);
	}

	if (prc == RPMRC_OK)
	    prc = rpmvsVerify(vs, RPMSIG_VERIFIABLE_TYPE, vfyCb, &vd);

	/* Record verify result */
	if (vd.type[RPMSIG_SIGNATURE_TYPE] == RPMRC_OK)
	    verified |= RPMSIG_SIGNATURE_TYPE;
	if (vd.type[RPMSIG_DIGEST_TYPE] == RPMRC_OK)
	    verified |= RPMSIG_DIGEST_TYPE;
	rpmteSetVerified(p, verified);

	if (prc)
	    rpmteAddProblem(p, RPMPROB_VERIFY, NULL, vd.msg, 0);

	vd.msg = _free(vd.msg);
	rpmvsFree(vs);
    }
    rpmtsNotify(ts, NULL, RPMCALLBACK_VERIFY_STOP, total, total);

    (void) rpmswExit(rpmtsOp(ts, RPMTS_OP_VERIFY), 0);

    rpmtsiFree(pi);
    rpmKeyringFree(keyring);
    return rc;
}

static void checkAdded(rpmts ts, rpmprobFilterFlags probFilter, rpmte p)
{
    if (!(probFilter & RPMPROB_FILTER_IGNOREARCH) && badArch(rpmteA(p)))
	rpmteAddProblem(p, RPMPROB_BADARCH, rpmteA(p), NULL, 0);

    if (!(probFilter & RPMPROB_FILTER_IGNOREOS) && badOs(rpmteO(p)))
	rpmteAddProblem(p, RPMPROB_BADOS, rpmteO(p), NULL, 0);

    if (!(probFilter & RPMPROB_FILTER_OLDPACKAGE)) {
	rpmstrPool tspool = rpmtsPool(ts);
	Header h;
	rpmdbMatchIterator mi;
	mi = rpmtsInitIterator(ts, RPMDBI_NAME, rpmteN(p), 0);
	while ((h = rpmdbNextIterator(mi)) != NULL)
	    ensureOlder(tspool, p, h);
	rpmdbFreeIterator(mi);
    }

    if (!(probFilter & RPMPROB_FILTER_REPLACEPKG) && rpmteAddOp(p) != RPMTE_REINSTALL) {
	Header h;
	rpmdbMatchIterator mi = rpmtsTeIterator(ts, p, 0);

	if ((h = rpmdbNextIterator(mi)) != NULL) {
	    rpmteAddProblem(p, RPMPROB_PKG_INSTALLED, NULL, NULL,
			    headerGetInstance(h));
	}
	rpmdbFreeIterator(mi);
    }

    if (!(probFilter & RPMPROB_FILTER_FORCERELOCATE))
	rpmteAddRelocProblems(p);
}

static void checkRemoved(rpmts ts, rpmprobFilterFlags probFilter, rpmte p)
{
    unsigned int offset = rpmteDBInstance(p);
    int found = 0;
    rpmdbMatchIterator mi;

    mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, &offset, sizeof(offset));
    while (rpmdbNextIterator(mi)) {
	found = 1;
	break;
    }
    rpmdbFreeIterator(mi);

    if (!found)
	rpmteAddProblem(p, RPMPROB_PKG_INSTALLED, NULL, NULL, 0);
}

/*
 * For packages being installed:
 * - verify package arch/os.
 * - verify package epoch:version-release is newer.
 */
static rpmps checkProblems(rpmts ts)
{
    rpmprobFilterFlags probFilter = rpmtsFilterFlags(ts);
    rpmElementTypes etypes = (TR_ADDED|TR_REMOVED);
    rpm_loff_t npkgs = countPkgs(ts, etypes);
    rpm_loff_t ninst = 0;
    rpmtsi pi;
    rpmte p;

    if (npkgs == 0)
	goto exit;

    /* The ordering doesn't matter here */
    /* XXX Only added packages need be checked. */
    rpmlog(RPMLOG_DEBUG, "sanity checking %" PRIu64 " elements\n", npkgs);
    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, etypes)) != NULL) {
	switch (rpmteType(p)) {
	case TR_ADDED:
	    checkAdded(ts, probFilter, p);
	    ninst++;
	    break;
	case TR_REMOVED:
	    checkRemoved(ts, probFilter, p);
	    break;
	default:
	    break;
	}
    }
    rpmtsiFree(pi);

    if (ninst > 0 && rpmtsVfyLevel(ts) && !(probFilter & RPMPROB_FILTER_VERIFY))
	verifyPackageFiles(ts, ninst);

exit:
    return rpmtsProblems(ts);
}

/*
 * Run pre/post transaction scripts for transaction set
 * param ts	Transaction set
 * param goal	PKG_PRETRANS/PKG_POSTTRANS
 * return	0 on success
 */
static int runTransScripts(rpmts ts, pkgGoal goal) 
{
    int rc = 0;
    rpmte p;
    rpmtsi pi = rpmtsiInit(ts);
    rpmElementTypes types;
    int i = 0;

    switch (goal) {
    case PKG_TRANSFILETRIGGERUN:
    case PKG_PREUNTRANS:
    case PKG_POSTUNTRANS:
	types = TR_REMOVED;
	break;
    default:
	types = TR_ADDED;
	break;
    }

    while ((p = rpmtsiNext(pi, types)) != NULL) {
	rc += rpmteProcess(p, goal, i++);
    }
    rpmtsiFree(pi);
    return rc;
}

static int rpmtsSetup(rpmts ts, rpmprobFilterFlags ignoreSet)
{
    rpm_tid_t tid = (rpm_tid_t) rpmtsGetTime(ts, 0);
    int dbmode = (rpmtsFlags(ts) & RPMTRANS_FLAG_TEST) ?  O_RDONLY : (O_RDWR|O_CREAT);

    if (rpmtsFlags(ts) & RPMTRANS_FLAG_NOSCRIPTS)
	(void) rpmtsSetFlags(ts, (rpmtsFlags(ts) | _noTransScripts | _noTransTriggers));
    if (rpmtsFlags(ts) & RPMTRANS_FLAG_NOTRIGGERS)
	(void) rpmtsSetFlags(ts, (rpmtsFlags(ts) | _noTransTriggers));

    if (rpmtsFlags(ts) & (RPMTRANS_FLAG_JUSTDB | RPMTRANS_FLAG_TEST))
	(void) rpmtsSetFlags(ts, (rpmtsFlags(ts) | _noTransScripts | _noTransTriggers));

    /* 
     * Make sure the database is open RDWR for package install/erase.
     * Note that we initialize chroot state here even if it's just "/" as
     * this ensures we can successfully perform open(".") which is
     * required to reliably restore cwd after Lua scripts.
     */ 
    if (rpmtsOpenDB(ts, dbmode) || rpmChrootSet(rpmtsRootDir(ts)))
	return -1;

    ts->ignoreSet = ignoreSet;
    (void) rpmtsSetTid(ts, tid);

    /* Get available space on mounted file systems. */
    (void) rpmtsInitDSI(ts);

    return 0;
}

/* XXX _minimize_writes is not safe for mass-consumption yet */
#if 0
/* Push a macro with current value or default if no previous value exists */
static void ensureMacro(const char *name, const char *def)
{
    char *s = rpmExpand("%{?", name, "}", NULL);

    if (*s != '\0' && atoi(s) >= 0)
	def = s;

    rpmPushMacro(NULL, name, NULL, def, 0);
    free(s);
}

/* Enable / disable optimizations for solid state disks */
static void setSSD(int enable)
{
    if (enable) {
	rpmlog(RPMLOG_DEBUG, "optimizing for non-rotational disks\n");
	ensureMacro("_minimize_writes", "1");
    } else {
	rpmPopMacro(NULL, "_minimize_writes");
    }
}
#else
static void setSSD(int enable)
{
}
#endif

static int rpmtsFinish(rpmts ts)
{
    if (rpmtsGetDSIRotational(ts) == 0)
	setSSD(0);
    rpmtsFreeDSI(ts);
    return rpmChrootSet(NULL);
}

static int rpmtsPrepare(rpmts ts)
{
    tsMembers tsmem = rpmtsMembers(ts);
    rpmtsi pi;
    rpmte p;
    int rc = 0;
    uint64_t fileCount = countFiles(ts);
    const char *dbhome = NULL;
    struct stat dbstat;

    fingerPrintCache fpc = fpCacheCreate(fileCount/2 + 10001, rpmtsPool(ts));

    rpmlog(RPMLOG_DEBUG, "computing %" PRIu64 " file fingerprints\n", fileCount);

    /* Reset actions, set skip for netshared paths and excluded files */
    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, 0)) != NULL) {
	rpmfiles files = rpmteFiles(p);
	if (rpmfilesFC(files) > 0) {
	    rpmfs fs = rpmteGetFileStates(p);
	    /* Ensure clean state, this could get called more than once. */
	    rpmfsResetActions(fs);
	    if (rpmteType(p) == TR_ADDED) {
		skipInstallFiles(ts, files, fs);
	    } else {
		skipEraseFiles(ts, files, fs);
	    }
	}
	rpmfilesFree(files);
    }
    rpmtsiFree(pi);

    /* Open rpmdb & enter chroot for fingerprinting if necessary */
    if (rpmdbOpenAll(ts->rdb) || rpmChrootIn()) {
	rc = -1;
	goto exit;
    }
    
    rpmtsNotify(ts, NULL, RPMCALLBACK_TRANS_START, 6, tsmem->orderCount);
    /* Add fingerprint for each file not skipped. */
    fpCachePopulate(fpc, ts, fileCount);
    /* check against files in the rpmdb */
    checkInstalledFiles(ts, fileCount, fpc);

    dbhome = rpmdbHome(rpmtsGetRdb(ts));
    /* If we can't stat, ignore db growth. Probably not right but... */
    if (dbhome && stat(dbhome, &dbstat))
	dbhome = NULL;

    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, 0)) != NULL) {
	rpmfiles files = rpmteFiles(p);;
	if (files == NULL)
	    continue;   /* XXX can't happen */

	(void) rpmswEnter(rpmtsOp(ts, RPMTS_OP_FINGERPRINT), 0);
	/* check files in ts against each other and update disk space
	   needs on each partition for this package. */
	handleOverlappedFiles(ts, fpc, p, files);

	/* Check added package has sufficient space on each partition used. */
	if (rpmteType(p) == TR_ADDED) {
	    /*
	     * Try to estimate space needed for rpmdb growth: guess that the
	     * db grows 4 times the header size (indexes and all).
	     */
	    if (dbhome) {
		int64_t hsize = rpmteHeaderSize(p) * 4;
		rpmtsUpdateDSI(ts, dbstat.st_dev, dbhome,
			       hsize, 0, 0, FA_CREATE);
	    }

	    if (!(rpmtsFilterFlags(ts) & RPMPROB_FILTER_DISKSPACE))
		rpmtsCheckDSIProblems(ts, p);
	}
	(void) rpmswExit(rpmtsOp(ts, RPMTS_OP_FINGERPRINT), 0);
	rpmfilesFree(files);
    }
    rpmtsiFree(pi);
    rpmtsNotify(ts, NULL, RPMCALLBACK_TRANS_STOP, 6, tsmem->orderCount);

    /* return from chroot if done earlier */
    if (rpmChrootOut())
	rc = -1;

    /* On actual transaction, file info sets are not needed after this */
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_TEST|RPMTRANS_FLAG_BUILD_PROBS))) {
	pi = rpmtsiInit(ts);
	while ((p = rpmtsiNext(pi, 0)) != NULL) {
	    rpmteCleanFiles(p);
	}
	rpmtsiFree(pi);
    }

    if (rpmtsGetDSIRotational(ts) == 0)
	setSSD(1);

exit:
    fpCacheFree(fpc);
    return rc;
}

/*
 * Transaction main loop: install and remove packages
 */
static int rpmtsProcess(rpmts ts)
{
    rpmtsi pi;	rpmte p;
    int rc = 0;
    int i = 0;

    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, 0)) != NULL) {
	int failed;

	rpmlog(RPMLOG_DEBUG, "========== +++ %s %s-%s 0x%x\n",
		rpmteNEVR(p), rpmteA(p), rpmteO(p), rpmteColor(p));

	failed = rpmteProcess(p, (pkgGoal)rpmteType(p), i++);
	if (failed) {
	    rpmlog(RPMLOG_ERR, "%s: %s %s\n", rpmteNEVRA(p),
		   rpmteTypeString(p), failed > 1 ? _("skipped") : _("failed"));
	    rc++;
	}
    }
    rpmtsiFree(pi);
    return rc;
}

rpmRC rpmtsSetupTransactionPlugins(rpmts ts)
{
    rpmRC rc = RPMRC_OK;
    ARGV_t files = NULL;
    int nfiles = 0;
    char *dsoPath = NULL;

    /*
     * Assume allocated equals initialized. There are some oddball cases
     * (verification of non-installed package) where this is not true
     * currently but that's not a new issue.
     */
    if ((rpmtsFlags(ts) & RPMTRANS_FLAG_NOPLUGINS) || ts->plugins != NULL)
	return RPMRC_OK;

    dsoPath = rpmExpand("%{__plugindir}/*.so", NULL);
    if (rpmGlob(dsoPath, &nfiles, &files) == 0) {
	rpmPlugins tsplugins = rpmtsPlugins(ts);
	for (int i = 0; i < nfiles; i++) {
	    char *bn = basename(files[i]);
	    bn[strlen(bn)-strlen(".so")] = '\0';
	    if (rpmpluginsAddPlugin(tsplugins, "transaction", bn) == RPMRC_FAIL)
		rc = RPMRC_FAIL;
	}
	files = argvFree(files);
    }
    free(dsoPath);

    return rc;
}
/**
 * Run a scriptlet with args.
 *
 * Run a script with an interpreter. If the interpreter is not specified,
 * /bin/sh will be used. If the interpreter is /bin/sh, then the args from
 * the header will be ignored, passing instead arg1 and arg2.
 *
 * @param ts		transaction set
 * @param te		transaction element
 * @param prefixes	install prefixes
 * @param script	scriptlet from header
 * @param arg1		no. instances of package installed after scriptlet exec
 *			(-1 is no arg)
 * @param arg2		ditto, but for the target package
 * @return		0 on success
 */
rpmRC runScript(rpmts ts, rpmte te, Header h, ARGV_const_t prefixes,
		       rpmScript script, int arg1, int arg2)
{
    rpmte xte = te;
    rpmRC stoprc, rc = RPMRC_OK;
    rpmTagVal stag = rpmScriptTag(script);
    FD_t sfd = NULL;
    int warn_only = !(rpmScriptFlags(script) & RPMSCRIPT_FLAG_CRITICAL);

    if (rpmScriptChrootIn(script))
	return RPMRC_FAIL;

    /* Create a temporary transaction element for triggers from rpmdb */
    if (te == NULL) {
	te = rpmteNew(ts, h, TR_RPMDB, NULL, NULL, 0);
	rpmteSetHeader(te, h);
    }

    sfd = (FD_t)rpmtsNotify(ts, te, RPMCALLBACK_SCRIPT_START, stag, 0);
    if (sfd == NULL)
	sfd = rpmtsScriptFd(ts);

    rpmswEnter(rpmtsOp(ts, RPMTS_OP_SCRIPTLETS), 0);
    rc = rpmScriptRun(script, arg1, arg2, sfd,
		      prefixes, rpmtsPlugins(ts));
    rpmswExit(rpmtsOp(ts, RPMTS_OP_SCRIPTLETS), 0);

    /* Map warn-only errors to "notfound" for script stop callback */
    stoprc = (rc != RPMRC_OK && warn_only) ? RPMRC_NOTFOUND : rc;
    rpmtsNotify(ts, te, RPMCALLBACK_SCRIPT_STOP, stag, stoprc);

    /*
     * Notify callback for all errors. "total" abused for warning/error,
     * rc only reflects whether the condition prevented install/erase
     * (which is only happens with %prein and %preun scriptlets) or not.
     */
    if (rc != RPMRC_OK) {
	if (warn_only) {
	    rc = RPMRC_OK;
	}
	rpmtsNotify(ts, te, RPMCALLBACK_SCRIPT_ERROR, stag, rc);
    }

    rpmScriptChrootOut(script);

    if (te != xte)
	rpmteFree(te);

    return rc;
}

static void rpmtsSync(rpmts ts)
{
    if (rpmChrootDone())
	return;

#ifdef HAVE_SYNCFS
    for (rpmDiskSpaceInfo dsi = ts->dsi; dsi->bsize; dsi++) {
	int fd = open(dsi->mntPoint, O_RDONLY);
	if (fd != -1) {
	    rpmlog(RPMLOG_DEBUG, "syncing fs %s\n", dsi->mntPoint);
	    syncfs(fd);
	    close(fd);
	}
    }
#else
    rpmlog(RPMLOG_DEBUG, "syncing all filesystems\n");
    sync();
#endif
}

int rpmtsRun(rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet)
{
    int rc = -1; /* assume failure */
    int nfailed = -1;
    tsMembers tsmem = rpmtsMembers(ts);
    rpmtxn txn = NULL;
    rpmps tsprobs = NULL;
    int TsmPreDone = 0; /* TsmPre hook hasn't been called */
    int nelem = rpmtsNElements(ts);
    /* Ignore SIGPIPE for the duration of transaction */
    struct sigaction act, oact;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, &oact);
    
    /* Force default 022 umask during transaction for consistent results */
    mode_t oldmask = umask(022);

    /* Empty transaction, nothing to do */
    if (nelem <= 0) {
	rc = 0;
	goto exit;
    }

    /* If we are in test mode, then there's no need for transaction lock. */
    if (!(rpmtsFlags(ts) & RPMTRANS_FLAG_TEST)) {
	if (!(txn = rpmtxnBegin(ts, RPMTXN_WRITE))) {
	    goto exit;
	}
    }

    /* Setup flags and such, open the DB */
    if (rpmtsSetup(ts, ignoreSet)) {
	goto exit;
    }

    /* Check package set for problems */
    tsprobs = checkProblems(ts);

    /* Run pre transaction hook for all plugins */
    TsmPreDone = 1;
    if (rpmpluginsCallTsmPre(rpmtsPlugins(ts), ts) == RPMRC_FAIL) {
	goto exit;
    }

    /* Run %pretrans scripts, but only if there are no known problems up to
     * this point and not disabled otherwise. This is evil as it runs before
     * fingerprinting and problem checking and is best avoided.
     */
    if (!((rpmtsFlags(ts) & (RPMTRANS_FLAG_BUILD_PROBS|RPMTRANS_FLAG_NOPRETRANS))
     	  || (rpmpsNumProblems(tsprobs)))) {
	rpmlog(RPMLOG_DEBUG, "running %%pretrans scripts\n");
	runTransScripts(ts, PKG_PRETRANS);
    }
    tsprobs = rpmpsFree(tsprobs);

    /* Compute file disposition for each package in transaction set. */
    if (rpmtsPrepare(ts)) {
	goto exit;
    }
    /* Check again for problems (now including file conflicts,  duh */
    tsprobs = rpmtsProblems(ts);

     /* If unfiltered problems exist, free memory and return. */
    if ((rpmtsFlags(ts) & RPMTRANS_FLAG_BUILD_PROBS) || (rpmpsNumProblems(tsprobs))) {
	rc = nelem;
	goto exit;
    }

    /* Free up memory taken by problem sets */
    tsprobs = rpmpsFree(tsprobs);
    rpmtsCleanProblems(ts);

    /*
     * Free up the global string pool unless we expect it to be needed
     * again. During the transaction, private pools will be used for
     * rpmfi's etc.
     */
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_TEST|RPMTRANS_FLAG_BUILD_PROBS)))
	tsmem->pool = rpmstrPoolFree(tsmem->pool);

    /* Run %preuntrans scripts unless disabled */
    if (!(rpmtsFlags(ts) & RPMTRANS_FLAG_NOPREUNTRANS)) {
	rpmlog(RPMLOG_DEBUG, "running %%preuntrans scripts\n");
	runTransScripts(ts, PKG_PREUNTRANS);
    }
    /* Run %transfiletriggerun scripts unless disabled */
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_NOPRETRANS|RPMTRANS_FLAG_NOTRIGGERUN))) {
	runFileTriggers(ts, NULL, -1, RPMSENSE_TRIGGERUN,
			RPMSCRIPT_TRANSFILETRIGGER, 0);
	runTransScripts(ts, PKG_TRANSFILETRIGGERUN);
    }

    /* Actually install and remove packages */
    nfailed = rpmtsProcess(ts);

    /* Run %posttrans scripts unless disabled */
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_NOPOSTTRANS))) {
	rpmlog(RPMLOG_DEBUG, "running %%posttrans scripts\n");
	runTransScripts(ts, PKG_POSTTRANS);
    }
    /* Run %postuntrans scripts unless disabled */
    if (!(rpmtsFlags(ts) & RPMTRANS_FLAG_NOPOSTUNTRANS)) {
	rpmlog(RPMLOG_DEBUG, "running %%postuntrans scripts\n");
	runTransScripts(ts, PKG_POSTUNTRANS);
    }

    /* Run %transfiletriggerpostun scripts unless disabled */
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_NOPOSTTRANS|RPMTRANS_FLAG_NOTRIGGERIN))) {
	runFileTriggers(ts, NULL, -1, RPMSENSE_TRIGGERIN, RPMSCRIPT_TRANSFILETRIGGER, 0);
    }
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_NOPOSTTRANS|RPMTRANS_FLAG_NOTRIGGERPOSTUN))) {
	runPostUnTransFileTrigs(ts);
    }

    /* Run %transfiletriggerin scripts unless disabled */
    if (!(rpmtsFlags(ts) & (RPMTRANS_FLAG_NOPOSTTRANS|RPMTRANS_FLAG_NOTRIGGERIN))) {
	runTransScripts(ts, PKG_TRANSFILETRIGGERIN);
    }
    /* Final exit code */
    rc = nfailed ? -1 : 0;

exit:
    /* Run post transaction hook for all plugins */
    if (TsmPreDone) /* If TsmPre hook has been called, call the TsmPost hook */
	rpmpluginsCallTsmPost(rpmtsPlugins(ts), ts, rc);

    /* Finish up... */
    if (!(rpmtsFlags(ts) & RPMTRANS_FLAG_TEST) && nfailed >= 0) {
	rpmtsSync(ts);
    }
    (void) umask(oldmask);
    (void) rpmtsFinish(ts);
    rpmpsFree(tsprobs);
    rpmtxnEnd(txn);
    /* Restore SIGPIPE *after* unblocking signals in rpmtxnEnd() */
    sigaction(SIGPIPE, &oact, NULL);
    return rc;
}
