/** \ingroup rpmbuild
 * \file build/files.c
 *  The post-build, pre-packaging file tree walk to assemble the package
 *  manifest.
 */

#include "system.h"

#define	MYALLPERMS	07777

#include <errno.h>
#include <stdlib.h>
#include <regex.h>
#include <fcntl.h>
#ifdef WITH_CAP
#include <sys/capability.h>
#endif

#ifdef HAVE_LIBDW
#include <libelf.h>
#include <elfutils/libdwelf.h>
#endif

#include <rpm/argv.h>
#include <rpm/rpmfc.h>
#include <rpm/rpmfileutil.h>	/* rpmDoDigest() */
#include <rpm/rpmlog.h>
#include <rpm/rpmbase64.h>

#include "rpmio_internal.h"	/* XXX rpmioSlurp */
#include "rpmfts.h"
#include "rpmfi_internal.h"	/* XXX fi->apath */
#include "rpmbuild_internal.h"
#include "rpmbuild_misc.h"

#include "debug.h"
#include <libgen.h>

#define SKIPSPACE(s) { while (*(s) && risspace(*(s))) (s)++; }
#define	SKIPWHITE(_x)	{while (*(_x) && (risspace(*_x) || *(_x) == ',')) (_x)++;}
#define	SKIPNONWHITE(_x){while (*(_x) &&!(risspace(*_x) || *(_x) == ',')) (_x)++;}

/* the following defines must be in sync with the equally hardcoded paths from
 * scripts/find-debuginfo.sh
 */
#define BUILD_ID_DIR		"/usr/lib/.build-id"
#define DEBUG_SRC_DIR		"/usr/src/debug"
#define DEBUG_LIB_DIR		"/usr/lib/debug"
#define DEBUG_LIB_PREFIX	"/usr/lib/debug/"
#define DEBUG_ID_DIR		"/usr/lib/debug/.build-id"
#define DEBUG_DWZ_DIR 		"/usr/lib/debug/.dwz"

#define HASHTYPE fileRenameHash
#define HTKEYTYPE const char *
#define HTDATATYPE const char *
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

/**
 */
enum specfFlags_e {
    SPECD_DEFFILEMODE	= (1 << 0),
    SPECD_DEFDIRMODE	= (1 << 1),
    SPECD_DEFUID	= (1 << 2),
    SPECD_DEFGID	= (1 << 3),
    SPECD_DEFVERIFY	= (1 << 4),

    SPECD_FILEMODE	= (1 << 8),
    SPECD_DIRMODE	= (1 << 9),
    SPECD_UID		= (1 << 10),
    SPECD_GID		= (1 << 11),
    SPECD_VERIFY	= (1 << 12)
};

typedef rpmFlags specfFlags;

/* internal %files parsing state attributes */
enum parseAttrs_e {
    RPMFILE_EXCLUDE	= (1 << 16),	/*!< from %%exclude */
    RPMFILE_DOCDIR	= (1 << 17),	/*!< from %%docdir */
    RPMFILE_DIR		= (1 << 18),	/*!< from %%dir */
    RPMFILE_SPECIALDIR	= (1 << 19),	/*!< from special %%doc */
};

/* bits up to 15 (for now) reserved for exported rpmfileAttrs */
#define PARSEATTR_MASK 0x0000ffff

/**
 */
typedef struct FileListRec_s {
    struct stat fl_st;
#define	fl_dev	fl_st.st_dev
#define	fl_ino	fl_st.st_ino
#define	fl_mode	fl_st.st_mode
#define	fl_nlink fl_st.st_nlink
#define	fl_rdev	fl_st.st_rdev
#define	fl_size	fl_st.st_size
#define	fl_mtime fl_st.st_mtime

    char *diskPath;		/* get file from here       */
    char *cpioPath;		/* filename in cpio archive */
    rpmsid uname;
    rpmsid gname;
    unsigned	flags;
    specfFlags	specdFlags;	/* which attributes have been explicitly specified. */
    rpmVerifyFlags verifyFlags;
    char *langs;		/* XXX locales separated with | */
    char *caps;
} * FileListRec;

/**
 */
typedef struct AttrRec_s {
    rpmsid	ar_fmodestr;
    rpmsid	ar_dmodestr;
    rpmsid	ar_user;
    rpmsid	ar_group;
    mode_t	ar_fmode;
    mode_t	ar_dmode;
} * AttrRec;

/* list of files */
static StringBuf check_fileList = NULL;

typedef struct FileEntry_s {
    rpmfileAttrs attrFlags;
    specfFlags specdFlags;
    rpmVerifyFlags verifyFlags;
    struct AttrRec_s ar;

    ARGV_t langs;
    char *caps;

    /* these are only ever relevant for current entry */
    unsigned devtype;
    unsigned devmajor;
    int devminor;
    int isDir;
} * FileEntry;

struct FileEntries_s {
    struct FileEntry_s defEntry;
    struct FileEntry_s curEntry;
};

typedef struct specialDir_s {
    char * dirname;
    ARGV_t files;
    struct AttrRec_s ar;
    struct AttrRec_s def_ar;
    rpmFlags sdtype;

    int entriesCount;
    int entriesAlloced;

    struct FileEntries_s *entries;
} * specialDir;

typedef struct FileRecords_s {
    FileListRec recs;
    int alloced;
    int used;
} * FileRecords;

/**
 * Package file tree walk data.
 */
typedef struct FileList_s {
    /* global filelist state */
    char * buildRoot;
    size_t buildRootLen;
    int processingFailed;
    int haveCaps;
    int largeFiles;
    ARGV_t docDirs;
    rpmBuildPkgFlags pkgFlags;
    rpmstrPool pool;

    /* actual file records */
    struct FileRecords_s files;

    /* active defaults */
    struct FileEntry_s def;

    /* current file-entry state */
    struct FileEntry_s cur;
} * FileList;

static void nullAttrRec(AttrRec ar)
{
    memset(ar, 0, sizeof(*ar));
}

static void dupAttrRec(const AttrRec oar, AttrRec nar)
{
    if (oar == nar)
	return;
    *nar = *oar; /* struct assignment */
}

/* Creates a default $defattr string. Can be used with argvAdd().
   Caller owns the new string which needs to be freed when done.  */
static char *mkattr(void)
{
    char *s = NULL;
    rasprintf(&s, "%s(644,%s,%s,755)", "%defattr", UID_0_USER, GID_0_GROUP);
    return s;
}

static void copyFileEntry(FileEntry src, FileEntry dest)
{
    /* Copying struct makes just shallow copy */
    *dest = *src;

    /* Do also deep copying */
    if (src->langs != NULL) {
	dest->langs = argvNew();
	argvAppend(&dest->langs, src->langs);
    }

    if (src->caps != NULL) {
	dest->caps = xstrdup(src->caps);
    }
}

static void FileEntryFree(FileEntry entry)
{
    argvFree(entry->langs);
    free(entry->caps);
    memset(entry, 0, sizeof(*entry));
}

/**
 * strtokWithQuotes.
 * @param s		string to tokenize
 * @param delim		delimiter chars
 * @param[out] quotes	0 if unquoted, 1 if missing quote, 2 if quoted
 */
static char *strtokWithQuotes(char *s, const char *delim, int *quotes)
{
    static char *olds = NULL;
    char *token;

    if (s == NULL)
	s = olds;
    if (s == NULL)
	return NULL;

    /* Skip leading delimiters */
    s += strspn(s, delim);
    if (*s == '\0')
	return NULL;

    /* Leading quote escapes original delim until next quote */
    *quotes = 0;
    if (*s == '"') {
	*quotes = 1;
	delim = "\"";
	s++;
    }

    /* Find the end of the token.  */
    token = s;
    while (!strchr(delim, *s)) {
	if (*s == '\\')
	    s++;
	if (*s != '\0')
	    s++;
    }

    /* Terminate it */
    if (*s == '\0') {
	/* This token finishes the string */
	olds = s;
    } else {
	/* Terminate the token and make olds point past it */
	if (*s == '"' && *quotes)
	    *quotes = 2;
	*s = '\0';
	olds = s+1;
    }

    return token;
}

/**
 */
typedef const struct VFA {
    const char * attribute;
    int	flag;
} VFA_t;

/**
 */
static VFA_t const verifyAttrs[] = {
    { "md5",		RPMVERIFY_FILEDIGEST },
    { "filedigest",	RPMVERIFY_FILEDIGEST },
    { "size",		RPMVERIFY_FILESIZE },
    { "link",		RPMVERIFY_LINKTO },
    { "user",		RPMVERIFY_USER },
    { "owner",		RPMVERIFY_USER },
    { "group",		RPMVERIFY_GROUP },
    { "mtime",		RPMVERIFY_MTIME },
    { "mode",		RPMVERIFY_MODE },
    { "rdev",		RPMVERIFY_RDEV },
    { "caps",		RPMVERIFY_CAPS },
    { NULL, 0 }
};

static rpmFlags vfaMatch(VFA_t *attrs, const char *token, rpmFlags *flags)
{
    VFA_t *vfa;

    for (vfa = attrs; vfa->attribute != NULL; vfa++) {
	if (rstreq(token, vfa->attribute)) {
	    *flags |= vfa->flag;
	    break;
	}
    }
    return vfa->flag;
}

/**
 * Parse %verify and %defverify from file manifest.
 * @param buf		current spec file line
 * @param def		parse for %defverify or %verify?
 * @param entry		file entry data (current or default)
 * @return		RPMRC_OK on success
 */
static rpmRC parseForVerify(char * buf, int def, FileEntry entry)
{
    char *p, *pe, *q = NULL;
    const char *name = def ? "%defverify" : "%verify";
    int negated = 0;
    rpmVerifyFlags verifyFlags = RPMVERIFY_NONE;
    rpmRC rc = RPMRC_FAIL;

    if ((p = strstr(buf, name)) == NULL)
	return RPMRC_OK;

    for (pe = p; (pe-p) < strlen(name); pe++)
	*pe = ' ';

    SKIPSPACE(pe);

    if (*pe != '(') {
	rpmlog(RPMLOG_ERR, _("Missing '(' in %s %s\n"), name, pe);
	goto exit;
    }

    /* Bracket %*verify args */
    *pe++ = ' ';
    for (p = pe; *pe && *pe != ')'; pe++)
	{};

    if (*pe == '\0') {
	rpmlog(RPMLOG_ERR, _("Missing ')' in %s(%s\n"), name, p);
	goto exit;
    }

    /* Localize. Erase parsed string */
    q = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(q, p, (pe-p) + 1);
    while (p <= pe)
	*p++ = ' ';

    for (p = q; *p != '\0'; p = pe) {
	SKIPWHITE(p);
	if (*p == '\0')
	    break;
	pe = p;
	SKIPNONWHITE(pe);
	if (*pe != '\0')
	    *pe++ = '\0';

	if (vfaMatch(verifyAttrs, p, &verifyFlags))
	    continue;

	if (rstreq(p, "not")) {
	    negated ^= 1;
	} else {
	    rpmlog(RPMLOG_ERR, _("Invalid %s token: %s\n"), name, p);
	    goto exit;
	}
    }

    entry->verifyFlags = negated ? ~(verifyFlags) : verifyFlags;
    entry->specdFlags |= SPECD_VERIFY;
    rc = RPMRC_OK;

exit:
    free(q);

    return rc;
}

static int isAttrDefault(rpmstrPool pool, rpmsid arsid)
{
    const char *ars = rpmstrPoolStr(pool, arsid);
    return (ars && ars[0] == '-' && ars[1] == '\0');
}

/**
 * Parse %dev from file manifest.
 * @param buf		current spec file line
 * @param cur		current file entry data
 * @return		RPMRC_OK on success
 */
static rpmRC parseForDev(char * buf, FileEntry cur)
{
    const char * name;
    const char * errstr = NULL;
    char *p, *pe, *q = NULL;
    rpmRC rc = RPMRC_FAIL;	/* assume error */
    char *attr_parameters = NULL;

    if ((p = strstr(buf, (name = "%dev"))) == NULL)
	return RPMRC_OK;

    for (pe = p; (pe-p) < strlen(name); pe++)
	*pe = ' ';
    SKIPSPACE(pe);

    if (*pe != '(') {
	errstr = "'('";
	goto exit;
    }

    /* Bracket %dev args */
    *pe++ = ' ';
    for (p = pe; *pe && *pe != ')'; pe++)
	{};
    if (*pe != ')') {
	errstr = "')'";
	goto exit;
    }

    /* Localize. Erase parsed string */
    q = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(q, p, (pe-p) + 1);

    attr_parameters = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(attr_parameters, p, (pe-p) + 1);

    while (p <= pe)
	*p++ = ' ';

    p = q; SKIPWHITE(p);
    pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe++ = '\0';
    if (*p == 'b')
	cur->devtype = 'b';
    else if (*p == 'c')
	cur->devtype = 'c';
    else {
	errstr = "devtype";
	goto exit;
    }

    p = pe; SKIPWHITE(p);
    pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe = '\0';
    for (pe = p; *pe && risdigit(*pe); pe++)
	{} ;
    if (*pe == '\0') {
	cur->devmajor = atoi(p);
	if (!(cur->devmajor >= 0 && cur->devmajor < 256)) {
	    errstr = "devmajor";
	    goto exit;
	}
	pe++;
    } else {
	errstr = "devmajor";
	goto exit;
    }

    p = pe; SKIPWHITE(p);
    pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe = '\0';
    for (pe = p; *pe && risdigit(*pe); pe++)
	{} ;
    if (*pe == '\0') {
	cur->devminor = atoi(p);
	if (!(cur->devminor >= 0 && cur->devminor < 256)) {
	    errstr = "devminor";
	    goto exit;
	}
    } else {
	errstr = "devminor";
	goto exit;
    }

    rc = RPMRC_OK;

exit:
    if (rc) {
	rpmlog(RPMLOG_ERR, _("Missing %s in %s(%s)\n"), errstr, name, attr_parameters);
    }
    free(attr_parameters);
    free(q);
    return rc;
}

/**
 * Parse %attr and %defattr from file manifest.
 * @param pool		string pool
 * @param buf		current spec file line
 * @param def		parse for %defattr or %attr?
 * @param entry		file entry data (current / default)
 * @return		0 on success
 */
static rpmRC parseForAttr(rpmstrPool pool, char * buf, int def, FileEntry entry)
{
    const char *name = def ? "%defattr" : "%attr";
    char *p, *pe, *q = NULL;
    char *attr_parameters = NULL;
    int x;
    struct AttrRec_s arbuf;
    AttrRec ar = &arbuf;
    rpmRC rc = RPMRC_FAIL;

    if ((p = strstr(buf, name)) == NULL)
	return RPMRC_OK;

    for (pe = p; (pe-p) < strlen(name); pe++)
	*pe = ' ';

    SKIPSPACE(pe);

    if (*pe != '(') {
	rpmlog(RPMLOG_ERR, _("Missing '(' in %s %s\n"), name, pe);
	goto exit;
    }

    /* Bracket %*attr args */
    *pe++ = ' ';
    for (p = pe; *pe && *pe != ')'; pe++)
	{};

    if (*pe == '\0') {
	rpmlog(RPMLOG_ERR, _("Missing ')' in %s(%s\n"), name, p);
	goto exit;
    }

    if (def) {	/* %defattr */
	char *r = pe;
	r++;
	SKIPSPACE(r);
	if (*r != '\0') {
	    rpmlog(RPMLOG_ERR,
		     _("Non-white space follows %s(): %s\n"), name, r);
	    goto exit;
	}
    }

    /* Localize. Erase parsed string */
    q = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(q, p, (pe-p) + 1);

    attr_parameters = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(attr_parameters, p, (pe-p) + 1);

    while (p <= pe)
	*p++ = ' ';

    nullAttrRec(ar);

    p = q; SKIPWHITE(p);
    if (*p != '\0') {
	pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe++ = '\0';
	ar->ar_fmodestr = rpmstrPoolId(pool, p, 1);
	p = pe; SKIPWHITE(p);
    }
    if (*p != '\0') {
	pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe++ = '\0';
	ar->ar_user = rpmstrPoolId(pool, p, 1);
	p = pe; SKIPWHITE(p);
    }
    if (*p != '\0') {
	pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe++ = '\0';
	ar->ar_group = rpmstrPoolId(pool, p, 1);
	p = pe; SKIPWHITE(p);
    }
    if (*p != '\0' && def) {	/* %defattr */
	pe = p; SKIPNONWHITE(pe); if (*pe != '\0') *pe++ = '\0';
	ar->ar_dmodestr = rpmstrPoolId(pool, p, 1);
	p = pe; SKIPWHITE(p);
    }

    if (!(ar->ar_fmodestr && ar->ar_user && ar->ar_group) || *p != '\0') {
	rpmlog(RPMLOG_ERR, _("Bad syntax: %s(%s)\n"), name, attr_parameters);
	goto exit;
    }

    /* Do a quick test on the mode argument and adjust for "-" */
    if (ar->ar_fmodestr && !isAttrDefault(pool, ar->ar_fmodestr)) {
	unsigned int ui;
	x = sscanf(rpmstrPoolStr(pool, ar->ar_fmodestr), "%o", &ui);
	if ((x == 0) || (ar->ar_fmode & ~MYALLPERMS)) {
	    rpmlog(RPMLOG_ERR, _("Bad mode spec: %s(%s)\n"), name, attr_parameters);
	    goto exit;
	}
	ar->ar_fmode = ui;
    } else {
	ar->ar_fmodestr = 0;
    }

    if (ar->ar_dmodestr && !isAttrDefault(pool, ar->ar_dmodestr)) {
	unsigned int ui;
	x = sscanf(rpmstrPoolStr(pool, ar->ar_dmodestr), "%o", &ui);
	if ((x == 0) || (ar->ar_dmode & ~MYALLPERMS)) {
	    rpmlog(RPMLOG_ERR, _("Bad dirmode spec: %s(%s)\n"), name, attr_parameters);
	    goto exit;
	}
	ar->ar_dmode = ui;
    } else {
	ar->ar_dmodestr = 0;
    }

    if (!(ar->ar_user && !isAttrDefault(pool, ar->ar_user))) {
	ar->ar_user = 0;
    }

    if (!(ar->ar_group && !isAttrDefault(pool, ar->ar_group))) {
	ar->ar_group = 0;
    }

    dupAttrRec(ar, &(entry->ar));

    /* XXX fix all this */
    entry->specdFlags |= SPECD_UID | SPECD_GID | SPECD_FILEMODE | SPECD_DIRMODE;
    rc = RPMRC_OK;

exit:
    free(q);
    free(attr_parameters);
    
    return rc;
}

static VFA_t const configAttrs[] = {
    { "missingok",	RPMFILE_MISSINGOK },
    { "noreplace",	RPMFILE_NOREPLACE },
    { NULL, 0 }
};

/**
 * Parse %config from file manifest.
 * @param buf		current spec file line
 * @param cur		current file entry data
 * @return		RPMRC_OK on success
 */
static rpmRC parseForConfig(char * buf, FileEntry cur)
{
    char *p, *pe, *q = NULL;
    const char *name;
    rpmRC rc = RPMRC_FAIL;

    if ((p = strstr(buf, (name = "%config"))) == NULL)
	return RPMRC_OK;

    cur->attrFlags |= RPMFILE_CONFIG;

    /* Erase "%config" token. */
    for (pe = p; (pe-p) < strlen(name); pe++)
	*pe = ' ';
    SKIPSPACE(pe);
    if (*pe != '(')
	return RPMRC_OK;

    /* Bracket %config args */
    *pe++ = ' ';
    for (p = pe; *pe && *pe != ')'; pe++)
	{};

    if (*pe == '\0') {
	rpmlog(RPMLOG_ERR, _("Missing ')' in %s(%s\n"), name, p);
	goto exit;
    }

    /* Localize. Erase parsed string. */
    q = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(q, p, (pe-p) + 1);
    while (p <= pe)
	*p++ = ' ';

    for (p = q; *p != '\0'; p = pe) {
	SKIPWHITE(p);
	if (*p == '\0')
	    break;
	pe = p;
	SKIPNONWHITE(pe);
	if (*pe != '\0')
	    *pe++ = '\0';
	if (!vfaMatch(configAttrs, p, &(cur->attrFlags))) {
	    rpmlog(RPMLOG_ERR, _("Invalid %s token: %s\n"), name, p);
	    goto exit;
	}
    }
    rc = RPMRC_OK;
    
exit:
    free(q);

    return rc;
}

static rpmRC addLang(ARGV_t *av, const char *lang, size_t n, const char *ent)
{
    rpmRC rc = RPMRC_FAIL;
    char lbuf[n + 1];
    rstrlcpy(lbuf, lang, sizeof(lbuf));
    SKIPWHITE(ent);

    /* Sanity check locale length */
    if (n < 1 || (n == 1 && *lang != 'C') || n >= 32) {
	rpmlog(RPMLOG_ERR, _("Unusual locale length: \"%s\" in %%lang(%s)\n"),
		lbuf, ent);
	goto exit;
    }

    /* Check for duplicate locales */
    if (argvSearch(*av, lbuf, NULL)) {
	rpmlog(RPMLOG_WARNING, _("Duplicate locale %s in %%lang(%s)\n"),
		lbuf, ent);
    } else {
	argvAdd(av, lbuf);
	argvSort(*av, NULL);
    }
    rc = RPMRC_OK;

exit:
    return rc;
}

/**
 * Parse %lang from file manifest.
 * @param buf		current spec file line
 * @param cur		current file entry data
 * @return		RPMRC_OK on success
 */
static rpmRC parseForLang(char * buf, FileEntry cur)
{
    char *p, *pe, *q = NULL;
    const char *name;
    rpmRC rc = RPMRC_FAIL;

  while ((p = strstr(buf, (name = "%lang"))) != NULL) {

    for (pe = p; (pe-p) < strlen(name); pe++)
	*pe = ' ';
    SKIPSPACE(pe);

    if (*pe != '(') {
	rpmlog(RPMLOG_ERR, _("Missing '(' in %s %s\n"), name, pe);
	goto exit;
    }

    /* Bracket %lang args */
    *pe = ' ';
    for (pe = p; *pe && *pe != ')'; pe++)
	{};

    if (*pe == '\0') {
	rpmlog(RPMLOG_ERR, _("Missing ')' in %s(%s\n"), name, p);
	goto exit;
    }

    /* Localize. Erase parsed string. */
    q = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(q, p, (pe-p) + 1);
    while (p <= pe)
	*p++ = ' ';

    /* Parse multiple arguments from %lang */
    for (p = q; *p != '\0'; p = pe) {
	SKIPWHITE(p);
	pe = p;
	SKIPNONWHITE(pe);

	if (addLang(&(cur->langs), p, (pe-p), q))
	    goto exit;

	if (*pe == ',') pe++;	/* skip , if present */
    }

    q = _free(q);
  }

    rc = RPMRC_OK;

exit:
    free(q);

    return rc;
}

/**
 * Parse %caps from file manifest.
 * @param buf		current spec file line
 * @param cur		current file entry data
 * @return		RPMRC_OK on success
 */
static rpmRC parseForCaps(char * buf, FileEntry cur)
{
    char *p, *pe, *q = NULL;
    const char *name;
    rpmRC rc = RPMRC_FAIL;

    if ((p = strstr(buf, (name = "%caps"))) == NULL)
	return RPMRC_OK;

    /* Erase "%caps" token. */
    for (pe = p; (pe-p) < strlen(name); pe++)
	*pe = ' ';
    SKIPSPACE(pe);
    if (*pe != '(')
	return RPMRC_OK;

    /* Bracket %caps args */
    *pe++ = ' ';
    for (p = pe; *pe && *pe != ')'; pe++)
	{};

    if (*pe == '\0') {
	rpmlog(RPMLOG_ERR, _("Missing ')' in %s(%s\n"), name, p);
	goto exit;
    }

    /* Localize. Erase parsed string. */
    q = (char *)xmalloc((pe-p) + 1);
    rstrlcpy(q, p, (pe-p) + 1);
    while (p <= pe)
	*p++ = ' ';

#ifdef WITH_CAP
    {
	char *captxt = NULL;
	cap_t fcaps = cap_from_text(q);
	if (fcaps == NULL) {
	    rpmlog(RPMLOG_ERR, _("Invalid capability: %s\n"), q);
	    goto exit;
	}
	/* run our string through cap_to_text() to get libcap presentation */
	captxt = cap_to_text(fcaps, NULL);
	cur->caps = xstrdup(captxt);
	cap_free(captxt);
	cap_free(fcaps);
    }
#else
	rpmlog(RPMLOG_ERR, _("File capability support not built in\n"));
	goto exit;
#endif

    rc = RPMRC_OK;
    
exit:
    free(q);

    return rc;
}
/**
 */
static VFA_t const virtualAttrs[] = {
    { "%dir",		RPMFILE_DIR },
    { "%docdir",	RPMFILE_DOCDIR },
    { "%doc",		RPMFILE_DOC },
    { "%ghost",		RPMFILE_GHOST },
    { "%exclude",	RPMFILE_EXCLUDE },
    { "%readme",	RPMFILE_README },
    { "%license",	RPMFILE_LICENSE },
    { "%pubkey",	RPMFILE_PUBKEY },
    { "%missingok",	RPMFILE_MISSINGOK },
    { "%artifact",	RPMFILE_ARTIFACT },
    { NULL, 0 }
};

/**
 * Parse simple attributes (e.g. %dir) from file manifest.
 * @param buf		current spec file line
 * @param cur		current file entry data
 * @param[out] *fileNames	file names
 * @return		RPMRC_OK on success
 */
static rpmRC parseForSimple(char * buf, FileEntry cur, ARGV_t * fileNames)
{
    char *s, *t, *end;
    const char *delim = " \t\n";
    int quotes = 0;
    rpmRC res = RPMRC_OK;
    int allow_relative = (RPMFILE_PUBKEY|RPMFILE_DOC|RPMFILE_LICENSE);

    t = buf;
    while ((s = strtokWithQuotes(t, delim, &quotes)) != NULL) {
	t = NULL;
	end = s + strlen(s) - 1;

	/* Syntax checks */
	if (quotes == 1) {
	    rpmlog(RPMLOG_ERR, _("Missing quote: %s\n"), s);
	    res = RPMRC_FAIL;
	    break;
	}
	if (*end == '\n') {
	    /* Newline escaping is not supported */
	    rpmlog(RPMLOG_ERR, _("Trailing backslash: %s\n"), s);
	    res = RPMRC_FAIL;
	    break;
	}

    	/* Set flags for virtual file attributes */
	if (vfaMatch(virtualAttrs, s, &(cur->attrFlags)))
	    continue;

	/* normally paths need to be absolute */
	if (*s != '/') {
	   if (!(cur->attrFlags & allow_relative)) {
		rpmlog(RPMLOG_ERR, _("File must begin with \"/\": %s\n"), s);
		res = RPMRC_FAIL;
		continue;
	    }
	    /* non-absolute %doc and %license paths are special */
	    if (cur->attrFlags & (RPMFILE_DOC | RPMFILE_LICENSE))
		cur->attrFlags |= RPMFILE_SPECIALDIR;
	}

	if (!quotes)
	    rpmUnescape(s, delim);
	else {
	    rpmUnescape(s, "\"");
	    s = rpmEscape(s, "?*[]{}");
	}

	argvAdd(fileNames, s);

	if (quotes)
	    free(s);
    }

    return res;
}

/**
 */
static int compareFileListRecs(const void * ap, const void * bp)	
{
    const char *a = ((FileListRec)ap)->cpioPath;
    const char *b = ((FileListRec)bp)->cpioPath;
    return strcmp(a, b);
}

/**
 * Test if file is located in a %docdir.
 * @param docDirs	doc dirs
 * @param fileName	file path
 * @return		1 if doc file, 0 if not
 */
static int isDoc(ARGV_const_t docDirs, const char * fileName)	
{
    size_t k, l;

    k = strlen(fileName);
    for (ARGV_const_t dd = docDirs; *dd; dd++) {
	l = strlen(*dd);
	if (l < k && rstreqn(fileName, *dd, l) && fileName[l] == '/')
	    return 1;
    }
    return 0;
}

static int isLinkable(mode_t mode)
{
    return (S_ISREG(mode) || S_ISLNK(mode));
}

static int isHardLink(FileListRec flp, FileListRec tlp)
{
    return ((isLinkable(flp->fl_mode) && isLinkable(tlp->fl_mode)) &&
	    ((flp->fl_nlink > 1) && (flp->fl_nlink == tlp->fl_nlink)) &&
	    (flp->fl_ino == tlp->fl_ino) && 
	    (flp->fl_dev == tlp->fl_dev));
}

/**
 * Verify that file attributes scope over hardlinks correctly.
 * If partial hardlink sets are possible, then add tracking dependency.
 * @param files		package file records
 * @return		1 if partial hardlink sets can exist, 0 otherwise.
 */
static int checkHardLinks(FileRecords files)
{
    FileListRec ilp, jlp;
    int i, j;

    for (i = 0;  i < files->used; i++) {
	ilp = files->recs + i;
	if (!(isLinkable(ilp->fl_mode) && ilp->fl_nlink > 1))
	    continue;

	for (j = i + 1; j < files->used; j++) {
	    jlp = files->recs + j;
	    if (isHardLink(ilp, jlp)) {
		return 1;
	    }
	}
    }
    return 0;
}

static int seenHardLink(FileRecords files, FileListRec flp, rpm_ino_t *fileid)
{
    for (FileListRec ilp = files->recs; ilp < flp; ilp++) {
	if (isHardLink(flp, ilp)) {
	    *fileid = ilp - files->recs;
	    return 1;
	}
    }
    return 0;
}

/**
 * Add file entries to header.
 * @todo Should directories have %doc/%config attributes? (#14531)
 * @todo Remove RPMTAG_OLDFILENAMES, add dirname/basename instead.
 * @param fl		package file tree walk data
 * @param pkg		(sub) package
 * @param isSrc		pass 1 for source packages 0 otherwise
 */
static void genCpioListAndHeader(FileList fl, rpmSpec spec, Package pkg, int isSrc)
{
    FileListRec flp;
    char buf[BUFSIZ];
    int i, npaths = 0;
    int fail_on_dupes = rpmExpandNumeric("%{?_duplicate_files_terminate_build}") > 0;
    uint32_t defaultalgo = RPM_HASH_SHA256, digestalgo;
    rpm_loff_t totalFileSize = 0;
    Header h = pkg->header; /* just a shortcut */
    int override_date = 0;
    time_t mtime_clamp = 0;
    char *srcdate = getenv("SOURCE_DATE_EPOCH");
    char *mtime_policy_str = rpmExpand("%{?build_mtime_policy}", NULL);

    /* backward compatibility */
    if (!*mtime_policy_str) {
        if (srcdate && rpmExpandNumeric("%{?clamp_mtime_to_source_date_epoch}")) {
	    free(mtime_policy_str);
	    mtime_policy_str = xstrdup("clamp_to_source_date_epoch");
	    rpmlog(RPMLOG_WARNING,
		    _("%%clamp_mtime_to_source_date_epoch is deprecated, please use %%build_mtime_policy\n"));
	}
    }

    if (!strcmp(mtime_policy_str, "clamp_to_buildtime")) {
	mtime_clamp = spec->buildTime;
	override_date = 1;
    } else if (!strcmp(mtime_policy_str, "clamp_to_source_date_epoch")) {
	/* Limit the maximum date to SOURCE_DATE_EPOCH if defined
	 * similar to the tar --clamp-mtime option
	 * https://reproducible-builds.org/specs/source-date-epoch/
	 */
	if (srcdate) {
	    char *endptr;
	    errno = 0;
	    mtime_clamp = strtol(srcdate, &endptr, 10);
	    if (srcdate == endptr || *endptr || errno != 0) {
		rpmlog(RPMLOG_ERR, _("unable to parse %s=%s\n"), "SOURCE_DATE_EPOCH", srcdate);
		fl->processingFailed = 1;
	    }
	    override_date = 1;
	}
    } else if (*mtime_policy_str) {
	rpmlog(RPMLOG_WARNING,
		_("Unknown mtime policy '%s'\n"), mtime_policy_str);
    }
    free(mtime_policy_str);

    /*
     * See if non-default file digest algorithm is requested. If not
     * specified, quietly assume default. Otherwise check if supported type.
     */
    digestalgo = rpmExpandNumeric(isSrc ? "%{_source_filedigest_algorithm}" :
					  "%{_binary_filedigest_algorithm}");
    if (digestalgo == 0) {
	digestalgo = defaultalgo;
    }

    if (rpmDigestLength(digestalgo) == 0) {
	rpmlog(RPMLOG_WARNING,
		_("Unknown file digest algorithm %u, falling back to %u\n"),
		digestalgo, defaultalgo);
	digestalgo = defaultalgo;
    }

    /* Adjust paths if needed */
    if (!isSrc && pkg->removePostfixes) {
	pkg->fileRenameMap = fileRenameHashCreate(fl->files.used,
	                                          rstrhash, strcmp,
	                                          (fileRenameHashFreeKey)rfree, (fileRenameHashFreeData)rfree);
	for (i = 0, flp = fl->files.recs; i < fl->files.used; i++, flp++) {
	    char * cpiopath = flp->cpioPath;
	    char * cpiopath_orig = xstrdup(cpiopath);

	    for (ARGV_const_t postfix_p = pkg->removePostfixes; *postfix_p; postfix_p++) {
		int len = strlen(*postfix_p);
		int plen = strlen(cpiopath);
		if (len <= plen && !strncmp(cpiopath+plen-len, *postfix_p, len)) {
		    cpiopath[plen-len] = '\0';
		    if (plen-len > 0 && cpiopath[plen-len-1] == '/') {
			cpiopath[plen-len-1] = '\0';
		    }
		}
	    }
	    if (strcmp(cpiopath_orig, cpiopath))
		fileRenameHashAddEntry(pkg->fileRenameMap, xstrdup(cpiopath), cpiopath_orig);
	    else
		_free(cpiopath_orig);
	}
    }

    /* Sort the big list */
    if (fl->files.recs) {
	qsort(fl->files.recs, fl->files.used,
	      sizeof(*(fl->files.recs)), compareFileListRecs);
    }
    
    pkg->dpaths = (char **)xmalloc((fl->files.used + 1) * sizeof(*pkg->dpaths));

    /* Generate the header. */
    for (i = 0, flp = fl->files.recs; i < fl->files.used; i++, flp++) {
	rpm_ino_t fileid = flp - fl->files.recs;

 	/* Merge duplicate entries. */
	while (i < (fl->files.used - 1) &&
	    rstreq(flp->cpioPath, flp[1].cpioPath)) {

	    /* Two entries for the same file found, merge the entries. */
	    /* Note that an %exclude is a duplication of a file reference */

	    /* file flags */
	    flp[1].flags |= flp->flags;	

	    if (!(flp[1].flags & RPMFILE_EXCLUDE)) {
		int lvl = RPMLOG_WARNING;
		if (fail_on_dupes) {
		    lvl = RPMLOG_ERR;
		    fl->processingFailed = 1;
		}
		rpmlog(lvl, _("File listed twice: %s\n"), flp->cpioPath);
	    }
   
	    /* file mode */
	    if (S_ISDIR(flp->fl_mode)) {
		if ((flp[1].specdFlags & (SPECD_DIRMODE | SPECD_DEFDIRMODE)) <
		    (flp->specdFlags & (SPECD_DIRMODE | SPECD_DEFDIRMODE)))
			flp[1].fl_mode = flp->fl_mode;
	    } else {
		if ((flp[1].specdFlags & (SPECD_FILEMODE | SPECD_DEFFILEMODE)) <
		    (flp->specdFlags & (SPECD_FILEMODE | SPECD_DEFFILEMODE)))
			flp[1].fl_mode = flp->fl_mode;
	    }

	    /* uid */
	    if ((flp[1].specdFlags & (SPECD_UID | SPECD_DEFUID)) <
		(flp->specdFlags & (SPECD_UID | SPECD_DEFUID)))
	    {
		flp[1].uname = flp->uname;
	    }

	    /* gid */
	    if ((flp[1].specdFlags & (SPECD_GID | SPECD_DEFGID)) <
		(flp->specdFlags & (SPECD_GID | SPECD_DEFGID)))
	    {
		flp[1].gname = flp->gname;
	    }

	    /* verify flags */
	    if ((flp[1].specdFlags & (SPECD_VERIFY | SPECD_DEFVERIFY)) <
		(flp->specdFlags & (SPECD_VERIFY | SPECD_DEFVERIFY)))
		    flp[1].verifyFlags = flp->verifyFlags;

	    /* XXX to-do: language */

	    flp++; i++;
	}

	/* Skip files that were marked with %exclude. */
	if (flp->flags & RPMFILE_EXCLUDE)
	{
	    argvAdd(&pkg->fileExcludeList, flp->cpioPath);
	    continue;
	}

	/* Collect on-disk paths for archive creation */
	pkg->dpaths[npaths++] = xstrdup(flp->diskPath);

	headerPutString(h, RPMTAG_OLDFILENAMES, flp->cpioPath);
	headerPutString(h, RPMTAG_FILEUSERNAME,
			rpmstrPoolStr(fl->pool, flp->uname));
	headerPutString(h, RPMTAG_FILEGROUPNAME,
			rpmstrPoolStr(fl->pool, flp->gname));

	/* Only use 64bit filesizes tag if required. */
	if (fl->largeFiles) {
	    rpm_loff_t rsize64 = (rpm_loff_t)flp->fl_size;
	    headerPutUint64(h, RPMTAG_LONGFILESIZES, &rsize64, 1);
            (void) rpmlibNeedsFeature(pkg, "LargeFiles", "4.12.0-1");
	} else {
	    rpm_off_t rsize32 = (rpm_off_t)flp->fl_size;
	    headerPutUint32(h, RPMTAG_FILESIZES, &rsize32, 1);
	}
	/* Excludes and dupes have been filtered out by now. */
	if (isLinkable(flp->fl_mode)) {
	    if (flp->fl_nlink == 1 || !seenHardLink(&fl->files, flp, &fileid)) {
		totalFileSize += flp->fl_size;
	    }
	}
	
	if (override_date && flp->fl_mtime > mtime_clamp) {
	    flp->fl_mtime = mtime_clamp;
	}
	/*
 	 * For items whose size varies between systems, always explicitly 
 	 * cast to the header type before inserting.
 	 * TODO: check and warn if header type overflows for each case.
 	 */
	{   rpm_time_t rtime = (rpm_time_t) flp->fl_mtime;
	    headerPutUint32(h, RPMTAG_FILEMTIMES, &rtime, 1);
	}

	{   rpm_mode_t rmode = (rpm_mode_t) flp->fl_mode;
	    headerPutUint16(h, RPMTAG_FILEMODES, &rmode, 1);
	}

	{   rpm_rdev_t rrdev = (rpm_rdev_t) flp->fl_rdev;
	    headerPutUint16(h, RPMTAG_FILERDEVS, &rrdev, 1);
	}
	
	/*
	 * To allow rpmbuild to work on filesystems with 64bit inodes numbers,
	 * remap them into 32bit integers based on filelist index, just
	 * preserving semantics for determining hardlinks.
	 * Start at 1 as inode zero as that could be considered as an error.
	 * Since we flatten all the inodes to appear within a single fs,
	 * we also need to flatten the devices.
	 */
	{   rpm_ino_t rino = fileid + 1;
	    rpm_dev_t rdev = flp->fl_dev ? 1 : 0;
	    headerPutUint32(h, RPMTAG_FILEINODES, &rino, 1);
	    headerPutUint32(h, RPMTAG_FILEDEVICES, &rdev, 1);
	}
	
	headerPutString(h, RPMTAG_FILELANGS, flp->langs);

	if (fl->haveCaps) {
	    headerPutString(h, RPMTAG_FILECAPS, flp->caps);
	}
	
	buf[0] = '\0';
	if (S_ISREG(flp->fl_mode) && !(flp->flags & RPMFILE_GHOST))
	    (void) rpmDoDigest(digestalgo, flp->diskPath, 1, 
			       (unsigned char *)buf);
	headerPutString(h, RPMTAG_FILEDIGESTS, buf);
	
	buf[0] = '\0';
	if (S_ISLNK(flp->fl_mode)) {
	    ssize_t llen = readlink(flp->diskPath, buf, BUFSIZ-1);
	    if (llen == -1) {
		rpmlog(RPMLOG_ERR, _("reading symlink %s failed: %s\n"),
			flp->diskPath, strerror(errno));
		fl->processingFailed = 1;
	    } else {
		buf[llen] = '\0';
		if (buf[0] == '/') {
		    rpmlog(RPMLOG_WARNING, _("absolute symlink: %s -> %s\n"),
			flp->cpioPath, buf);
		}
		if (buf[0] == '/' && !rstreq(fl->buildRoot, "/") &&
			rstreqn(buf, fl->buildRoot, fl->buildRootLen)) {
		    rpmlog(RPMLOG_ERR,
				_("Symlink points to BuildRoot: %s -> %s\n"),
				flp->cpioPath, buf);
		    fl->processingFailed = 1;
		}
	    }
	}
	headerPutString(h, RPMTAG_FILELINKTOS, buf);
	
	if (flp->flags & RPMFILE_GHOST) {
	    flp->verifyFlags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
				RPMVERIFY_LINKTO | RPMVERIFY_MTIME);
	}
	headerPutUint32(h, RPMTAG_FILEVERIFYFLAGS, &(flp->verifyFlags),1);
	
	if (!isSrc && isDoc(fl->docDirs, flp->cpioPath))
	    flp->flags |= RPMFILE_DOC;
	/* XXX Should directories have %doc/%config attributes? (#14531) */
	if (S_ISDIR(flp->fl_mode))
	    flp->flags &= ~(RPMFILE_CONFIG|RPMFILE_DOC|RPMFILE_LICENSE);
	/* Strip internal parse data */
	flp->flags &= PARSEATTR_MASK;

	headerPutUint32(h, RPMTAG_FILEFLAGS, &(flp->flags) ,1);
    }
    pkg->dpaths[npaths] = NULL;

    if (totalFileSize < UINT32_MAX) {
	rpm_off_t totalsize = totalFileSize;
	headerPutUint32(h, RPMTAG_SIZE, &totalsize, 1);
    } else {
	rpm_loff_t totalsize = totalFileSize;
	headerPutUint64(h, RPMTAG_LONGSIZE, &totalsize, 1);
    }

    if (digestalgo != RPM_HASH_MD5) {
	headerPutUint32(h, RPMTAG_FILEDIGESTALGO, &digestalgo, 1);
	rpmlibNeedsFeature(pkg, "FileDigests", "4.6.0-1");
    }

    if (fl->haveCaps) {
	rpmlibNeedsFeature(pkg, "FileCaps", "4.6.1-1");
    }

    if (!isSrc && !rpmExpandNumeric("%{_noPayloadPrefix}"))
	(void) rpmlibNeedsFeature(pkg, "PayloadFilesHavePrefix", "4.0-1");

    /* rpmfiNew() only groks compressed filelists */
    headerConvert(h, HEADERCONV_COMPRESSFILELIST);
    pkg->cpioList = rpmfilesNew(NULL, h, RPMTAG_BASENAMES, 0);

    if (pkg->cpioList == NULL || rpmfilesFC(pkg->cpioList) != npaths) {
	fl->processingFailed = 1;
    }

    if (fl->pkgFlags & RPMBUILD_PKG_NODIRTOKENS) {
	/* Uncompress filelist if legacy format requested */
	headerConvert(h, HEADERCONV_EXPANDFILELIST);
    } else {
	/* Binary packages with dirNames cannot be installed by legacy rpm. */
	(void) rpmlibNeedsFeature(pkg, "CompressedFileNames", "3.0.4-1");
    }
}

static FileRecords FileRecordsFree(FileRecords files)
{
    for (int i = 0; i < files->used; i++) {
	free(files->recs[i].diskPath);
	free(files->recs[i].cpioPath);
	free(files->recs[i].langs);
	free(files->recs[i].caps);
    }
    free(files->recs);
    return NULL;
}

static void FileListFree(FileList fl)
{
    FileEntryFree(&(fl->cur));
    FileEntryFree(&(fl->def));
    FileRecordsFree(&(fl->files));
    free(fl->buildRoot);
    argvFree(fl->docDirs);
    rpmstrPoolFree(fl->pool);
}

/* forward ref */
static rpmRC recurseDir(FileList fl, const char * diskPath);

/* Hack up a stat structure for a %dev or non-existing %ghost */
static struct stat * fakeStat(FileEntry cur, struct stat * statp)
{
    time_t now = time(NULL);

    if (cur->devtype) {
	statp->st_rdev = ((cur->devmajor & 0xff) << 8) | (cur->devminor & 0xff);
	statp->st_dev = statp->st_rdev;
	statp->st_mode = (cur->devtype == 'b' ? S_IFBLK : S_IFCHR);
    } else {
	/* non-existing %ghost file or directory */
	statp->st_mode = cur->isDir ? S_IFDIR : S_IFREG;
	/* can't recurse into non-existing directory */
	if (cur->isDir)
	    cur->isDir = 1;
    }
    statp->st_mode |= (cur->ar.ar_fmode & 0777);
    statp->st_atime = now;
    statp->st_mtime = now;
    statp->st_ctime = now;
    statp->st_nlink = 1;
    return statp;
}

static int validFilename(const char *fn)
{
    int rc = 1;
    /* char is signed but we're dealing with unsigned values here! */
    for (const unsigned char *s = (const unsigned char *)fn; *s; s++) {
	/* Ban DEL and anything below space, UTF-8 is validated elsewhere */
	if (*s == 0x7f || *s < 0x20) {
	    rpmlog(RPMLOG_ERR,
		_("Illegal character (0x%x) in filename: %s\n"), *s, fn);
	    rc = 0;
	    break;
	}
    }
    return rc;
}

/**
 * Add a file to the package manifest.
 * @param fl		package file tree walk data
 * @param diskPath	path to file
 * @param statp		file stat (possibly NULL)
 * @return		RPMRC_OK on success
 */
static rpmRC addFile(FileList fl, const char * diskPath,
		struct stat * statp)
{
    size_t plen = strlen(diskPath);
    char buf[plen + 1];
    const char *cpioPath;
    struct stat statbuf;
    mode_t fileMode;
    const char *fileUname;
    const char *fileGname;
    rpmRC rc = RPMRC_FAIL; /* assume failure */

    /* Strip trailing slash. The special case of '/' path is handled below. */
    if (plen > 0 && diskPath[plen - 1] == '/') {
	diskPath = strcpy(buf, diskPath);
	buf[plen - 1] = '\0';
    }
    cpioPath = diskPath;
	
    if (strncmp(diskPath, fl->buildRoot, fl->buildRootLen)) {
	rpmlog(RPMLOG_ERR, _("Path is outside buildroot: %s\n"), diskPath);
	goto exit;
    }

    if (!validFilename(diskPath))
	goto exit;
    
    /* Path may have prepended buildRoot, so locate the original filename. */
    /*
     * XXX There are 3 types of entry into addFile:
     *
     *	From			diskUrl			statp
     *	=====================================================
     *  processBinaryFile	path			NULL
     *  processBinaryFile	glob result path	NULL
     *  myftw			path			stat
     *
     */
    if (fl->buildRoot && !rstreq(fl->buildRoot, "/"))
    	cpioPath += fl->buildRootLen;

    /* XXX make sure '/' can be packaged also */
    if (*cpioPath == '\0')
	cpioPath = "/";

    /*
     * Unless recursing, we dont have stat() info at hand. Handle the
     * various cases, preserving historical behavior wrt %dev():
     * - for %dev() entries we fake it up whether the file exists or not
     * - otherwise try to grab the data by lstat()
     * - %ghost entries might not exist, fake it up
     */
    if (statp == NULL) {
	memset(&statbuf, 0, sizeof(statbuf));

	if (fl->cur.devtype) {
	    statp = fakeStat(&(fl->cur), &statbuf);
	} else if (lstat(diskPath, &statbuf) == 0) {
	    statp = &statbuf;
	} else if (fl->cur.attrFlags & RPMFILE_GHOST) {
	    statp = fakeStat(&(fl->cur), &statbuf);
	} else {
	    int lvl = RPMLOG_ERR;
	    int ignore = 0;
	    const char *msg = fl->cur.isDir ? _("Directory not found: %s\n") :
					      _("File not found: %s\n");
	    if (fl->cur.attrFlags & RPMFILE_EXCLUDE)
		ignore = 1;
	    if (fl->cur.attrFlags & RPMFILE_DOC) {
		int strict_doc =
		    rpmExpandNumeric("%{?_missing_doc_files_terminate_build}");
		if (!strict_doc)
		    ignore = 1;
	    }

	    if (ignore) {
		lvl = RPMLOG_WARNING;
		rc = RPMRC_OK;
	    }
	    rpmlog(lvl, msg, diskPath);
	    goto exit;
	}
    }

    /* Error out when a non-directory is specified as one in spec */
    if (fl->cur.isDir && (statp == &statbuf) && !S_ISDIR(statp->st_mode)) {
	rpmlog(RPMLOG_ERR, _("Not a directory: %s\n"), diskPath);
	goto exit;
    }

    /* Don't recurse into explicit %dir, don't double-recurse from fts */
    if ((fl->cur.isDir != 1) && (statp == &statbuf) && S_ISDIR(statp->st_mode)) {
	return recurseDir(fl, diskPath);
    }

    fileMode = statp->st_mode;

    /* Explicit %attr() always wins */
    if (fl->cur.ar.ar_fmodestr) {
	if (S_ISLNK(fileMode)) {
	    rpmlog(RPMLOG_WARNING,
		   "Explicit %%attr() mode not applicable to symlink: %s\n",
		   diskPath);
	} else {
	    fileMode &= S_IFMT;
	    fileMode |= fl->cur.ar.ar_fmode;
	}
    } else {
	/* ...but %defattr() for directories and files is different */
	if (S_ISDIR(fileMode)) {
	    if (fl->def.ar.ar_dmodestr) {
		fileMode &= S_IFMT;
		fileMode |= fl->def.ar.ar_dmode;
	    }
	} else if (!S_ISLNK(fileMode) && fl->def.ar.ar_fmodestr) {
	    fileMode &= S_IFMT;
	    fileMode |= fl->def.ar.ar_fmode;
	}
    }
    if (fl->cur.ar.ar_user) {
	fileUname = rpmstrPoolStr(fl->pool, fl->cur.ar.ar_user);
    } else if (fl->def.ar.ar_user) {
	fileUname = rpmstrPoolStr(fl->pool, fl->def.ar.ar_user);
    } else {
	fileUname = UID_0_USER;
    }
    if (fl->cur.ar.ar_group) {
	fileGname = rpmstrPoolStr(fl->pool, fl->cur.ar.ar_group);
    } else if (fl->def.ar.ar_group) {
	fileGname = rpmstrPoolStr(fl->pool, fl->def.ar.ar_group);
    } else {
	fileGname = GID_0_GROUP;
    }
	
    /* S_XXX macro must be consistent with type in find call at check-files script */
    if (check_fileList && (S_ISREG(fileMode) || S_ISLNK(fileMode))) {
	appendStringBuf(check_fileList, diskPath);
	appendStringBuf(check_fileList, "\n");
    }

    /* Add to the file list */
    if (fl->files.used == fl->files.alloced) {
	fl->files.alloced += 128;
	fl->files.recs = xrealloc(fl->files.recs,
			fl->files.alloced * sizeof(*(fl->files.recs)));
    }
	    
    {	FileListRec flp = &fl->files.recs[fl->files.used];

	flp->fl_st = *statp;	/* structure assignment */
	flp->fl_mode = fileMode;
	if (S_ISDIR(fileMode))
	    flp->fl_size = 0;

	flp->cpioPath = xstrdup(cpioPath);
	flp->diskPath = xstrdup(diskPath);
	flp->uname = rpmstrPoolId(fl->pool, fileUname, 1);
	flp->gname = rpmstrPoolId(fl->pool, fileGname, 1);

	if (fl->cur.langs) {
	    flp->langs = argvJoin(fl->cur.langs, "|");
	} else {
	    flp->langs = xstrdup("");
	}

	if (fl->cur.caps) {
	    flp->caps = xstrdup(fl->cur.caps);
	} else {
	    flp->caps = xstrdup("");
	}

	flp->flags = fl->cur.attrFlags;
	flp->specdFlags = fl->cur.specdFlags;
	flp->verifyFlags = fl->cur.verifyFlags;

	if (!(flp->flags & RPMFILE_EXCLUDE) && S_ISREG(flp->fl_mode)) {
	    if (flp->fl_size >= UINT32_MAX) {
		fl->largeFiles = 1;
	    }
	}
    }

    rc = RPMRC_OK;
    fl->files.used++;

exit:
    if (rc != RPMRC_OK)
	fl->processingFailed = 1;

    return rc;
}

/**
 * Add directory (and all of its files) to the package manifest.
 * @param fl		package file tree walk data
 * @param diskPath	path to file
 * @return		RPMRC_OK on success
 */
static rpmRC recurseDir(FileList fl, const char * diskPath)
{
    char * ftsSet[2];
    FTS * ftsp;
    FTSENT * fts;
    int myFtsOpts = (FTS_COMFOLLOW | FTS_NOCHDIR | FTS_PHYSICAL);
    rpmRC rc = RPMRC_FAIL;

    ftsSet[0] = (char *) diskPath;
    ftsSet[1] = NULL;
    ftsp = Fts_open(ftsSet, myFtsOpts, NULL);
    while ((fts = Fts_read(ftsp)) != NULL) {
	switch (fts->fts_info) {
	case FTS_D:		/* preorder directory */
	case FTS_F:		/* regular file */
	case FTS_SL:		/* symbolic link */
	case FTS_SLNONE:	/* symbolic link without target */
	case FTS_DEFAULT:	/* none of the above */
	    rc = addFile(fl, fts->fts_accpath, fts->fts_statp);
	    break;
	case FTS_DOT:		/* dot or dot-dot */
	case FTS_DP:		/* postorder directory */
	    rc = RPMRC_OK;
	    break;
	case FTS_NS:		/* stat(2) failed */
	case FTS_DNR:		/* unreadable directory */
	case FTS_ERR:		/* error; errno is set */
	case FTS_DC:		/* directory that causes cycles */
	case FTS_NSOK:		/* no stat(2) requested */
	case FTS_INIT:		/* initialized only */
	case FTS_W:		/* whiteout object */
	default:
	    rpmlog(RPMLOG_ERR, _("Can't read content of file: %s\n"),
		fts->fts_path);
	    rc = RPMRC_FAIL;
	    break;
	}
	if (rc)
	    break;
    }
    (void) Fts_close(ftsp);

    return rc;
}

/**
 * Add a pubkey/icon to a binary package.
 * @param pkg
 * @param fl		package file tree walk data
 * @param fileName	path to file, relative is builddir, absolute buildroot.
 * @param tag		tag to add
 * @return		RPMRC_OK on success
 */
static rpmRC processMetadataFile(Package pkg, FileList fl, 
				 const char * fileName, rpmTagVal tag)
{
    char * fn = NULL;
    char * apkt = NULL;
    uint8_t * pkt = NULL;
    ssize_t pktlen = 0;
    int absolute = 0;
    rpmRC rc = RPMRC_FAIL;
    int xx;

    if (*fileName == '/') {
	fn = rpmGenPath(fl->buildRoot, NULL, fileName);
	absolute = 1;
    } else
	fn = rpmGenPath("%{builddir}", "%{?buildsubdir}", fileName);

    switch (tag) {
    default:
	rpmlog(RPMLOG_ERR, _("%s: can't load unknown tag (%d).\n"),
		fn, tag);
	goto exit;
	break;
    case RPMTAG_PUBKEYS: {
	if ((xx = pgpReadPkts(fn, &pkt, (size_t *)&pktlen)) <= 0) {
	    rpmlog(RPMLOG_ERR, _("%s: public key read failed.\n"), fn);
	    goto exit;
	}
	if (xx != PGPARMOR_PUBKEY) {
	    rpmlog(RPMLOG_ERR, _("%s: not an armored public key.\n"), fn);
	    goto exit;
	}
	apkt = pgpArmorWrap(PGPARMOR_PUBKEY, pkt, pktlen);
	break;
    }
    }

    if (!apkt) {
	rpmlog(RPMLOG_ERR, _("%s: failed to encode\n"), fn);
	goto exit;
    }

    headerPutString(pkg->header, tag, apkt);
    rc = RPMRC_OK;

    if (absolute)
	rc = addFile(fl, fn, NULL);

exit:
    free(apkt);
    free(pkt);
    free(fn);
    if (rc) {
	fl->processingFailed = 1;
	rc = RPMRC_FAIL;
    }
    return rc;
}

/* add a file with possible virtual attributes to the file list */
static void argvAddAttr(ARGV_t *filesp, rpmfileAttrs attrs, const char *path)
{
    char *line = NULL;

    for (VFA_t *vfa = virtualAttrs; vfa->attribute != NULL; vfa++) {
	if (vfa->flag & attrs)
	    line = rstrscat(&line, vfa->attribute, " ", NULL);
    }
    line = rstrscat(&line, path, NULL);
    argvAdd(filesp, line);
    free(line);
}

#ifdef HAVE_LIBDW
/* How build id links are generated.  See macros.in for description.  */
#define BUILD_IDS_NONE     0
#define BUILD_IDS_ALLDEBUG 1
#define BUILD_IDS_SEPARATE 2
#define BUILD_IDS_COMPAT   3

static int addNewIDSymlink(ARGV_t *files,
			   char *targetpath, char *idlinkpath,
			   int isDbg, int *dups)
{
    const char *linkerr = _("failed symlink");
    int rc = 0;
    int nr = 0;
    int exists = 0;
    char *origpath, *linkpath;

    if (isDbg)
	rasprintf(&linkpath, "%s.debug", idlinkpath);
    else
	linkpath = idlinkpath;
    origpath = linkpath;

    while (faccessat(AT_FDCWD, linkpath, F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
        /* We don't care about finding dups for compat links, they are
	   OK as is.  Otherwise we will need to double check if
	   existing link points to the correct target. */
	if (dups == NULL)
	  {
	    exists = 1;
	    break;
	  }

	char ltarget[PATH_MAX];
	ssize_t llen;
	/* In short-circuited builds the link might already exist  */
	if ((llen = readlink(linkpath, ltarget, sizeof(ltarget)-1)) != -1) {
	    ltarget[llen] = '\0';
	    if (rstreq(ltarget, targetpath)) {
		exists = 1;
		break;
	    }
	}

	if (nr > 0)
	    free(linkpath);
	nr++;
	rasprintf(&linkpath, "%s.%d%s", idlinkpath, nr,
		  isDbg ? ".debug" : "");
    }

    if (!exists && symlink(targetpath, linkpath) < 0) {
	rc = 1;
	rpmlog(RPMLOG_ERR, "%s: %s -> %s: %m\n",
	       linkerr, linkpath, targetpath);
    } else {
	argvAddAttr(files, RPMFILE_ARTIFACT, linkpath);
    }

    if (nr > 0) {
	/* Lets see why there are multiple build-ids. If the original
	   targets are hard linked, then it is OK, otherwise warn
	   something fishy is going on. Would be nice to call
	   something like eu-elfcmp to see if they are really the same
	   ELF file or not. */
	struct stat st1, st2;
	if (stat (origpath, &st1) != 0) {
	    rpmlog(RPMLOG_WARNING, _("Duplicate build-id, stat %s: %m\n"),
		   origpath);
	} else if (stat (linkpath, &st2) != 0) {
	    rpmlog(RPMLOG_WARNING, _("Duplicate build-id, stat %s: %m\n"),
		   linkpath);
	} else if (!(S_ISREG(st1.st_mode) && S_ISREG(st2.st_mode)
		  && st1.st_nlink > 1 && st2.st_nlink == st1.st_nlink
		  && st1.st_ino == st2.st_ino && st1.st_dev == st2.st_dev)) {
	    char *rpath1 = realpath(origpath, NULL);
	    char *rpath2 = realpath(linkpath, NULL);
	    rpmlog(RPMLOG_WARNING, _("Duplicate build-ids %s and %s\n"),
		   rpath1, rpath2);
	    free(rpath1);
	    free(rpath2);
	}
    }

    if (isDbg)
	free(origpath);
    if (nr > 0)
	free(linkpath);
    if (dups != NULL)
      *dups = nr;

    return rc;
}

static int haveModinfo(Elf *elf)
{
    Elf_Scn * scn = NULL;
    size_t shstrndx;
    int have_modinfo = 0;
    const char *sname;

    if (elf_getshdrstrndx(elf, &shstrndx) == 0) {
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
	    GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
	    if (shdr == NULL)
		continue;
	    sname = elf_strptr(elf, shstrndx, shdr->sh_name);
	    if (sname && rstreq(sname, ".modinfo")) {
		have_modinfo = 1;
		break;
	    }
	}
    }
    return have_modinfo;
}

static int generateBuildIDs(FileList fl, ARGV_t *files)
{
    int rc = 0;
    int i;
    FileListRec flp;
    char **ids = NULL;
    char **paths = NULL;
    size_t nr_ids, allocated;
    nr_ids = allocated = 0;

    /* How are we supposed to create the build-id links?  */
    char *build_id_links_macro = rpmExpand("%{?_build_id_links}", NULL);
    int build_id_links;
    if (*build_id_links_macro == '\0') {
	rpmlog(RPMLOG_WARNING,
	       _("_build_id_links macro not set, assuming 'compat'\n"));
	build_id_links = BUILD_IDS_COMPAT;
    } else if (strcmp(build_id_links_macro, "none") == 0) {
	build_id_links = BUILD_IDS_NONE;
    } else if (strcmp(build_id_links_macro, "alldebug") == 0) {
	build_id_links = BUILD_IDS_ALLDEBUG;
    } else if (strcmp(build_id_links_macro, "separate") == 0) {
	build_id_links = BUILD_IDS_SEPARATE;
    } else if (strcmp(build_id_links_macro, "compat") == 0) {
	build_id_links = BUILD_IDS_COMPAT;
    } else {
	rc = 1;
	rpmlog(RPMLOG_ERR,
	       _("_build_id_links macro set to unknown value '%s'\n"),
	       build_id_links_macro);
	build_id_links = BUILD_IDS_NONE;
    }
    free(build_id_links_macro);

    if (build_id_links == BUILD_IDS_NONE || rc != 0)
	return rc;

    /* Historically we have only checked build_ids when __debug_package
       was defined. So don't terminate the build if __debug_package is
       unset, even when _missing_build_ids_terminate_build is. */
    int terminate = (rpmExpandNumeric("%{?_missing_build_ids_terminate_build}")
		     && rpmExpandNumeric("%{?__debug_package}"));

    /* Collect and check all build-ids for ELF files in this package.  */
    int needMain = 0;
    int needDbg = 0;
    for (i = 0, flp = fl->files.recs; i < fl->files.used; i++, flp++) {
	struct stat sbuf;
	if (lstat(flp->diskPath, &sbuf) == 0 && S_ISREG (sbuf.st_mode)) {
	    /* We determine whether this is a main or
	       debug ELF based on path.  */
	    int isDbg = strncmp (flp->cpioPath,
				 DEBUG_LIB_PREFIX, strlen (DEBUG_LIB_PREFIX)) == 0;

	    /* For the main package files mimic what find-debuginfo.sh does.
	       Only check build-ids for executable files. Debug files are
	       always non-executable. */
	    if (!isDbg
		&& (sbuf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
	      continue;

	    int fd = open (flp->diskPath, O_RDONLY);
	    if (fd >= 0) {
		/* Only real ELF files, that are ET_EXEC, ET_DYN or
		   kernel modules (ET_REL files with .modinfo section)
		   should have build-ids. */
		GElf_Ehdr ehdr;
#ifdef HAVE_DWELF_ELF_BEGIN
		Elf *elf = dwelf_elf_begin(fd);
#else
		Elf *elf = elf_begin (fd, ELF_C_READ, NULL);
#endif
		if (elf != NULL && elf_kind(elf) == ELF_K_ELF
		    && gelf_getehdr(elf, &ehdr) != NULL
		    && (ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN
			|| (ehdr.e_type == ET_REL && haveModinfo(elf)))) {
		    const void *build_id;
		    ssize_t len = dwelf_elf_gnu_build_id (elf, &build_id);
		    /* len == -1 means error. Zero means no
		       build-id. We want at least a length of 2 so we
		       have at least a xx/yy (hex) dir/file. But
		       reasonable build-ids are between 16 bytes (md5
		       is 128 bits) and 64 bytes (largest sha3 is 512
		       bits), common is 20 bytes (sha1 is 160 bits). */
		    if (len >= 16 && len <= 64) {
			int addid = 0;
			if (isDbg) {
			    needDbg = 1;
			    addid = 1;
			}
			else if (build_id_links != BUILD_IDS_ALLDEBUG) {
			    needMain = 1;
			    addid = 1;
			}
			if (addid) {
			    const unsigned char *p = (const unsigned char *)build_id;
			    const unsigned char *end = p + len;
			    char *id_str;
			    if (allocated <= nr_ids) {
				allocated += 16;
				paths = xrealloc (paths,
						  allocated * sizeof(char *));
				ids = xrealloc (ids,
						allocated * sizeof(char *));
			    }

			    paths[nr_ids] = xstrdup(flp->cpioPath);
			    id_str = ids[nr_ids] = (char *)xmalloc(2 * len + 1);
			    while (p < end)
				id_str += sprintf(id_str, "%02x",
						  (unsigned)*p++);
			    *id_str = '\0';
			    nr_ids++;
			}
		    } else {
			if (len < 0) {
			    rpmlog(terminate ? RPMLOG_ERR : RPMLOG_WARNING,
				   _("error reading build-id in %s: %s\n"),
				   flp->diskPath, elf_errmsg (-1));
			} else if (len == 0) {
			      rpmlog(terminate ? RPMLOG_ERR : RPMLOG_WARNING,
				     _("Missing build-id in %s\n"),
				     flp->diskPath);
			} else {
			    rpmlog(terminate ? RPMLOG_ERR : RPMLOG_WARNING,
				   (len < 16
				    ? _("build-id found in %s too small\n")
				    : _("build-id found in %s too large\n")),
				   flp->diskPath);
			}
			if (terminate)
			    rc = 1;
		    }
		}
		elf_end (elf);
		close (fd);
	    }
	}
    }

    /* Process and clean up all build-ids.  */
    if (nr_ids > 0) {
	const char *errdir = _("failed to create directory");
	char *mainiddir = NULL;
	char *debugiddir = NULL;
	if (rc == 0) {
	    char *attrstr;
	    /* Add .build-id directories to hold the subdirs/symlinks.  */

	    mainiddir = rpmGetPath(fl->buildRoot, BUILD_ID_DIR, NULL);
	    debugiddir = rpmGetPath(fl->buildRoot, DEBUG_ID_DIR, NULL);

	    /* Make sure to reset all file flags to defaults.  */
	    attrstr = mkattr();
	    argvAdd(files, attrstr);
	    free (attrstr);

	    /* Supported, but questionable.  */
	    if (needMain && needDbg)
		rpmlog(RPMLOG_WARNING,
		       _("Mixing main ELF and debug files in package\n"));

	    if (needMain) {
		if ((rc = rpmioMkpath(mainiddir, 0755, -1, -1)) != 0) {
		    rpmlog(RPMLOG_ERR, "%s %s: %m\n", errdir, mainiddir);
		} else {
		    argvAddAttr(files, RPMFILE_DIR|RPMFILE_ARTIFACT, mainiddir);
		}
	    }

	    if (rc == 0 && needDbg) {
		if ((rc = rpmioMkpath(debugiddir, 0755, -1, -1)) != 0) {
		    rpmlog(RPMLOG_ERR, "%s %s: %m\n", errdir, debugiddir);
		} else {
		    argvAddAttr(files, RPMFILE_DIR|RPMFILE_ARTIFACT, debugiddir);
		}
	    }
	}

	/* In case we need ALLDEBUG links we might need the vra as
	   tagged onto the .debug file name. */
	char *vra = NULL;
	if (rc == 0 && needDbg && build_id_links == BUILD_IDS_ALLDEBUG) {
	    int unique_debug_names =
		rpmExpandNumeric("%{?_unique_debug_names}");
	    if (unique_debug_names == 1)
		vra = rpmExpand("-%{VERSION}-%{RELEASE}.%{_arch}", NULL);
	}

	/* Now add a subdir and symlink for each buildid found.  */
	for (i = 0; i < nr_ids; i++) {
	    /* Don't add anything more when an error occurred. But do
	       cleanup.  */
	    if (rc == 0) {
		int isDbg = strncmp (paths[i], DEBUG_LIB_PREFIX,
				     strlen (DEBUG_LIB_PREFIX)) == 0;

		char *buildidsubdir;
		char subdir[4];
		subdir[0] = '/';
		subdir[1] = ids[i][0];
		subdir[2] = ids[i][1];
		subdir[3] = '\0';
		if (isDbg)
		    buildidsubdir = rpmGetPath(debugiddir, subdir, NULL);
		else
		    buildidsubdir = rpmGetPath(mainiddir, subdir, NULL);
		/* We only need to create and add the subdir once. */
		int addsubdir = access (buildidsubdir, F_OK) == -1;
		if (addsubdir
		    && (rc = rpmioMkpath(buildidsubdir, 0755, -1, -1)) != 0) {
		    rpmlog(RPMLOG_ERR, "%s %s: %m\n", errdir, buildidsubdir);
		} else {
		    if (addsubdir)
		       argvAddAttr(files, RPMFILE_DIR|RPMFILE_ARTIFACT, buildidsubdir);
		    if (rc == 0) {
			const char *linkpattern, *targetpattern;
			char *linkpath, *targetpath;
			int dups = 0;
			if (isDbg) {
			    linkpattern = "%s/%s";
			    targetpattern = "../../../../..%s";
			} else {
			    linkpattern = "%s/%s";
			    targetpattern = "../../../..%s";
			}
			rasprintf(&linkpath, linkpattern,
				  buildidsubdir, &ids[i][2]);
			rasprintf(&targetpath, targetpattern, paths[i]);
			rc = addNewIDSymlink(files, targetpath, linkpath,
					     isDbg, &dups);

			/* We might want to have a link from the debug
			   build_ids dir to the main one. We create it
			   when we are creating compat links or doing
			   an old style alldebug build-ids package. In
			   the first case things are simple since we
			   just link to the main build-id symlink. The
			   second case is a bit tricky, since we
			   cannot be 100% sure the file names in the
			   main and debug package match. Currently
			   they do, but when creating parallel
			   installable debuginfo packages they might
			   not (in that case we might have to also
			   strip the nvr from the debug name).

			   In general either method is discouraged
                           since it might create dangling symlinks if
                           the package versions get out of sync.  */
			if (rc == 0 && isDbg
			    && build_id_links == BUILD_IDS_COMPAT) {
			    /* buildidsubdir already points to the
			       debug buildid. We just need to setup
			       the symlink to the main one. There
			       might be duplicate IDs, those are found
			       by the addNewIDSymlink above. Target
			       the last found duplicate, if any. */
			    free(linkpath);
			    free(targetpath);
			    if (dups == 0)
			      {
				rasprintf(&linkpath, "%s/%s",
					  buildidsubdir, &ids[i][2]);
				rasprintf(&targetpath,
					  "../../../.build-id%s/%s",
					  subdir, &ids[i][2]);
			      }
			    else
			      {
				rasprintf(&linkpath, "%s/%s.%d",
					  buildidsubdir, &ids[i][2], dups);
				rasprintf(&targetpath,
					  "../../../.build-id%s/%s.%d",
					  subdir, &ids[i][2], dups);
			      }
			    rc = addNewIDSymlink(files, targetpath, linkpath,
						 0, NULL);
			}

			if (rc == 0 && isDbg
			    && build_id_links == BUILD_IDS_ALLDEBUG) {
			    /* buildidsubdir already points to the
			       debug buildid. We do have to figure out
			       the main ELF file though (which is most
			       likely not in this package). Guess we
			       can find it by stripping the
			       /usr/lib/debug path and .debug
			       prefix. Which might not really be
			       correct if there was a more involved
			       transformation (for example for
			       parallel installable debuginfo
			       packages), but then we shouldn't be
			       using ALLDEBUG in the first place.
			       Also ignore things like .dwz multifiles
			       which don't end in ".debug". */
			    int pathlen = strlen(paths[i]);
			    int debuglen = strlen(".debug");
			    int prefixlen = strlen(DEBUG_LIB_DIR);
			    int vralen = vra == NULL ? 0 : strlen(vra);
			    if (pathlen > prefixlen + debuglen + vralen
				&& strcmp ((paths[i] + pathlen - debuglen),
					   ".debug") == 0) {
				free(linkpath);
				free(targetpath);
				char *targetstr = xstrdup (paths[i]
							   + prefixlen);
				int targetlen = pathlen - prefixlen;
				int targetend = targetlen - debuglen - vralen;
				targetstr[targetend] = '\0';
				rasprintf(&linkpath, "%s/%s",
					  buildidsubdir, &ids[i][2]);
				rasprintf(&targetpath, "../../../../..%s",
					  targetstr);
				rc = addNewIDSymlink(files, targetpath,
						     linkpath, 0, &dups);
				free(targetstr);
			    }
			}
			free(linkpath);
			free(targetpath);
		    }
		}
		free(buildidsubdir);
	    }
	    free(paths[i]);
	    free(ids[i]);
	}
	free(mainiddir);
	free(debugiddir);
	free(vra);
	free(paths);
	free(ids);
    }
    return rc;
}
#endif

/**
 * Add a file to a binary package.
 * @param pkg
 * @param fl		package file tree walk data
 * @param fileName	file to add
 * @param doGlob	expand file as a glob pattern
 * @return		RPMRC_OK on success
 */
static rpmRC processBinaryFile(Package pkg, FileList fl, const char * fileName,
			       int doGlob)
{
    char *diskPath = NULL;
    rpmRC rc = RPMRC_OK;
    size_t fnlen = strlen(fileName);
    int trailing_slash = (fnlen > 0 && fileName[fnlen-1] == '/');
    ARGV_t argv = NULL;
    int argc = 0;
    int i;

    /* XXX differentiate other directories from explicit %dir */
    if (trailing_slash && !fl->cur.isDir)
	fl->cur.isDir = -1;
    
    /* Check that file starts with leading "/" */
    if (*fileName != '/') {
	rpmlog(RPMLOG_ERR, _("File needs leading \"/\": %s\n"), fileName);
    	rc = RPMRC_FAIL;
    	goto exit;
    }
    
    /* Copy file name or glob pattern removing multiple "/" chars. */
    /*
     * Note: rpmCleanPath should guarantee a "canonical" path. That means
     * that the following pathologies should be weeded out:
     *		//bin//sh
     *		//usr//bin/
     *		/.././../usr/../bin//./sh
     */
    diskPath = rpmCleanPath(rstrscat(NULL, fl->buildRoot, "/", fileName, NULL));

    /* Arrange trailing slash on directories */
    if (fl->cur.isDir)
	diskPath = rstrcat(&diskPath, "/");

    if (fl->cur.devtype)
	doGlob = 0;

    if (!doGlob) {
	rc = addFile(fl, diskPath, NULL);
	goto exit;
    }

    if (rpmGlobPath(diskPath, RPMGLOB_NOCHECK, &argc, &argv))
	goto exit;

    for (i = 0; i < argc; i++)
	rc = addFile(fl, argv[i], NULL);
    argvFree(argv);

exit:
    free(diskPath);
    if (rc) {
	fl->processingFailed = 1;
	rc = RPMRC_FAIL;
    }
    return rc;
}

int readManifest(rpmSpec spec, const char *path, const char *descr, int flags,
		ARGV_t *avp, StringBuf *sbp)
{
    char *fn, buf[BUFSIZ];
    FILE *fd = NULL;
    int lineno = 0;
    int nlines = -1;

    if (*path == '/') {
	fn = rpmGetPath(path, NULL);
    } else {
	fn = rpmGenPath("%{builddir}", "%{?buildsubdir}", path);
    }
    fd = fopen(fn, "r");

    if (fd == NULL) {
	rpmlog(RPMLOG_ERR, _("Could not open %s file %s: %m\n"), descr, fn);
	goto exit;
    }

    rpmPushMacroFlags(spec->macros, "__file_name", NULL, fn, RMIL_SPEC, RPMMACRO_LITERAL);

    nlines = 0;
    while (fgets(buf, sizeof(buf), fd)) {
	char *expanded = NULL;
	lineno++;
	if ((flags & STRIP_COMMENTS) && handleComments(buf))
	    continue;
	if (specExpand(spec, lineno, buf, &expanded))
	    goto exit;
	if (avp)
	    argvAdd(avp, expanded);
	if (sbp)
	    appendStringBufAux(*sbp, expanded, (flags & STRIP_TRAILINGSPACE));
	free(expanded);
	nlines++;
    }

    if (nlines == 0) {
	int emptyok = (flags & ALLOW_EMPTY);
	rpmlog(emptyok ? RPMLOG_WARNING : RPMLOG_ERR,
	       _("Empty %s file %s\n"), descr, fn);
	if (!emptyok)
	    nlines = -1;
    }

exit:
    if (fd) {
	fclose(fd);
	rpmPopMacro(spec->macros, "__file_name");
    }
    free(fn);

    return nlines;
}

static rpmRC readFilesManifest(rpmSpec spec, Package pkg, const char *path)
{
    int nlines = 0;
    int flags = STRIP_COMMENTS | STRIP_TRAILINGSPACE;

    if (!rpmExpandNumeric("%{?_empty_manifest_terminate_build}"))
	flags |= ALLOW_EMPTY;

    /* XXX unmask %license while parsing files manifest*/
    rpmPushMacroFlags(spec->macros, "license", NULL, "%license", RMIL_SPEC, RPMMACRO_LITERAL);

    nlines = readManifest(spec, path, "%files", flags, &(pkg->fileList), NULL);

    rpmPopMacro(NULL, "license");

    return (nlines >= 0) ? RPMRC_OK : RPMRC_FAIL;
}

static char * getSpecialDocDir(Header h, rpmFlags sdtype)
{
    const char *errstr = NULL;
    const char *dirtype = (sdtype == RPMFILE_DOC) ? "docdir" : "licensedir";
    const char *fmt_default = "%{NAME}-%{VERSION}";
    char *fmt_macro = rpmExpand("%{?_docdir_fmt}", NULL);
    char *fmt = NULL; 
    char *res = NULL;

    if (fmt_macro && strlen(fmt_macro) > 0) {
	fmt = headerFormat(h, fmt_macro, &errstr);
	if (errstr) {
	    rpmlog(RPMLOG_WARNING, _("illegal _docdir_fmt %s: %s\n"),
		   fmt_macro, errstr);
	}
    }

    if (fmt == NULL)
	fmt = headerFormat(h, fmt_default, &errstr);

    res = rpmGetPath("%{_", dirtype, "}/", fmt, NULL);

    free(fmt);
    free(fmt_macro);
    return res;
}

static specialDir specialDirNew(Header h, rpmFlags sdtype)
{
    specialDir sd = (specialDir)xcalloc(1, sizeof(*sd));

    sd->entriesCount = 0;
    sd->entriesAlloced = 10;
    sd->entries = (struct FileEntries_s *)xcalloc(sd->entriesAlloced, sizeof(*(sd->entries)));

    sd->dirname = getSpecialDocDir(h, sdtype);
    sd->sdtype = sdtype;
    return sd;
}

static void addSpecialFile(specialDir sd, const char *path, FileEntry cur,
    FileEntry def)
{
    argvAdd(&sd->files, path);

    if (sd->entriesCount >= sd->entriesAlloced) {
	sd->entriesAlloced <<= 1;
	sd->entries = xrealloc(sd->entries, sd->entriesAlloced *
	    sizeof(sd->entries[0]));
    }

    copyFileEntry(cur, &sd->entries[sd->entriesCount].curEntry);
    copyFileEntry(def, &sd->entries[sd->entriesCount].defEntry);
    sd->entriesCount++;
}

static specialDir specialDirFree(specialDir sd)
{
    int i = 0;

    if (sd) {
	argvFree(sd->files);
	free(sd->dirname);
	for (i = 0; i < sd->entriesCount; i++) {
	    FileEntryFree(&sd->entries[i].curEntry);
	    FileEntryFree(&sd->entries[i].defEntry);
	}
	free(sd->entries);
	free(sd);
    }
    return NULL;
}

static void processSpecialDir(rpmSpec spec, Package pkg, FileList fl,
				specialDir sd, int install, int test)
{
    const char *sdenv = (sd->sdtype == RPMFILE_DOC) ? "DOCDIR" : "LICENSEDIR";
    const char *sdname = (sd->sdtype == RPMFILE_DOC) ? "%doc" : "%license";
    char *mkdocdir = rpmExpand("%{__mkdir_p} $", sdenv, NULL);
    StringBuf docScript = newStringBuf();
    int count = sd->entriesCount;
    char *basepath = rpmGenPath(spec->rootDir, "%{builddir}", "%{?buildsubdir}");
    ARGV_t *files = (ARGV_t *)xmalloc(sizeof(*files) * count);
    int i, j;

    /* Glob and copy file entries from builddir to buildroot */
    appendStringBuf(docScript, sdenv);
    appendStringBuf(docScript, "=$RPM_BUILD_ROOT");
    appendLineStringBuf(docScript, sd->dirname);
    appendLineStringBuf(docScript, "export LC_ALL=" C_LOCALE);
    appendStringBuf(docScript, "export ");
    appendLineStringBuf(docScript, sdenv);
    appendLineStringBuf(docScript, mkdocdir);
    for (i = 0; i < count; i++) {
	char *origfile = rpmCleanPath(rstrscat(NULL, basepath, "/",
					       sd->files[i], NULL));
	ARGV_t argv = NULL;
	int argc = 0;
	if (rpmGlobPath(origfile, RPMGLOB_NOCHECK, &argc, &argv) == 0) {
	    for (j = 0; j < argc; j++) {
		appendStringBuf(docScript, "cp -pr '");
		appendStringBuf(docScript, argv[j]);
		appendStringBuf(docScript, "' $");
		appendStringBuf(docScript, sdenv);
		appendLineStringBuf(docScript, " ||:");
	    }
	}
	free(origfile);
	files[i] = argv;
    }
    free(basepath);
    if (install) {
	if (doScript(spec, RPMBUILD_STRINGBUF, sdname,
			    getStringBuf(docScript), test, NULL)) {
	    fl->processingFailed = 1;
	}
    }

    /* Add copied files in buildroot to file list */
    for (i = 0; i < count; i++) {
	char *newfile;

	FileEntryFree(&fl->cur);
	FileEntryFree(&fl->def);
	copyFileEntry(&sd->entries[i].curEntry, &fl->cur);
	copyFileEntry(&sd->entries[i].defEntry, &fl->def);

	for (ARGV_const_t fn = files[i]; fn && *fn; fn++) {
	    rasprintf(&newfile, "%s/%s", sd->dirname, basename(*fn));
	    processBinaryFile(pkg, fl, newfile, 0);
	    free(newfile);
	}
	argvFree(files[i]);
    }
    free(files);

    FileEntryFree(&fl->cur);
    FileEntryFree(&fl->def);
    copyFileEntry(&sd->entries[0].defEntry, &fl->def);
    copyFileEntry(&sd->entries[0].curEntry, &fl->cur);
    fl->cur.isDir = 1;
    (void) processBinaryFile(pkg, fl, sd->dirname, 1);

    freeStringBuf(docScript);
    free(mkdocdir);
}


/* Resets the default settings for files in the package list.
   Used in processPackageFiles whenever a new set of files is added. */
static void resetPackageFilesDefaults (struct FileList_s *fl,
				       rpmBuildPkgFlags pkgFlags)
{
    struct AttrRec_s root_ar = { 0, 0, 0, 0, 0, 0 };

    root_ar.ar_user = rpmstrPoolId(fl->pool, UID_0_USER, 1);
    root_ar.ar_group = rpmstrPoolId(fl->pool, GID_0_GROUP, 1);
    dupAttrRec(&root_ar, &fl->def.ar);	/* XXX assume %defattr(-,root,root) */

    fl->def.verifyFlags = RPMVERIFY_ALL;

    fl->pkgFlags = pkgFlags;
}

/* Adds the given fileList to the package. If fromSpecFileList is not zero
   then the specialDirs are also filled in and the files are sanitized
   through processBinaryFile(). Otherwise no special files are processed
   and the files are added directly through addFile().  */
static void addPackageFileList (struct FileList_s *fl, Package pkg,
				ARGV_t *fileList,
				specialDir *specialDoc, specialDir *specialLic,
				int fromSpecFileList)
{
    ARGV_t fileNames = NULL;
    for (ARGV_const_t fp = *fileList; *fp != NULL; fp++) {
	char buf[strlen(*fp) + 1];
	const char *s = *fp;
	SKIPSPACE(s);
	if (*s == '\0')
	    continue;
	fileNames = argvFree(fileNames);
	rstrlcpy(buf, s, sizeof(buf));
	
	/* Reset for a new line in %files */
	FileEntryFree(&fl->cur);

	/* turn explicit flags into %def'd ones (gosh this is hacky...) */
	fl->cur.specdFlags = ((unsigned)fl->def.specdFlags) >> 8;
	fl->cur.verifyFlags = fl->def.verifyFlags;

	if (parseForVerify(buf, 0, &fl->cur) ||
	    parseForVerify(buf, 1, &fl->def) ||
	    parseForAttr(fl->pool, buf, 0, &fl->cur) ||
	    parseForAttr(fl->pool, buf, 1, &fl->def) ||
	    parseForDev(buf, &fl->cur) ||
	    parseForConfig(buf, &fl->cur) ||
	    parseForLang(buf, &fl->cur) ||
	    parseForCaps(buf, &fl->cur) ||
	    parseForSimple(buf, &fl->cur, &fileNames))
	{
	    fl->processingFailed = 1;
	    continue;
	}

	for (ARGV_const_t fn = fileNames; fn && *fn; fn++) {

	    /* For file lists that don't come from a spec file list
	       processing is easy. There are no special files and the
	       file names don't need to be adjusted. */
	    if (!fromSpecFileList) {
	        if (fl->cur.attrFlags & RPMFILE_SPECIALDIR
		    || fl->cur.attrFlags & RPMFILE_DOCDIR
		    || fl->cur.attrFlags & RPMFILE_PUBKEY) {
			rpmlog(RPMLOG_ERR,
			       _("Special file in generated file list: %s\n"),
			       *fn);
			fl->processingFailed = 1;
			continue;
		}
		if (fl->cur.attrFlags & RPMFILE_DIR)
		    fl->cur.isDir = 1;
		addFile(fl, *fn, NULL);
		continue;
	    }

	    /* File list does come from the spec, try to detect special
	       files and adjust the actual file names.  */
	    if (fl->cur.attrFlags & RPMFILE_SPECIALDIR) {
		rpmFlags oattrs = (fl->cur.attrFlags & ~RPMFILE_SPECIALDIR);
		specialDir *sdp = NULL;
		if (oattrs == RPMFILE_DOC) {
		    sdp = specialDoc;
		} else if (oattrs == RPMFILE_LICENSE) {
		    sdp = specialLic;
		}

		if (sdp == NULL || **fn == '/') {
		    rpmlog(RPMLOG_ERR,
			   _("Can't mix special %s with other forms: %s\n"),
			   (oattrs & RPMFILE_DOC) ? "%doc" : "%license", *fn);
		    fl->processingFailed = 1;
		    continue;
		}

		/* save attributes on first special doc/license for later use */
		if (*sdp == NULL) {
		    *sdp = specialDirNew(pkg->header, oattrs);
		}
		addSpecialFile(*sdp, *fn, &fl->cur, &fl->def);
		continue;
	    }

	    /* this is now an artificial limitation */
	    if (fn != fileNames) {
		rpmlog(RPMLOG_ERR, _("More than one file on a line: %s\n"),*fn);
		fl->processingFailed = 1;
		continue;
	    }

	    if (fl->cur.attrFlags & RPMFILE_DOCDIR) {
		argvAdd(&(fl->docDirs), *fn);
	    } else if (fl->cur.attrFlags & RPMFILE_PUBKEY) {
		(void) processMetadataFile(pkg, fl, *fn, RPMTAG_PUBKEYS);
	    } else {
		if (fl->cur.attrFlags & RPMFILE_DIR)
		    fl->cur.isDir = 1;
		(void) processBinaryFile(pkg, fl, *fn, 1);
	    }
	}

	if (fl->cur.caps)
	    fl->haveCaps = 1;
    }
    argvFree(fileNames);
}

static rpmRC processPackageFiles(rpmSpec spec, rpmBuildPkgFlags pkgFlags,
				 Package pkg, int didInstall, int test)
{
    struct FileList_s fl;
    specialDir specialDoc = NULL;
    specialDir specialLic = NULL;

    pkg->cpioList = NULL;

    for (ARGV_const_t fp = pkg->fileFile; fp && *fp != NULL; fp++) {
	if (readFilesManifest(spec, pkg, *fp))
	    return RPMRC_FAIL;
    }
    /* Init the file list structure */
    memset(&fl, 0, sizeof(fl));

    fl.pool = rpmstrPoolLink(spec->pool);
    /* XXX spec->buildRoot == NULL, then xstrdup("") is returned */
    fl.buildRoot = rpmGenPath(spec->rootDir, spec->buildRoot, NULL);
    fl.buildRootLen = strlen(fl.buildRoot);

    resetPackageFilesDefaults (&fl, pkgFlags);

    {	char *docs = rpmGetPath("%{?__docdir_path}", NULL);
	argvSplit(&fl.docDirs, docs, ":");
	free(docs);
    }

    addPackageFileList (&fl, pkg, &pkg->fileList,
			&specialDoc, &specialLic, 1);

    /* Now process special docs and licenses if present */
    if (specialDoc)
	processSpecialDir(spec, pkg, &fl, specialDoc, didInstall, test);
    if (specialLic)
	processSpecialDir(spec, pkg, &fl, specialLic, didInstall, test);
    
    if (fl.processingFailed)
	goto exit;

#ifdef HAVE_LIBDW
{
    /* Check build-ids and add build-ids links for files to package list. */
    const char *arch = headerGetString(pkg->header, RPMTAG_ARCH);
    if (rpmExpandNumeric("%{?__debug_package}") && !rstreq(arch, "noarch")) {
	/* Go through the current package list and generate a files list. */
	ARGV_t idFiles = NULL;
	if (generateBuildIDs (&fl, &idFiles) != 0) {
	    rpmlog(RPMLOG_ERR, _("Generating build-id links failed\n"));
	    fl.processingFailed = 1;
	    argvFree(idFiles);
	    goto exit;
	}

	if (idFiles != NULL) {
	    resetPackageFilesDefaults (&fl, pkgFlags);
	    addPackageFileList (&fl, pkg, &idFiles, NULL, NULL, 0);
	}
	argvFree(idFiles);

	if (fl.processingFailed)
	    goto exit;
    }
}
#endif

    /* Verify that file attributes scope over hardlinks correctly. */
    if (checkHardLinks(&fl.files))
	(void) rpmlibNeedsFeature(pkg, "PartialHardlinkSets", "4.0.4-1");

    genCpioListAndHeader(&fl, spec, pkg, 0);

exit:
    FileListFree(&fl);
    specialDirFree(specialDoc);
    specialDirFree(specialLic);
    return fl.processingFailed ? RPMRC_FAIL : RPMRC_OK;
}

rpmRC processSourceFiles(rpmSpec spec, rpmBuildPkgFlags pkgFlags)
{
    struct Source *srcPtr;
    struct FileList_s fl;
    ARGV_t files = NULL;
    Package pkg;
    Package sourcePkg = spec->sourcePackage;
    static char *_srcdefattr;
    static int oneshot;

    if (!oneshot) {
	_srcdefattr = rpmExpand("%{?_srcdefattr}", NULL);
	if (_srcdefattr && !*_srcdefattr)
	    _srcdefattr = _free(_srcdefattr);
	oneshot = 1;
    }

    /* Construct the file list and source entries */
    argvAdd(&files, spec->specFile);
    for (srcPtr = spec->sources; srcPtr != NULL; srcPtr = srcPtr->next) {
	char * sfn = rpmGetPath( ((srcPtr->flags & RPMBUILD_ISNO) ? "!" : ""),
				srcPtr->path, NULL);
	argvAdd(&files, sfn);
	free(sfn);
    }

    for (pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	for (srcPtr = pkg->icon; srcPtr != NULL; srcPtr = srcPtr->next) {
	    char * sfn;
	    sfn = rpmGetPath( ((srcPtr->flags & RPMBUILD_ISNO) ? "!" : ""),
				srcPtr->path, NULL);
	    argvAdd(&files, sfn);
	    free(sfn);
	}
    }

    sourcePkg->cpioList = NULL;

    /* Init the file list structure */
    memset(&fl, 0, sizeof(fl));
    fl.pool = rpmstrPoolLink(spec->pool);
    if (_srcdefattr) {
	char *a = rstrscat(NULL, "%defattr ", _srcdefattr, NULL);
	parseForAttr(fl.pool, a, 1, &fl.def);
	free(a);
    }
    fl.files.alloced = spec->numSources + 1;
    fl.files.recs = (FileListRec)xcalloc(fl.files.alloced, sizeof(*fl.files.recs));
    fl.pkgFlags = pkgFlags;

    for (ARGV_const_t fp = files; *fp != NULL; fp++) {
	const char *diskPath = *fp;
	char *tmp;
	FileListRec flp;

	SKIPSPACE(diskPath);
	if (! *diskPath)
	    continue;

	flp = &fl.files.recs[fl.files.used];

	/* The first source file is the spec file */
	flp->flags = (fl.files.used == 0) ? RPMFILE_SPECFILE : 0;
	/* files with leading ! are no source files */
	if (*diskPath == '!') {
	    flp->flags |= RPMFILE_GHOST;
	    diskPath++;
	}

	tmp = xstrdup(diskPath); /* basename() might modify */
	flp->diskPath = xstrdup(diskPath);
	flp->cpioPath = xstrdup(basename(tmp));
	flp->verifyFlags = RPMVERIFY_ALL;
	free(tmp);

	if (stat(diskPath, &flp->fl_st)) {
	    rpmlog(RPMLOG_ERR, _("Bad file: %s: %s\n"),
		diskPath, strerror(errno));
	    fl.processingFailed = 1;
	} else {
	    if (S_ISREG(flp->fl_mode) && flp->fl_size >= UINT32_MAX)
		fl.largeFiles = 1;
	}

	if (fl.def.ar.ar_fmodestr) {
	    flp->fl_mode &= S_IFMT;
	    flp->fl_mode |= fl.def.ar.ar_fmode;
	}

	if (fl.def.ar.ar_user) {
	    flp->uname = fl.def.ar.ar_user;
	}
	if (! flp->uname) {
	    flp->uname = rpmstrPoolId(fl.pool, UID_0_USER, 1);
	}

	if (fl.def.ar.ar_group) {
	    flp->gname = fl.def.ar.ar_group;
	}
	if (! flp->gname) {
	    flp->gname = rpmstrPoolId(fl.pool, GID_0_GROUP, 1);
	}

	flp->langs = xstrdup("");
	fl.files.used++;
    }
    argvFree(files);

    if (! fl.processingFailed) {
	if (sourcePkg->header != NULL) {
	    genCpioListAndHeader(&fl, spec, sourcePkg, 1);
	}
    }

    FileListFree(&fl);
    return fl.processingFailed ? RPMRC_FAIL : RPMRC_OK;
}

/**
 * Check packaged file list against what's in the build root.
 * @param buildRoot	path of build root
 * @param fileList	packaged file list
 * @return		-1 if skipped, 0 on OK, 1 on error
 */
static int checkFiles(const char *buildRoot, StringBuf fileList)
{
    static const char * av_ckfile[] = { "%{?__check_files}", NULL };
    StringBuf sb_stdout = NULL;
    int rc = -1;
    char * s = rpmExpand(av_ckfile[0], NULL);
    
    if (!(s && *s))
	goto exit;

    rpmlog(RPMLOG_NOTICE, _("Checking for unpackaged file(s): %s\n"), s);

    rc = rpmfcExec((ARGV_const_t)av_ckfile, fileList, &sb_stdout, 0, buildRoot);
    if (rc < 0)
	goto exit;
    
    if (sb_stdout) {
	int _unpackaged_files_terminate_build =
		rpmExpandNumeric("%{?_unpackaged_files_terminate_build}");
	const char * t = getStringBuf(sb_stdout);
	if ((*t != '\0') && (*t != '\n')) {
	    rc = (_unpackaged_files_terminate_build) ? 1 : 0;
	    rpmlog((rc ? RPMLOG_ERR : RPMLOG_WARNING),
		_("Installed (but unpackaged) file(s) found:\n%s"), t);
	}
    }
    
exit:
    freeStringBuf(sb_stdout);
    free(s);
    return rc;
}

static rpmTagVal copyTagsFromMainDebug[] = {
    RPMTAG_ARCH,
    RPMTAG_SUMMARY,
    RPMTAG_DESCRIPTION,
    RPMTAG_GROUP,
    /* see addTargets */
    RPMTAG_OS,
    RPMTAG_PLATFORM,
    RPMTAG_OPTFLAGS,
    RPMTAG_SOURCERPM,
    0
};

/* this is a hack: patch the summary and the description to include
 * the correct package name */
static void patchDebugPackageString(Package dbg, rpmTag tag, Package pkg, Package mainpkg)
{
    const char *oldname, *newname, *old, *p;
    char *oldsubst = NULL, *newsubst = NULL;
    oldname = headerGetString(mainpkg->header, RPMTAG_NAME);
    newname = headerGetString(pkg->header, RPMTAG_NAME);
    rasprintf(&oldsubst, "package %s", oldname);
    rasprintf(&newsubst, "package %s", newname);
    old = headerGetString(dbg->header, tag);
    p = old ? strstr(old, oldsubst) : NULL;
    if (p) {
	char *newval = NULL;
	rasprintf(&newval, "%.*s%s%s", (int)(p - old), old, newsubst, p + strlen(oldsubst));
	headerDel(dbg->header, tag);
	headerPutString(dbg->header, tag, newval);
	_free(newval);
    }
    _free(oldsubst);
    _free(newsubst);
}

/* Early prototype for use in filterDebuginfoPackage. */
static void addPackageDeps(Package from, Package to, enum rpmTag_e tag);

/* create a new debuginfo subpackage for package pkg from the
 * main debuginfo package */
static Package cloneDebuginfoPackage(rpmSpec spec, Package pkg, Package maindbg)
{
    Package dbg = NULL;
    char *dbgname = headerFormat(pkg->header, "%{name}-debuginfo", NULL);

    if (lookupPackage(spec, dbgname, PART_NAME|PART_QUIET, &dbg) == RPMRC_OK) {
	rpmlog(RPMLOG_WARNING, _("package %s already exists\n"), dbgname);
	goto exit;
    }

    dbg = newPackage(dbgname, spec->pool, &spec->packages);
    headerPutString(dbg->header, RPMTAG_NAME, dbgname);
    copyInheritedTags(dbg->header, pkg->header);
    headerDel(dbg->header, RPMTAG_GROUP);
    headerCopyTags(maindbg->header, dbg->header, copyTagsFromMainDebug);
    dbg->autoReq = maindbg->autoReq;
    dbg->autoProv = maindbg->autoProv;

    /* patch summary and description strings */
    patchDebugPackageString(dbg, RPMTAG_SUMMARY, pkg, spec->packages);
    patchDebugPackageString(dbg, RPMTAG_DESCRIPTION, pkg, spec->packages);

    /* Add self-provides (normally done by addTargets) */
    addPackageProvides(dbg);
    dbg->ds = rpmdsThis(dbg->header, RPMTAG_REQUIRENAME, RPMSENSE_EQUAL);

exit:
    _free(dbgname);
    return dbg;
}

/* collect the debug files for package pkg and put them into
 * a (possibly new) debuginfo subpackage */
static void filterDebuginfoPackage(rpmSpec spec, Package pkg,
				   Package maindbg, Package dbgsrc,
				   const char *buildroot,
				   const char *uniquearch)
{
    rpmfi fi;
    ARGV_t files = NULL;
    ARGV_t dirs = NULL;
    int lastdiridx = -1, dirsadded;
    char *path = NULL, *p, *pmin;
    size_t buildrootlen = strlen(buildroot);

    /* ignore noarch subpackages */
    if (rstreq(headerGetString(pkg->header, RPMTAG_ARCH), "noarch"))
	return;

    if (!uniquearch)
	uniquearch = "";

    fi = rpmfilesIter(pkg->cpioList, RPMFI_ITER_FWD);
    /* Check if the current package has files with debug info
       and add them to the file list */
    fi = rpmfiInit(fi, 0);
    while (rpmfiNext(fi) >= 0) {
	const char *name = rpmfiFN(fi);
	int namel = strlen(name);

	/* strip trailing .debug like in find-debuginfo.sh */
	if (namel > 6 && !strcmp(name + namel - 6, ".debug"))
	    namel -= 6;

	/* fileRenameMap doesn't necessarily have to be initialized */
	if (pkg->fileRenameMap) {
	    const char **names = NULL;
	    int namec = 0;
	    fileRenameHashGetEntry(pkg->fileRenameMap, name, &names, &namec, NULL);
	    if (namec) {
		if (namec > 1)
		    rpmlog(RPMLOG_WARNING, _("%s was mapped to multiple filenames"), name);
		name = *names;
		namel = strlen(name);
	    }
	}
	
	/* generate path */
	rasprintf(&path, "%s%s%.*s%s.debug", buildroot, DEBUG_LIB_DIR, namel, name, uniquearch);

	/* If that file exists we have debug information for it */
	if (access(path, F_OK) == 0) {
	    /* Append the file list preamble */
	    if (!files) {
		char *attr = mkattr();
		argvAdd(&files, attr);
		argvAddAttr(&files, RPMFILE_DIR, DEBUG_LIB_DIR);
		free(attr);
	    }

	    /* Add the files main debug-info file */
	    argvAdd(&files, path + buildrootlen);

	    /* Add the dir(s) */
	    dirsadded = 0;
	    pmin = path + buildrootlen + strlen(DEBUG_LIB_DIR);
	    while ((p = strrchr(path + buildrootlen, '/')) != NULL && p > pmin) {
		*p = 0;
		if (lastdiridx >= 0 && !strcmp(dirs[lastdiridx], path + buildrootlen))
		    break;		/* already added this one */
		argvAdd(&dirs, path + buildrootlen);
		dirsadded++;
	    }
	    if (dirsadded)
		lastdiridx = argvCount(dirs) - dirsadded;	/* remember longest dir */
	}
	path = _free(path);
    }
    rpmfiFree(fi);
    /* Exclude debug files for files which were excluded in respective non-debug package */
    for (ARGV_const_t excl = pkg->fileExcludeList; excl && *excl; excl++) {
        const char *name = *excl;

	/* generate path */
	rasprintf(&path, "%s%s%s%s.debug", buildroot, DEBUG_LIB_DIR, name, uniquearch);
	/* Exclude only debuginfo files which actually exist */
	if (access(path, F_OK) == 0) {
	    char *line = NULL;
	    rasprintf(&line, "%%exclude %s", path + buildrootlen);
	    argvAdd(&files, line);
	    _free(line);
	}
	path = _free(path);
    }

    /* add collected directories to file list */
    if (dirs) {
	int i;
	argvSort(dirs, NULL);
	for (i = 0; dirs[i]; i++) {
	    if (!i || strcmp(dirs[i], dirs[i - 1]) != 0)
		argvAddAttr(&files, RPMFILE_DIR, dirs[i]);
	}
	dirs = argvFree(dirs);
    }

    if (files) {
	/* we have collected some files. Now put them in a debuginfo
         * package. If this is not the main package, clone the main
         * debuginfo package */
	if (pkg == spec->packages)
	    maindbg->fileList = files;
	else {
	    Package dbg = cloneDebuginfoPackage(spec, pkg, maindbg);
	    dbg->fileList = files;
	    /* Recommend the debugsource package (or the main debuginfo).  */
	    addPackageDeps(dbg, dbgsrc ? dbgsrc : maindbg,
			   RPMTAG_RECOMMENDNAME);
	}
    }
}

/* add the debug dwz files to package pkg.
 * return 1 if something was added, 0 otherwise. */
static int addDebugDwz(Package pkg, char *buildroot)
{
    int ret = 0;
    char *path = NULL;
    struct stat sbuf;

    rasprintf(&path, "%s%s", buildroot, DEBUG_DWZ_DIR);
    if (lstat(path, &sbuf) == 0 && S_ISDIR(sbuf.st_mode)) {
	if (!pkg->fileList) {
	    char *attr = mkattr();
	    argvAdd(&pkg->fileList, attr);
	    argvAddAttr(&pkg->fileList, RPMFILE_DIR|RPMFILE_ARTIFACT, DEBUG_LIB_DIR);
	    free(attr);
	}
	argvAddAttr(&pkg->fileList, RPMFILE_ARTIFACT, DEBUG_DWZ_DIR);
	ret = 1;
    }
    path = _free(path);
    return ret;
}

/* add the debug source files to package pkg.
 * return 1 if something was added, 0 otherwise. */
static int addDebugSrc(Package pkg, char *buildroot)
{
    int ret = 0;
    char *path = NULL;
    DIR *d;
    struct dirent *de;

    /* not needed if we have an extra debugsource subpackage */
    if (rpmExpandNumeric("%{?_debugsource_packages}"))
	return 0;

    rasprintf(&path, "%s%s", buildroot, DEBUG_SRC_DIR);
    d = opendir(path);
    path = _free(path);
    if (d) {
	while ((de = readdir(d)) != NULL) {
	    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
		continue;
	    rasprintf(&path, "%s/%s", DEBUG_SRC_DIR, de->d_name);
	    if (!pkg->fileList) {
		char *attr = mkattr();
		argvAdd(&pkg->fileList, attr);
		free(attr);
	    }
	    argvAdd(&pkg->fileList, path);
	    path = _free(path);
	    ret = 1;
	}
	closedir(d);
    }
    return ret;
}

/* find the debugsource package, if it has been created.
 * We do this simply by searching for a package with the right name. */
static Package findDebugsourcePackage(rpmSpec spec)
{
    Package pkg = NULL;
    if (lookupPackage(spec, "debugsource", PART_SUBNAME|PART_QUIET, &pkg))
	return NULL;
    return pkg && pkg->fileList ? pkg : NULL;
}

/* find the main debuginfo package. We do this simply by
 * searching for a package with the right name. */
static Package findDebuginfoPackage(rpmSpec spec)
{
    Package pkg = NULL;
    if (lookupPackage(spec, "debuginfo", PART_SUBNAME|PART_QUIET, &pkg))
	return NULL;
    return pkg && pkg->fileList ? pkg : NULL;
}

/* add a dependency (e.g. RPMTAG_REQUIRENAME or RPMTAG_RECOMMENDNAME)
   for package "to" into package "from". */
static void addPackageDeps(Package from, Package to, enum rpmTag_e tag)
{
    const char *name;
    char *evr, *isaprov;
    name = headerGetString(to->header, RPMTAG_NAME);
    evr = headerGetAsString(to->header, RPMTAG_EVR);
    isaprov = rpmExpand(name, "%{?_isa}", NULL);
    addReqProv(from, tag, isaprov, evr, RPMSENSE_EQUAL, 0);
    free(isaprov);
    free(evr);
}

rpmRC processBinaryFiles(rpmSpec spec, rpmBuildPkgFlags pkgFlags,
			int didInstall, int test)
{
    Package pkg;
    rpmRC rc = RPMRC_OK;
    char *buildroot;
    char *uniquearch = NULL;
    Package maindbg = NULL;		/* the (existing) main debuginfo package */
    Package deplink = NULL;		/* create requires to this package */
    /* The debugsource package, if it exists, that the debuginfo package(s)
       should Recommend.  */
    Package dbgsrcpkg = NULL;
    int processDebug = rpmExpandNumeric("%{?__debug_package}");
    
#ifdef HAVE_LIBDW
    elf_version (EV_CURRENT);
#endif
    check_fileList = newStringBuf();
    buildroot = rpmGenPath(spec->rootDir, spec->buildRoot, NULL);

    if (processDebug)
	dbgsrcpkg = findDebugsourcePackage(spec);

    if (processDebug && rpmExpandNumeric("%{?_debuginfo_subpackages}")) {
	maindbg = findDebuginfoPackage(spec);
	if (maindbg) {
	    /* move debuginfo package to back */
	    if (maindbg->next) {
		Package *pp;
		/* dequeue */
		for (pp = &spec->packages; *pp != maindbg; pp = &(*pp)->next)
		    ;
		*pp = maindbg->next;
		maindbg->next = 0;
		/* enqueue at tail */
		for (; *pp; pp = &(*pp)->next)
		    ;
		*pp = maindbg;
	    }
	    /* delete unsplit file list, we will re-add files back later */
	    maindbg->fileFile = argvFree(maindbg->fileFile);
	    maindbg->fileList = argvFree(maindbg->fileList);
	    if (rpmExpandNumeric("%{?_unique_debug_names}"))
		uniquearch = rpmExpand("-%{VERSION}-%{RELEASE}.%{_arch}", NULL);
	}
    } else if (dbgsrcpkg != NULL) {
	/* We have a debugsource package, but no debuginfo subpackages.
	   The main debuginfo package should recommend the debugsource one. */
	Package dbgpkg = findDebuginfoPackage(spec);
	if (dbgpkg)
	    addPackageDeps(dbgpkg, dbgsrcpkg, RPMTAG_RECOMMENDNAME);
    }

    for (pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	char *nvr;
	const char *a;
	int header_color;
	int arch_color;

	if (pkg == maindbg) {
	    /* if there is just one debuginfo package, we put our extra stuff
	     * in it. Otherwise we put it in the main debug package */
	    Package extradbg = !maindbg->fileList && maindbg->next && !maindbg->next->next ?
		 maindbg->next : maindbg;
	    if (addDebugDwz(extradbg, buildroot))
		deplink = extradbg;
	    if (addDebugSrc(extradbg, buildroot))
		deplink = extradbg;
	    if (dbgsrcpkg != NULL)
		addPackageDeps(extradbg, dbgsrcpkg, RPMTAG_RECOMMENDNAME);
	    maindbg = NULL;	/* all normal packages processed */
	}

	if (pkg->fileList == NULL)
	    continue;

	nvr = headerGetAsString(pkg->header, RPMTAG_NVRA);
	rpmlog(RPMLOG_NOTICE, _("Processing files: %s\n"), nvr);
	free(nvr);

	if ((rc = processPackageFiles(spec, pkgFlags, pkg, didInstall, test)) != RPMRC_OK)
	    goto exit;

	if (maindbg)
	    filterDebuginfoPackage(spec, pkg, maindbg, dbgsrcpkg,
				   buildroot, uniquearch);
	else if (deplink && pkg != deplink)
	    addPackageDeps(pkg, deplink, RPMTAG_REQUIRENAME);

        if ((rc = rpmfcGenerateDepends(spec, pkg)) != RPMRC_OK)
	    goto exit;

	a = headerGetString(pkg->header, RPMTAG_ARCH);
	header_color = headerGetNumber(pkg->header, RPMTAG_HEADERCOLOR);
	if (!rstreq(a, "noarch")) {
	    arch_color = rpmGetArchColor(a);
	    if (arch_color > 0 && header_color > 0 &&
					!(arch_color & header_color)) {
		rpmlog(RPMLOG_WARNING,
		       _("Binaries arch (%d) not matching the package arch (%d).\n"),
		       header_color, arch_color);
	    }
	} else if (header_color != 0) {
	    int terminate = rpmExpandNumeric("%{?_binaries_in_noarch_packages_terminate_build}");
	    rpmlog(terminate ? RPMLOG_ERR : RPMLOG_WARNING, 
		   _("Arch dependent binaries in noarch package\n"));
	    if (terminate) {
		rc = RPMRC_FAIL;
		goto exit;
	    }
	}
    }

    /* Now we have in fileList list of files from all packages.
     * We pass it to a script which does the work of finding missing
     * and duplicated files.
     */
    
    
    if (checkFiles(spec->buildRoot, check_fileList) > 0) {
	rc = RPMRC_FAIL;
    }
exit:
    check_fileList = freeStringBuf(check_fileList);
    _free(buildroot);
    _free(uniquearch);
    
    return rc;
}
