/** \ingroup rpmbuild
 * \file build/parsePreamble.c
 *  Parse tags in global section from spec file.
 */

#include "system.h"

#include <ctype.h>
#include <errno.h>

#include <rpm/header.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmurl.h>
#include <rpm/rpmfileutil.h>
#include "rpmbuild_internal.h"
#include "rpmbuild_misc.h"
#include "debug.h"

#define SKIPSPACE(s) { while (*(s) && risspace(*(s))) (s)++; }
#define SKIPNONSPACE(s) { while (*(s) && !risspace(*(s))) (s)++; }
#define SKIPWHITE(_x)	{while (*(_x) && (risspace(*_x) || *(_x) == ',')) (_x)++;}
#define SKIPNONWHITE(_x){while (*(_x) &&!(risspace(*_x) || *(_x) == ',')) (_x)++;}

/**
 */
static const rpmTagVal copyTagsDuringParse[] = {
    RPMTAG_EPOCH,
    RPMTAG_VERSION,
    RPMTAG_RELEASE,
    RPMTAG_LICENSE,
    RPMTAG_PACKAGER,
    RPMTAG_DISTRIBUTION,
    RPMTAG_DISTURL,
    RPMTAG_VENDOR,
    RPMTAG_ICON,
    RPMTAG_URL,
    RPMTAG_VCS,
    RPMTAG_CHANGELOGTIME,
    RPMTAG_CHANGELOGNAME,
    RPMTAG_CHANGELOGTEXT,
    RPMTAG_PREFIXES,
    RPMTAG_DISTTAG,
    RPMTAG_BUGURL,
    RPMTAG_TRANSLATIONURL,
    RPMTAG_UPSTREAMRELEASES,
    RPMTAG_GROUP,
    RPMTAG_MODULARITYLABEL,
    0
};

/**
 */
static const rpmTagVal requiredTagsForBuild[] = {
    RPMTAG_NAME,
    RPMTAG_VERSION,
    RPMTAG_RELEASE,
    0
};

/**
 */
static const rpmTagVal requiredTags[] = {
    RPMTAG_NAME,
    RPMTAG_VERSION,
    RPMTAG_RELEASE,
    RPMTAG_SUMMARY,
    RPMTAG_LICENSE,
    0
};

/**
 */
static rpmRC addOrAppendListEntry(Header h, rpmTagVal tag, const char * line)
{
    int xx;
    int argc;
    const char **argv;

    if ((xx = poptParseArgvString(line, &argc, &argv))) {
	rpmlog(RPMLOG_ERR, _("Error parsing tag field: %s\n"), poptStrerror(xx));
	return RPMRC_FAIL;
    }
    if (argc) 
	headerPutStringArray(h, tag, argv, argc);
    argv = _free(argv);

    return RPMRC_OK;
}

/* Parse a simple part line that only take -n <pkg> or <pkg> */
/* <pkg> is returned in name as a pointer into a dynamic buffer */

/**
 */
static int parseSimplePart(const char *line, char **name, int *flag)
{
    char *tok;
    char *linebuf = xstrdup(line);
    int rc;

    /* Throw away the first token (the %xxxx) */
    (void)strtok(linebuf, " \t\n");
    *name = NULL;

    if (!(tok = strtok(NULL, " \t\n"))) {
	rc = 1;
	goto exit;
    }
    
    if (rstreq(tok, "-n")) {
	if (!(tok = strtok(NULL, " \t\n"))) {
	    rc = 1;
	    goto exit;
	}
	*flag = PART_NAME;
    } else {
	*flag = PART_SUBNAME;
    }
    *name = xstrdup(tok);
    rc = strtok(NULL, " \t\n") ? 1 : 0;

exit:
    free(linebuf);
    return rc;
}

/**
 */
static inline int parseYesNo(const char * s)
{
    return ((!s || (s[0] == 'n' || s[0] == 'N' || s[0] == '0') ||
	!rstrcasecmp(s, "false") || !rstrcasecmp(s, "off"))
	    ? 0 : 1);
}

static struct Source *newSource(uint32_t num, const char *path, int flags)
{
    struct Source *p = (struct Source *)xmalloc(sizeof(*p));
    p->num = num;
    p->fullSource = xstrdup(path);
    p->flags = flags;
    p->source = strrchr(p->fullSource, '/');
    if (p->source) {
	const char *buf = strrchr(p->source,'=');
	if (buf)
	    p->source = buf;
	p->source++;
    } else {
	p->source = p->fullSource;
    }
    p->path = rpmGetPath("%{_sourcedir}/", p->source, NULL);
    return p;
}

struct Source *findSource(rpmSpec spec, uint32_t num, int flag)
{
    struct Source *p;

    for (p = spec->sources; p != NULL; p = p->next)
	if ((num == p->num) && (p->flags & flag)) return p;

    return NULL;
}

static int parseNoSource(rpmSpec spec, const char * field, rpmTagVal tag)
{
    const char *f, *fe;
    const char *name;
    int flag;
    uint32_t num;

    if (tag == RPMTAG_NOSOURCE) {
	flag = RPMBUILD_ISSOURCE;
	name = "source";
    } else {
	flag = RPMBUILD_ISPATCH;
	name = "patch";
    }
    
    fe = field;
    for (f = fe; *f != '\0'; f = fe) {
        struct Source *p;

	SKIPWHITE(f);
	if (*f == '\0')
	    break;
	fe = f;
	SKIPNONWHITE(fe);
	if (*fe != '\0') fe++;

	if (parseUnsignedNum(f, &num)) {
	    rpmlog(RPMLOG_ERR, _("line %d: Bad number: %s\n"),
		     spec->lineNum, f);
	    return RPMRC_FAIL;
	}

	if (! (p = findSource(spec, num, flag))) {
	    rpmlog(RPMLOG_ERR, _("line %d: Bad no%s number: %u\n"),
		     spec->lineNum, name, num);
	    return RPMRC_FAIL;
	}

	p->flags |= RPMBUILD_ISNO;

    }

    return 0;
}

static int tryDownload(const struct Source *p)
{
    int rc = 0;
    struct stat st;

    /* try to download source/patch if it's missing */
    if (lstat(p->path, &st) != 0 && errno == ENOENT) {
	char *url = NULL;
	if (urlIsURL(p->fullSource) != URL_IS_UNKNOWN) {
	    url = rstrdup(p->fullSource);
	} else {
	    url = rpmExpand("%{_default_source_url}", NULL);
	    rstrcat(&url, p->source);
	    if (*url == '%') url = _free(url);
	}
	if (url) {
	    rpmlog(RPMLOG_WARNING, _("Downloading %s to %s\n"), url, p->path);
	    if (urlGetFile(url, p->path) != 0) {
		rpmlog(RPMLOG_ERR, _("Couldn't download %s\n"), p->fullSource);
		rc = -1;
	    }
	}
	free(url);
    }
    return rc;
}

/*
 * Parse an option number of a tag, such as in sources and patches.
 * Return -1 on error, 0 if number present and 1 if no number found.
 */
static int parseTagNumber(const char *line, uint32_t *snum)
{
    int rc = 0;
    char *l = xstrdup(line);
    char *fieldp = l;
    char *nump = l;

    /* We already know that a ':' exists, and that there */
    /* are no spaces before it.                          */
    /* This also now allows for spaces and tabs between  */
    /* the number and the ':'                            */
    while ((*fieldp != ':') && (*fieldp != ' ') && (*fieldp != '\t')) {
	fieldp++;
    }
    *fieldp = '\0';

    SKIPSPACE(nump);
    if (nump == NULL || *nump == '\0') {
	rc = 1;
    } else {
	rc = parseUnsignedNum(l, snum);
    }
    free(l);
    return rc;
}

int addSource(rpmSpec spec, int specline, const char *srcname, rpmTagVal tag)
{
    struct Source *p;
    int flag = 0;
    int nonum = 1; /* assume autonumbering */
    const char *name = NULL;
    char *buf = NULL;
    uint32_t num = 0;
    int *autonum = NULL;
    int nofetch = (spec->flags & RPMSPEC_FORCE) ||
		      rpmExpandNumeric("%{_disable_source_fetch}");

    switch (tag) {
      case RPMTAG_SOURCE:
	flag = RPMBUILD_ISSOURCE;
	name = "source";
	autonum = &spec->autonum_source;
	break;
      case RPMTAG_PATCH:
	flag = RPMBUILD_ISPATCH;
	name = "patch";
	autonum = &spec->autonum_patch;
	break;
      default:
	return -1;
	break;
    }

    if (specline) {
	char * s = spec->line;
	SKIPSPACE(s);
	nonum = parseTagNumber(s + strlen(name), &num);
	if (nonum < 0) {
	    rpmlog(RPMLOG_ERR, _("line %d: Bad %s number: %s\n"),
		     spec->lineNum, name, spec->line);
	    return RPMRC_FAIL;
	}
    }

    if (nonum > 0) {
	/* No number specified, use autonumbering */
	(*autonum)++;
	num = *autonum;
    } else {
	/* Autonumbering continues from last specified number */
	if ((int)num > *autonum)
	    *autonum = num;
    }

    /* Check whether tags of the same number haven't already been defined */
    if (findSource(spec, num, flag)) {
	rpmlog(RPMLOG_ERR, _("%s %d defined multiple times\n"), name, num);
	return RPMRC_FAIL;
    }

    /* Create the entry and link it in */
    p = newSource(num, srcname, flag);
    p->next = spec->sources;
    spec->sources = p;
    spec->numSources++;

    rasprintf(&buf, "%s%d",
	    (flag & RPMBUILD_ISPATCH) ? "PATCH" : "SOURCE", num);
    rpmPushMacro(spec->macros, buf, NULL, p->path, RMIL_SPEC);
    free(buf);
    rasprintf(&buf, "%sURL%d",
	    (flag & RPMBUILD_ISPATCH) ? "PATCH" : "SOURCE", num);
    rpmPushMacro(spec->macros, buf, NULL, p->fullSource, RMIL_SPEC);
    free(buf);

    addLuaSource(p);

    if (!nofetch && tryDownload(p))
	return RPMRC_FAIL;
    
    return 0;
}

typedef const struct tokenBits_s {
    const char * name;
    rpmsenseFlags bits;
} * tokenBits;

/**
 */
static struct tokenBits_s const installScriptBits[] = {
    { "interp",		RPMSENSE_INTERP },
    { "meta",		RPMSENSE_META },
    { "preun",		RPMSENSE_SCRIPT_PREUN },
    { "pre",		RPMSENSE_SCRIPT_PRE },
    { "postun",		RPMSENSE_SCRIPT_POSTUN },
    { "post",		RPMSENSE_SCRIPT_POST },
    { "rpmlib",		RPMSENSE_RPMLIB },
    { "verify",		RPMSENSE_SCRIPT_VERIFY },
    { "pretrans",	RPMSENSE_PRETRANS },
    { "posttrans",	RPMSENSE_POSTTRANS },
    { "preuntrans",	RPMSENSE_PREUNTRANS },
    { "postuntrans",	RPMSENSE_POSTUNTRANS },
    { NULL, 0 }
};

/**
 */
static int parseBits(const char * s, const tokenBits tokbits,
		rpmsenseFlags * bp)
{
    tokenBits tb = NULL;
    const char * se;
    rpmsenseFlags bits = RPMSENSE_ANY;
    int c = 0;
    int rc = RPMRC_OK;

    if (s) {
	for (;;) {
	    while ((c = *s) && risspace(c)) s++;
	    se = s;
	    while ((c = *se) && risalpha(c)) se++;
	    if (s == se) {
		if (c || tb)
		    rc = RPMRC_FAIL;
		break;
	    }
	    for (tb = tokbits; tb->name; tb++) {
		if (tb->name != NULL &&
		    strlen(tb->name) == (se-s) && rstreqn(tb->name, s, (se-s)))
		    break;
	    }
	    if (tb->name == NULL) {
		rc = RPMRC_FAIL;
		break;
	    }
	    bits |= tb->bits;
	    while ((c = *se) && risspace(c)) se++;
	    if (c != ',') {
		if (c)
		    rc = RPMRC_FAIL;
		break;
	    }
	    s = ++se;
	}
    }
    *bp |= bits;
    return rc;
}

/**
 */
static inline char * findLastChar(char * s)
{
    char *res = s;

    while (*s != '\0') {
	if (! risspace(*s))
	    res = s;
	s++;
    }

    return res;
}

/**
 */
int isMemberInEntry(Header h, const char *name, rpmTagVal tag)
{
    struct rpmtd_s td;
    int found = 0;
    const char *str;

    if (!headerGet(h, tag, &td, HEADERGET_MINMEM))
	return -1;

    while ((str = rpmtdNextString(&td))) {
	if (!rstrcasecmp(str, name)) {
	    found = 1;
	    break;
	}
    }
    rpmtdFreeData(&td);

    return found;
}

/**
 */
rpmRC checkForValidArchitectures(rpmSpec spec)
{
    char *arch = rpmExpand("%{_target_cpu}", NULL);
    char *os = rpmExpand("%{_target_os}", NULL);
    rpmRC rc = RPMRC_FAIL; /* assume failure */

    if (!strcmp(arch, "noarch")) {
	free(arch);
	arch = rpmExpand("%{_build_cpu}", NULL);
    }
    
    if (isMemberInEntry(spec->buildRestrictions,
			arch, RPMTAG_EXCLUDEARCH) == 1) {
	rpmlog(RPMLOG_ERR, _("Architecture is excluded: %s\n"), arch);
	goto exit;
    }
    if (isMemberInEntry(spec->buildRestrictions,
			arch, RPMTAG_EXCLUSIVEARCH) == 0) {
	rpmlog(RPMLOG_ERR, _("Architecture is not included: %s\n"), arch);
	goto exit;
    }
    if (isMemberInEntry(spec->buildRestrictions,
			os, RPMTAG_EXCLUDEOS) == 1) {
	rpmlog(RPMLOG_ERR, _("OS is excluded: %s\n"), os);
	goto exit;
    }
    if (isMemberInEntry(spec->buildRestrictions,
			os, RPMTAG_EXCLUSIVEOS) == 0) {
	rpmlog(RPMLOG_ERR, _("OS is not included: %s\n"), os);
	goto exit;
    }
    rc = RPMRC_OK;

exit:
    free(arch);
    free(os);

    return rc;
}

/**
 * Check that required tags are present in header.
 * @param h		header
 * @param NVR		package name-version-release
 * @return		RPMRC_OK if OK
 */
int checkForRequired(Header h)
{
    int res = RPMRC_OK;
    const rpmTagVal * p;

    for (p = requiredTags; *p != 0; p++) {
	if (!headerIsEntry(h, *p)) {
	    rpmlog(RPMLOG_ERR,
			_("%s field must be present in package: %s\n"),
			rpmTagGetName(*p), headerGetString(h, RPMTAG_NAME));
	    res = RPMRC_FAIL;
	}
    }

    return res;
}

/**
 * Check that required tags are present in header.
 * @param h		header
 * @param NVR		package name-version-release
 * @return		RPMRC_OK if OK
 */
static int checkForRequiredForBuild(Header h)
{
    int res = RPMRC_OK;
    const rpmTagVal * p;

    for (p = requiredTagsForBuild; *p != 0; p++) {
	if (!headerIsEntry(h, *p)) {
	    rpmlog(RPMLOG_ERR,
			_("%s field must be present before build in package: %s\n"),
			rpmTagGetName(*p), headerGetString(h, RPMTAG_NAME));
	    res = RPMRC_FAIL;
	}
    }

    return res;
}

/**
 * Check that no duplicate tags are present in header.
 * @param h		header
 * @param NVR		package name-version-release
 * @return		RPMRC_OK if OK
 */
int checkForDuplicates(Header h)
{
    int res = RPMRC_OK;
    rpmTagVal tag, lastTag = RPMTAG_NOT_FOUND;
    HeaderIterator hi = headerInitIterator(h);

    while ((tag = headerNextTag(hi)) != RPMTAG_NOT_FOUND) {
	if (tag == lastTag) {
	    rpmlog(RPMLOG_ERR, _("Duplicate %s entries in package: %s\n"),
		     rpmTagGetName(tag), headerGetString(h, RPMTAG_NAME));
	    res = RPMRC_FAIL;
	}
	lastTag = tag;
    }
    headerFreeIterator(hi);

    return res;
}

/**
 */
static struct optionalTag {
    rpmTagVal	ot_tag;
    const char * ot_mac;
} const optionalTags[] = {
    { RPMTAG_VENDOR,		"%{vendor}" },
    { RPMTAG_PACKAGER,		"%{packager}" },
    { RPMTAG_DISTRIBUTION,	"%{distribution}" },
    { RPMTAG_DISTURL,		"%{disturl}" },
    { RPMTAG_DISTTAG,		"%{disttag}" },
    { RPMTAG_BUGURL,		"%{bugurl}" },
    { RPMTAG_TRANSLATIONURL,	"%{translationurl}" },
    { RPMTAG_UPSTREAMRELEASES,	"%{upstreamreleases}" },
    { RPMTAG_MODULARITYLABEL,	"%{modularitylabel}"},
    { 0, NULL }
};

/**
 */
void fillOutMainPackage(Header h)
{
    const struct optionalTag *ot;

    for (ot = optionalTags; ot->ot_mac != NULL; ot++) {
	if (!headerIsEntry(h, ot->ot_tag)) {
	    char *val = rpmExpand(ot->ot_mac, NULL);
	    if (val && *val != '%') {
		headerPutString(h, ot->ot_tag, val);
	    }
	    free(val);
	}
    }
}

/**
 */
void copyInheritedTags(Header h, Header fromh)
{
    headerCopyTags(fromh, h, (rpmTagVal *)copyTagsDuringParse);
}

/**
 */
static rpmRC addIcon(Package pkg, const char * file)
{
    struct Source *p = newSource(0, file, RPMBUILD_ISICON);
    char *fn = NULL;
    uint8_t *icon = NULL;
    FD_t fd = NULL;
    rpmRC rc = RPMRC_FAIL; /* assume failure */
    off_t size;
    size_t nb, iconsize;

    p->next = pkg->icon;
    pkg->icon = p;

    /* XXX use rpmGenPath(rootdir, "%{_sourcedir}/", file) for icon path. */
    fn = rpmGetPath("%{_sourcedir}/", file, NULL);

    fd = Fopen(fn, "r.ufdio");
    if (fd == NULL) {
	rpmlog(RPMLOG_ERR, _("Unable to open icon %s: %s\n"),
		fn, Fstrerror(fd));
	goto exit;
    }
    size = fdSize(fd);
    iconsize = (size >= 0 ? size : (8 * BUFSIZ));
    if (iconsize == 0) {
	rc = RPMRC_OK; /* XXX Eh? */
	goto exit;
    }

    icon = (uint8_t *)xmalloc(iconsize + 1);
    *icon = '\0';

    nb = Fread(icon, sizeof(icon[0]), iconsize, fd);
    if (Ferror(fd) || (size >= 0 && nb != size)) {
	rpmlog(RPMLOG_ERR, _("Unable to read icon %s: %s\n"),
		fn, Fstrerror(fd));
	goto exit;
    }

    if (rstreqn((char*)icon, "GIF", sizeof("GIF")-1)) {
	headerPutBin(pkg->header, RPMTAG_GIF, icon, iconsize);
    } else if (rstreqn((char*)icon, "/* XPM", sizeof("/* XPM")-1)) {
	headerPutBin(pkg->header, RPMTAG_XPM, icon, iconsize);
    } else {
	rpmlog(RPMLOG_ERR, _("Unknown icon type: %s\n"), file);
	goto exit;
    }
    rc = RPMRC_OK;
    
exit:
    Fclose(fd);
    free(fn);
    free(icon);
    return rc;
}

#define SINGLE_TOKEN_ONLY \
if (multiToken) { \
    rpmlog(RPMLOG_ERR, _("line %d: Tag takes single token only: %s\n"), \
	     spec->lineNum, spec->line); \
    return RPMRC_FAIL; \
}

static void specLog(rpmSpec spec, int lvl, const char *line, const char *msg)
{
    if (spec) {
	rpmlog(lvl, _("line %d: %s in: %s\n"), spec->lineNum, msg, spec->line);
    } else {
	rpmlog(lvl, _("%s in: %s\n"), msg, line);
    }
}

/**
 * Check for inappropriate characters. All alphanums are considered sane.
 * @param spec		spec (or NULL)
 * @param field		string to check
 * @param allowedchars	string of permitted characters
 * @return		RPMRC_OK if OK
 */
rpmRC rpmCharCheck(rpmSpec spec, const char *field,
		   const char *allowedchars,
		   const char *allowedfirstchars)
{
    const char *ch;
    char *err = NULL;
    rpmRC rc = RPMRC_OK;

    if (allowedfirstchars && !(risalnum(*field) ||
			       strchr(allowedfirstchars, *field))) {
	rasprintf(&err, _("Illegal char '%c' (0x%x)"),
		  isprint(*field) ? *field : '?', *field);
    }

    for (ch=field; *ch; ch++) {
	if (ch==field && allowedfirstchars) continue;
	if (risalnum(*ch) || strchr(allowedchars, *ch)) continue;
	rasprintf(&err, _("Illegal char '%c' (0x%x)"),
		  isprint(*ch) ? *ch : '?', *ch);
    }

    for (ch=field; *ch; ch++) {
	if (strchr("%{}", *ch)) {
	    specLog(spec, RPMLOG_WARNING, field,
		    _("Possible unexpanded macro"));
	    break;
	}
    }

    if (err == NULL && strstr(field, "..") != NULL) {
	rasprintf(&err, _("Illegal sequence \"..\""));
    }

    if (err) {
	specLog(spec, RPMLOG_ERR, field, err);
	free(err);
	rc = RPMRC_FAIL;
    }
    return rc;
}

static int haveLangTag(Header h, rpmTagVal tag, const char *lang)
{
    int rc = 0;	/* assume tag not present */
    int langNum = -1;

    if (lang && *lang) {
	/* See if the language is in header i18n table */
	struct rpmtd_s langtd;
	const char *s = NULL;
	headerGet(h, RPMTAG_HEADERI18NTABLE, &langtd, HEADERGET_MINMEM);
	while ((s = rpmtdNextString(&langtd)) != NULL) {
	    if (rstreq(s, lang)) {
		langNum = rpmtdGetIndex(&langtd);
		break;
	    }
	}
	rpmtdFreeData(&langtd);
    } else {
	/* C locale */
	langNum = 0;
    }

    /* If locale is present, check the actual tag content */
    if (langNum >= 0) {
	struct rpmtd_s td;
	headerGet(h, tag, &td, HEADERGET_MINMEM|HEADERGET_RAW);
	if (rpmtdSetIndex(&td, langNum) == langNum) {
	    const char *s = rpmtdGetString(&td);
	    /* non-empty string means a dupe */
	    if (s && *s)
		rc = 1;
	}
	rpmtdFreeData(&td);
    };

    return rc;
}

int addLangTag(rpmSpec spec, Header h, rpmTagVal tag,
		      const char *field, const char *lang)
{
    int skip = 0;

    if (haveLangTag(h, tag, lang)) {
	/* Turn this into an error eventually */
	rpmlog(RPMLOG_WARNING, _("line %d: second %s\n"),
		spec->lineNum, rpmTagGetName(tag));
    }

    if (!*lang) {
	headerPutString(h, tag, field);
    } else {
    	skip = ((spec->flags & RPMSPEC_NOLANG) &&
		!rstreq(lang, RPMBUILD_DEFAULT_LANG));
	if (skip)
	    return 0;
	headerAddI18NString(h, tag, field, lang);
    }

    return 0;
}

static int addBuildOption(rpmSpec spec, const char *sect, const char *opt)
{
    rpmRC rc = RPMRC_FAIL;
    if (*sect == '\0')
	sect = "conf";

    const struct sectname_s *sc = getSection(sect, 0);
    if (sc) {
	argvAdd(&(spec->buildopts[sc->section]), opt);
	rc = RPMRC_OK;
    }
    return rc;
}

static rpmRC handlePreambleTag(rpmSpec spec, enum parseStages stage,
			       Package pkg, rpmTagVal tag,
			       const char *macro, const char *lang)
{
    char * field = spec->line;
    char * end;
    int multiToken = 0;
    rpmsenseFlags tagflags = RPMSENSE_ANY;
    rpmRC rc = RPMRC_FAIL;
    
    if (field == NULL) /* XXX can't happen */
	goto exit;
    /* Find the start of the "field" and strip trailing space */
    while ((*field) && (*field != ':'))
	field++;
    if (*field != ':') {
	rpmlog(RPMLOG_ERR, _("line %d: Malformed tag: %s\n"),
		 spec->lineNum, spec->line);
	goto exit;
    }
    field++;
    SKIPSPACE(field);
    if (!*field) {
	/* Empty field */
	rpmlog(RPMLOG_ERR, _("line %d: Empty tag: %s\n"),
		 spec->lineNum, spec->line);
	goto exit;
    }
    end = findLastChar(field);
    *(end+1) = '\0';

    /* See if this is multi-token */
    end = field;
    SKIPNONSPACE(end);
    if (*end != '\0')
	multiToken = 1;

    switch (tag) {
    case RPMTAG_BUILDSYSTEM:
	SINGLE_TOKEN_ONLY;
	if (checkBuildsystem(spec, field))
	    goto exit;
	break;
    case RPMTAG_BUILDOPTION:
	if (addBuildOption(spec, lang, field))
	    goto exit;
	break;
    case RPMTAG_NAME:
	SINGLE_TOKEN_ONLY;
	if (rpmCharCheck(spec, field,
			 ALLOWED_CHARS_NAME, ALLOWED_FIRSTCHARS_NAME))
	   goto exit;
	headerPutString(pkg->header, tag, field);
	/* Main pkg name is unknown at the start, populate as soon as we can */
	if (pkg == spec->packages)
	    pkg->name = rpmstrPoolId(spec->pool, field, 1);
	break;
    case RPMTAG_VERSION:
    case RPMTAG_RELEASE:
	SINGLE_TOKEN_ONLY;
	if (rpmCharCheck(spec, field, ALLOWED_CHARS_VERREL, NULL))
	   goto exit;
	headerPutString(pkg->header, tag, field);
	break;
    case RPMTAG_URL:
    case RPMTAG_DISTTAG:
    case RPMTAG_BUGURL:
    case RPMTAG_MODULARITYLABEL:
    /* XXX TODO: validate format somehow */
    case RPMTAG_VCS:
	SINGLE_TOKEN_ONLY;
	/* fallthrough */
    case RPMTAG_TRANSLATIONURL:
    case RPMTAG_UPSTREAMRELEASES:
	headerPutString(pkg->header, tag, field);
	break;
    case RPMTAG_GROUP:
    case RPMTAG_SUMMARY:
    case RPMTAG_DISTRIBUTION:
    case RPMTAG_VENDOR:
    case RPMTAG_LICENSE:
    case RPMTAG_PACKAGER:
	if (addLangTag(spec, pkg->header, tag, field, lang))
	    goto exit;
	break;
    case RPMTAG_SOURCELICENSE:
	if (addLangTag(spec, spec->sourcePackage->header,
		       RPMTAG_LICENSE, field, lang))
	    goto exit;
	break;
    case RPMTAG_BUILDROOT:
	/* just silently ignore BuildRoot */
	break;
    case RPMTAG_PREFIXES: {
	struct rpmtd_s td;
	const char *str;
	if (addOrAppendListEntry(pkg->header, tag, field))
	   goto exit;
	headerGet(pkg->header, tag, &td, HEADERGET_MINMEM);
	while ((str = rpmtdNextString(&td))) {
	    size_t len = strlen(str);
	    if (len > 1 && str[len-1] == '/') {
		rpmlog(RPMLOG_ERR,
			 _("line %d: Prefixes must not end with \"/\": %s\n"),
			 spec->lineNum, spec->line);
		rpmtdFreeData(&td);
		goto exit;
	    }
	}
	rpmtdFreeData(&td);
	break;
    }
    case RPMTAG_DOCDIR:
	SINGLE_TOKEN_ONLY;
	if (field[0] != '/') {
	    rpmlog(RPMLOG_ERR, _("line %d: Docdir must begin with '/': %s\n"),
		     spec->lineNum, spec->line);
	    goto exit;
	}
	rpmPopMacro(NULL, "_docdir");
	rpmPushMacro(NULL, "_docdir", NULL, field, RMIL_SPEC);
	break;
    case RPMTAG_EPOCH: {
	SINGLE_TOKEN_ONLY;
	uint32_t epoch;
	if (parseUnsignedNum(field, &epoch)) {
	    rpmlog(RPMLOG_ERR,
		   _("line %d: Epoch field must be an unsigned number: %s\n"),
		   spec->lineNum, spec->line);
	    goto exit;
	}
	headerPutUint32(pkg->header, tag, &epoch, 1);
	break;
    }
    case RPMTAG_AUTOREQPROV:
	pkg->autoReq = parseYesNo(field);
	pkg->autoProv = pkg->autoReq;
	break;
    case RPMTAG_AUTOREQ:
	pkg->autoReq = parseYesNo(field);
	break;
    case RPMTAG_AUTOPROV:
	pkg->autoProv = parseYesNo(field);
	break;
    case RPMTAG_SOURCE:
    case RPMTAG_PATCH:
	if (addSource(spec, 1, field, tag))
	    goto exit;
	break;
    case RPMTAG_ICON:
	SINGLE_TOKEN_ONLY;
	if (addIcon(pkg, field))
	    goto exit;
	spec->numSources++;
	break;
    case RPMTAG_NOSOURCE:
    case RPMTAG_NOPATCH:
	spec->noSource = 1;
	if (parseNoSource(spec, field, tag))
	    goto exit;
	break;
    case RPMTAG_ORDERNAME:
    case RPMTAG_REQUIRENAME:
    case RPMTAG_RECOMMENDNAME:
    case RPMTAG_SUGGESTNAME:
    case RPMTAG_SUPPLEMENTNAME:
    case RPMTAG_ENHANCENAME:
	if (parseBits(lang, installScriptBits, &tagflags)) {
	    rpmlog(RPMLOG_ERR, _("line %d: Bad %s: qualifiers: %s\n"),
		     spec->lineNum, rpmTagGetName(tag), spec->line);
	    goto exit;
	}
	/* fallthrough */
    case RPMTAG_PREREQ:
    case RPMTAG_CONFLICTNAME:
    case RPMTAG_OBSOLETENAME:
    case RPMTAG_PROVIDENAME:
	if (parseRCPOT(spec, pkg, field, tag, 0, tagflags, addReqProvPkg, NULL))
	    goto exit;
	break;
    case RPMTAG_BUILDPREREQ:
    case RPMTAG_BUILDREQUIRES:
    case RPMTAG_BUILDCONFLICTS:
	if (parseRCPOT(spec, spec->sourcePackage, field, tag, 0, tagflags, addReqProvPkg, NULL))
	    goto exit;
	break;
    case RPMTAG_EXCLUDEARCH:
    case RPMTAG_EXCLUSIVEARCH:
    case RPMTAG_EXCLUDEOS:
    case RPMTAG_EXCLUSIVEOS:
	if (addOrAppendListEntry(spec->buildRestrictions, tag, field))
	   goto exit;
	break;
    case RPMTAG_BUILDARCHS: {
	int BACount;
	const char **BANames = NULL;
	if (poptParseArgvString(field, &BACount, &BANames)) {
	    rpmlog(RPMLOG_ERR,
		     _("line %d: Bad BuildArchitecture format: %s\n"),
		     spec->lineNum, spec->line);
	    goto exit;
	}
	if (spec->packages == pkg) {
	    if (spec->BANames) {
		rpmlog(RPMLOG_ERR,
		       _("line %d: Duplicate BuildArch entry: %s\n"),
		       spec->lineNum, spec->line);
		BANames = _free(BANames);
		goto exit;
	    }
	    if (stage == PARSE_GENERATED &&
		(BACount != 1 || !rstreq(BANames[0], "noarch"))) {
		rpmlog(RPMLOG_ERR,
		       _("line %d: Only noarch is allowed after the build: %s\n"),
		       spec->lineNum, spec->line);
		BANames = _free(BANames);
		goto exit;		
	    }
	    spec->BACount = BACount;
	    spec->BANames = BANames;
	} else {
	    if (BACount != 1 || !rstreq(BANames[0], "noarch")) {
		rpmlog(RPMLOG_ERR,
		     _("line %d: Only noarch subpackages are supported: %s\n"),
		     spec->lineNum, spec->line);
		BANames = _free(BANames);
		goto exit;
	    }
	    BANames = _free(BANames);
	    headerPutString(pkg->header, RPMTAG_ARCH, "noarch");
	}
	if (!BACount)
	    spec->BANames = _free(spec->BANames);
	break;
    }
    case RPMTAG_REMOVEPATHPOSTFIXES:
	argvSplit(&pkg->removePostfixes, field, ":");
	break;
    default:
	rpmlog(RPMLOG_ERR, _("Internal error: Bogus tag %d\n"), tag);
	goto exit;
    }

    if (macro) {
	rpmPushMacro(spec->macros, macro, NULL, field, RMIL_SPEC);
	/* Add a separate uppercase macro for tags from the main package */
	if (pkg == spec->packages) {
	    char *m = xstrdup(macro);
	    for (char *p = m; *p; ++p)
		*p = rtoupper(*p);
	    rpmPushMacro(spec->macros, m, NULL, field, RMIL_SPEC);
	    free(m);
	}
    }
    rc = RPMRC_OK;
exit:
    return rc;	
}

/* This table has to be in a peculiar order.  If one tag is the */
/* same as another, plus a few letters, it must come first.     */

/**
 */
typedef const struct PreambleRec_s {
    rpmTagVal tag;
    int type;
    int deprecated;
    int ismacro;
    int prebuildonly;
    size_t len;
    const char * token;
} * PreambleRec;

static struct PreambleRec_s const preambleList[] = {
    {RPMTAG_NAME,		0, 0, 1, 0, LEN_AND_STR("name")},
    {RPMTAG_VERSION,		0, 0, 1, 0, LEN_AND_STR("version")},
    {RPMTAG_RELEASE,		0, 0, 1, 0, LEN_AND_STR("release")},
    {RPMTAG_EPOCH,		0, 0, 1, 0, LEN_AND_STR("epoch")},
    {RPMTAG_SUMMARY,		1, 0, 1, 0, LEN_AND_STR("summary")},
    {RPMTAG_LICENSE,		0, 0, 1, 0, LEN_AND_STR("license")},
    {RPMTAG_SOURCELICENSE,	0, 0, 1, 0, LEN_AND_STR("sourcelicense")},
    {RPMTAG_DISTRIBUTION,	0, 0, 1, 0, LEN_AND_STR("distribution")},
    {RPMTAG_DISTURL,		0, 0, 1, 0, LEN_AND_STR("disturl")},
    {RPMTAG_VENDOR,		0, 0, 1, 0, LEN_AND_STR("vendor")},
    {RPMTAG_GROUP,		1, 0, 1, 0, LEN_AND_STR("group")},
    {RPMTAG_PACKAGER,		0, 0, 1, 0, LEN_AND_STR("packager")},
    {RPMTAG_URL,		0, 0, 1, 0, LEN_AND_STR("url")},
    {RPMTAG_VCS,		0, 0, 1, 0, LEN_AND_STR("vcs")},
    {RPMTAG_SOURCE,		0, 0, 0, 1, LEN_AND_STR("source")},
    {RPMTAG_PATCH,		0, 0, 0, 1, LEN_AND_STR("patch")},
    {RPMTAG_NOSOURCE,		0, 0, 0, 1, LEN_AND_STR("nosource")},
    {RPMTAG_NOPATCH,		0, 0, 0, 1, LEN_AND_STR("nopatch")},
    {RPMTAG_EXCLUDEARCH,	0, 0, 0, 1, LEN_AND_STR("excludearch")},
    {RPMTAG_EXCLUSIVEARCH,	0, 0, 0, 1, LEN_AND_STR("exclusivearch")},
    {RPMTAG_EXCLUDEOS,		0, 0, 0, 1, LEN_AND_STR("excludeos")},
    {RPMTAG_EXCLUSIVEOS,	0, 0, 0, 1, LEN_AND_STR("exclusiveos")},
    {RPMTAG_ICON,		0, 0, 0, 0, LEN_AND_STR("icon")},
    {RPMTAG_PROVIDENAME,	0, 0, 0, 0, LEN_AND_STR("provides")},
    {RPMTAG_REQUIRENAME,	2, 0, 0, 0, LEN_AND_STR("requires")},
    {RPMTAG_RECOMMENDNAME,	2, 0, 0, 0, LEN_AND_STR("recommends")},
    {RPMTAG_SUGGESTNAME,	2, 0, 0, 0, LEN_AND_STR("suggests")},
    {RPMTAG_SUPPLEMENTNAME,	2, 0, 0, 0, LEN_AND_STR("supplements")},
    {RPMTAG_ENHANCENAME,	2, 0, 0, 0, LEN_AND_STR("enhances")},
    {RPMTAG_PREREQ,		2, 1, 0, 0, LEN_AND_STR("prereq")},
    {RPMTAG_CONFLICTNAME,	0, 0, 0, 0, LEN_AND_STR("conflicts")},
    {RPMTAG_OBSOLETENAME,	0, 0, 0, 0, LEN_AND_STR("obsoletes")},
    {RPMTAG_PREFIXES,		0, 0, 1, 0, LEN_AND_STR("prefixes")},
    {RPMTAG_PREFIXES,		0, 0, 1, 0, LEN_AND_STR("prefix")},
    {RPMTAG_BUILDROOT,		0, 0, 0, 1, LEN_AND_STR("buildroot")},
    {RPMTAG_BUILDARCHS,		0, 0, 0, 0, LEN_AND_STR("buildarchitectures")},
    {RPMTAG_BUILDARCHS,		0, 0, 0, 0, LEN_AND_STR("buildarch")},
    {RPMTAG_BUILDCONFLICTS,	0, 0, 0, 1, LEN_AND_STR("buildconflicts")},
    {RPMTAG_BUILDOPTION,	2, 0, 0, 1, LEN_AND_STR("buildoption")},
    {RPMTAG_BUILDPREREQ,	0, 1, 0, 1, LEN_AND_STR("buildprereq")},
    {RPMTAG_BUILDREQUIRES,	0, 0, 0, 1, LEN_AND_STR("buildrequires")},
    {RPMTAG_BUILDSYSTEM,	0, 0, 1, 1, LEN_AND_STR("buildsystem")},
    {RPMTAG_AUTOREQPROV,	0, 0, 0, 0, LEN_AND_STR("autoreqprov")},
    {RPMTAG_AUTOREQ,		0, 0, 0, 0, LEN_AND_STR("autoreq")},
    {RPMTAG_AUTOPROV,		0, 0, 0, 0, LEN_AND_STR("autoprov")},
    {RPMTAG_DOCDIR,		0, 0, 0, 0, LEN_AND_STR("docdir")},
    {RPMTAG_DISTTAG,		0, 0, 1, 0, LEN_AND_STR("disttag")},
    {RPMTAG_BUGURL,		0, 0, 1, 0, LEN_AND_STR("bugurl")},
    {RPMTAG_TRANSLATIONURL,	0, 0, 1, 0, LEN_AND_STR("translationurl")},
    {RPMTAG_UPSTREAMRELEASES,	0, 0, 1, 0, LEN_AND_STR("upstreamreleases")},
    {RPMTAG_ORDERNAME,		2, 0, 0, 0, LEN_AND_STR("orderwithrequires")},
    {RPMTAG_REMOVEPATHPOSTFIXES,0, 0, 1, 0, LEN_AND_STR("removepathpostfixes")},
    {RPMTAG_MODULARITYLABEL,	0, 0, 1, 0, LEN_AND_STR("modularitylabel")},
    {0, 0, 0, 0}
};

/**
 */
static int findPreambleTag(rpmSpec spec, PreambleRec * pr, const char ** macro, char * lang)
{
    PreambleRec p;
    char *s = spec->line;
    SKIPSPACE(s);

    for (p = preambleList; p->token != NULL; p++) {
	if (!(p->token && !rstrncasecmp(s, p->token, p->len)))
	    continue;
	if (p->deprecated) {
	    rpmlog(RPMLOG_WARNING, _("line %d: %s is deprecated: %s\n"),
			spec->lineNum, p->token, spec->line);
	}
	break;
    }
    if (p == NULL || p->token == NULL)
	return 1;

    s = s + p->len;
    SKIPSPACE(s);

    switch (p->type) {
    default:
    case 0:
	/* Unless this is a source or a patch, a ':' better be next */
	if (p->tag != RPMTAG_SOURCE && p->tag != RPMTAG_PATCH) {
	    if (*s != ':') return 1;
	}
	*lang = '\0';
	break;
    case 1:	/* Parse optional ( <token> ). */
    case 2:
	if (*s == ':') {
	    /* Type 1 is multilang, 2 is qualifiers with no defaults */
	    strcpy(lang, (p->type == 1) ? RPMBUILD_DEFAULT_LANG : "");
	    break;
	}
	if (*s != '(') return 1;
	s++;
	SKIPSPACE(s);
	while (!risspace(*s) && *s != ')')
	    *lang++ = *s++;
	*lang = '\0';
	SKIPSPACE(s);
	if (*s != ')') return 1;
	s++;
	SKIPSPACE(s);
	if (*s != ':') return 1;
	break;
    }
    *macro = p->ismacro ? p->token : NULL;
    *pr = p;
    return 0;
}

int parsePreamble(rpmSpec spec, int initialPackage, enum parseStages stage)
{
    int nextPart = PART_ERROR;
    int res = PART_ERROR; /* assume failure */
    int rc;
    char *linep;
    int flag = 0;
    Package pkg;
    char *name = NULL;
    char *NVR = NULL;
    char lang[BUFSIZ];

    if (! initialPackage) {
	/* There is one option to %package: <pkg> or -n <pkg> */
	if (parseSimplePart(spec->line, &name, &flag)) {
	    rpmlog(RPMLOG_ERR, _("Bad package specification: %s\n"),
			spec->line);
	    goto exit;
	}

	if (rpmCharCheck(spec, name, ALLOWED_CHARS_NAME, flag == PART_SUBNAME ? NULL : ALLOWED_FIRSTCHARS_NAME))
	    goto exit;
	
	if (!lookupPackage(spec, name, flag, NULL))
	    goto exit;
	
	/* Construct the package */
	if (flag == PART_SUBNAME) {
	    rasprintf(&NVR, "%s-%s", 
		    headerGetString(spec->packages->header, RPMTAG_NAME), name);
	} else
	    NVR = xstrdup(name);
	pkg = newPackage(NVR, spec->pool, &spec->packages);
	headerPutString(pkg->header, RPMTAG_NAME, NVR);
    } else if (spec->sourcePackage) {
	NVR = xstrdup("(main package)");
	pkg = spec->packages;
    } else {
	NVR = xstrdup("(main package)");
	pkg = newPackage(NULL, spec->pool, &spec->packages);
	spec->sourcePackage = newPackage(NULL, spec->pool, NULL);
    }

    if ((rc = readLine(spec, STRIP_TRAILINGSPACE | STRIP_COMMENTS)) > 0) {
	nextPart = PART_NONE;
    } else if (rc < 0) {
	goto exit;
    } else {
	while (! (nextPart = isPart(spec->line))) {
	    const char * macro;
	    PreambleRec p;

	    /* Skip blank lines */
	    linep = spec->line;
	    SKIPSPACE(linep);
	    if (*linep != '\0') {
		if (findPreambleTag(spec, &p, &macro, lang)) {
		    if (spec->lineNum == 1 &&
			(unsigned char)(spec->line[0]) == 0xed &&
			(unsigned char)(spec->line[1]) == 0xab &&
			(unsigned char)(spec->line[2]) == 0xee &&
			(unsigned char)(spec->line[3]) == 0xdb) {
			rpmlog(RPMLOG_ERR, _("Binary rpm package found. Expected spec file!\n"));
			goto exit;
		    }
		    rpmlog(RPMLOG_ERR, _("line %d: Unknown tag: %s\n"),
				spec->lineNum, spec->line);
		    goto exit;
		}
		if (stage == PARSE_GENERATED && p->prebuildonly) {
		    rpmlog(RPMLOG_ERR, _("line %d: Tag not allowed after build is done: %s\n"),
			   spec->lineNum, spec->line);
		    goto exit;
		}
		if (handlePreambleTag(spec, stage, pkg, p->tag, macro, lang)) {
		    goto exit;
		}
		if (spec->BANames && !spec->recursing) {
		    res = PART_BUILDARCHITECTURES;
		    goto exit;
		}
	    }
	    if ((rc =
		 readLine(spec, STRIP_TRAILINGSPACE | STRIP_COMMENTS)) > 0) {
		nextPart = PART_NONE;
		break;
	    }
	    if (rc) {
		goto exit;
	    }
	}
    }

    if (initialPackage) {
	if (checkForRequiredForBuild(pkg->header)) {
	    goto exit;
	}

	if (!spec->buildDir) {
	    /* Using release here causes a buildid no-recompute test to fail */
	    char *bn = rpmExpand("%{NAME}-%{VERSION}-build", NULL);
	    /* Tilde and caret in paths are evil, convert to underscores */
	    for (char *t = bn; *t; t++) {
		if (*t == '^' || *t == '~')
		    *t = '_';
	    }
	    spec->buildDir = rpmExpand("%{_top_builddir}/", bn, NULL);
	    free(bn);

	    /* Override toplevel _builddir for backwards compatibility */
	    rpmPushMacroFlags(spec->macros, "_builddir", NULL, spec->buildDir,
				RMIL_SPEC, RPMMACRO_LITERAL);

	    /* A user-oriented, unambiguous name for the thing */
	    rpmPushMacroFlags(spec->macros, "builddir", NULL, spec->buildDir,
				RMIL_SPEC, RPMMACRO_LITERAL);

	    char *specparts = rpmGetPath(spec->buildDir, "/SPECPARTS", NULL);
	    rpmPushMacroFlags(spec->macros, "specpartsdir", NULL, specparts,
				RMIL_SPEC, RPMMACRO_LITERAL);
	    free(specparts);
	}

	if (!spec->buildRoot) {
	    spec->buildRoot = rpmGetPath(spec->buildDir, "/BUILDROOT", NULL);
	} else {
	    char *buildRoot = rpmGetPath(spec->buildRoot, NULL);
	    free(spec->buildRoot);
	    spec->buildRoot = buildRoot;
	}

	if (rstreq(spec->buildRoot, "") || rstreq(spec->buildRoot, "/")) {
	    rpmlog(RPMLOG_ERR, _("Invalid buildroot: '%s'\n"), spec->buildRoot);
	    goto exit;
	}

	rpmPushMacroFlags(spec->macros, "buildroot", NULL, spec->buildRoot,
			    RMIL_SPEC, RPMMACRO_LITERAL);

	/* Silly compat thing, but many specs use %_buildrootdir */
	rpmPushMacroFlags(spec->macros, "_buildrootdir", NULL,
			    "%{dirname:%{buildroot}}", RMIL_GLOBAL, 0);
    }

    /* if we get down here nextPart has been set to non-error */
    res = nextPart;

exit:
    free(name);
    free(NVR);
    return res;
}
