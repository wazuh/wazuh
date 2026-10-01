/** \ingroup rpmbuild
 * \file build/parseSpec.c
 *  Top level dispatcher for spec file parsing.
 */

#include "system.h"

#include <errno.h>
#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>		/* RPM_MACHTABLE & related */
#include <rpm/rpmds.h>
#include <rpm/rpmts.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include "rpmbuild_internal.h"
#include "rpmbuild_misc.h"
#include "debug.h"

#define SKIPSPACE(s) { while (*(s) && risspace(*(s))) (s)++; }
#define SKIPNONSPACE(s) { while (*(s) && !risspace(*(s))) (s)++; }
#define ISMACRO(s,m,len) (rstreqn((s), (m), len) && !risalpha((s)[len]))
#define ISMACROWITHARG(s,m,len) (rstreqn((s), (m), len) && (risblank((s)[len]) || !(s)[len]))


static rpmRC parseSpecParts(rpmSpec spec, const char *pattern,
			    enum parseStages stage);

typedef struct OpenFileInfo {
    char * fileName;
    FILE *fp;
    int lineNum;
    char *readBuf;
    size_t readBufLen;
    const char * readPtr;
    struct OpenFileInfo * next;
} OFI_t;

static const struct PartRec {
    int part;
    int prebuildonly;
    size_t len;
    const char * token;
} partList[] = {
    { PART_PREAMBLE,      0, LEN_AND_STR("%package")},
    { PART_PREP,          1, LEN_AND_STR("%prep")},
    { PART_BUILDREQUIRES, 1, LEN_AND_STR("%generate_buildrequires")},
    { PART_CONF,          1, LEN_AND_STR("%conf")},
    { PART_BUILD,         1, LEN_AND_STR("%build")},
    { PART_INSTALL,       1, LEN_AND_STR("%install")},
    { PART_CHECK,         1, LEN_AND_STR("%check")},
    { PART_CLEAN,         1, LEN_AND_STR("%clean")},
    { PART_PREUN,         0, LEN_AND_STR("%preun")},
    { PART_POSTUN,        0, LEN_AND_STR("%postun")},
    { PART_PRETRANS,      0, LEN_AND_STR("%pretrans")},
    { PART_POSTTRANS,     0, LEN_AND_STR("%posttrans")},
    { PART_PREUNTRANS,    0, LEN_AND_STR("%preuntrans")},
    { PART_POSTUNTRANS,   0, LEN_AND_STR("%postuntrans")},
    { PART_PRE,           0, LEN_AND_STR("%pre")},
    { PART_POST,          0, LEN_AND_STR("%post")},
    { PART_FILES,         0, LEN_AND_STR("%files")},
    { PART_CHANGELOG,     0, LEN_AND_STR("%changelog")},
    { PART_DESCRIPTION,   0, LEN_AND_STR("%description")},
    { PART_TRIGGERPOSTUN, 0, LEN_AND_STR("%triggerpostun")},
    { PART_TRIGGERPREIN,  0, LEN_AND_STR("%triggerprein")},
    { PART_TRIGGERUN,     0, LEN_AND_STR("%triggerun")},
    { PART_TRIGGERIN,     0, LEN_AND_STR("%triggerin")},
    { PART_TRIGGERIN,     0, LEN_AND_STR("%trigger")},
    { PART_VERIFYSCRIPT,  0, LEN_AND_STR("%verifyscript")},
    { PART_POLICIES,      0, LEN_AND_STR("%sepolicy")},
    { PART_FILETRIGGERIN,	    0, LEN_AND_STR("%filetriggerin")},
    { PART_FILETRIGGERIN,	    0, LEN_AND_STR("%filetrigger")},
    { PART_FILETRIGGERUN,	    0, LEN_AND_STR("%filetriggerun")},
    { PART_FILETRIGGERPOSTUN,	    0, LEN_AND_STR("%filetriggerpostun")},
    { PART_TRANSFILETRIGGERIN,	    0, LEN_AND_STR("%transfiletriggerin")},
    { PART_TRANSFILETRIGGERIN,	    0, LEN_AND_STR("%transfiletrigger")},
    { PART_TRANSFILETRIGGERUN,	    0, LEN_AND_STR("%transfiletriggerun")},
    { PART_TRANSFILETRIGGERPOSTUN,  0, LEN_AND_STR("%transfiletriggerpostun")},
    { PART_EMPTY,		    0, LEN_AND_STR("%end")},
    { PART_PATCHLIST,               1, LEN_AND_STR("%patchlist")},
    { PART_SOURCELIST,              1, LEN_AND_STR("%sourcelist")},
    {0, 0, 0, 0}
};

int isPart(const char *line)
{
    const struct PartRec *p;

    for (p = partList; p->token != NULL; p++) {
	char c;
	if (rstrncasecmp(line, p->token, p->len))
	    continue;
	c = *(line + p->len);
	if (c == '\0' || risspace(c))
	    break;
    }

    return (p->token ? p->part : PART_NONE);
}

static const struct PartRec * getPart(int part)
{
    const struct PartRec *p;

    for (p = partList; p->token != NULL; p++) {
	if (p->part == part) {
	    return p;
	}
    }
    return NULL;
}

/**
 */
static int matchTok(const char *token, const char *line)
{
    const char *b, *be = line;
    size_t toklen = strlen(token);
    int rc = 0;

    while ( *(b = be) != '\0' ) {
	SKIPSPACE(b);
	be = b;
	SKIPNONSPACE(be);
	if (be == b)
	    break;
	if (toklen != (be-b) || rstrncasecmp(token, b, (be-b)))
	    continue;
	rc = 1;
	break;
    }

    return rc;
}

int handleComments(char *s)
{
    SKIPSPACE(s);
    if (*s == '#') {
	*s = '\0';
	return 1;
    }
    return 0;
}

static void ofilineMacro(rpmMacroBuf mb,
			rpmMacroEntry me, ARGV_t margs, size_t *parsed)
{
    OFI_t *ofi = (OFI_t *)rpmMacroEntryPriv(me);
    if (ofi) {
	char lnobuf[16];
	snprintf(lnobuf, sizeof(lnobuf), "%d", ofi->lineNum);
	rpmMacroBufAppendStr(mb, lnobuf);
    }
}

/* Push a file to spec's file stack, return the newly pushed entry */
static OFI_t * pushOFI(rpmSpec spec, const char *fn)
{
    OFI_t *ofi = (OFI_t *)xcalloc(1, sizeof(*ofi));

    ofi->fp = NULL;
    ofi->fileName = xstrdup(fn);
    ofi->lineNum = 0;
    ofi->readBufLen = BUFSIZ;
    ofi->readBuf = (char *)xmalloc(ofi->readBufLen);
    ofi->readBuf[0] = '\0';
    ofi->readPtr = NULL;
    ofi->next = spec->fileStack;

    rpmPushMacroFlags(spec->macros, "__file_name", NULL, fn, RMIL_SPEC, RPMMACRO_LITERAL);
    rpmPushMacroAux(spec->macros, "__file_lineno", NULL, ofilineMacro, ofi, -1, 0, 0);

    spec->fileStack = ofi;
    return spec->fileStack;
}

/* Pop from spec's file stack */
static OFI_t * popOFI(rpmSpec spec)
{
    if (spec->fileStack) {
	OFI_t * ofi = spec->fileStack;

	spec->fileStack = ofi->next;
	if (ofi->fp)
	    fclose(ofi->fp);
	free(ofi->fileName);
	free(ofi->readBuf);
	free(ofi);
	rpmPopMacro(spec->macros, "__file_name");
	rpmPopMacro(spec->macros, "__file_lineno");
    }
    return spec->fileStack;
}

static int restoreFirstChar(rpmSpec spec)
{
    /* Restore 1st char in (possible) next line */
    if (spec->nextline != NULL && spec->nextpeekc != '\0') {
	*spec->nextline = spec->nextpeekc;
	spec->nextpeekc = '\0';
	return 1;
    }
    return 0;
}

static parsedSpecLine parseLineType(char *line)
{
    parsedSpecLine condition;

    for (condition = lineTypes; condition->text != NULL; condition++) {
	if (condition->withArgs) {
	    if (ISMACROWITHARG(line, condition->text, condition->textLen))
		return condition;
	} else {
	    if (ISMACRO(line, condition->text, condition->textLen))
		return condition;
	}
    }

    return NULL;
}

int specExpand(rpmSpec spec, int lineno, const char *sbuf,
		char **obuf)
{
    return (rpmExpandMacros(spec->macros, sbuf, obuf, 0) < 0);
}

static int expandMacrosInSpecBuf(rpmSpec spec, int strip)
{
    char *lbuf = NULL;
    int isComment = 0;
    parsedSpecLine condition;
    OFI_t *ofi = spec->fileStack;

    lbuf = spec->lbuf;
    SKIPSPACE(lbuf);
    if (lbuf[0] == '#')
	isComment = 1;

    condition = parseLineType(lbuf);
    if ((condition) && (!condition->withArgs)) {
	const char *s = lbuf + condition->textLen;
	SKIPSPACE(s);
	if (s[0] && s[0] != '#') {
	    rpmlog(RPMLOG_ERR,
		_("extra tokens at the end of %s directive in line %d:  %s\n"),
		condition->text, spec->lineNum, lbuf);
	    return 1;
	}
    }

    /* Don't expand macros after %elif (resp. %elifarch, %elifos) in a false branch */
    if (condition && (condition->id & LINE_ELIFANY)) {
	if (!spec->readStack->readable)
	    return 0;
    /* Don't expand macros (eg. %define) in false branch of %if clause */
    } else {
	if (!spec->readStack->reading)
	    return 0;
    }

    if (specExpand(spec, ofi->lineNum, spec->lbuf, &lbuf))
	return 1;

    if (strip & STRIP_COMMENTS && isComment) {
	char *bufA = spec->lbuf;
	char *bufB = lbuf;

	while (*bufA != '\0' && *bufB != '\0') {
	    if (*bufA == '%' && *(bufA + 1) == '%')
		bufA++;

	    if (*bufA != *bufB)
		break;

	    bufA++;
	    bufB++;
	}

	if (*bufA != '\0' || *bufB != '\0')
	    rpmlog(RPMLOG_WARNING,
		_("Macro expanded in comment on line %d: %s\n"),
		spec->lineNum, bufA);
    }

    free(spec->lbuf);
    spec->lbuf = lbuf;
    spec->lbufSize = strlen(spec->lbuf) + 1;

    return 0;
}

/* Return zero on success, 1 if we need to read more and -1 on errors. */
static int copyNextLineFromOFI(rpmSpec spec, OFI_t *ofi, int strip)
{
    /* Expand next line from file into line buffer */
    if (!(spec->nextline && *spec->nextline)) {
	int pc = 0, bc = 0, xc = 0, nc = 0;
	const char *from = ofi->readPtr;
	char ch = ' ';
	while (from && *from && ch != '\n') {
	    ch = spec->lbuf[spec->lbufOff] = *from;
	    spec->lbufOff++; from++;

	    if (spec->lbufOff >= spec->lbufSize) {
		spec->lbufSize += BUFSIZ;
		spec->lbuf = xrealloc(spec->lbuf, spec->lbufSize);
	    }
	}
	spec->lbuf[spec->lbufOff] = '\0';
	ofi->readPtr = from;

	/* Check if we need another line before expanding the buffer. */
	for (const char *p = spec->lbuf; *p; p++) {
	    switch (*p) {
		case '\\':
		    switch (*(p+1)) {
			case '\n': p++, nc = 1; break;
			case '\0': break;
			default: p++; break;
		    }
		    break;
		case '\n': nc = 0; break;
		case '%':
		    switch (*(p+1)) {
			case '{': p++, bc++; break;
			case '(': p++, pc++; break;
			case '[': p++, xc++; break;
			case '%': p++; break;
		    }
		    break;
		case '{': if (bc > 0) bc++; break;
		case '}': if (bc > 0) bc--; break;
		case '(': if (pc > 0) pc++; break;
		case ')': if (pc > 0) pc--; break;
		case '[': if (xc > 0) xc++; break;
		case ']': if (xc > 0) xc--; break;
	    }
	}
	
	/* If it doesn't, ask for one more line. */
	if (pc || bc || xc || nc ) {
	    spec->nextline = NULL;
	    return 1;
	}
	spec->lbufOff = 0;

	if (expandMacrosInSpecBuf(spec, strip))
	    return -1;

	spec->nextline = spec->lbuf;
    }
    return 0;
}

static parsedSpecLine copyNextLineFinish(rpmSpec spec, int strip)
{
    char *last;
    char ch;
    char *s;
    parsedSpecLine lineType;

    /* Find next line in expanded line buffer */
    s = spec->line = last = spec->nextline;
    ch = ' ';

    /* skip space until '\n' or non space is reached */
    while (*(s) && (*s != '\n') && risspace(*(s)))
	(s)++;
    lineType = parseLineType(s);

    while (*spec->nextline && ch != '\n') {
	/* for conditionals and %include trim trailing '\' */
	if (lineType && (*spec->nextline == '\\') &&
	    (*spec->nextline+1) && (*(spec->nextline+1) == '\n')) {
	    *spec->nextline = ' ';
	    *(spec->nextline+1) = ' ';
	}
	ch = *spec->nextline++;
	if (!risspace(ch))
	    last = spec->nextline;
    }

    /* Save 1st char of next line in order to terminate current line. */
    if (*spec->nextline != '\0') {
	spec->nextpeekc = *spec->nextline;
	*spec->nextline = '\0';
    }
    
    if (strip & STRIP_COMMENTS)
	handleComments(spec->line);
    
    if (strip & STRIP_TRAILINGSPACE)
	*last = '\0';

    return lineType;
}

static int readLineFromOFI(rpmSpec spec, OFI_t *ofi)
{
retry:
    /* Make sure the current file is open */
    if (ofi->fp == NULL) {
	ofi->fp = fopen(ofi->fileName, "r");
	if (ofi->fp == NULL) {
	    rpmlog(RPMLOG_ERR, _("Unable to open %s: %s\n"),
		     ofi->fileName, strerror(errno));
	    return PART_ERROR;
	}
	spec->lineNum = ofi->lineNum = 0;
    }

    /* Make sure we have something in the read buffer */
    if (!(ofi->readPtr && *(ofi->readPtr))) {
	if (getline(&ofi->readBuf, &ofi->readBufLen, ofi->fp) <= 0) {
	    /* EOF, remove this file from the stack */
	    ofi = popOFI(spec);

	    /* only on last file do we signal EOF to caller */
	    if (ofi == NULL)
		return 1;

	    /* otherwise, go back and try the read again. */
	    goto retry;
	}
	ofi->readPtr = ofi->readBuf;
	ofi->lineNum++;
	spec->lineNum = ofi->lineNum;
    }
    return 0;
}

#define ARGMATCH(s,token,match) \
do { \
    char *os = s; \
    char *exp = rpmExpand(token, NULL); \
    while (*s && !risblank(*s)) s++; \
    while (*s && risblank(*s)) s++; \
    if (!*s) { \
	rpmlog(RPMLOG_ERR, _("%s:%d: Argument expected for %s\n"), ofi->fileName, ofi->lineNum, os); \
	free(exp); \
	return PART_ERROR; \
    } \
    match = matchTok(exp, s); \
    free(exp); \
} while (0)


int readLine(rpmSpec spec, int strip)
{
    char *s;
    int match = 0;
    struct ReadLevelEntry *rl;
    OFI_t *ofi = spec->fileStack;
    int rc;
    int startLine = 0;
    parsedSpecLine lineType;
    int prevType = spec->readStack->lastConditional->id;
    int checkCondition;

    if (!restoreFirstChar(spec)) {
retry:
	if ((rc = readLineFromOFI(spec, ofi)) != 0) {
	    if (spec->readStack->next) {
		rpmlog(RPMLOG_ERR, _("line %d: Unclosed %%if\n"),
			spec->readStack->lineNum);
		rc = PART_ERROR;
	    } else if (startLine > 0) {
		rpmlog(RPMLOG_ERR,
		    _("line %d: unclosed macro or bad line continuation\n"),
		    startLine);
		rc = PART_ERROR;
	    }
	    return rc;
	}
	ofi = spec->fileStack;

	/* Copy next file line into the spec line buffer */
	rc = copyNextLineFromOFI(spec, ofi, strip);
	if (rc > 0) {
	    if (startLine == 0)
		startLine = spec->lineNum;
	    goto retry;
	} else if (rc < 0) {
	    return PART_ERROR;
	}
    }

    lineType = copyNextLineFinish(spec, strip);
    s = spec->line;
    SKIPSPACE(s);
    if (!lineType)
	goto after_classification;

    /* check ordering of the conditional */
    if (lineType->isConditional && (prevType & lineType->wrongPrecursors)) {
	if (prevType == LINE_ENDIF) {
	    rpmlog(RPMLOG_ERR,_("%s: line %d: %s with no %%if\n"),
		ofi->fileName, ofi->lineNum, lineType->text);
	} else {
	    rpmlog(RPMLOG_ERR,_("%s: line %d: %s after %s\n"),
		ofi->fileName, ofi->lineNum, lineType->text,
		spec->readStack->lastConditional->text);
	}
	return PART_ERROR;
    }

    if (lineType->id & (LINE_IFARCH | LINE_ELIFARCH)) {
	ARGMATCH(s, "%{_target_cpu}", match);
    } else if (lineType->id == LINE_IFNARCH) {
	ARGMATCH(s, "%{_target_cpu}", match);
	match = !match;
    } else if (lineType->id & (LINE_IFOS | LINE_ELIFOS)) {
	ARGMATCH(s, "%{_target_os}", match);
    } else if (lineType->id == LINE_IFNOS) {
	ARGMATCH(s, "%{_target_os}", match);
	match = !match;
    } else if (lineType->id & (LINE_IF | LINE_ELIF)) {
	s += lineType->textLen;
	if (lineType->id == LINE_IF)
	    checkCondition = spec->readStack->reading;
	else
	    checkCondition = spec->readStack->readable;
	if (checkCondition) {
	    match = rpmExprBoolFlags(s, 0);
	    if (match < 0) {
		rpmlog(RPMLOG_ERR,
			    _("%s:%d: bad %s condition: %s\n"),
			    ofi->fileName, ofi->lineNum, lineType->text, s);
		return PART_ERROR;
	    }
	}
    } else if (lineType->id == LINE_ELSE) {
	spec->readStack->lastConditional = lineType;
	spec->readStack->reading =
	    spec->readStack->next->reading && spec->readStack->readable;
	spec->line[0] = '\0';
    } else if (lineType->id == LINE_ENDIF) {
	rl = spec->readStack;
	spec->readStack = spec->readStack->next;
	free(rl);
	spec->line[0] = '\0';
    } else if (spec->readStack->reading && (lineType->id == LINE_INCLUDE)) {
	char *fileName, *endFileName, *p;

	fileName = s+8;
	SKIPSPACE(fileName);
	endFileName = fileName;
	do {
	    SKIPNONSPACE(endFileName);
	    p = endFileName;
	    SKIPSPACE(p);
	    if (*p != '\0') endFileName = p;
	} while (*p != '\0');
	if (*fileName == '\0') {
	    rpmlog(RPMLOG_ERR, _("%s:%d: malformed %%include statement\n"),
				ofi->fileName, ofi->lineNum);
	    return PART_ERROR;
	}
	*endFileName = '\0';

	ofi = pushOFI(spec, fileName);
	goto retry;
    }

    if (lineType->id & LINE_IFANY) {
	rl = (struct ReadLevelEntry *)xmalloc(sizeof(*rl));
	rl->reading = spec->readStack->reading && match;
	rl->next = spec->readStack;
	rl->lineNum = ofi->lineNum;
	rl->readable = (!rl->reading) && (spec->readStack->reading);
	rl->lastConditional = lineType;
	spec->readStack = rl;
	spec->line[0] = '\0';
    } else if (lineType->id & LINE_ELIFANY) {
	spec->readStack->reading = spec->readStack->readable && match;
	if (spec->readStack->reading)
	    spec->readStack->readable = 0;
	spec->line[0] = '\0';
    }

after_classification:
    if (! spec->readStack->reading) {
	spec->line[0] = '\0';
    }

    /* Collect parsed line */
    if (spec->parsed == NULL)
	spec->parsed = newStringBuf();
    appendStringBufAux(spec->parsed, spec->line,(strip & STRIP_TRAILINGSPACE));

    /* FIX: spec->readStack->next should be dependent */
    return 0;
}

int parseLines(rpmSpec spec, int strip, ARGV_t *avp, StringBuf *sbp)
{
    int rc, nextPart = PART_ERROR;
    int nl = (strip & STRIP_TRAILINGSPACE);

    if ((rc = readLine(spec, strip)) > 0) {
	nextPart = PART_NONE;
	goto exit;
    } else if (rc < 0) {
	goto exit;
    }

    if (sbp && *sbp == NULL)
	*sbp = newStringBuf();

    while (! (nextPart = isPart(spec->line))) {
	/* HACK: Emit a legible error on the obsolete %patchN form for now */
	if (sbp == &(spec->sections[SECT_PREP])) {
	    size_t slen = strlen(spec->line);
	    if (slen >= 7 && risdigit(spec->line[6]) &&
		rstreqn(spec->line, "%patch", 6))
	    {
		rpmlog(RPMLOG_ERR, _("%%patchN is obsolete, "
		    "use %%patch N (or %%patch -P N): %s\n"), spec->line);
		nextPart = PART_ERROR;
		break;
	    }
	}
	if (avp)
	    argvAdd(avp, spec->line);
	if (sbp)
	    appendStringBufAux(*sbp, spec->line, nl);
	if ((rc = readLine(spec, strip)) > 0) {
	    nextPart = PART_NONE;
	    break;
	} else if (rc < 0) {
	    nextPart = PART_ERROR;
	    break;
	}
    }

exit:
    return nextPart;
}

void closeSpec(rpmSpec spec)
{
    while (popOFI(spec)) {};
}

static const rpmTagVal sourceTags[] = {
    RPMTAG_NAME,
    RPMTAG_VERSION,
    RPMTAG_RELEASE,
    RPMTAG_EPOCH,
    RPMTAG_SUMMARY,
    RPMTAG_DESCRIPTION,
    RPMTAG_PACKAGER,
    RPMTAG_DISTRIBUTION,
    RPMTAG_DISTURL,
    RPMTAG_DISTTAG,
    RPMTAG_VENDOR,
    RPMTAG_LICENSE,
    RPMTAG_GROUP,
    RPMTAG_OS,
    RPMTAG_ARCH,
    RPMTAG_CHANGELOGTIME,
    RPMTAG_CHANGELOGNAME,
    RPMTAG_CHANGELOGTEXT,
    RPMTAG_URL,
    RPMTAG_BUGURL,
    RPMTAG_TRANSLATIONURL,
    RPMTAG_UPSTREAMRELEASES,
    RPMTAG_HEADERI18NTABLE,
    RPMTAG_VCS,
    RPMTAG_MODULARITYLABEL,
    0
};

static int initSourceHeader(rpmSpec spec)
{
    Package sourcePkg = spec->sourcePackage;
    struct Source *srcPtr;
    int rc = 0;

    if (headerIsEntry(sourcePkg->header, RPMTAG_NAME))
	return rc;

    char *os = rpmExpand("%{_target_os}", NULL);
    headerPutString(sourcePkg->header, RPMTAG_OS, os);
    free(os);

    /* Only specific tags are added to the source package header */
    headerCopyTags(spec->packages->header, sourcePkg->header, sourceTags);

    /* Add the build restrictions */
    for (int i=0; i<PACKAGE_NUM_DEPS; i++) {
	rpmdsPutToHeader(sourcePkg->dependencies[i], sourcePkg->header);
    }

    {
	HeaderIterator hi = headerInitIterator(spec->buildRestrictions);
	struct rpmtd_s td;
	while (headerNext(hi, &td)) {
	    if (rpmtdCount(&td) > 0) {
		(void) headerPut(sourcePkg->header, &td, HEADERPUT_DEFAULT);
	    }
	    rpmtdFreeData(&td);
	}
	headerFreeIterator(hi);
    }

    if (spec->BANames && spec->BACount > 0) {
	headerPutStringArray(sourcePkg->header, RPMTAG_BUILDARCHS,
		  spec->BANames, spec->BACount);
    }

    /* Add tags for sources and patches */
    for (srcPtr = spec->sources; srcPtr != NULL; srcPtr = srcPtr->next) {
	char *fn = rpmExpand(srcPtr->source, NULL);
	if (srcPtr->flags & RPMBUILD_ISSOURCE) {
	    headerPutString(sourcePkg->header, RPMTAG_SOURCE, fn);
	    if (srcPtr->flags & RPMBUILD_ISNO) {
		headerPutUint32(sourcePkg->header, RPMTAG_NOSOURCE,
				&srcPtr->num, 1);
	    }
	}
	if (srcPtr->flags & RPMBUILD_ISPATCH) {
	    headerPutString(sourcePkg->header, RPMTAG_PATCH, fn);
	    if (srcPtr->flags & RPMBUILD_ISNO) {
		headerPutUint32(sourcePkg->header, RPMTAG_NOPATCH,
				&srcPtr->num, 1);
	    }
	}
	free(fn);
    }
    if (spec->sourceRpmName == NULL) {
	char *nvr = headerGetAsString(spec->packages->header, RPMTAG_NVR);
	rasprintf(&spec->sourceRpmName, "%s.%ssrc.rpm", nvr,
		spec->noSource ? "no" : "");
	free(nvr);
    }

    rc = checkForRequired(spec->sourcePackage->header);

    return rc;
}

static void finalizeSourceHeader(rpmSpec spec)
{
    uint32_t one = 1;

    /* Only specific tags are added to the source package header */
    headerPutUint32(spec->sourcePackage->header, RPMTAG_SOURCEPACKAGE, &one, 1);
    headerCopyTags(spec->packages->header, spec->sourcePackage->header, sourceTags);

    /* Provide all package NEVRs that would be built */
    for (Package p = spec->packages; p != NULL; p = p->next) {
	if (p->fileList) {
	    Header h = spec->sourcePackage->header;
	    uint32_t dsflags = rpmdsFlags(p->ds);
	    headerPutString(h, RPMTAG_PROVIDENAME, rpmdsN(p->ds));
	    headerPutUint32(h, RPMTAG_PROVIDEFLAGS, &dsflags, 1);
	    headerPutString(h, RPMTAG_PROVIDEVERSION, rpmdsEVR(p->ds));
	}
    }
}

/* Add extra provides to package.  */
void addPackageProvides(Package pkg)
{
    const char *arch, *name;
    char *evr, *isaprov;
    rpmsenseFlags pflags = RPMSENSE_EQUAL;

    /* <name> = <evr> provide */
    name = headerGetString(pkg->header, RPMTAG_NAME);
    arch = headerGetString(pkg->header, RPMTAG_ARCH);
    evr = headerGetAsString(pkg->header, RPMTAG_EVR);
    addReqProv(pkg, RPMTAG_PROVIDENAME, name, evr, pflags, 0);

    /*
     * <name>(<isa>) = <evr> provide
     * FIXME: noarch needs special casing for now as BuildArch: noarch doesn't
     * cause reading in the noarch macros :-/ 
     */
    isaprov = rpmExpand(name, "%{?_isa}", NULL);
    if (!rstreq(arch, "noarch") && !rstreq(name, isaprov)) {
	addReqProv(pkg, RPMTAG_PROVIDENAME, isaprov, evr, pflags, 0);
    }
    free(isaprov);
    free(evr);
}

static void addArch(rpmSpec spec)
{
    char *arch = rpmExpand("%{_target_cpu}", NULL);

    for (Package pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	/* noarch subpackages already have arch set here, leave it alone */
	if (!headerIsEntry(pkg->header, RPMTAG_ARCH)) {
	    headerPutString(pkg->header, RPMTAG_ARCH, arch);
	}
    }
    free(arch);
}

rpmRC checkForEncoding(Header h, int addtag)
{
    rpmRC rc = RPMRC_OK;
#ifdef HAVE_ICONV
    const char *encoding = "utf-8";
    rpmTagVal tag;
    iconv_t ic;
    char *dest = NULL;
    size_t destlen = 0;
    int strict = rpmExpandNumeric("%{_invalid_encoding_terminates_build}");
    HeaderIterator hi = headerInitIterator(h);

    ic = iconv_open(encoding, encoding);
    if (ic == (iconv_t) -1) {
	rpmlog(RPMLOG_WARNING,
		_("encoding %s not supported by system\n"), encoding);
	goto exit;
    }

    while ((tag = headerNextTag(hi)) != RPMTAG_NOT_FOUND) {
	struct rpmtd_s td;
	const char *src = NULL;

	if (rpmTagGetClass(tag) != RPM_STRING_CLASS)
	    continue;

	headerGet(h, tag, &td, (HEADERGET_RAW|HEADERGET_MINMEM));
	while ((src = rpmtdNextString(&td)) != NULL) {
	    size_t srclen = strlen(src);
	    size_t outlen, inlen = srclen;
	    char *out, *in = (char *) src;

	    if (destlen < srclen) {
		destlen = srclen * 2;
		dest = xrealloc(dest, destlen);
	    }
	    out = dest;
	    outlen = destlen;

	    /* reset conversion state */
	    iconv(ic, NULL, &inlen, &out, &outlen);

	    if (iconv(ic, &in, &inlen, &out, &outlen) == (size_t) -1) {
		rpmlog(strict ? RPMLOG_ERR : RPMLOG_WARNING,
			_("Package %s: invalid %s encoding in %s: %s - %s\n"),
			headerGetString(h, RPMTAG_NAME),
			encoding, rpmTagGetName(tag), src, strerror(errno));
		rc = RPMRC_FAIL;
	    }

	}
	rpmtdFreeData(&td);
    }

    /* Stomp "known good utf" mark in header if requested */
    if (rc == RPMRC_OK && addtag)
	headerPutString(h, RPMTAG_ENCODING, encoding);
    if (!strict)
	rc = RPMRC_OK;

exit:
    if (ic != (iconv_t) -1)
	iconv_close(ic);
    headerFreeIterator(hi);
    free(dest);
#endif /* HAVE_ICONV */

    return rc;
}

static int parseEmpty(rpmSpec spec, int prevParsePart)
{
    int res = PART_ERROR;
    int nextPart, rc;
    char *line;

    if (prevParsePart != PART_NONE) {
	line = spec->line + sizeof("%end") - 1;
	SKIPSPACE(line);
	if (line[0] != '\0') {
	    rpmlog(RPMLOG_ERR,
		   _("line %d: %%end doesn't take any arguments: %s\n"),
		   spec->lineNum, spec->line);
	    goto exit;
	}
    }

    if (prevParsePart == PART_EMPTY) {
	rpmlog(RPMLOG_ERR,
	    _("line %d: %%end not expected here, no section to close: %s\n"),
	    spec->lineNum, spec->line);
	goto exit;
    }

    if ((rc = readLine(spec, STRIP_TRAILINGSPACE|STRIP_COMMENTS)) > 0) {
	nextPart = PART_NONE;
    } else if (rc < 0) {
	goto exit;
    } else {
	while (! (nextPart = isPart(spec->line))) {
	    line = spec->line;
	    SKIPSPACE(line);

	    if (line[0] != '\0') {
		rpmlog(RPMLOG_ERR,
		    _("line %d doesn't belong to any section: %s\n"),
		    spec->lineNum, spec->line);
		goto exit;
	    }
	    if ((rc = readLine(spec, STRIP_TRAILINGSPACE|STRIP_COMMENTS)) > 0) {
		nextPart = PART_NONE;
		break;
	    } else if (rc < 0) {
		goto exit;
	    }
	}
    }

    res = nextPart;

exit:
    return res;
}

struct sectname_s sectList[] = {
    { "prep", SECT_PREP, PART_PREP, 0 },
    { "conf", SECT_CONF, PART_CONF, 0 },
    { "generate_buildrequires", SECT_BUILDREQUIRES, PART_BUILDREQUIRES, 0 },
    { "build", SECT_BUILD, PART_BUILD, 1 },
    { "install", SECT_INSTALL, PART_INSTALL, 1 },
    { "check", SECT_CHECK, PART_CHECK, 0 },
    { "clean", SECT_CLEAN, PART_CLEAN, 0 },
    { NULL, -1, -1, 0 }
};

const struct sectname_s *getSection(const char *name, int part)
{
    for (const struct sectname_s *sc = sectList; sc->name; sc++) {
	if (name && rstreq(name, sc->name))
	    return sc;
	if (part && part == sc->part)
	    return sc;
    }
    return NULL;
}

int checkBuildsystem(rpmSpec spec, const char *name)
{
    if (rpmCharCheck(spec, name,
			ALLOWED_CHARS_NAME, ALLOWED_FIRSTCHARS_NAME))
	return -1;

    int rc = 0;
    int found = 0;
    char * mmn = NULL;
    for (struct sectname_s *sc = sectList; sc->name; sc++) {
	char *mn = rstrscat(NULL, "buildsystem_", name, "_", sc->name, NULL);
	if (!rpmMacroIsParametric(NULL, mn)) {
	    if (sc->required) {
		if (!mmn)
		    mmn = xstrdup(mn);
		rc = -1;
	    }
	} else {
	    found = 1;
	}
	free(mn);
    }

    if (!found) {
	rpmlog(RPMLOG_ERR, _("line %d: Unknown buildsystem: %s\n"),
	       spec->lineNum, name);
    } else if (mmn) {
	rpmlog(RPMLOG_ERR,
	       _("line %d: Required parametric macro %%%s not defined for buildsystem %s\n"),
		spec->lineNum, mmn, name);
    }
    free(mmn);
    return rc;
}

static rpmRC parseBuildsysSect(rpmSpec spec, const char *prefix,
				struct sectname_s *sc, FD_t fd)
{
    rpmRC rc = RPMRC_OK;

    if (spec->sections[sc->section] == NULL) {
	char *mn = rstrscat(NULL, "buildsystem_", prefix, "_", sc->name, NULL);
	if (rpmMacroIsParametric(NULL, mn)) {
	    char *args = NULL;
	    if (spec->buildopts[sc->section]) {
		ARGV_t av = NULL;
		argvAdd(&av, "--");
		argvAppend(&av, spec->buildopts[sc->section]);
		args = argvJoin(av, " ");
		argvFree(av);
	    }
	    char *buf = rstrscat(NULL, "%", sc->name, "\n",
				       "%", mn, " ",
				       args ? args : "",
				       "\n", NULL);
	    size_t blen = strlen(buf);
	    if (Fwrite(buf, blen, 1, fd) < blen) {
		rc = RPMRC_FAIL;
		rpmlog(RPMLOG_ERR,
			    _("failed to write buildsystem %s %%%s: %s\n"),
			    prefix, sc->name, strerror(errno));
	    }
	    free(buf);
	    free(args);
	}
	free(mn);
    }
    return rc;
}

static rpmRC parseBuildsystem(rpmSpec spec)
{
    rpmRC rc = RPMRC_OK;
    char *buildsystem = rpmExpand("%{?buildsystem}", NULL);
    if (*buildsystem) {
	char *path = NULL;

	FD_t fd = rpmMkTempFile(NULL, &path);
	if (fd == NULL) {
	    rpmlog(RPMLOG_ERR,
		_("failed to create temp file for buildsystem: %s\n"),
		strerror(errno));
	    rc = RPMRC_FAIL;
	    goto exit;
	}

	for (struct sectname_s *sc = sectList; !rc && sc->name; sc++) {
	    rc = parseBuildsysSect(spec, buildsystem, sc, fd);
	    if (!rc && spec->sections[sc->section] == NULL)
		rc = parseBuildsysSect(spec, "default", sc, fd);
	}

	if (!rc)
	    rc = parseSpecParts(spec, path, PARSE_BUILDSYS);
	if (!rc)
	    unlink(path);
	Fclose(fd);
	free(path);
    }

exit:
    free(buildsystem);
    return rc;
}

static rpmRC applyAppendPrepend(rpmSpec spec)
{
    for (struct sectname_s *sc = sectList; sc->name; sc++) {
	ARGV_const_t sp = spec->sectionparts[sc->section];
	if (sp) {
	    int nparts = argvCount(sp);
	    int *modes = argiData(spec->sectionops[sc->section]);
	    StringBuf *sbp = &spec->sections[sc->section];
	    if (*sbp == NULL)
		*sbp = newStringBuf();
	    for (int i = 0; i < nparts; i++) {
		if (modes[i] == PARSE_APPEND) {
		    appendStringBuf(*sbp, sp[i]);
		} else if (modes[i] == PARSE_PREPEND) {
		    StringBuf nbuf = newStringBuf();
		    appendStringBuf(nbuf, sp[i]);
		    appendStringBuf(nbuf, getStringBuf(*sbp));
		    freeStringBuf(*sbp);
		    *sbp = nbuf;
		}
	    }
	}
    }
    return RPMRC_OK;
}

static rpmSpec parseSpec(const char *specFile, rpmSpecFlags flags,
			 const char *buildRoot, int recursing);

/* is part allowed at this stage */
static int checkPart(int parsePart, enum parseStages stage) {
    if (stage == PARSE_GENERATED) {
	const struct PartRec *p = getPart(parsePart);
	if (p && p->prebuildonly ) {
	    rpmlog(RPMLOG_ERR, _("Section %s is not allowed after build is done!\n"), p->token);
	    return 1;
	}
    }
    return 0;
}

static int parseBuildScript(rpmSpec spec, int part)
{
    const struct sectname_s *sc = getSection(NULL, part);
    if (sc == NULL) /* can't happen */
	return -1;

    int mode = 0;
    int rc = parseSimpleScript(spec, sc->name,
				&spec->sections[sc->section],
				&spec->sectionparts[sc->section],
				&mode);

    if (mode) {
	int ix = argvCount(spec->sectionparts[sc->section]);
	argiAdd(&spec->sectionops[sc->section], ix-1, mode);
    }

    return rc;
}

static rpmRC parseSpecSection(rpmSpec *specptr, enum parseStages stage)
{
    rpmSpec spec = *specptr;
    int parsePart = PART_PREAMBLE;
    int prevParsePart = PART_EMPTY;
    int storedParsePart;
    int initialPackage = 1;

    /* All the parse*() functions expect to have a line pre-read */
    /* in the spec's line buffer.  Except for parsePreamble(),   */
    /* which handles the initial entry into a spec file.         */
    
    while (parsePart != PART_NONE) {
	int goterror = 0;
	storedParsePart = parsePart;
	switch (parsePart) {
	case PART_ERROR: /* fallthrough */
	default:
	    goterror = 1;
	    break;
	case PART_EMPTY:
	    parsePart = parseEmpty(spec, prevParsePart);
	    break;
	case PART_PREAMBLE:
	    parsePart = parsePreamble(spec, initialPackage, stage);
	    initialPackage = 0;
	    break;
	case PART_PATCHLIST:
	    parsePart = parseList(spec, "%patchlist", RPMTAG_PATCH);
	    break;
	case PART_SOURCELIST:
	    parsePart = parseList(spec, "%sourcelist", RPMTAG_SOURCE);
	    break;
	case PART_PREP:
	    rpmPushMacroAux(NULL, "setup", "-", doSetupMacro, spec, -1, 0, 0);
	    rpmPushMacroAux(NULL, "patch", "-", doPatchMacro, spec, -1, 0, 0);
	    parsePart = parseBuildScript(spec, parsePart);
	    rpmPopMacro(NULL, "patch");
	    rpmPopMacro(NULL, "setup");
	    break;
	case PART_CONF:
	case PART_BUILDREQUIRES:
	case PART_BUILD:
	case PART_INSTALL:
	case PART_CHECK:
	case PART_CLEAN:
	    parsePart = parseBuildScript(spec, parsePart);
	    break;
	case PART_CHANGELOG:
	    parsePart = parseChangelog(spec);
	    break;
	case PART_DESCRIPTION:
	    parsePart = parseDescription(spec);
	    break;

	case PART_PRE:
	case PART_POST:
	case PART_PREUN:
	case PART_POSTUN:
	case PART_PRETRANS:
	case PART_POSTTRANS:
	case PART_PREUNTRANS:
	case PART_POSTUNTRANS:
	case PART_VERIFYSCRIPT:
	case PART_TRIGGERPREIN:
	case PART_TRIGGERIN:
	case PART_TRIGGERUN:
	case PART_TRIGGERPOSTUN:
	case PART_FILETRIGGERIN:
	case PART_FILETRIGGERUN:
	case PART_FILETRIGGERPOSTUN:
	case PART_TRANSFILETRIGGERIN:
	case PART_TRANSFILETRIGGERUN:
	case PART_TRANSFILETRIGGERPOSTUN:
	    parsePart = parseScript(spec, parsePart);
	    break;

	case PART_FILES:
	    parsePart = parseFiles(spec);
	    break;

	case PART_POLICIES:
	    parsePart = parsePolicies(spec);
	    break;

	case PART_NONE:		/* XXX avoid gcc whining */
	case PART_LAST:
	case PART_BUILDARCHITECTURES:
	    break;
	}
	prevParsePart = storedParsePart;

	if (goterror || parsePart >= PART_LAST) {
	    goto errxit;
	}

	if (checkPart(parsePart, stage)) {
	    goto errxit;
	}
	if (parsePart == PART_BUILDARCHITECTURES) {
	    int index;
	    int x;

	    closeSpec(spec);

	    spec->BASpecs = (rpmSpec *)xcalloc(spec->BACount, sizeof(*spec->BASpecs));
	    index = 0;
	    if (spec->BANames != NULL)
	    for (x = 0; x < spec->BACount; x++) {

		/* Skip if not arch is not compatible. */
		if (!rpmMachineScore(RPM_MACHTABLE_BUILDARCH, spec->BANames[x]))
		    continue;
		rpmPushMacro(NULL, "_target_cpu", NULL, spec->BANames[x], RMIL_RPMRC);
		spec->BASpecs[index] = parseSpec(spec->specFile, spec->flags, spec->buildRoot, 1);
		if (spec->BASpecs[index] == NULL) {
			spec->BACount = index;
			goto errxit;
		}
		rpmPopMacro(NULL, "_target_cpu");
		index++;
	    }

	    spec->BACount = index;
	    if (! index) {
		rpmlog(RPMLOG_ERR,
			_("No compatible architectures found for build\n"));
		goto errxit;
	    }

	    /*
	     * Return the 1st child's fully parsed Spec structure.
	     * The restart of the parse when encountering BuildArch
	     * causes problems for "rpm -q --specfile". This is
	     * still a hack because there may be more than 1 arch
	     * specified (unlikely but possible.) There's also the
	     * further problem that the macro context, particularly
	     * %{_target_cpu}, disagrees with the info in the header.
	     */
	    if (spec->BACount >= 1) {
		rpmSpec nspec = spec->BASpecs[0];
		spec->BASpecs = _free(spec->BASpecs);
		rpmSpecFree(spec);
		*specptr = spec = nspec;
	    }

	    goto exit;
	}
    }

    if (stage == PARSE_SPECFILE) {
	if (parseBuildsystem(spec))
	    goto errxit;
	if (applyAppendPrepend(spec))
	    goto errxit;
    }

    /* Add arch for each package */
    addArch(spec);

    /* Check for encoding in each package unless disabled */
    if (!(spec->flags & RPMSPEC_NOUTF8)) {
	int badenc = 0;
	for (Package pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	    if (checkForEncoding(pkg->header, 0) != RPMRC_OK) {
		badenc = 1;
	    }
	}
	if (badenc)
	    goto errxit;
    }

    closeSpec(spec);

exit:
    return RPMRC_OK;

errxit:
    return RPMRC_FAIL;
}



static rpmSpec parseSpec(const char *specFile, rpmSpecFlags flags,
			 const char *buildRoot, int recursing)
{
    rpmSpec spec;

    /* Set up a new Spec structure with no packages. */
    spec = newSpec();

    spec->specFile = rpmGetPath(specFile, NULL);
    pushOFI(spec, spec->specFile);
    /* If explicit --buildroot was passed, grab hold of it */
    if (buildRoot)
	spec->buildRoot = xstrdup(buildRoot);

    /* Grab top builddir on first entry as we'll override _builddir */
    if (!rpmMacroIsDefined(spec->macros, "_top_builddir")) {
	char *top_builddir = rpmExpand("%{_builddir}", NULL);
	rpmPushMacroFlags(spec->macros, "_top_builddir", NULL,
			top_builddir, RMIL_GLOBAL, RPMMACRO_LITERAL);

	/* Undefine (!!) %_builddir so %global misuses fall through */
	while (rpmMacroIsDefined(spec->macros, "_builddir"))
	    rpmPopMacro(spec->macros, "_builddir");
	free(top_builddir);
    }

    rpmPushMacro(NULL, "_docdir", NULL, "%{_defaultdocdir}", RMIL_SPEC);
    rpmPushMacro(NULL, "_licensedir", NULL, "%{_defaultlicensedir}", RMIL_SPEC);
    spec->recursing = recursing;
    spec->flags = flags;

    if (parseSpecSection(&spec, PARSE_SPECFILE) != RPMRC_OK)
	goto errxit;

    /* Assemble source header from parsed components */
    if (initSourceHeader(spec))
	goto errxit;
    return spec;

errxit:
    spec = rpmSpecFree(spec);
    return NULL;
}

static rpmRC finalizeSpec(rpmSpec spec)
{
    rpmRC rc = RPMRC_FAIL;

    char *platform = rpmExpand("%{_target_platform}", NULL);
    char *os = rpmExpand("%{_target_os}", NULL);
    char *optflags = rpmExpand("%{optflags}", NULL);

    /* XXX Skip valid arch check if not building binary package */
    if (!(spec->flags & RPMSPEC_ANYARCH) && checkForValidArchitectures(spec)) {
	goto exit;
    }

    fillOutMainPackage(spec->packages->header);
    /* Define group tag to something when group is undefined in main package*/
    if (!headerIsEntry(spec->packages->header, RPMTAG_GROUP)) {
	headerPutString(spec->packages->header, RPMTAG_GROUP, "Unspecified");
    }

    for (Package pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	headerPutString(pkg->header, RPMTAG_OS, os);
	headerPutString(pkg->header, RPMTAG_PLATFORM, platform);
	headerPutString(pkg->header, RPMTAG_OPTFLAGS, optflags);
	headerPutString(pkg->header, RPMTAG_SOURCERPM, spec->sourceRpmName);


	if (pkg != spec->packages) {
	    copyInheritedTags(pkg->header, spec->packages->header);
	}

	/* Add manual dependencies early for rpmspec etc to look at */
	addPackageProvides(pkg);

	for (int i=0; i<PACKAGE_NUM_DEPS; i++) {
	    rpmdsPutToHeader(pkg->dependencies[i], pkg->header);
	}

	pkg->ds = rpmdsThis(pkg->header, RPMTAG_REQUIRENAME, RPMSENSE_EQUAL);

	if (checkForRequired(pkg->header)) {
	    goto exit;
	}
	if (!headerIsEntry(pkg->header, RPMTAG_DESCRIPTION)) {
	    rpmlog(RPMLOG_ERR, _("Package has no %%description: %s\n"),
		   headerGetString(pkg->header, RPMTAG_NAME));
	    goto exit;
	}
	if (checkForDuplicates(pkg->header)) {
	    goto exit;
	}
    }

    finalizeSourceHeader(spec);

    rc = RPMRC_OK;
 exit:
    free(platform);
    free(os);
    free(optflags);
    return rc;
}

rpmSpec rpmSpecParse(const char *specFile, rpmSpecFlags flags,
		     const char *buildRoot)
{
    rpmSpec spec = parseSpec(specFile, flags, buildRoot, 0);
    if (spec && !(flags & RPMSPEC_NOFINALIZE)) {
	finalizeSpec(spec);
    }
    return spec;
}

static rpmRC parseSpecParts(rpmSpec spec, const char *pattern,
			    enum parseStages stage)
{
    ARGV_t argv = NULL;
    int argc = 0;
    rpmRC rc = RPMRC_OK;

    /* rpmGlob returns files sorted */
    if (rpmGlob(pattern, &argc, &argv) == 0) {
	for (int i = 0; i < argc; i++) {
	    rpmlog(RPMLOG_INFO, "Reading %s\n", argv[i]);
	    pushOFI(spec, argv[i]);
	    snprintf(spec->fileStack->readBuf, spec->fileStack->readBufLen,
		     "# Spec part read from %s\n\n", argv[i]);
	    if (parseSpecSection(&spec, stage) != RPMRC_OK) {
		rpmlog(RPMLOG_ERR, "parsing failed\n");
		rc = RPMRC_FAIL;
		break;
	    }
	}
	argvFree(argv);
    }
    return rc;
}

rpmRC parseGeneratedSpecs(rpmSpec spec)
{
    char * specPattern = rpmGenPath("%{specpartsdir}", NULL, "*.specpart");
    rpmRC rc = parseSpecParts(spec, specPattern, PARSE_GENERATED);
    free(specPattern);
    if (!rc) {
	rc = finalizeSpec(spec);
	if (rc != RPMRC_OK) {
	    rpmlog(RPMLOG_ERR, "parsing failed\n");
	}
    }
    return rc;
}
