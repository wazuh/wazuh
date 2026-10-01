/** \ingroup rpmbuild
 * \file build/spec.c
 * Handle spec data structure.
 */

#include "system.h"
#include <errno.h>

#include <rpm/header.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmts.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>

#include "rpmfi_internal.h"		/* rpmfiles stuff */
#include "rpmbuild_internal.h"

#include "debug.h"

#define SKIPSPACE(s) { while (*(s) && risspace(*(s))) (s)++; }

/**
 * @param p		trigger entry chain
 * @return		NULL always
 */
static inline
struct TriggerFileEntry * freeTriggerFiles(struct TriggerFileEntry * p)
{
    struct TriggerFileEntry *o, *q = p;
    
    while (q != NULL) {
	o = q;
	q = q->next;
	o->fileName = _free(o->fileName);
	o->script = _free(o->script);
	o->prog = _free(o->prog);
	free(o);
    }
    return NULL;
}

struct Source * freeSources(struct Source * s)
{
    struct Source *r, *t = s;

    while (t != NULL) {
	r = t;
	t = t->next;
	r->fullSource = _free(r->fullSource);
	r->path = _free(r->path);
	free(r);
    }
    return NULL;
}

rpmRC lookupPackage(rpmSpec spec, const char *name, int flag,Package *pkg)
{
    char *fullName = NULL;
    rpmsid nameid = 0;
    Package p;

    /* "main" package */
    if (name == NULL) {
	if (pkg)
	    *pkg = spec->packages;
	return RPMRC_OK;
    }

    /* Construct partial package name */
    if (!(flag & PART_NAME)) {
	rasprintf(&fullName, "%s-%s",
		 headerGetString(spec->packages->header, RPMTAG_NAME), name);
	name = fullName;
    }
    nameid = rpmstrPoolId(spec->pool, name, 1);

    /* Locate package the name */
    for (p = spec->packages; p != NULL; p = p->next) {
	if (p->name && p->name == nameid) {
	    break;
	}
    }

    if (!(flag & PART_QUIET)) {
	if (p == NULL && pkg != NULL) {
	    rpmlog(RPMLOG_ERR, _("line %d: %s: package %s does not exist\n"),
				    spec->lineNum, spec->line, name);
	} else if (p != NULL && pkg == NULL) {
	    rpmlog(RPMLOG_ERR, _("line %d: %s: package %s already exists\n"),
				    spec->lineNum, spec->line, name);
	}
    }

    if (fullName == name)
	free(fullName);

    if (pkg)
	*pkg = p;
    return ((p == NULL) ? RPMRC_FAIL : RPMRC_OK);
}

Package newPackage(const char *name, rpmstrPool pool, Package *pkglist)
{
    Package p = (Package)xcalloc(1, sizeof(*p));
    p->header = headerNew();
    p->autoProv = 1;
    p->autoReq = 1;
    p->fileList = NULL;
    p->fileExcludeList = NULL;
    p->fileFile = NULL;
    p->policyList = NULL;
    p->fileRenameMap = NULL;
    p->pool = rpmstrPoolLink(pool);
    p->dpaths = NULL;

    if (name)
	p->name = rpmstrPoolId(p->pool, name, 1);

    if (pkglist) {
	if (*pkglist == NULL) {
	    *pkglist = p;
	} else {
	    Package pp;
	    /* Always add package to end of list */
	    for (pp = *pkglist; pp->next != NULL; pp = pp->next)
		{};
	    pp->next = p;
	}
    }
    p->next = NULL;

    return p;
}

Package freePackage(Package pkg)
{
    if (pkg == NULL) return NULL;
    
    pkg->filename = _free(pkg->filename);
    pkg->preInFile = _free(pkg->preInFile);
    pkg->postInFile = _free(pkg->postInFile);
    pkg->preUnFile = _free(pkg->preUnFile);
    pkg->postUnFile = _free(pkg->postUnFile);
    pkg->verifyFile = _free(pkg->verifyFile);
    pkg->preTransFile = _free(pkg->preTransFile);
    pkg->postTransFile = _free(pkg->postTransFile);
    pkg->preunTransFile = _free(pkg->preunTransFile);
    pkg->postunTransFile = _free(pkg->postunTransFile);

    pkg->header = headerFree(pkg->header);
    pkg->ds = rpmdsFree(pkg->ds);

    for (int i=0; i<PACKAGE_NUM_DEPS; i++) {
	pkg->dependencies[i] = rpmdsFree(pkg->dependencies[i]);
    }

    pkg->fileList = argvFree(pkg->fileList);
    pkg->fileExcludeList = argvFree(pkg->fileExcludeList);
    pkg->fileFile = argvFree(pkg->fileFile);
    pkg->policyList = argvFree(pkg->policyList);
    pkg->removePostfixes = argvFree(pkg->removePostfixes);
    pkg->fileRenameMap = fileRenameHashFree(pkg->fileRenameMap);
    pkg->cpioList = rpmfilesFree(pkg->cpioList);
    pkg->dpaths = argvFree(pkg->dpaths);

    pkg->icon = freeSources(pkg->icon);
    pkg->triggerFiles = freeTriggerFiles(pkg->triggerFiles);
    pkg->fileTriggerFiles = freeTriggerFiles(pkg->fileTriggerFiles);
    pkg->transFileTriggerFiles = freeTriggerFiles(pkg->transFileTriggerFiles);
    pkg->pool = rpmstrPoolFree(pkg->pool);

    free(pkg);
    return NULL;
}

static Package freePackages(Package packages)
{
    Package p;

    while ((p = packages) != NULL) {
	packages = p->next;
	p->next = NULL;
	freePackage(p);
    }
    return NULL;
}

rpmds * packageDependencies(Package pkg, rpmTagVal tag)
{
    for (int i=0; i<PACKAGE_NUM_DEPS; i++) {
	if (pkg->dependencies[i] == NULL) {
	    return &pkg->dependencies[i];
	}
	rpmTagVal tagN = rpmdsTagN(pkg->dependencies[i]);
	if (tagN == tag || tagN == 0) {
	    return &pkg->dependencies[i];
	}
    }
    return NULL;
}

rpmSpec newSpec(void)
{
    rpmSpec spec = (rpmSpec)xcalloc(1, sizeof(*spec));
    
    spec->specFile = NULL;

    spec->fileStack = NULL;
    spec->lbufSize = BUFSIZ * 10;
    spec->lbuf = (char *)xmalloc(spec->lbufSize);
    spec->lbuf[0] = '\0';
    spec->line = spec->lbuf;
    spec->nextline = NULL;
    spec->nextpeekc = '\0';
    spec->lineNum = 0;
    spec->readStack = (struct ReadLevelEntry*)xcalloc(1, sizeof(*spec->readStack));
    spec->readStack->next = NULL;
    spec->readStack->reading = 1;
    spec->readStack->lastConditional = lineTypes;
    spec->readStack->readable = 1;

    spec->rootDir = NULL;

    spec->sources = NULL;
    spec->packages = NULL;
    spec->noSource = 0;
    spec->numSources = 0;
    spec->autonum_patch = -1;
    spec->autonum_source = -1;

    spec->sourceRpmName = NULL;
    spec->sourcePkgId = NULL;
    spec->sourcePackage = NULL;
    
    spec->buildRoot = NULL;
    spec->buildDir = NULL;

    spec->buildRestrictions = headerNew();
    spec->BANames = NULL;
    spec->BACount = 0;
    spec->recursing = 0;
    spec->BASpecs = NULL;

    spec->flags = RPMSPEC_NONE;

    spec->macros = rpmGlobalMacroContext;
    spec->pool = rpmstrPoolCreate();
    
    specLuaInit(spec);
    return spec;
}

rpmSpec rpmSpecFree(rpmSpec spec)
{

    if (spec == NULL) return NULL;

    for (int i = 0; i < NR_SECT; i++)
	freeStringBuf(spec->sections[i]);
    freeStringBuf(spec->parsed);

    spec->buildRoot = _free(spec->buildRoot);
    spec->buildDir = _free(spec->buildDir);
    spec->specFile = _free(spec->specFile);

    closeSpec(spec);

    while (spec->readStack) {
	struct ReadLevelEntry *rl = spec->readStack;
	spec->readStack = rl->next;
	rl->next = NULL;
	free(rl);
    }
    spec->lbuf = _free(spec->lbuf);
    
    spec->sourceRpmName = _free(spec->sourceRpmName);
    spec->sourcePkgId = _free(spec->sourcePkgId);
    spec->sourcePackage = freePackage(spec->sourcePackage);

    spec->buildRestrictions = headerFree(spec->buildRestrictions);

    for (int i = 0; i < NR_SECT; i++) {
	argvFree(spec->buildopts[i]);
	argvFree(spec->sectionparts[i]);
	argiFree(spec->sectionops[i]);
    }

    if (!spec->recursing) {
	if (spec->BASpecs != NULL)
	while (spec->BACount--) {
	    spec->BASpecs[spec->BACount] =
			rpmSpecFree(spec->BASpecs[spec->BACount]);
	}
	spec->BASpecs = _free(spec->BASpecs);
    }
    spec->BANames = _free(spec->BANames);

    // only destroy lua tables if there are no BASpecs left
    if (spec->recursing || spec->BACount == 0) {
	specLuaFini(spec);
    }

    spec->sources = freeSources(spec->sources);
    spec->packages = freePackages(spec->packages);
    spec->pool = rpmstrPoolFree(spec->pool);

    spec->buildHost = _free(spec->buildHost);

    spec = _free(spec);

    return spec;
}

Header rpmSpecSourceHeader(rpmSpec spec)
{
    return (spec && spec->sourcePackage) ? spec->sourcePackage->header : NULL;
}

rpmds rpmSpecDS(rpmSpec spec, rpmTagVal tag)
{
    return (spec != NULL) ? rpmdsNew(spec->sourcePackage->header, tag, 0) : NULL;
}

rpmps rpmSpecCheckDeps(rpmts ts, rpmSpec spec)
{
    rpmps probs = NULL;

    rpmtsEmpty(ts);

    rpmtsAddInstallElement(ts, rpmSpecSourceHeader(spec), NULL, 0, NULL);
    rpmtsCheck(ts);
    probs = rpmtsProblems(ts);

    rpmtsEmpty(ts);
    return probs;
}

struct rpmSpecIter_s {
    void *next;
};

#define SPEC_LISTITER_INIT(_itertype, _iteritem)	\
    _itertype iter = NULL;				\
    if (spec) {						\
	iter = (_itertype)xcalloc(1, sizeof(*iter));		\
	iter->next = spec->_iteritem;			\
    }							\
    return iter

#define SPEC_LISTITER_NEXT(_valuetype)			\
    _valuetype item = NULL;				\
    if (iter) {						\
	item = (_valuetype)iter->next;				\
	iter->next = (item) ? item->next : NULL;	\
    }							\
    return item

#define SPEC_LISTITER_FREE()				\
    free(iter);						\
    return NULL


rpmSpecPkgIter rpmSpecPkgIterInit(rpmSpec spec)
{
    SPEC_LISTITER_INIT(rpmSpecPkgIter, packages);
}

rpmSpecPkgIter rpmSpecPkgIterFree(rpmSpecPkgIter iter)
{
    SPEC_LISTITER_FREE();
}

rpmSpecPkg rpmSpecPkgIterNext(rpmSpecPkgIter iter)
{
    SPEC_LISTITER_NEXT(rpmSpecPkg);
}

Header rpmSpecPkgHeader(rpmSpecPkg pkg)
{
    return (pkg != NULL) ? pkg->header : NULL;
}

char* rpmSpecPkgGetSection(rpmSpecPkg pkg, int section)
{
    if (pkg) {
        switch (section) {
        case RPMBUILD_FILE_FILE: return argvJoin(pkg->fileFile, "");
        case RPMBUILD_FILE_LIST: return argvJoin(pkg->fileList, "");
        case RPMBUILD_POLICY:    return argvJoin(pkg->policyList, "");
        }
    }
    return NULL;
}

rpmSpecSrcIter rpmSpecSrcIterInit(rpmSpec spec)
{
    SPEC_LISTITER_INIT(rpmSpecSrcIter, sources);
}

rpmSpecSrcIter rpmSpecSrcIterFree(rpmSpecSrcIter iter)
{
    SPEC_LISTITER_FREE();
}

rpmSpecSrc rpmSpecSrcIterNext(rpmSpecSrcIter iter)
{
    SPEC_LISTITER_NEXT(rpmSpecSrc);
}

rpmSourceFlags rpmSpecSrcFlags(rpmSpecSrc src)
{
    return (src != NULL) ? src->flags : 0;
}

int rpmSpecSrcNum(rpmSpecSrc src)
{
    return (src != NULL) ? src->num : -1;
}

const char * rpmSpecSrcFilename(rpmSpecSrc src, int full)
{
    const char *source = NULL;
    if (src) {
	source = full ? src->fullSource : src->source;
    }
    return source;
}

const char * rpmSpecGetSection(rpmSpec spec, int section)
{
    if (spec) {
	switch (section) {
	case RPMBUILD_NONE:
	    return getStringBuf(spec->parsed);
	case RPMBUILD_PREP:
	    return getStringBuf(spec->sections[SECT_PREP]);
	case RPMBUILD_CONF:
	    return getStringBuf(spec->sections[SECT_CONF]);
	case RPMBUILD_BUILDREQUIRES:
	    return getStringBuf(spec->sections[SECT_BUILDREQUIRES]);
	case RPMBUILD_BUILD:
	    return getStringBuf(spec->sections[SECT_BUILD]);
	case RPMBUILD_INSTALL:
	    return getStringBuf(spec->sections[SECT_INSTALL]);
	case RPMBUILD_CHECK:
	    return getStringBuf(spec->sections[SECT_CHECK]);
	case RPMBUILD_CLEAN:
	    return getStringBuf(spec->sections[SECT_CLEAN]);
	}
    }
    return NULL;
}

int rpmspecQuery(rpmts ts, QVA_t qva, const char * arg)
{
    rpmSpec spec = NULL;
    int res = 1;

    if (qva->qva_showPackage == NULL)
	goto exit;

    spec = rpmSpecParse(arg, (RPMSPEC_ANYARCH|RPMSPEC_FORCE), NULL);
    if (spec == NULL) {
	rpmlog(RPMLOG_ERR,
	    		_("query of specfile %s failed, can't parse\n"), arg);
	goto exit;
    }

    if (qva->qva_source == RPMQV_SPECRPMS ||
	    qva->qva_source == RPMQV_SPECBUILTRPMS) {

	res = 0;
	for (Package pkg = spec->packages; pkg != NULL; pkg = pkg->next) {

	    if (qva->qva_source == RPMQV_SPECBUILTRPMS && pkg->fileList == NULL)
		continue;

	    res += qva->qva_showPackage(qva, ts, pkg->header);
	}
    } else {
	Package sourcePkg = spec->sourcePackage;
	res = qva->qva_showPackage(qva, ts, sourcePkg->header);
    }

exit:
    rpmSpecFree(spec);
    return res;
}
