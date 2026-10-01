/** \ingroup rpmbuild
 * \file build/policies.c
 *  The post-build, packaging of policies
 */

#include "system.h"

#include <rpm/rpmbuild.h>
#include <rpm/argv.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmbase64.h>

#include "rpmio_internal.h"
#include "rpmbuild_internal.h"

#include "debug.h"

#ifdef WITH_SELINUX
enum rpmpolFlags_e {
	RPMPOL_FLAG_NONE = 0,
	RPMPOL_FLAG_BASE = (1 << 0)
};

typedef rpmFlags rpmpolFlags;

#define RPMPOL_TYPE_DEFAULT "default"
typedef struct ModuleRec_s {
    char *path;
    char *data;
    char *name;
    ARGV_t types;
    uint32_t flags;
} *ModuleRec;

static rpmRC writeModuleToHeader(ModuleRec mod, Package pkg)
{
    rpmRC rc = RPMRC_FAIL;
    ARGV_t av;
    uint32_t count;
    struct rpmtd_s policies;
    struct rpmtd_s policynames;
    struct rpmtd_s policyflags;
    struct rpmtd_s policytypes;
    struct rpmtd_s policytypesidx;
    rpmtdReset(&policies);
    rpmtdReset(&policynames);
    rpmtdReset(&policyflags);
    rpmtdReset(&policytypes);
    rpmtdReset(&policytypesidx);

    if (!mod || !pkg) {
	goto exit;
    }

    /* check for duplicates */
    if (headerIsEntry(pkg->header, RPMTAG_POLICYNAMES)) {
	int typeCount;
	const char *name;
	char *type;
	int i;
	int idx;

	headerGet(pkg->header, RPMTAG_POLICYNAMES, &policynames, HEADERGET_MINMEM);
	headerGet(pkg->header, RPMTAG_POLICYFLAGS, &policyflags, HEADERGET_ARGV | HEADERGET_MINMEM);
	headerGet(pkg->header, RPMTAG_POLICYTYPES, &policytypes, HEADERGET_ARGV | HEADERGET_MINMEM);
	headerGet(pkg->header, RPMTAG_POLICYTYPESINDEXES, &policytypesidx, HEADERGET_ARGV | HEADERGET_MINMEM);
	typeCount = rpmtdCount(&policytypes);

	while ((name = rpmtdNextString(&policynames))) {
	    int overlappingtypes = 0;

	    idx = rpmtdGetIndex(&policynames);

	    for (i = 0; i < typeCount; i++) {
		if (((int *) policytypesidx.data)[i] != idx) {
		    continue;
		}

		type = ((char **) policytypes.data)[i];

		if (rstreq(type, RPMPOL_TYPE_DEFAULT) ||
		    argvSearch(mod->types, type, NULL) ||
		    argvSearch(mod->types, RPMPOL_TYPE_DEFAULT, NULL)) {
		    overlappingtypes = 1;
		    break;
		}
	    }

	    if (!overlappingtypes) {
		continue;
	    }

	    if (rstreq(mod->name, name)) {
		rpmlog(RPMLOG_ERR, _("Policy module '%s' duplicated with overlapping types\n"), name);
		goto exit;
	    }

	    if ((mod->flags && RPMPOL_FLAG_BASE) &&
		(((int *) policyflags.data)[idx] & RPMPOL_FLAG_BASE)) {
		rpmlog(RPMLOG_ERR, _("Base modules '%s' and '%s' have overlapping types\n"), mod->name, name);
		goto exit;
	    }
	}
    }

    if (headerIsEntry(pkg->header, RPMTAG_POLICIES)) {
	if (!headerGet(pkg->header, RPMTAG_POLICIES, &policies, HEADERGET_MINMEM)) {
	    rpmlog(RPMLOG_ERR, _("Failed to get policies from header\n"));
	    goto exit;
	}
	count = rpmtdCount(&policies);
    } else {
	count = 0;
    }

    /* save everything to the header */
    headerPutString(pkg->header, RPMTAG_POLICIES, mod->data);
    headerPutString(pkg->header, RPMTAG_POLICYNAMES, mod->name);
    headerPutUint32(pkg->header, RPMTAG_POLICYFLAGS, &mod->flags, 1);

    for (av = mod->types; av && *av; av++) {
	headerPutString(pkg->header, RPMTAG_POLICYTYPES, *av);
	headerPutUint32(pkg->header, RPMTAG_POLICYTYPESINDEXES, &count, 1);
    }

    rc = RPMRC_OK;

  exit:

    rpmtdFreeData(&policies);
    rpmtdFreeData(&policynames);
    rpmtdFreeData(&policyflags);
    rpmtdFreeData(&policytypes);
    rpmtdFreeData(&policytypesidx);

    return rc;
}

static ModuleRec freeModule(ModuleRec mod)
{
    if (mod) {
	_free(mod->path);
	_free(mod->data);
	_free(mod->name);
	argvFree(mod->types);
	_free(mod);
    }

    return NULL;
}

static ModuleRec newModule(const char *path, const char *name,
			   const char *types, uint32_t flags)
{
    ModuleRec mod;
    uint8_t *raw = NULL;
    ssize_t rawlen = 0;
    const char *buildDir = "%{builddir}/%{?buildsubdir}/";

    if (!path) {
	rpmlog(RPMLOG_ERR, _("%%semodule requires a file path\n"));
	return NULL;
    }

    mod = (ModuleRec)xcalloc(1, sizeof(*mod));

    mod->path = rpmGenPath(buildDir, NULL, path);

    if ((rpmioSlurp(mod->path, &raw, &rawlen)) != 0 || raw == NULL) {
	rpmlog(RPMLOG_ERR, _("Failed to read  policy file: %s\n"),
	       mod->path);
	goto err;
    }

    mod->data = rpmBase64Encode(raw, rawlen, -1);
    if (!mod->data) {
	rpmlog(RPMLOG_ERR, _("Failed to encode policy file: %s\n"),
	       mod->path);
	goto err;
    }

    if (name) {
	mod->name = xstrdup(name);
    } else {
	/* assume base name (minus extension) if name is not given */
	char *tmp = xstrdup(mod->path);
	char *bname = basename(tmp);
	char *end = strchr(bname, '.');
	if (end)
	    *end = '\0';
	if (strlen(bname) > 0) {
	    mod->name = xstrdup(bname);
	} else {
	    rpmlog(RPMLOG_ERR, _("Failed to determine a policy name: %s\n"),
		   mod->path);
	    _free(tmp);
	    goto err;
	}
	_free(tmp);
    }

    if (types) {
	mod->types = argvSplitString(types, ",", ARGV_SKIPEMPTY);
	argvSort(mod->types, NULL);
	if (argvSearch(mod->types, RPMPOL_TYPE_DEFAULT, NULL) && argvCount(mod->types) > 1) {
	    rpmlog(RPMLOG_WARNING, _("'%s' type given with other types in %%semodule %s. Compacting types to '%s'.\n"),
		   RPMPOL_TYPE_DEFAULT, mod->path, RPMPOL_TYPE_DEFAULT);
	    mod->types = argvFree(mod->types);
	    argvAdd(&mod->types, RPMPOL_TYPE_DEFAULT);
	}
    } else {
	argvAdd(&mod->types, RPMPOL_TYPE_DEFAULT);
    }

    mod->flags = flags;

    return mod;

  err:
    freeModule(mod);
    return NULL;
}

static rpmRC processPolicies(rpmSpec spec, Package pkg, int test)
{
    const char *path = NULL;
    char *name = NULL;
    char *types = NULL;
    uint32_t flags = 0;
    poptContext optCon = NULL;
    ModuleRec mod = NULL;

    rpmRC rc = RPMRC_FAIL;

    struct poptOption optionsTable[] = {
	{"name",  'n', POPT_ARG_STRING, &name,  'n', NULL, NULL},
	{"types", 't', POPT_ARG_STRING, &types, 't', NULL, NULL},
	{"base",  'b', POPT_ARGFLAG_OR, &flags, RPMPOL_FLAG_BASE, NULL, NULL},
	POPT_TABLEEND
    };

    if (!spec || !pkg) {
	goto exit;
    }

    for (ARGV_const_t pol = pkg->policyList; *pol != NULL; pol++) {
	const char *line = *pol;
	const char **argv = NULL;
	int argc = 0;
	int err;

	if ((err = poptParseArgvString(line, &argc, &argv))) {
	    rpmlog(RPMLOG_ERR, _("Error parsing %s: %s\n"),
		   line, poptStrerror(err));
	    goto exit;
	}

	if (!rstreq(argv[0], "%semodule")) {
	    rpmlog(RPMLOG_ERR, _("Expecting %%semodule tag: %s\n"), line);
	    goto exit;
	}

	optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
	while (poptGetNextOpt(optCon) > 0) {
	}

	path = poptGetArg(optCon);
	if (!path) {
	    rpmlog(RPMLOG_ERR, _("Missing module path in line: %s\n"),
		   line);
	    goto exit;
	}

	if (poptPeekArg(optCon)) {
	    rpmlog(RPMLOG_ERR, _("Too many arguments in line: %s\n"),
		   line);
	    goto exit;
	}

	mod = newModule(path, name, types, flags);
	if (!mod) {
	    goto exit;
	}

	if (writeModuleToHeader(mod, pkg) != RPMRC_OK) {
	    goto exit;
	}

	mod = freeModule(mod);
	name = _free(name);
	types = _free(types);
	optCon = poptFreeContext(optCon);
    }

    rc = RPMRC_OK;

  exit:
    freeModule(mod);
    free(name);
    free(types);
    poptFreeContext(optCon);

    return rc;
}
#endif

rpmRC processBinaryPolicies(rpmSpec spec, int test)
{
    rpmRC rc = RPMRC_OK;
#ifdef WITH_SELINUX
    Package pkg;
    char *nvr;

    for (pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	if (pkg->policyList == NULL) {
	    continue;
	}

	nvr = headerGetAsString(pkg->header, RPMTAG_NVRA);
	rpmlog(RPMLOG_NOTICE, _("Processing policies: %s\n"), nvr);
	free(nvr);

	if (processPolicies(spec, pkg, test) != RPMRC_OK) {
	    rc = RPMRC_FAIL;
	    break;
	}
    }
#endif

    return rc;
}
