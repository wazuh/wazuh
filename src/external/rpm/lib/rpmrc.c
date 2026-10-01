#include "system.h"

#include <fcntl.h>
#include <stdarg.h>
#include <pthread.h>

#if defined(__linux__)
#include <elf.h>
#include <link.h>
#endif


#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#include <ctype.h>	/* XXX for /etc/rpm/platform contents */

#ifdef HAVE_SYS_SYSTEMCFG_H
#include <sys/systemcfg.h>
#else
#define __power_pc() 0
#endif

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

#include <rpm/rpmlib.h>			/* RPM_MACTABLE*, Rc-prototypes */
#include <rpm/rpmmacro.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>
#include <rpm/argv.h>

#include "rpmlua.h"
#include "rpmio_internal.h"	/* XXX for rpmioSlurp */
#include "misc.h"
#include "backend/dbi.h"
#include "rpmug.h"

#include "debug.h"

static const char * defrcfiles = NULL;
const char * macrofiles = NULL;

typedef struct machCacheEntry_s {
    char * name;
    int count;
    char ** equivs;
    int visited;
} * machCacheEntry;

typedef struct machCache_s {
    machCacheEntry cache;
    int size;
} * machCache;

typedef struct machEquivInfo_s {
    char * name;
    int score;
} * machEquivInfo;

typedef struct machEquivTable_s {
    int count;
    machEquivInfo list;
} * machEquivTable;

struct rpmvarValue {
    char * value;
    /* eventually, this arch will be replaced with a generic condition */
    char * arch;
struct rpmvarValue * next;
};

struct rpmOption {
    const char * name;
    int var;
    int archSpecific;
    int macroize;
    int localize;
};

static struct rpmat_s {
    const char *platform;
    uint64_t hwcap;
} rpmat;

typedef struct defaultEntry_s {
    char * name;
    char * defName;
} * defaultEntry;

typedef struct canonEntry_s {
    char * name;
    char * short_name;
    short num;
} * canonEntry;

/* tags are 'key'canon, 'key'translate, 'key'compat
 *
 * for giggles, 'key'_canon, 'key'_compat, and 'key'_canon will also work
 */
typedef struct tableType_s {
    const char *key;
    const int hasCanon;
    const int hasTranslate;
    struct machEquivTable_s equiv;
    struct machCache_s cache;
    defaultEntry defaults;
    canonEntry canons;
    int defaultsLength;
    int canonsLength;
} * tableType;

/* XXX get rid of this stuff... */
/* Stuff for maintaining "variables" like SOURCEDIR, BUILDDIR, etc */
#define RPMVAR_OPTFLAGS                 3
#define RPMVAR_ARCHCOLOR                42
#define RPMVAR_INCLUDE                  43
#define RPMVAR_MACROFILES               49

#define RPMVAR_NUM                      55      /* number of RPMVAR entries */

/* this *must* be kept in alphabetical order */
/* The order of the flags is archSpecific, macroize, localize */

static const struct rpmOption optionTable[] = {
    { "archcolor",		RPMVAR_ARCHCOLOR,               1, 0, 0 },
    { "include",		RPMVAR_INCLUDE,			0, 0, 2 },
    { "macrofiles",		RPMVAR_MACROFILES,		0, 0, 1 },
    { "optflags",		RPMVAR_OPTFLAGS,		1, 1, 0 },
};

static const size_t optionTableSize = sizeof(optionTable) / sizeof(*optionTable);

#define OS	0
#define ARCH	1

typedef struct rpmrcCtx_s * rpmrcCtx;
struct rpmrcCtx_s {
    ARGV_t platpat;
    char *current[2];
    int currTables[2];
    struct rpmvarValue values[RPMVAR_NUM];
    struct tableType_s tables[RPM_MACHTABLE_COUNT];
    int machDefaults;
    int pathDefaults;
    pthread_rwlock_t lock;
};

/* prototypes */
static rpmRC doReadRC(rpmrcCtx ctx, const char * urlfn);

static void rpmSetVarArch(rpmrcCtx ctx,
			  int var, const char * val, const char * arch);

static void rebuildCompatTables(rpmrcCtx ctx, int type, const char * name);

static void rpmRebuildTargetVars(rpmrcCtx ctx, const char **target, const char ** canontarget);

/* Force context (lock) acquisition through a function */
static rpmrcCtx rpmrcCtxAcquire(int write)
{
    static struct rpmrcCtx_s _globalCtx = {
	.currTables = { RPM_MACHTABLE_INSTOS, RPM_MACHTABLE_INSTARCH },
	.tables = {
	    { "arch", 1, 0 },
	    { "os", 1, 0 },
	    { "buildarch", 0, 1 },
	    { "buildos", 0, 1 }
	},
	.lock = PTHREAD_RWLOCK_INITIALIZER,
    };
    rpmrcCtx ctx = &_globalCtx;

    /* XXX: errors should be handled */
    if (write)
	pthread_rwlock_wrlock(&ctx->lock);
    else
	pthread_rwlock_rdlock(&ctx->lock);

    return ctx;
}

/* Release context (lock) */
static rpmrcCtx rpmrcCtxRelease(rpmrcCtx ctx)
{
    pthread_rwlock_unlock(&ctx->lock);
    return NULL;
}

static int optionCompare(const void * a, const void * b)
{
    return rstrcasecmp(((const struct rpmOption *) a)->name,
		      ((const struct rpmOption *) b)->name);
}

static machCacheEntry
machCacheFindEntry(const machCache cache, const char * key)
{
    int i;

    for (i = 0; i < cache->size; i++)
	if (rstreq(cache->cache[i].name, key)) return cache->cache + i;

    return NULL;
}

static int machCompatCacheAdd(char * name, const char * fn, int linenum,
				machCache cache)
{
    machCacheEntry entry = NULL;
    char * chptr;
    char * equivs;
    int delEntry = 0;
    int i;

    while (*name && risspace(*name)) name++;

    chptr = name;
    while (*chptr && *chptr != ':') chptr++;
    if (!*chptr) {
	rpmlog(RPMLOG_ERR, _("missing second ':' at %s:%d\n"), fn, linenum);
	return 1;
    } else if (chptr == name) {
	rpmlog(RPMLOG_ERR, _("missing architecture name at %s:%d\n"), fn,
			     linenum);
	return 1;
    }

    while (*chptr == ':' || risspace(*chptr)) chptr--;
    *(++chptr) = '\0';
    equivs = chptr + 1;
    while (*equivs && risspace(*equivs)) equivs++;
    if (!*equivs) {
	delEntry = 1;
    }

    if (cache->size) {
	entry = machCacheFindEntry(cache, name);
	if (entry) {
	    for (i = 0; i < entry->count; i++)
		entry->equivs[i] = _free(entry->equivs[i]);
	    entry->equivs = _free(entry->equivs);
	    entry->count = 0;
	}
    }

    if (!entry) {
	cache->cache = xrealloc(cache->cache,
			       (cache->size + 1) * sizeof(*cache->cache));
	entry = cache->cache + cache->size++;
	entry->name = xstrdup(name);
	entry->count = 0;
	entry->visited = 0;
    }

    if (delEntry) return 0;

    while ((chptr = strtok(equivs, " ")) != NULL) {
	equivs = NULL;
	if (chptr[0] == '\0')	/* does strtok() return "" ever?? */
	    continue;
	if (entry->count)
	    entry->equivs = xrealloc(entry->equivs, sizeof(*entry->equivs)
					* (entry->count + 1));
	else
	    entry->equivs = (char **)xmalloc(sizeof(*entry->equivs));

	entry->equivs[entry->count] = xstrdup(chptr);
	entry->count++;
    }

    return 0;
}

static machEquivInfo
machEquivSearch(const machEquivTable table, const char * name)
{
    int i;

    for (i = 0; i < table->count; i++)
	if (!rstrcasecmp(table->list[i].name, name))
	    return table->list + i;

    return NULL;
}

static void machAddEquiv(machEquivTable table, const char * name,
			   int distance)
{
    machEquivInfo equiv;

    equiv = machEquivSearch(table, name);
    if (!equiv) {
	if (table->count)
	    table->list = xrealloc(table->list, (table->count + 1)
				    * sizeof(*table->list));
	else
	    table->list = (machEquivInfo)xmalloc(sizeof(*table->list));

	table->list[table->count].name = xstrdup(name);
	table->list[table->count++].score = distance;
    }
}

static void machCacheEntryVisit(machCache cache,
		machEquivTable table, const char * name, int distance)
{
    machCacheEntry entry;
    int i;

    entry = machCacheFindEntry(cache, name);
    if (!entry || entry->visited) return;

    entry->visited = 1;

    for (i = 0; i < entry->count; i++) {
	machAddEquiv(table, entry->equivs[i], distance);
    }

    for (i = 0; i < entry->count; i++) {
	machCacheEntryVisit(cache, table, entry->equivs[i], distance + 1);
    }
}

static void machFindEquivs(machCache cache, machEquivTable table,
		const char * key)
{
    int i;

    for (i = 0; i < cache->size; i++)
	cache->cache[i].visited = 0;

    while (table->count > 0) {
	--table->count;
	table->list[table->count].name = _free(table->list[table->count].name);
    }
    table->count = 0;
    table->list = _free(table->list);

    /*
     *	We have a general graph built using strings instead of pointers.
     *	Yuck. We have to start at a point at traverse it, remembering how
     *	far away everything is.
     */
   	/* FIX: table->list may be NULL. */
    machAddEquiv(table, key, 1);
    machCacheEntryVisit(cache, table, key, 2);
    return;
}

static rpmRC addCanon(canonEntry * table, int * tableLen, char * line,
		    const char * fn, int lineNum)
{
    canonEntry t;
    char *s, *s1;
    const char * tname;
    const char * tshort_name;
    int tnum;

    (*tableLen) += 2;
    *table = xrealloc(*table, sizeof(**table) * (*tableLen));

    t = & ((*table)[*tableLen - 2]);

    tname = strtok(line, ": \t");
    tshort_name = strtok(NULL, " \t");
    s = strtok(NULL, " \t");
    if (! (tname && tshort_name && s)) {
	rpmlog(RPMLOG_ERR, _("Incomplete data line at %s:%d\n"),
		fn, lineNum);
	return RPMRC_FAIL;
    }
    if (strtok(NULL, " \t")) {
	rpmlog(RPMLOG_ERR, _("Too many args in data line at %s:%d\n"),
	      fn, lineNum);
	return RPMRC_FAIL;
    }

    tnum = strtoul(s, &s1, 10);
    if ((*s1) || (s1 == s) || (tnum == ULONG_MAX)) {
	rpmlog(RPMLOG_ERR, _("Bad arch/os number: %s (%s:%d)\n"), s,
	      fn, lineNum);
	return RPMRC_FAIL;
    }

    t[0].name = xstrdup(tname);
    t[0].short_name = (tshort_name ? xstrdup(tshort_name) : xstrdup(""));
    t[0].num = tnum;

    /* From A B C entry */
    /* Add  B B C entry */
    t[1].name = (tshort_name ? xstrdup(tshort_name) : xstrdup(""));
    t[1].short_name = (tshort_name ? xstrdup(tshort_name) : xstrdup(""));
    t[1].num = tnum;

    return RPMRC_OK;
}

static rpmRC addDefault(defaultEntry * table, int * tableLen, char * line,
			const char * fn, int lineNum)
{
    defaultEntry t;

    (*tableLen)++;
    *table = xrealloc(*table, sizeof(**table) * (*tableLen));

    t = & ((*table)[*tableLen - 1]);

    t->name = strtok(line, ": \t");
    t->defName = strtok(NULL, " \t");
    if (! (t->name && t->defName)) {
	rpmlog(RPMLOG_ERR, _("Incomplete default line at %s:%d\n"),
		 fn, lineNum);
	return RPMRC_FAIL;
    }
    if (strtok(NULL, " \t")) {
	rpmlog(RPMLOG_ERR, _("Too many args in default line at %s:%d\n"),
	      fn, lineNum);
	return RPMRC_FAIL;
    }

    t->name = xstrdup(t->name);
    t->defName = (t->defName ? xstrdup(t->defName) : NULL);

    return RPMRC_OK;
}

static canonEntry lookupInCanonTable(const char * name,
		const canonEntry table, int tableLen)
{
    while (tableLen) {
	tableLen--;
	if (!rstreq(name, table[tableLen].name))
	    continue;
	return &(table[tableLen]);
    }

    return NULL;
}

static
const char * lookupInDefaultTable(const char * name,
		const defaultEntry table, int tableLen)
{
    while (tableLen) {
	tableLen--;
	if (table[tableLen].name && rstreq(name, table[tableLen].name))
	    return table[tableLen].defName;
    }

    return name;
}

static void setDefaults(void)
{
    /* If either is missing, we need to go through this whole dance */
    if (defrcfiles && macrofiles)
	return;

    const char *confdir = rpmConfigDir();
    const char *xdgconf = getenv("XDG_CONFIG_HOME");
    if (!(xdgconf && *xdgconf))
	xdgconf = "~/.config";
    char *userdir = rpmGetPath(xdgconf, "/rpm", NULL);
    char *usermacros = rpmGetPath(userdir, "/macros", NULL);
    char *userrc = rpmGetPath(userdir, "/rpmrc", NULL);

    /*
     * Prefer XDG_CONFIG_HOME/rpm/{macros,rpmrc} but fall back to ~/.rpmmacros
     * and ~/.rpmrc iff either exists and the XDG rpm directory doesn't.
     */
    if (rpmGlob(userdir, NULL, NULL)) {
	const char *oldmacros = "~/.rpmmacros";
	const char *oldrc = "~/.rpmrc";
	if (rpmGlob(oldmacros, NULL, NULL) == 0 || rpmGlob(oldrc, NULL, NULL) == 0) {
	    free(usermacros);
	    free(userrc);
	    usermacros = xstrdup(oldmacros);
	    userrc = xstrdup(oldrc);
	}
    }

    if (!defrcfiles) {
	defrcfiles = rstrscat(NULL, confdir, "/rpmrc", ":",
				confdir, "/" RPM_VENDOR "/rpmrc", ":",
				SYSCONFDIR "/rpmrc", ":",
				userrc, NULL);
    }

    /* macrofiles may be pre-set from --macros */
    if (!macrofiles) {
	macrofiles = rstrscat(NULL, confdir, "/macros", ":",
				confdir, "/macros.d/macros.*", ":",
				confdir, "/platform/%{_target}/macros", ":",
				confdir, "/fileattrs/*.attr", ":",
				confdir, "/" RPM_VENDOR "/macros", ":",
				SYSCONFDIR "/rpm/macros.*", ":",
				SYSCONFDIR "/rpm/macros", ":",
				SYSCONFDIR "/rpm/%{_target}/macros", ":",
				usermacros, NULL);
    }

    free(usermacros);
    free(userrc);
    free(userdir);
}

/* FIX: se usage inconsistent, W2DO? */
static rpmRC doReadRC(rpmrcCtx ctx, const char * urlfn)
{
    char *s;
    char *se, *next, *buf = NULL, *fn;
    int linenum = 0;
    struct rpmOption searchOption, * option;
    rpmRC rc = RPMRC_FAIL;

    fn = rpmGetPath(urlfn, NULL);
    if (rpmioSlurp(fn, (uint8_t **) &buf, NULL) || buf == NULL) {
	goto exit;
    }
	
    next = buf;
    while (*next != '\0') {
	linenum++;

	s = se = next;

	/* Find end-of-line. */
	while (*se && *se != '\n') se++;
	if (*se != '\0') *se++ = '\0';
	next = se;

	/* Trim leading spaces */
	while (*s && risspace(*s)) s++;

	/* We used to allow comments to begin anywhere, but not anymore. */
	if (*s == '#' || *s == '\0') continue;

	/* Find end-of-keyword. */
	se = (char *)s;
	while (*se && !risspace(*se) && *se != ':') se++;

	if (risspace(*se)) {
	    *se++ = '\0';
	    while (*se && risspace(*se) && *se != ':') se++;
	}

	if (*se != ':') {
	    rpmlog(RPMLOG_ERR, _("missing ':' (found 0x%02x) at %s:%d\n"),
		     (unsigned)(0xff & *se), fn, linenum);
	    goto exit;
	}
	*se++ = '\0';	/* terminate keyword or option, point to value */
	while (*se && risspace(*se)) se++;

	/* Find keyword in table */
	searchOption.name = s;
	option = (struct rpmOption *)bsearch(&searchOption, optionTable,
			optionTableSize, sizeof(optionTable[0]), optionCompare);

	if (option) {	/* For configuration variables  ... */
	    const char *arch, *val;

	    arch = val = NULL;
	    if (*se == '\0') {
		rpmlog(RPMLOG_ERR, _("missing argument for %s at %s:%d\n"),
		      option->name, fn, linenum);
		goto exit;
	    }

	    if (option->var == RPMVAR_INCLUDE) {
		s = se;
		while (*se && !risspace(*se)) se++;
		if (*se != '\0') *se = '\0';

		if (doReadRC(ctx, s)) {
		    rpmlog(RPMLOG_ERR, _("cannot open %s at %s:%d: %m\n"),
			s, fn, linenum);
		    goto exit;
		}
		/* XXX don't save include value as var/macro */
		continue;
	    }

	    if (option->archSpecific) {
		arch = se;
		while (*se && !risspace(*se)) se++;
		if (*se == '\0') {
		    rpmlog(RPMLOG_ERR,
				_("missing architecture for %s at %s:%d\n"),
			  	option->name, fn, linenum);
		    goto exit;
		}
		*se++ = '\0';
		while (*se && risspace(*se)) se++;
		if (*se == '\0') {
		    rpmlog(RPMLOG_ERR,
				_("missing argument for %s at %s:%d\n"),
			  	option->name, fn, linenum);
		    goto exit;
		}
	    }
	
	    val = se;

	    /* Only add macros if appropriate for this arch */
	    if (option->macroize &&
	      (arch == NULL || rstreq(arch, ctx->current[ARCH]))) {
		char *n, *name;
		n = name = (char *)xmalloc(strlen(option->name)+2);
		if (option->localize)
		    *n++ = '_';
		strcpy(n, option->name);
		rpmPushMacro(NULL, name, NULL, val, RMIL_RPMRC);
		free(name);
	    }
	    rpmSetVarArch(ctx, option->var, val, arch);
	    fn = _free(fn);

	} else {	/* For arch/os compatibility tables ... */
	    int gotit;
	    int i;

	    gotit = 0;

	    for (i = 0; i < RPM_MACHTABLE_COUNT; i++) {
		if (rstreqn(ctx->tables[i].key, s, strlen(ctx->tables[i].key)))
		    break;
	    }

	    if (i < RPM_MACHTABLE_COUNT) {
		const char *rest = s + strlen(ctx->tables[i].key);
		if (*rest == '_') rest++;

		if (rstreq(rest, "compat")) {
		    if (machCompatCacheAdd(se, fn, linenum,
						&ctx->tables[i].cache))
			goto exit;
		    gotit = 1;
		} else if (ctx->tables[i].hasTranslate &&
			   rstreq(rest, "translate")) {
		    if (addDefault(&ctx->tables[i].defaults,
				   &ctx->tables[i].defaultsLength,
				   se, fn, linenum))
			goto exit;
		    gotit = 1;
		} else if (ctx->tables[i].hasCanon &&
			   rstreq(rest, "canon")) {
		    if (addCanon(&ctx->tables[i].canons,
				 &ctx->tables[i].canonsLength,
				 se, fn, linenum))
			goto exit;
		    gotit = 1;
		}
	    }

	    if (!gotit) {
		rpmlog(RPMLOG_ERR, _("bad option '%s' at %s:%d\n"),
			    s, fn, linenum);
		goto exit;
	    }
	}
    }
    rc = RPMRC_OK;

exit:
    free(fn);
    free(buf);

    return rc;
}


/**
 */
static rpmRC rpmPlatform(rpmrcCtx ctx, const char * platform)
{
    const char *cpu = NULL, *vendor = NULL, *os = NULL, *gnu = NULL;
    uint8_t * b = NULL;
    ssize_t blen = 0;
    int init_platform = 0;
    char * p, * pe;
    rpmRC rc;

    rc = (rpmioSlurp(platform, &b, &blen) == 0) ? RPMRC_OK : RPMRC_FAIL;

    if (rc || b == NULL || blen <= 0) {
	rc = RPMRC_FAIL;
	goto exit;
    }

    p = (char *)b;
    for (pe = p; p && *p; p = pe) {
	pe = strchr(p, '\n');
	if (pe)
	    *pe++ = '\0';

	while (*p && isspace(*p))
	    p++;
	if (*p == '\0' || *p == '#')
	    continue;

	if (init_platform) {
	    char * t = p + strlen(p);

	    while (--t > p && isspace(*t))
		*t = '\0';
	    if (t > p) {
		argvAdd(&ctx->platpat, p);
	    }
	    continue;
	}

	cpu = p;
	vendor = "unknown";
	os = "unknown";
	gnu = NULL;
	while (*p && !(*p == '-' || isspace(*p)))
	    p++;
	if (*p != '\0') *p++ = '\0';

	vendor = p;
	while (*p && !(*p == '-' || isspace(*p)))
	    p++;
	if (*p != '-') {
	    if (*p != '\0') *p = '\0';
	    os = vendor;
	    vendor = "unknown";
	} else {
	    if (*p != '\0') *p++ = '\0';

	    os = p;
	    while (*p && !(*p == '-' || isspace(*p)))
		p++;
	    if (*p == '-') {
		*p++ = '\0';

		gnu = p;
		while (*p && !(*p == '-' || isspace(*p)))
		    p++;
	    }
	    if (*p != '\0') *p = '\0';
	}

	rpmPushMacro(NULL, "_host_cpu", NULL, cpu, -1);
	rpmPushMacro(NULL, "_host_vendor", NULL, vendor, -1);
	rpmPushMacro(NULL, "_host_os", NULL, os, -1);

	char *plat = rpmExpand("%{_host_cpu}-%{_host_vendor}-%{_host_os}",
				(gnu && *gnu ? "-" : NULL), gnu, NULL);
	argvAdd(&ctx->platpat, plat);
	free(plat);
	
	init_platform++;
    }
    rc = (init_platform ? RPMRC_OK : RPMRC_FAIL);

exit:
    b = _free(b);
    return rc;
}

#	if defined(__linux__) && defined(__x86_64__)
#           if defined(__has_builtin)
#               if __has_builtin(__builtin_cpu_supports)
#                   define HAS_BUILTIN_CPU_SUPPORTS
#               endif
#           endif
#           if defined(HAS_BUILTIN_CPU_SUPPORTS)
static inline void cpuid(uint32_t op, uint32_t op2, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    asm volatile (
	"cpuid\n"
    : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
    : "a" (op), "c" (op2));
}

/* From gcc's gcc/config/i386/cpuid.h */
/* Features (%eax == 1) */
/* %ecx */
#define bit_SSE3	(1 << 0)
#define bit_SSSE3	(1 << 9)
#define bit_FMA		(1 << 12)
#define bit_CMPXCHG16B	(1 << 13)
#define bit_SSE4_1	(1 << 19)
#define bit_SSE4_2	(1 << 20)
#define bit_MOVBE	(1 << 22)
#define bit_POPCNT	(1 << 23)
#define bit_OSXSAVE	(1 << 27)
#define bit_AVX		(1 << 28)
#define bit_F16C	(1 << 29)

/* Extended Features (%eax == 0x80000001) */
/* %ecx */
#define bit_LAHF_LM	(1 << 0)
#define bit_LZCNT	(1 << 5)

/* Extended Features (%eax == 7) */
/* %ebx */
#define bit_BMI		(1 << 3)
#define bit_AVX2	(1 << 5)
#define bit_BMI2	(1 << 8)
#define bit_AVX512F	(1 << 16)
#define bit_AVX512DQ	(1 << 17)
#define bit_AVX512CD	(1 << 28)
#define bit_AVX512BW	(1 << 30)
#define bit_AVX512VL	(1u << 31)

static int get_x86_64_level(void)
{
    int level = 1;

    unsigned int op_0_eax = 0, op_1_ecx = 0, op_80000001_ecx = 0, op_7_ebx = 0, unused;
    cpuid(0, 0, &op_0_eax, &unused, &unused, &unused);
    cpuid(1, 0, &unused, &unused, &op_1_ecx, &unused);
    cpuid(0x80000001, 0, &unused, &unused, &op_80000001_ecx, &unused);
    cpuid(7, 0, &unused, &op_7_ebx, &unused, &unused);

    /* CPUID is unfortunately not quite enough: It indicates whether the hardware supports it,
     * but software support (kernel/hypervisor) is also needed for register saving/restoring.
     * For that we can ask the compiler's runtime lib through __builtin_cpu_supports. This is
     * not usable as a complete replacement for the CPUID code though as not all extensions are
     * supported (yet). */

    const unsigned int op_1_ecx_lv2 = bit_SSE3 | bit_SSSE3 | bit_CMPXCHG16B | bit_SSE4_1 | bit_SSE4_2 | bit_POPCNT;
    if ((op_1_ecx & op_1_ecx_lv2) == op_1_ecx_lv2 && (op_80000001_ecx & bit_LAHF_LM))
	level = 2;

    const unsigned int op_1_ecx_lv3 = bit_FMA | bit_MOVBE | bit_OSXSAVE | bit_AVX | bit_F16C;
    const unsigned int op_7_ebx_lv3 = bit_BMI | bit_AVX2 | bit_BMI2;
    if (level == 2 && (op_1_ecx & op_1_ecx_lv3) == op_1_ecx_lv3
        && op_0_eax >= 7 && (op_7_ebx & op_7_ebx_lv3) == op_7_ebx_lv3
        && (op_80000001_ecx & bit_LZCNT)
        && __builtin_cpu_supports("avx2"))
    {
        level = 3;
    }

    const unsigned int op_7_ebx_lv4 = bit_AVX512F | bit_AVX512DQ | bit_AVX512CD | bit_AVX512BW | bit_AVX512VL;
    if (level == 3 && (op_7_ebx & op_7_ebx_lv4) == op_7_ebx_lv4
        && __builtin_cpu_supports("avx512f"))
    {
        level = 4;
    }

    return level;
}
#           else /* defined(HAS_BUILTIN_CPU_SUPPORTS) */
static int get_x86_64_level(void)
{
    return 1;
}
#           endif
#	endif

#	if defined(__linux__) && defined(__i386__)
#include <setjmp.h>
#include <signal.h>

/*
 * Generic CPUID function
 */
static inline void cpuid(unsigned int op, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
    asm volatile (
	"pushl	%%ebx		\n"
	"cpuid			\n"
	"movl	%%ebx,	%%esi	\n"
	"popl	%%ebx		\n"
    : "=a" (*eax), "=S" (*ebx), "=c" (*ecx), "=d" (*edx)
    : "a" (op));
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int tmp, val;
	cpuid(op, &val, &tmp, &tmp, &tmp);
	return val;
}

static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int tmp, val;
	cpuid(op, &tmp, &val, &tmp, &tmp);
	return val;
}

static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int tmp, val;
	cpuid(op, &tmp, &tmp, &val, &tmp);
	return val;
}

static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int tmp, val;
	cpuid(op, &tmp, &tmp, &tmp, &val);
	return val;
}

static sigjmp_buf jenv;

static inline void model3(int _unused)
{
	siglongjmp(jenv, 1);
}

static inline int RPMClass(void)
{
	int cpu;
	unsigned int tfms, junk, cap, capamd;
	struct sigaction oldsa;
	
	sigaction(SIGILL, NULL, &oldsa);
	signal(SIGILL, model3);
	
	if (sigsetjmp(jenv, 1)) {
		sigaction(SIGILL, &oldsa, NULL);
		return 3;
	}
		
	if (cpuid_eax(0x000000000)==0) {
		sigaction(SIGILL, &oldsa, NULL);
		return 4;
	}

	cpuid(0x00000001, &tfms, &junk, &junk, &cap);
	cpuid(0x80000001, &junk, &junk, &junk, &capamd);
	
	cpu = (tfms>>8)&15;
	
	if (cpu == 5
	    && cpuid_ecx(0) == 0x3638784d /* '68xM' */
	    && cpuid_edx(0) == 0x54656e69 /* 'Teni' */
	    && (cpuid_edx(1) & ((1<<8)|(1<<15))) == ((1<<8)|(1<<15))) {
		sigaction(SIGILL, &oldsa, NULL);
		return 6;	/* has CX8 and CMOV */
	}

	sigaction(SIGILL, &oldsa, NULL);

#define USER686 ((1<<4) | (1<<8) | (1<<15))
	/* Transmeta Crusoe CPUs say that their CPU family is "5" but they have enough features for i686. */
	if (cpu == 5 && (cap & USER686) == USER686)
		return 6;

	if (cpu < 6)
		return cpu;
		
	if (cap & (1<<15)) {
		/* CMOV supported? */
		if (capamd & (1<<30))
			return 7;	/* 3DNOWEXT supported */
		return 6;
	}
		
	return 5;
}

/* should only be called for model 6 CPU's */
static int is_athlon(void)
{
	unsigned int eax, ebx, ecx, edx;
	char vendor[16];
	int i;
	
	cpuid (0, &eax, &ebx, &ecx, &edx);

 	memset(vendor, 0, sizeof(vendor));
 	
 	for (i=0; i<4; i++)
 		vendor[i] = (unsigned char) (ebx >>(8*i));
 	for (i=0; i<4; i++)
 		vendor[4+i] = (unsigned char) (edx >>(8*i));
 	for (i=0; i<4; i++)
 		vendor[8+i] = (unsigned char) (ecx >>(8*i));
 		
 	if (!rstreqn(vendor, "AuthenticAMD", 12))  
 		return 0;

	return 1;
}

static unsigned int x86_family(unsigned int processor_sig)
{
    unsigned int base_family = (processor_sig >> 8) & 0x0f;
    unsigned int family;
    if (base_family == 0x0f) {
	unsigned int extended_family = (processor_sig >> 20) & 0x0ff;
	family = base_family + extended_family;
    } else
	family = base_family;
    return family;
}

static unsigned int x86_model(unsigned int processor_sig)
{
    unsigned int base_model = (processor_sig >> 4) & 0x0f;
    unsigned int family = x86_family(processor_sig);
    unsigned int model;
    if (family >= 0x6) {
	unsigned int extended_model = (processor_sig >> 16) & 0x0f;
	model = (extended_model << 4) | base_model;
    } else
	model = base_model;
    return model;
}

static int is_pentium3(void)
{
    unsigned int eax, ebx, ecx, edx, family, model;
    char vendor[16];
    cpuid(0, &eax, &ebx, &ecx, &edx);
    memset(vendor, 0, sizeof(vendor));
    *((unsigned int *)&vendor[0]) = ebx;
    *((unsigned int *)&vendor[4]) = edx;
    *((unsigned int *)&vendor[8]) = ecx;
    if (!rstreqn(vendor, "GenuineIntel", 12))
	return 0;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    family = x86_family(eax);
    model = x86_model(eax);
    if (family == 6)
	switch (model)
	{
	    case 7:	// Pentium III, Pentium III Xeon (model 7)
	    case 8:	// Pentium III, Pentium III Xeon, Celeron (model 8)
	    case 9:	// Pentium M
	    case 10:	// Pentium III Xeon (model A)
	    case 11:	// Pentium III (model B)
		return 1;
	}
    return 0;
}

static int is_pentium4(void)
{
    unsigned int eax, ebx, ecx, edx, family, model;
    char vendor[16];
    cpuid(0, &eax, &ebx, &ecx, &edx);
    memset(vendor, 0, sizeof(vendor));
    *((unsigned int *)&vendor[0]) = ebx;
    *((unsigned int *)&vendor[4]) = edx;
    *((unsigned int *)&vendor[8]) = ecx;
    if (!rstreqn(vendor, "GenuineIntel", 12))
	return 0;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    family = x86_family(eax);
    model = x86_model(eax);
    if (family == 15)
	switch (model)
	{
	    case 0:	// Pentium 4, Pentium 4 Xeon                 (0.18um)
	    case 1:	// Pentium 4, Pentium 4 Xeon MP, Celeron     (0.18um)
	    case 2:	// Pentium 4, Mobile Pentium 4-M,
			// Pentium 4 Xeon, Pentium 4 Xeon MP,
			// Celeron, Mobile Celron                    (0.13um)
	    case 3:	// Pentium 4, Celeron                        (0.09um)
		return 1;
	}
    return 0;
}

static int is_geode(void)
{
    unsigned int eax, ebx, ecx, edx, family, model;
    char vendor[16];
    memset(vendor, 0, sizeof(vendor));
    
    cpuid(0, &eax, &ebx, &ecx, &edx);
    memset(vendor, 0, sizeof(vendor));
    *((unsigned int *)&vendor[0]) = ebx;
    *((unsigned int *)&vendor[4]) = edx;
    *((unsigned int *)&vendor[8]) = ecx;
    if (!rstreqn(vendor, "AuthenticAMD", 12))
        return 0;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    family = x86_family(eax);
    model = x86_model(eax);
    if (family == 5)
	switch (model)
	{
            case 10: // Geode 
                return 1;
        }
    return 0;
}
#endif


#if defined(__linux__)
/**
 * Populate rpmat structure with auxv values
 */
static void read_auxv(void)
{
    static int oneshot = 1;

    if (oneshot) {
#ifdef HAVE_GETAUXVAL
	rpmat.platform = (char *) getauxval(AT_PLATFORM);
	if (!rpmat.platform)
	    rpmat.platform = "";
	rpmat.hwcap = getauxval(AT_HWCAP);
#else
	rpmat.platform = "";
	int fd = open("/proc/self/auxv", O_RDONLY);

	if (fd == -1) {
	    rpmlog(RPMLOG_WARNING,
		   _("Failed to read auxiliary vector, /proc not mounted?\n"));
            return;
	} else {
	    ElfW(auxv_t) auxv;
	    while (read(fd, &auxv, sizeof(auxv)) == sizeof(auxv)) {
                switch (auxv.a_type)
                {
                    case AT_NULL:
                        break;
                    case AT_PLATFORM:
                        rpmat.platform = strdup((char *) auxv.a_un.a_val);
                        break;
                    case AT_HWCAP:
                        rpmat.hwcap = auxv.a_un.a_val;
                        break;
                }
	    }
	    close(fd);
	}
#endif
	oneshot = 0; /* only try once even if it fails */
    }
    return;
}
#endif

/**
 */
static void defaultMachine(rpmrcCtx ctx, const char ** arch, const char ** os)
{
    const char * const platform_path = SYSCONFDIR "/rpm/platform";
    static struct utsname un;
    char * chptr;
    canonEntry canon;
    int rc;

#if defined(__linux__)
    /* Populate rpmat struct with hw info */
    read_auxv();
#endif

    while (!ctx->machDefaults) {
	if (!rpmPlatform(ctx, platform_path)) {
	    char * s = rpmExpand("%{_host_cpu}", NULL);
	    if (s) {
		rstrlcpy(un.machine, s, sizeof(un.machine));
		free(s);
	    }
	    s = rpmExpand("%{_host_os}", NULL);
	    if (s) {
		rstrlcpy(un.sysname, s, sizeof(un.sysname));
		free(s);
	    }
	    ctx->machDefaults = 1;
	    break;
	}
	rc = uname(&un);
	if (rc < 0) return;

#if !defined(__linux__)
	if (rstreq(un.sysname, "AIX")) {
	    strcpy(un.machine, __power_pc() ? "ppc" : "rs6000");
	    sprintf(un.sysname,"aix%s.%s", un.version, un.release);
	}
	else if (rstreq(un.sysname, "Darwin")) { 
#if defined(__ppc__)
	    strcpy(un.machine, "ppc");
#elif defined(__i386__)
	    strcpy(un.machine, "i386");
#elif defined(__x86_64__)
	    strcpy(un.machine, "x86_64");
#elif defined(__aarch64__)
	    strcpy(un.machine, "aarch64");
#else
	    #warning "No architecture defined! Automatic detection may not work!"
#endif 
	}
	else if (rstreq(un.sysname, "SunOS")) {
	    /* Solaris 2.x: n.x.x becomes n-3.x.x */
	    sprintf(un.sysname, "solaris%1d%s", atoi(un.release)-3,
		    un.release+1+(atoi(un.release)/10));

	    /* Solaris on Intel hardware reports i86pc instead of i386
	     * (at least on 2.6 and 2.8)
	     */
	    if (rstreq(un.machine, "i86pc"))
		sprintf(un.machine, "i386");
	}
	else if (rstreq(un.sysname, "HP-UX"))
	    /*make un.sysname look like hpux9.05 for example*/
	    sprintf(un.sysname, "hpux%s", strpbrk(un.release, "123456789"));
	else if (rstreq(un.sysname, "OSF1"))
	    /*make un.sysname look like osf3.2 for example*/
	    sprintf(un.sysname, "osf%s", strpbrk(un.release, "123456789"));
#endif	/* __linux__ */

	/* get rid of the hyphens in the sysname */
	for (chptr = un.machine; *chptr != '\0'; chptr++)
	    if (*chptr == '/') *chptr = '-';

#	if defined(__MIPSEL__) || defined(__MIPSEL) || defined(_MIPSEL)
	    /* little endian */
#		if defined(__mips64)
		    /* 64-bit */
#			if !defined(__mips_isa_rev) || __mips_isa_rev < 6
			    /* r1-r5 */
			    strcpy(un.machine, "mips64el");
#			else
			    /* r6 */
			    strcpy(un.machine, "mips64r6el");
#			endif
#		else
		    /* 32-bit */
#			if !defined(__mips_isa_rev) || __mips_isa_rev < 6
			    /* r1-r5 */
			    strcpy(un.machine, "mipsel");
#			else
			    /* r6 */
			    strcpy(un.machine, "mipsr6el");
#			endif
#		endif
#	elif defined(__MIPSEB__) || defined(__MIPSEB) || defined(_MIPSEB)
	   /* big endian */
#		if defined(__mips64)
		    /* 64-bit */
#			if !defined(__mips_isa_rev) || __mips_isa_rev < 6
			    /* r1-r5 */
			    strcpy(un.machine, "mips64");
#			else
			    /* r6 */
			    strcpy(un.machine, "mips64r6");
#			endif
#		else
		    /* 32-bit */
#			if !defined(__mips_isa_rev) || __mips_isa_rev < 6
			    /* r1-r5 */
			    strcpy(un.machine, "mips");
#			else
			    /* r6 */
			    strcpy(un.machine, "mipsr6");
#			endif
#		endif
#	endif

#if defined(__loongarch64)
	strcpy(un.machine, "loongarch64");
#endif


#if defined(__linux__)
	/* in linux, lets rename parisc to hppa */
	if (rstreq(un.machine, "parisc"))
	    strcpy(un.machine, "hppa");
#endif

#	if defined(__hpux) && defined(_SC_CPU_VERSION)
	{
#	    if !defined(CPU_PA_RISC1_2)
#                define CPU_PA_RISC1_2  0x211 /* HP PA-RISC1.2 */
#           endif
#           if !defined(CPU_PA_RISC2_0)
#               define CPU_PA_RISC2_0  0x214 /* HP PA-RISC2.0 */
#           endif
	    int cpu_version = sysconf(_SC_CPU_VERSION);

#	    if defined(CPU_HP_MC68020)
		if (cpu_version == CPU_HP_MC68020)
		    strcpy(un.machine, "m68k");
#	    endif
#	    if defined(CPU_HP_MC68030)
		if (cpu_version == CPU_HP_MC68030)
		    strcpy(un.machine, "m68k");
#	    endif
#	    if defined(CPU_HP_MC68040)
		if (cpu_version == CPU_HP_MC68040)
		    strcpy(un.machine, "m68k");
#	    endif

#	    if defined(CPU_PA_RISC1_0)
		if (cpu_version == CPU_PA_RISC1_0)
		    strcpy(un.machine, "hppa1.0");
#	    endif
#	    if defined(CPU_PA_RISC1_1)
		if (cpu_version == CPU_PA_RISC1_1)
		    strcpy(un.machine, "hppa1.1");
#	    endif
#	    if defined(CPU_PA_RISC1_2)
		if (cpu_version == CPU_PA_RISC1_2)
		    strcpy(un.machine, "hppa1.2");
#	    endif
#	    if defined(CPU_PA_RISC2_0)
		if (cpu_version == CPU_PA_RISC2_0)
		    strcpy(un.machine, "hppa2.0");
#	    endif
	}
#	endif	/* hpux */

#	if defined(__linux__) && defined(__sparc__)
#	if !defined(HWCAP_SPARC_BLKINIT)
#	    define HWCAP_SPARC_BLKINIT	0x00000040
#	endif
	if (rstreq(un.machine, "sparc")) {
	    #define PERS_LINUX		0x00000000
	    #define PERS_LINUX_32BIT	0x00800000
	    #define PERS_LINUX32	0x00000008

	    extern int personality(unsigned long);
	    int oldpers;
	    
	    oldpers = personality(PERS_LINUX_32BIT);
	    if (oldpers != -1) {
		if (personality(PERS_LINUX) != -1) {
		    uname(&un);
		    if (rstreq(un.machine, "sparc64")) {
			strcpy(un.machine, "sparcv9");
			oldpers = PERS_LINUX32;
		    }
		}
		personality(oldpers);
	    }

	    /* This is how glibc detects Niagara so... */
	    if (rpmat.hwcap & HWCAP_SPARC_BLKINIT) {
		if (rstreq(un.machine, "sparcv9") || rstreq(un.machine, "sparc")) {
		    strcpy(un.machine, "sparcv9v");
		} else if (rstreq(un.machine, "sparc64")) {
		    strcpy(un.machine, "sparc64v");
		}
	    }
	}
#	endif	/* sparc*-linux */

#	if defined(__linux__) && defined(__powerpc__)
#	if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	{
            int powerlvl;
            if (!rstreq(un.machine, "ppc") &&
		    sscanf(rpmat.platform, "power%d", &powerlvl) == 1 &&
		    powerlvl > 6) {
                strcpy(un.machine, "ppc64p7");
	    }
        }
#	endif	/* __ORDER_BIG_ENDIAN__ */
#	endif	/* ppc64*-linux */

#	if defined(__linux__) && defined(__arm__) && defined(__ARM_PCS_VFP)
#	if !defined(HWCAP_ARM_VFP)
#	    define HWCAP_ARM_VFP	(1 << 6)
#	endif
#	if !defined(HWCAP_ARM_NEON)
#	    define HWCAP_ARM_NEON	(1 << 12)
#	endif
#	if !defined(HWCAP_ARM_VFPv3)
#	    define HWCAP_ARM_VFPv3	(1 << 13)
#	endif
	if (rstreq(un.machine, "armv7l")) {
	    if (rpmat.hwcap & HWCAP_ARM_VFPv3) {
		if (rpmat.hwcap & HWCAP_ARM_NEON)
		    strcpy(un.machine, "armv7hnl");
		else
		    strcpy(un.machine, "armv7hl");
	    }
	} else if (rstreq(un.machine, "armv6l")) {
	    if (rpmat.hwcap & HWCAP_ARM_VFP)
		strcpy(un.machine, "armv6hl");
	}
#	endif	/* arm*-linux */

#	if defined(__linux__) && defined(__riscv__)
	if (rstreq(un.machine, "riscv")) {
		if (sizeof(long) == 4)
			strcpy(un.machine, "riscv32");
		else if (sizeof(long) == 8)
			strcpy(un.machine, "riscv64");
		else if (sizeof(long) == 16)
			strcpy(un.machine, "riscv128");
	}
#	endif	/* riscv */

#	if defined(__GNUC__) && defined(__alpha__)
	{
	    unsigned long amask, implver;
	    register long v0 __asm__("$0") = -1;
	    __asm__ (".long 0x47e00c20" : "=r"(v0) : "0"(v0));
	    amask = ~v0;
	    __asm__ (".long 0x47e03d80" : "=r"(v0));
	    implver = v0;
	    switch (implver) {
	    case 1:
	    	switch (amask) {
	    	case 0: strcpy(un.machine, "alphaev5"); break;
	    	case 1: strcpy(un.machine, "alphaev56"); break;
	    	case 0x101: strcpy(un.machine, "alphapca56"); break;
	    	}
	    	break;
	    case 2:
	    	switch (amask) {
	    	case 0x303: strcpy(un.machine, "alphaev6"); break;
	    	case 0x307: strcpy(un.machine, "alphaev67"); break;
	    	}
	    	break;
	    }
	}
#	endif

#	if defined(__linux__) && defined(__i386__)
	{
	    char mclass = (char) (RPMClass() | '0');

	    if ((mclass == '6' && is_athlon()) || mclass == '7')
	    	strcpy(un.machine, "athlon");
	    else if (is_pentium4())
		strcpy(un.machine, "pentium4");
	    else if (is_pentium3())
		strcpy(un.machine, "pentium3");
	    else if (is_geode())
		strcpy(un.machine, "geode");
	    else if (strchr("3456", un.machine[1]) && un.machine[1] != mclass)
		un.machine[1] = mclass;
	}
#	endif

# if defined(__linux__) && defined(__x86_64__)
	{
	    int x86_64_level = get_x86_64_level();
	    if (x86_64_level > 1) {
	        strcpy(un.machine, "x86_64_vX");
	        un.machine[8] = '0' + x86_64_level;
	    }
	}
#endif

	/* the uname() result goes through the arch_canon table */
	canon = lookupInCanonTable(un.machine,
			   ctx->tables[RPM_MACHTABLE_INSTARCH].canons,
			   ctx->tables[RPM_MACHTABLE_INSTARCH].canonsLength);
	if (canon)
	    rstrlcpy(un.machine, canon->short_name, sizeof(un.machine));

	canon = lookupInCanonTable(un.sysname,
			   ctx->tables[RPM_MACHTABLE_INSTOS].canons,
			   ctx->tables[RPM_MACHTABLE_INSTOS].canonsLength);
	if (canon)
	    rstrlcpy(un.sysname, canon->short_name, sizeof(un.sysname));
	ctx->machDefaults = 1;
	break;
    }

    if (arch) *arch = un.machine;
    if (os) *os = un.sysname;
}

static
const char * rpmGetVarArch(rpmrcCtx ctx, int var, const char * arch)
{
    const struct rpmvarValue * next;

    if (arch == NULL) arch = ctx->current[ARCH];

    if (arch) {
	next = &ctx->values[var];
	while (next) {
	    if (next->arch && rstreq(next->arch, arch)) return next->value;
	    next = next->next;
	}
    }

    next = ctx->values + var;
    while (next && next->arch) next = next->next;

    return next ? next->value : NULL;
}

static void rpmSetVarArch(rpmrcCtx ctx,
			  int var, const char * val, const char * arch)
{
    struct rpmvarValue * next = ctx->values + var;

    if (next->value) {
	if (arch) {
	    while (next->next) {
		if (next->arch && rstreq(next->arch, arch)) break;
		next = next->next;
	    }
	} else {
	    while (next->next) {
		if (!next->arch) break;
		next = next->next;
	    }
	}

	if (next->arch && arch && rstreq(next->arch, arch)) {
	    next->value = _free(next->value);
	    next->arch = _free(next->arch);
	} else if (next->arch || arch) {
	    next->next = (struct rpmvarValue *)xmalloc(sizeof(*next->next));
	    next = next->next;
	    next->value = NULL;
	    next->arch = NULL;
	    next->next = NULL;
	}
    }

    next->value = _free(next->value);
    next->value = xstrdup(val);
    next->arch = (arch ? xstrdup(arch) : NULL);
}

static void rpmSetTables(rpmrcCtx ctx, int archTable, int osTable)
{
    const char * arch, * os;

    defaultMachine(ctx, &arch, &os);

    if (ctx->currTables[ARCH] != archTable) {
	ctx->currTables[ARCH] = archTable;
	rebuildCompatTables(ctx, ARCH, arch);
    }

    if (ctx->currTables[OS] != osTable) {
	ctx->currTables[OS] = osTable;
	rebuildCompatTables(ctx, OS, os);
    }
}

/** \ingroup rpmrc
 * Set current arch/os names.
 * NULL as argument is set to the default value (munged uname())
 * pushed through a translation table (if appropriate).
 * @deprecated Use addMacro to set _target_* macros.
 * @todo Eliminate 
 *
 * @param ctx		rpmrc context
 * @param arch          arch name (or NULL)
 * @param os            os name (or NULL)
 *          */

static void rpmSetMachine(rpmrcCtx ctx, const char * arch, const char * os)
{
    const char * host_cpu, * host_os;

    defaultMachine(ctx, &host_cpu, &host_os);

    if (arch == NULL) {
	arch = host_cpu;
	if (ctx->tables[ctx->currTables[ARCH]].hasTranslate)
	    arch = lookupInDefaultTable(arch,
			    ctx->tables[ctx->currTables[ARCH]].defaults,
			    ctx->tables[ctx->currTables[ARCH]].defaultsLength);
    }
    if (arch == NULL) return;	/* XXX can't happen */

    if (os == NULL) {
	os = host_os;
	if (ctx->tables[ctx->currTables[OS]].hasTranslate)
	    os = lookupInDefaultTable(os,
			    ctx->tables[ctx->currTables[OS]].defaults,
			    ctx->tables[ctx->currTables[OS]].defaultsLength);
    }
    if (os == NULL) return;	/* XXX can't happen */

    if (!ctx->current[ARCH] || !rstreq(arch, ctx->current[ARCH])) {
	ctx->current[ARCH] = _free(ctx->current[ARCH]);
	ctx->current[ARCH] = xstrdup(arch);
	rebuildCompatTables(ctx, ARCH, host_cpu);
    }

    if (!ctx->current[OS] || !rstreq(os, ctx->current[OS])) {
	char * t = xstrdup(os);
	ctx->current[OS] = _free(ctx->current[OS]);
	/*
	 * XXX Capitalizing the 'L' is needed to insure that old
	 * XXX os-from-uname (e.g. "Linux") is compatible with the new
	 * XXX os-from-platform (e.g "linux" from "sparc-*-linux").
	 * XXX A copy of this string is embedded in headers and is
	 * XXX used by rpmInstallPackage->{os,arch}Okay->rpmMachineScore->
	 * XXX to verify correct arch/os from headers.
	 */
	if (rstreq(t, "linux"))
	    *t = 'L';
	ctx->current[OS] = t;
	
	rebuildCompatTables(ctx, OS, host_os);
    }
}

static void rebuildCompatTables(rpmrcCtx ctx, int type, const char * name)
{
    machFindEquivs(&ctx->tables[ctx->currTables[type]].cache,
		   &ctx->tables[ctx->currTables[type]].equiv,
		   name);
}

static void getMachineInfo(rpmrcCtx ctx,
			   int type, const char ** name, int * num)
{
    canonEntry canon;
    int which = ctx->currTables[type];

    /* use the normal canon tables, even if we're looking up build stuff */
    if (which >= 2) which -= 2;

    canon = lookupInCanonTable(ctx->current[type],
			       ctx->tables[which].canons,
			       ctx->tables[which].canonsLength);

    if (canon) {
	if (num) *num = canon->num;
	if (name) *name = canon->short_name;
    } else {
	if (num) *num = 255;
	if (name) *name = ctx->current[type];

	if (ctx->tables[ctx->currTables[type]].hasCanon) {
	    rpmlog(RPMLOG_WARNING, _("Unknown system: %s\n"),
		   ctx->current[type]);
	    rpmlog(RPMLOG_WARNING, _("Please contact %s\n"), PACKAGE_BUGREPORT);
	}
    }
}

static void rpmRebuildTargetVars(rpmrcCtx ctx,
			const char ** target, const char ** canontarget)
{

    char *ca = NULL, *co = NULL, *ct = NULL;
    int x;

    /* Rebuild the compat table to recalculate the current target arch.  */

    rpmSetMachine(ctx, NULL, NULL);
    rpmSetTables(ctx, RPM_MACHTABLE_INSTARCH, RPM_MACHTABLE_INSTOS);
    rpmSetTables(ctx, RPM_MACHTABLE_BUILDARCH, RPM_MACHTABLE_BUILDOS);

    if (target && *target) {
	char *c;
	/* Set arch and os from specified build target */
	ca = xstrdup(*target);
	if ((c = strchr(ca, '-')) != NULL) {
	    *c++ = '\0';
	    
	    if ((co = strrchr(c, '-')) == NULL) {
		co = c;
	    } else {
		if (!rstrcasecmp(co, "-gnu"))
		    *co = '\0';
		if ((co = strrchr(c, '-')) == NULL)
		    co = c;
		else
		    co++;
	    }
	    if (co != NULL) co = xstrdup(co);
	}
    } else {
	const char *a = NULL;
	const char *o = NULL;
	/* Set build target from rpm arch and os */
	getMachineInfo(ctx, ARCH, &a, NULL);
	ca = (a) ? xstrdup(a) : NULL;
	getMachineInfo(ctx, OS, &o, NULL);
	co = (o) ? xstrdup(o) : NULL;
    }

    /* If still not set, Set target arch/os from default uname(2) values */
    if (ca == NULL) {
	const char *a = NULL;
	defaultMachine(ctx, &a, NULL);
	ca = xstrdup(a ? a : "(arch)");
    }
    for (x = 0; ca[x] != '\0'; x++)
	ca[x] = rtolower(ca[x]);

    if (co == NULL) {
	const char *o = NULL;
	defaultMachine(ctx, NULL, &o);
	co = xstrdup(o ? o : "(os)");
    }
    for (x = 0; co[x] != '\0'; x++)
	co[x] = rtolower(co[x]);

    /* XXX For now, set canonical target to arch-os */
    if (ct == NULL) {
	rasprintf(&ct, "%s-%s", ca, co);
    }

/*
 * XXX All this macro pokery/jiggery could be achieved by doing a delayed
 *	rpmInitMacros(NULL, PER-PLATFORM-MACRO-FILE-NAMES);
 */
    rpmPopMacro(NULL, "_target");
    rpmPushMacro(NULL, "_target", NULL, ct, RMIL_RPMRC);
    rpmPopMacro(NULL, "_target_cpu");
    rpmPushMacro(NULL, "_target_cpu", NULL, ca, RMIL_RPMRC);
    rpmPopMacro(NULL, "_target_os");
    rpmPushMacro(NULL, "_target_os", NULL, co, RMIL_RPMRC);
/*
 * XXX Make sure that per-arch optflags is initialized correctly.
 */
  { const char *optflags = rpmGetVarArch(ctx, RPMVAR_OPTFLAGS, ca);
    /*
     * If not defined for the target arch, fall back to current arch
     * definitions, with buildarchtranslate applied. This is WRONG
     * but it's what we've always done, except for buildarchtranslate.
     */
    if (optflags == NULL) {
	optflags = rpmGetVarArch(ctx, RPMVAR_OPTFLAGS, NULL);
    }
    if (optflags != NULL) {
	rpmPopMacro(NULL, "optflags");
	rpmPushMacro(NULL, "optflags", NULL, optflags, RMIL_RPMRC);
    }
  }

    if (canontarget)
	*canontarget = ct;
    else
	free(ct);
    free(ca);
    free(co);
}

/** \ingroup rpmrc
 * Read rpmrc (and macro) configuration file(s).
 * @param ctx		rpmrc context
 * @param rcfiles	colon separated files to read (NULL uses default)
 * @return		RPMRC_OK on success
 */
static rpmRC rpmReadRC(rpmrcCtx ctx, const char * rcfiles)
{
    ARGV_t p, globs = NULL, files = NULL;
    rpmRC rc = RPMRC_FAIL;

    if (!ctx->pathDefaults) {
	setDefaults();
	ctx->pathDefaults = 1;
    }

    if (rcfiles == NULL)
	rcfiles = defrcfiles;

    /* Expand any globs in rcfiles. Missing files are ok here. */
    argvSplit(&globs, rcfiles, ":");
    for (p = globs; *p; p++) {
	ARGV_t av = NULL;
	if (rpmGlobPath(*p, RPMGLOB_NOCHECK, NULL, &av) == 0) {
	    argvAppend(&files, av);
	    argvFree(av);
	}
    }
    argvFree(globs);

    /* Read each file in rcfiles. */
    for (p = files; p && *p; p++) {
	/* XXX Only /usr/lib/rpm/rpmrc must exist in default rcfiles list */
	if (access(*p, R_OK) != 0) {
	    if (rcfiles == defrcfiles && p != files)
		continue;
	    rpmlog(RPMLOG_ERR, _("Unable to open %s for reading: %m.\n"), *p);
	    goto exit;
	    break;
	} else {
	    rc = doReadRC(ctx, *p);
	}
    }
    rc = RPMRC_OK;
    rpmSetMachine(ctx, NULL, NULL);	/* XXX WTFO? Why bother? */

exit:
    argvFree(files);
    return rc;
}

/* External interfaces */

int rpmReadConfigFiles(const char * file, const char * target)
{
    int rc = -1; /* assume failure */
    rpmrcCtx ctx = rpmrcCtxAcquire(1);

    if (rpmInitCrypto())
	goto exit;

    /* Preset target macros */
   	/* FIX: target can be NULL */
    rpmRebuildTargetVars(ctx, &target, NULL);

    /* Read the files */
    if (rpmReadRC(ctx, file))
	goto exit;

    if (macrofiles != NULL) {
	char *mf = rpmGetPath(macrofiles, NULL);
	rpmInitMacros(NULL, mf);
	_free(mf);
    }

    /* Reset target macros */
    rpmRebuildTargetVars(ctx, &target, NULL);

    /* Finally set target platform */
    {	char *cpu = rpmExpand("%{_target_cpu}", NULL);
	char *os = rpmExpand("%{_target_os}", NULL);
	rpmSetMachine(ctx, cpu, os);
	free(cpu);
	free(os);
    }

    /* Force Lua state initialization */
    rpmluaGetGlobalState();
    rc = 0;

exit:
    rpmrcCtxRelease(ctx);
    return rc;
}

void rpmFreeRpmrc(void)
{
    rpmrcCtx ctx = rpmrcCtxAcquire(1);
    int i, j, k;

    ctx->platpat = argvFree(ctx->platpat);

    for (i = 0; i < RPM_MACHTABLE_COUNT; i++) {
	tableType t;
	t = ctx->tables + i;
	if (t->equiv.list) {
	    for (j = 0; j < t->equiv.count; j++)
		t->equiv.list[j].name = _free(t->equiv.list[j].name);
	    t->equiv.list = _free(t->equiv.list);
	    t->equiv.count = 0;
	}
	if (t->cache.cache) {
	    for (j = 0; j < t->cache.size; j++) {
		machCacheEntry e;
		e = t->cache.cache + j;
		if (e == NULL)
		    continue;
		e->name = _free(e->name);
		if (e->equivs) {
		    for (k = 0; k < e->count; k++)
			e->equivs[k] = _free(e->equivs[k]);
		    e->equivs = _free(e->equivs);
		}
	    }
	    t->cache.cache = _free(t->cache.cache);
	    t->cache.size = 0;
	}
	if (t->defaults) {
	    for (j = 0; j < t->defaultsLength; j++) {
		t->defaults[j].name = _free(t->defaults[j].name);
		t->defaults[j].defName = _free(t->defaults[j].defName);
	    }
	    t->defaults = _free(t->defaults);
	    t->defaultsLength = 0;
	}
	if (t->canons) {
	    for (j = 0; j < t->canonsLength; j++) {
		t->canons[j].name = _free(t->canons[j].name);
		t->canons[j].short_name = _free(t->canons[j].short_name);
	    }
	    t->canons = _free(t->canons);
	    t->canonsLength = 0;
	}
    }

    for (i = 0; i < RPMVAR_NUM; i++) {
	struct rpmvarValue * vp;
	while ((vp = ctx->values[i].next) != NULL) {
	    ctx->values[i].next = vp->next;
	    vp->value = _free(vp->value);
	    vp->arch = _free(vp->arch);
	    vp = _free(vp);
	}
	ctx->values[i].value = _free(ctx->values[i].value);
	ctx->values[i].arch = _free(ctx->values[i].arch);
    }
    ctx->current[OS] = _free(ctx->current[OS]);
    ctx->current[ARCH] = _free(ctx->current[ARCH]);
    ctx->machDefaults = 0;
    ctx->pathDefaults = 0;

    /* XXX doesn't really belong here but... */
    rpmFreeCrypto();
    rpmlua lua = rpmluaGetGlobalState();
    rpmluaFree(lua);
    rpmugFree();

    rpmrcCtxRelease(ctx);
    return;
}

int rpmShowRC(FILE * fp)
{
    /* Write-context necessary as this calls rpmSetTables(), ugh */
    rpmrcCtx ctx = rpmrcCtxAcquire(1);
    const struct rpmOption *opt;
    rpmds ds = NULL;
    int i;
    machEquivTable equivTable;

    /* the caller may set the build arch which should be printed here */
    fprintf(fp, "ARCHITECTURE AND OS:\n");
    fprintf(fp, "build arch            : %s\n", ctx->current[ARCH]);

    fprintf(fp, "compatible build archs:");
    equivTable = &ctx->tables[RPM_MACHTABLE_BUILDARCH].equiv;
    for (i = 0; i < equivTable->count; i++)
	fprintf(fp," %s", equivTable->list[i].name);
    fprintf(fp, "\n");

    fprintf(fp, "build os              : %s\n", ctx->current[OS]);

    fprintf(fp, "compatible build os's :");
    equivTable = &ctx->tables[RPM_MACHTABLE_BUILDOS].equiv;
    for (i = 0; i < equivTable->count; i++)
	fprintf(fp," %s", equivTable->list[i].name);
    fprintf(fp, "\n");

    rpmSetTables(ctx, RPM_MACHTABLE_INSTARCH, RPM_MACHTABLE_INSTOS);
    rpmSetMachine(ctx, NULL, NULL);	/* XXX WTFO? Why bother? */

    fprintf(fp, "install arch          : %s\n", ctx->current[ARCH]);
    fprintf(fp, "install os            : %s\n", ctx->current[OS]);

    fprintf(fp, "compatible archs      :");
    equivTable = &ctx->tables[RPM_MACHTABLE_INSTARCH].equiv;
    for (i = 0; i < equivTable->count; i++)
	fprintf(fp," %s", equivTable->list[i].name);
    fprintf(fp, "\n");

    fprintf(fp, "compatible os's       :");
    equivTable = &ctx->tables[RPM_MACHTABLE_INSTOS].equiv;
    for (i = 0; i < equivTable->count; i++)
	fprintf(fp," %s", equivTable->list[i].name);
    fprintf(fp, "\n");

    dbShowRC(fp);

    fprintf(fp, "\nRPMRC VALUES:\n");
    for (i = 0, opt = optionTable; i < optionTableSize; i++, opt++) {
	const char *s = rpmGetVarArch(ctx, opt->var, NULL);
	if (s != NULL || rpmIsVerbose())
	    fprintf(fp, "%-21s : %s\n", opt->name, s ? s : "(not set)");
    }
    fprintf(fp, "\n");

    fprintf(fp, "Features supported by rpmlib:\n");
    rpmdsRpmlib(&ds, NULL);
    ds = rpmdsInit(ds);
    while (rpmdsNext(ds) >= 0) {
        const char * DNEVR = rpmdsDNEVR(ds);
        if (DNEVR != NULL)
            fprintf(fp, "    %s\n", DNEVR+2);
    }
    ds = rpmdsFree(ds);
    fprintf(fp, "\n");

    fprintf(fp, "Macro path: %s\n", macrofiles);
    fprintf(fp, "\n");

    rpmDumpMacroTable(NULL, fp);

    /* XXX: Move this earlier eventually... */
    rpmrcCtxRelease(ctx);

    return 0;
}

int rpmMachineScore(int type, const char * name)
{
    int score = 0;
    if (name) {
	rpmrcCtx ctx = rpmrcCtxAcquire(0);
	machEquivInfo info = machEquivSearch(&ctx->tables[type].equiv, name);
	if (info)
	    score = info->score;
	rpmrcCtxRelease(ctx);
    }
    return score;
}

int rpmIsKnownArch(const char *name)
{
    rpmrcCtx ctx = rpmrcCtxAcquire(0);
    canonEntry canon = lookupInCanonTable(name,
			    ctx->tables[RPM_MACHTABLE_INSTARCH].canons,
			    ctx->tables[RPM_MACHTABLE_INSTARCH].canonsLength);
    int known = (canon != NULL || rstreq(name, "noarch"));
    rpmrcCtxRelease(ctx);
    return known;
}

void rpmGetArchInfo(const char ** name, int * num)
{
    rpmrcCtx ctx = rpmrcCtxAcquire(0);
    getMachineInfo(ctx, ARCH, name, num);
    rpmrcCtxRelease(ctx);
}

int rpmGetArchColor(const char *arch)
{
    rpmrcCtx ctx = rpmrcCtxAcquire(0);
    const char *color;
    char *e;
    int color_i = -1; /* assume failure */

    arch = lookupInDefaultTable(arch,
			    ctx->tables[ctx->currTables[ARCH]].defaults,
			    ctx->tables[ctx->currTables[ARCH]].defaultsLength);
    color = rpmGetVarArch(ctx, RPMVAR_ARCHCOLOR, arch);
    if (color) {
	color_i = strtol(color, &e, 10);
	if (!(e && *e == '\0')) {
	    color_i = -1;
	}
    }
    rpmrcCtxRelease(ctx);

    return color_i;
}

void rpmGetOsInfo(const char ** name, int * num)
{
    rpmrcCtx ctx = rpmrcCtxAcquire(0);
    getMachineInfo(ctx, OS, name, num);
    rpmrcCtxRelease(ctx);
}

