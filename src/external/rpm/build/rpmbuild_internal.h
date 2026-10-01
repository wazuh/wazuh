#ifndef _RPMBUILD_INTERNAL_H
#define _RPMBUILD_INTERNAL_H

#include <rpm/rpmbuild.h>
#include <rpm/rpmutil.h>
#include <rpm/rpmstrpool.h>
#include "rpmbuild_misc.h"
#include "rpmlua.h"

#define HASHTYPE fileRenameHash
#define HTKEYTYPE const char *
#define HTDATATYPE const char *
#include "rpmhash.H"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

#define ALLOWED_CHARS_NAME ".-_+%{}"
#define ALLOWED_FIRSTCHARS_NAME "_%"
#define ALLOWED_CHARS_VERREL "._+%{}~^"
#define ALLOWED_CHARS_EVR ALLOWED_CHARS_VERREL "-:"
#define LEN_AND_STR(_tag) (sizeof(_tag)-1), (_tag)

enum parseStages {
    PARSE_SPECFILE,
    PARSE_BUILDSYS,
    PARSE_GENERATED,
};

enum sections_e {
    SECT_PREP		= 0,
    SECT_CONF		= 1,
    SECT_BUILDREQUIRES	= 2,
    SECT_BUILD		= 3,
    SECT_INSTALL	= 4,
    SECT_CHECK		= 5,
    SECT_CLEAN		= 6,
};
#define NR_SECT 7

enum parseOps_e {
    PARSE_NONE		= 0,
    PARSE_PREPEND	= (1 << 0),
    PARSE_APPEND	= (1 << 1),
};

struct sectname_s {
    const char *name;
    int section;
    int part;
    int required;
};

struct TriggerFileEntry {
    int index;
    char * fileName;
    char * script;
    char * prog;
    uint32_t flags;
    struct TriggerFileEntry * next;
    uint32_t priority;
};

typedef enum rpmParseLineType_e {
    LINE_DEFAULT           = 0,
    LINE_IF                = (1 << 0),
    LINE_IFARCH            = (1 << 1),
    LINE_IFNARCH           = (1 << 2),
    LINE_IFOS              = (1 << 3),
    LINE_IFNOS             = (1 << 4),
    LINE_ELSE              = (1 << 5),
    LINE_ENDIF             = (1 << 6),
    LINE_INCLUDE           = (1 << 7),
    LINE_ELIF              = (1 << 8),
    LINE_ELIFARCH          = (1 << 9),
    LINE_ELIFOS            = (1 << 10),
} rpmParseLineType;

typedef const struct parsedSpecLine_s {
    int id;
    size_t textLen;
    const char *text;
    int withArgs;
    int isConditional;
    int wrongPrecursors;
} * parsedSpecLine;

static struct parsedSpecLine_s const lineTypes[] = {
    { LINE_ENDIF,      LEN_AND_STR("%endif")  , 0, 1, LINE_ENDIF},
    { LINE_ELSE,       LEN_AND_STR("%else")   , 0, 1, LINE_ENDIF | LINE_ELSE },
    { LINE_IF,         LEN_AND_STR("%if")     , 1, 1, 0},
    { LINE_IFARCH,     LEN_AND_STR("%ifarch") , 1, 1, 0},
    { LINE_IFNARCH,    LEN_AND_STR("%ifnarch"), 1, 1, 0},
    { LINE_IFOS,       LEN_AND_STR("%ifos")   , 1, 1, 0},
    { LINE_IFNOS,      LEN_AND_STR("%ifnos")  , 1, 1, 0},
    { LINE_INCLUDE,    LEN_AND_STR("%include"), 1, 0, 0},
    { LINE_ELIFARCH,   LEN_AND_STR("%elifarch"), 1, 1, LINE_ENDIF | LINE_ELSE},
    { LINE_ELIFOS,     LEN_AND_STR("%elifos"),  1, 1, LINE_ENDIF | LINE_ELSE},
    { LINE_ELIF,       LEN_AND_STR("%elif")    ,1, 1, LINE_ENDIF | LINE_ELSE},
    { 0, 0, 0, 0, 0, 0 }
 };

#define LINE_IFANY (LINE_IF | LINE_IFARCH | LINE_IFNARCH | LINE_IFOS | LINE_IFNOS)
#define LINE_ELIFANY (LINE_ELIF | LINE_ELIFOS | LINE_ELIFARCH)

typedef struct ReadLevelEntry {
    int reading;
    int lineNum;
    int readable;
    parsedSpecLine lastConditional;
    struct ReadLevelEntry * next;
} RLE_t;

/** \ingroup rpmbuild
 */
struct Source {
    char * fullSource;
    const char * source;     /* Pointer into fullSource */
    char * path;             /* On-disk path (including %_sourcedir) */
    int flags;
    uint32_t num;
struct Source * next;
};

typedef struct Package_s * Package;

/** \ingroup rpmbuild
 * The structure used to store values parsed from a spec file.
 */
struct rpmSpec_s {
    char * buildHost;
    rpm_time_t buildTime;

    char * specFile;	/*!< Name of the spec file. */
    char * buildRoot;
    char * buildDir;
    const char * rootDir;

    struct OpenFileInfo * fileStack;
    char *lbuf;
    size_t lbufSize;
    size_t lbufOff;
    char nextpeekc;
    char * nextline;
    char * line;
    int lineNum;

    struct ReadLevelEntry * readStack;

    Header buildRestrictions;
    rpmSpec * BASpecs;
    const char ** BANames;
    int BACount;
    int recursing;		/*!< parse is recursive? */

    rpmSpecFlags flags;

    struct Source * sources;
    int numSources;
    int noSource;
    int autonum_patch;
    int autonum_source;

    char * sourceRpmName;
    unsigned char * sourcePkgId;
    Package sourcePackage;

    rpmMacroContext macros;
    rpmstrPool pool;

    StringBuf sections[NR_SECT]; /*!< spec sections (%prep etc) */
    ARGV_t buildopts[NR_SECT];	/*!< per-section buildsystem options */
    ARGV_t sectionparts[NR_SECT];
    ARGI_t sectionops[NR_SECT];

    StringBuf parsed;		/*!< parsed spec contents */

    Package packages;		/*!< Package list. */
};

#define PACKAGE_NUM_DEPS 12

/** \ingroup rpmbuild
 * The structure used to store values for a package.
 */
struct Package_s {
    rpmsid name;
    rpmstrPool pool;
    Header header;
    rpmds ds;			/*!< Requires: N = EVR */
    rpmds dependencies[PACKAGE_NUM_DEPS];
    rpmfiles cpioList;
    ARGV_t dpaths;

    struct Source * icon;

    int autoReq;
    int autoProv;

    char * preInFile;	/*!< %pre scriptlet. */
    char * postInFile;	/*!< %post scriptlet. */
    char * preUnFile;	/*!< %preun scriptlet. */
    char * postUnFile;	/*!< %postun scriptlet. */
    char * preTransFile;	/*!< %pretrans scriptlet. */
    char * postTransFile;	/*!< %posttrans scriptlet. */
    char * preunTransFile;	/*!< %preuntrans scriptlet. */
    char * postunTransFile;	/*!< %postuntrans scriptlet. */
    char * verifyFile;	/*!< %verifyscript scriptlet. */

    struct TriggerFileEntry * triggerFiles;
    struct TriggerFileEntry * fileTriggerFiles;
    struct TriggerFileEntry * transFileTriggerFiles;

    ARGV_t fileFile;
    ARGV_t fileList;		/* If NULL, package will not be written */
    ARGV_t fileExcludeList;
    ARGV_t removePostfixes;
    fileRenameHash fileRenameMap;
    ARGV_t policyList;

    char *filename;
    rpmRC rc;

    Package next;
};

#define PART_SUBNAME  0
#define PART_NAME     1
#define PART_QUIET    2

/** \ingroup rpmbuild
 * rpmSpec file parser states.
 */
#define PART_BASE       0 
typedef enum rpmParseState_e { 
    PART_ERROR          =  -1, /*!< */ 
    PART_NONE           =  0+PART_BASE, /*!< */ 
    /* leave room for RPMRC_NOTFOUND returns. */ 
    PART_PREAMBLE       = 11+PART_BASE, /*!< */ 
    PART_PREP           = 12+PART_BASE, /*!< */ 
    PART_BUILD          = 13+PART_BASE, /*!< */ 
    PART_INSTALL        = 14+PART_BASE, /*!< */ 
    PART_CHECK          = 15+PART_BASE, /*!< */ 
    PART_CLEAN          = 16+PART_BASE, /*!< */ 
    PART_FILES          = 17+PART_BASE, /*!< */ 
    PART_PRE            = 18+PART_BASE, /*!< */ 
    PART_POST           = 19+PART_BASE, /*!< */ 
    PART_PREUN          = 20+PART_BASE, /*!< */ 
    PART_POSTUN         = 21+PART_BASE, /*!< */ 
    PART_PRETRANS       = 22+PART_BASE, /*!< */ 
    PART_POSTTRANS      = 23+PART_BASE, /*!< */ 
    PART_DESCRIPTION    = 24+PART_BASE, /*!< */ 
    PART_CHANGELOG      = 25+PART_BASE, /*!< */ 
    PART_TRIGGERIN      = 26+PART_BASE, /*!< */ 
    PART_TRIGGERUN      = 27+PART_BASE, /*!< */ 
    PART_VERIFYSCRIPT   = 28+PART_BASE, /*!< */ 
    PART_BUILDARCHITECTURES= 29+PART_BASE,/*!< */ 
    PART_TRIGGERPOSTUN  = 30+PART_BASE, /*!< */ 
    PART_TRIGGERPREIN   = 31+PART_BASE, /*!< */ 
    PART_POLICIES       = 32+PART_BASE, /*!< */
    PART_FILETRIGGERIN		= 33+PART_BASE, /*!< */
    PART_FILETRIGGERUN		= 34+PART_BASE, /*!< */
    PART_FILETRIGGERPOSTUN	= 35+PART_BASE, /*!< */
    PART_TRANSFILETRIGGERIN	= 36+PART_BASE, /*!< */
    PART_TRANSFILETRIGGERUN	= 37+PART_BASE, /*!< */
    PART_TRANSFILETRIGGERPOSTUN	= 38+PART_BASE, /*!< */
    PART_EMPTY			= 39+PART_BASE, /*!< */
    PART_PATCHLIST		= 40+PART_BASE, /*!< */
    PART_SOURCELIST		= 41+PART_BASE, /*!< */
    PART_BUILDREQUIRES		= 42+PART_BASE, /*!< */
    PART_CONF			= 43+PART_BASE, /*!< */
    PART_PREUNTRANS		= 44+PART_BASE, /*!< */
    PART_POSTUNTRANS		= 45+PART_BASE, /*!< */
    PART_LAST			= 46+PART_BASE  /*!< */
} rpmParseState; 


#define STRIP_NOTHING             0
#define STRIP_TRAILINGSPACE (1 << 0)
#define STRIP_COMMENTS      (1 << 1)

#define ALLOW_EMPTY         (1 << 16)

/** \ingroup rpmbuild
 * Create and initialize rpmSpec structure.
 * @return spec		spec file control structure
 */
RPM_GNUC_INTERNAL
rpmSpec newSpec(void);

/** \ingroup rpmbuild
 * Stop reading from spec file, freeing resources.
 * @param spec		spec file control structure
 */
RPM_GNUC_INTERNAL
void closeSpec(rpmSpec spec);

/** \ingroup rpmbuild
 * Read next line from spec file.
 * @param spec		spec file control structure
 * @param strip		truncate comments?
 * @return		0 on success, 1 on EOF, <0 on error
 */
RPM_GNUC_INTERNAL
int readLine(rpmSpec spec, int strip);

/** \ingroup rpmbuild
 * Read next line from spec file.
 * @param spec		spec file control structure
 * @param strip		truncate comments?
 * @param[out] avp		pointer to argv (optional, alloced)
 * @param[out] sbp		pointer to string buf (optional, alloced)
 * @return		next spec part or PART_ERROR on error
 */
RPM_GNUC_INTERNAL
int parseLines(rpmSpec spec, int strip, ARGV_t *avp, StringBuf *sbp);

/** \ingroup rpmbuild
 * Destroy source component chain.
 * @param s		source component chain
 * @return		NULL always
 */
RPM_GNUC_INTERNAL
struct Source * freeSources(struct Source * s);

/** \ingroup rpmbuild
 * Check line for section separator, return next parser state.
 * @param		line from spec file
 * @return		next parser state
 */
RPM_GNUC_INTERNAL
int isPart(const char * line)	;

/** \ingroup rpmbuild
 * Parse %%build/%%install/%%clean section(s) of a spec file.
 * @param spec		spec file control structure
 * @param parsePart	current rpmParseState
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parseSimpleScript(rpmSpec spec, const char * name,
		      StringBuf *sbp, ARGV_t *avp, int *modep);

/** \ingroup rpmbuild
 * Parse %%changelog section of a spec file.
 * @param spec		spec file control structure
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parseChangelog(rpmSpec spec);

/** \ingroup rpmbuild
 * Parse %%description section of a spec file.
 * @param spec		spec file control structure
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parseDescription(rpmSpec spec);

/** \ingroup rpmbuild
 * Parse %%files section of a spec file.
 * @param spec		spec file control structure
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parseFiles(rpmSpec spec);

/** \ingroup rpmbuild
 * Parse %%sepolicy section of a spec file.
 * @param spec		spec file control structure
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parsePolicies(rpmSpec spec);

/** \ingroup rpmbuild
 * Parse tags from preamble of a spec file.
 * @param spec		spec file control structure
 * @param initialPackage
 * @param stage
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parsePreamble(rpmSpec spec, int initialPackage, enum parseStages stage);

/** \ingroup rpmbuild
 * Parse %%pre et al scriptlets from a spec file.
 * @param spec		spec file control structure
 * @param parsePart	current rpmParseState
 * @return		>= 0 next rpmParseState, < 0 on error
 */
RPM_GNUC_INTERNAL
int parseScript(rpmSpec spec, int parsePart);

RPM_GNUC_INTERNAL
int parseList(rpmSpec spec, const char *name, rpmTagVal stype);

/** \ingroup rpmbuild
 * Check for inappropriate characters. All alphanums are considered sane.
 * @param spec          spec
 * @param field         string to check
 * @param allowedchars  string of permitted characters
 * @return              RPMRC_OK if OK
 */
RPM_GNUC_INTERNAL
rpmRC rpmCharCheck(rpmSpec spec, const char *field,
		   const char *allowedchars,
		   const char *allowedcharsfirst);

typedef rpmRC (*addReqProvFunction) (void *cbdata, rpmTagVal tagN,
				     const char * N, const char * EVR, rpmsenseFlags Flags,
				     int index);

/** \ingroup rpmbuild
 * Parse dependency relations from spec file and/or autogenerated output buffer.
 * @param spec		spec file control structure
 * @param pkg		package control structure
 * @param field		text to parse (e.g. "foo < 0:1.2-3, bar = 5:6.7")
 * @param tagN		tag, identifies type of dependency
 * @param index		(0 always)
 * @param tagflags	dependency flags already known from context
 * @param cb		Callback for adding dependency (nullable)
 * @param cbdata	Callback data (@pkg if NULL)
 * @return		RPMRC_OK on success, RPMRC_FAIL on failure
 */
RPM_GNUC_INTERNAL
rpmRC parseRCPOT(rpmSpec spec, Package pkg, const char * field, rpmTagVal tagN,
		int index, rpmsenseFlags tagflags, addReqProvFunction cb, void *cbdata);

/** \ingroup rpmbuild
 * Parse spec piece generated during build
 *
 * @param spec		spec file control structure
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC parseGeneratedSpecs(rpmSpec spec);

/** \ingroup rpmbuild
 * Run a build script, assembled from spec file scriptlet section.
 *
 * @param spec		spec file control structure
 * @param what		type of script
 * @param name		name of scriptlet section
 * @param sb		lines that compose script body
 * @param test		don't execute scripts or package if testing
 * @param sb_stdoutp	StringBuf to catupre the stdout of the script or NULL
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC doScript(rpmSpec spec, rpmBuildFlags what, const char * name,
	       const char * sb, int test, StringBuf * sb_stdoutp);

/** \ingroup rpmbuild
 * Find sub-package control structure by name.
 * @param spec		spec file control structure
 * @param name		(sub-)package name
 * @param flag		if PART_SUBNAME, then 1st package name is prepended
 * @param[out] pkg		package control structure
 * @return		0 on success, 1 on failure
 */
RPM_GNUC_INTERNAL
rpmRC lookupPackage(rpmSpec spec, const char * name, int flag,
		Package * pkg);

/** \ingroup rpmbuild
 * Create and initialize package control structure.
 * @param name		package name for sub-packages (or NULL)
 * @param pool		string pool
 * @param pkglist	package list pointer to append to (or NULL)
 * @return		package control structure
 */
RPM_GNUC_INTERNAL
Package newPackage(const char *name, rpmstrPool pool, Package * pkglist);

/** \ingroup rpmbuild
 * Free a package control structure.
 * @param pkg          package control structure
 */
RPM_GNUC_INTERNAL
Package freePackage(Package pkg);

/** \ingroup rpmbuild
 * Return rpmds containing the dependencies of a given type
 * @param pkg		package
 * @param tag		name tag denominating the dependency
 * @return		pointer to dependency set
 */
RPM_GNUC_INTERNAL
rpmds * packageDependencies(Package pkg, rpmTagVal tag);

/** \ingroup rpmbuild
 * Post-build processing for binary package(s).
 * @param spec		spec file control structure
 * @param pkgFlags	bit(s) to control package generation
 * @param didInstall	was %install executed?
 * @param test		don't execute scripts or package if testing
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
rpmRC processBinaryFiles(rpmSpec spec, rpmBuildPkgFlags pkgFlags,
			int didInstall, int test);

/** \ingroup rpmfc
 * Generate package dependencies.
 * @param spec		spec file control
 * @param pkg		package control
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC rpmfcGenerateDepends(const rpmSpec spec, Package pkg);

/** \ingroup rpmfc
 * Return helper output.
 * @param av		helper argv (with possible macros)
 * @param sb_stdin	helper input
 * @param[out] *sb_stdoutp	helper output
 * @param failnonzero	IS non-zero helper exit status a failure?
 * @param buildRoot	buildRoot directory (or NULL)
 */
RPM_GNUC_INTERNAL
int rpmfcExec(ARGV_const_t av, StringBuf sb_stdin, StringBuf * sb_stdoutp,
		int failnonzero, const char *buildRoot);

/** \ingroup rpmbuild
 * Post-build processing for policies in binary package(s).
 * @param spec		spec file control structure
 * @param test		don't execute scripts or package if testing
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
rpmRC processBinaryPolicies(rpmSpec spec, int test);

/** \ingroup rpmbuild
 * Post-build processing for source package.
 * @param spec		spec file control structure
 * @param pkgFlags	bit(s) to control package generation
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
rpmRC processSourceFiles(rpmSpec spec, rpmBuildPkgFlags pkgFlags);

/** \ingroup rpmbuild
 * Generate binary package(s).
 * @param spec		spec file control structure
 * @param cookie	build identifier "cookie" or NULL
 * @param cheating	was build shortcircuited?
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC packageBinaries(rpmSpec spec, const char *cookie, int cheating);

/** \ingroup rpmbuild
 * Generate source package.
 * @param spec		spec file control structure
 * @param[out] cookie	build identifier "cookie" or NULL
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC packageSources(rpmSpec spec, char **cookie);

RPM_GNUC_INTERNAL
int addLangTag(rpmSpec spec, Header h, rpmTagVal tag,
		const char *field, const char *lang);

/** \ingroup rpmbuild
 * Add dependency to package, filtering duplicates.
 * @param pkg		package
 * @param tagN		tag, identifies type of dependency
 * @param N		(e.g. Requires: foo < 0:1.2-3, "foo")
 * @param EVR		(e.g. Requires: foo < 0:1.2-3, "0:1.2-3")
 * @param Flags		(e.g. Requires: foo < 0:1.2-3, both "Requires:" and "<")
 * @param index         (# trigger script for triggers, 0 for others)
 * @return		0 on success, 1 on error
 */
RPM_GNUC_INTERNAL
int addReqProv(Package pkg, rpmTagVal tagN,
	       const char * N, const char * EVR, rpmsenseFlags Flags,
	       uint32_t index);

RPM_GNUC_INTERNAL
rpmRC addReqProvPkg(void *cbdata, rpmTagVal tagN,
		    const char * N, const char * EVR, rpmsenseFlags Flags,
		    int index);

/** \ingroup rpmbuild
 * Add self-provides to package.
 * @param pkg		package
 */
RPM_GNUC_INTERNAL
void addPackageProvides(Package pkg);

RPM_GNUC_INTERNAL
int addSource(rpmSpec spec, int specline, const char *srcname, rpmTagVal tag);

/** \ingroup rpmbuild
 * Add rpmlib feature dependency.
 * @param pkg		package
 * @param feature	rpm feature name (i.e. "rpmlib(Foo)" for feature Foo)
 * @param featureEVR	rpm feature epoch/version/release
 * @return		0 always
 */
RPM_GNUC_INTERNAL
int rpmlibNeedsFeature(Package pkg, const char * feature, const char * featureEVR);

RPM_GNUC_INTERNAL
rpmRC checkForEncoding(Header h, int addtag);


/** \ingroup rpmbuild
 * Copy tags inherited by subpackages from the source header to the target header
 * @param h		target header
 * @param fromh		source header
 */
RPM_GNUC_INTERNAL
void copyInheritedTags(Header h, Header fromh);

RPM_GNUC_INTERNAL
int specExpand(rpmSpec spec, int lineno, const char *sbuf,
		char **obuf);

/*
 * Read expanded lines from a file into avp and/or sbp, controlled by
 * flags (STRIP_*, ALLOW_EMPTY)
 * Returns number or read lines, or -1 on error.
 */
RPM_GNUC_INTERNAL
int readManifest(rpmSpec spec, const char *path, const char *descr, int flags,
		ARGV_t *avp, StringBuf *sbp);

RPM_GNUC_INTERNAL
void * specLuaInit(rpmSpec spec);

RPM_GNUC_INTERNAL
void * specLuaFini(rpmSpec spec);

RPM_GNUC_INTERNAL
void addLuaSource(const struct Source *p);

RPM_GNUC_INTERNAL
int isMemberInEntry(Header h, const char *name, rpmTagVal tag);

RPM_GNUC_INTERNAL
rpmRC checkForValidArchitectures(rpmSpec spec);

RPM_GNUC_INTERNAL
int checkForRequired(Header h);

RPM_GNUC_INTERNAL
int checkForDuplicates(Header h);

RPM_GNUC_INTERNAL
int checkBuildsystem(rpmSpec spec, const char *buildsys);

RPM_GNUC_INTERNAL
void fillOutMainPackage(Header h);

RPM_GNUC_INTERNAL
void copyInheritedTags(Header h, Header fromh);

RPM_GNUC_INTERNAL
void doSetupMacro(rpmMacroBuf mb, rpmMacroEntry me, ARGV_t margs, size_t *parsed);
RPM_GNUC_INTERNAL
void doPatchMacro(rpmMacroBuf mb, rpmMacroEntry me, ARGV_t margs, size_t *parsed);

/* Return section number, -1 on error */
RPM_GNUC_INTERNAL
const struct sectname_s *getSection(const char *name, int part);

#endif /* _RPMBUILD_INTERNAL_H */
