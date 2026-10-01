/**
 * \file lib/tagname.c
 */

#include "system.h"

#include <pthread.h>

#include <rpm/header.h>
#include <rpm/rpmstring.h>
#include "debug.h"

/** \ingroup header
 * Associate tag names with numeric values.
 */
typedef const struct headerTagTableEntry_s * headerTagTableEntry;
struct headerTagTableEntry_s {
    const char * name;		/*!< Tag name. */
    const char * shortname;	/*!< "Human readable" short name. */
    rpmTagVal val;		/*!< Tag numeric value. */
    rpmTagType type;		/*!< Tag type. */
    rpmTagReturnType retype;	/*!< Tag return type. */
    int extension;		/*!< Extension or "real" tag */
};

#include "tagtbl.inc"

#define TABLESIZE (sizeof(rpmTagTable) / sizeof(rpmTagTable[0]) - 1)
static const int rpmTagTableSize = TABLESIZE;

static headerTagTableEntry tagsByName[TABLESIZE]; /*!< tags sorted by name. */
static headerTagTableEntry tagsByValue[TABLESIZE]; /*!< tags sorted by value. */

/**
 * Compare tag table entries by name.
 * @param *avp		tag table entry a
 * @param *bvp		tag table entry b
 * @return		comparison
 */
static int tagCmpName(const void * avp, const void * bvp)
{
    headerTagTableEntry a = *(const headerTagTableEntry *) avp;
    headerTagTableEntry b = *(const headerTagTableEntry *) bvp;
    return strcmp(a->name, b->name);
}

/**
 * Compare tag table entries by value.
 * @param *avp		tag table entry a
 * @param *bvp		tag table entry b
 * @return		comparison
 */
static int tagCmpValue(const void * avp, const void * bvp)
{
    headerTagTableEntry a = *(const headerTagTableEntry *) avp;
    headerTagTableEntry b = *(const headerTagTableEntry *) bvp;
    int ret = (a->val - b->val);
    /* Make sure that sort is stable, longest name first. */
    if (ret == 0)
	ret = (strlen(b->name) - strlen(a->name));
    return ret;
}

static pthread_once_t tagsLoaded = PTHREAD_ONCE_INIT;

/* Initialize tag by-value and by-name lookup tables */
static void loadTags(void)
{
    for (int i = 0; i < rpmTagTableSize; i++) {
	tagsByValue[i] = &rpmTagTable[i];
	tagsByName[i] = &rpmTagTable[i];
    }

    qsort(tagsByValue, rpmTagTableSize, sizeof(*tagsByValue), tagCmpValue);
    qsort(tagsByName, rpmTagTableSize, sizeof(*tagsByName), tagCmpName);
}

static headerTagTableEntry entryByTag(rpmTagVal tag)
{
    headerTagTableEntry entry = NULL;
    int i, comparison;
    int l = 0;
    int u = rpmTagTableSize;

    while (l < u) {
	i = (l + u) / 2;
	comparison = (tag - tagsByValue[i]->val);

	if (comparison < 0) {
	    u = i;
	} else if (comparison > 0) {
	    l = i + 1;
	} else {
	    /* Make sure that the bsearch retrieve is stable. */
	    while (i > 0 && tag == tagsByValue[i-1]->val) {
		i--;
	    }
	    entry = tagsByValue[i];
	    break;
	}
    }
    return entry;
}

static headerTagTableEntry entryByName(const char *tag)
{
    headerTagTableEntry entry = NULL;
    int i, comparison;
    int l = 0;
    int u = rpmTagTableSize;

    while (l < u) {
	i = (l + u) / 2;
	comparison = rstrcasecmp(tag, tagsByName[i]->shortname);

	if (comparison < 0) {
	    u = i;
	} else if (comparison > 0) {
	    l = i + 1;
	} else {
	    entry = tagsByName[i];
	    break;
	}
    }
    return entry;
}

const char * rpmTagGetName(rpmTagVal tag)
{
    const char *name = "(unknown)";
    const struct headerTagTableEntry_s *t;

    pthread_once(&tagsLoaded, loadTags);

    switch (tag) {
    case RPMDBI_PACKAGES:
	name = "Packages";
	break;
    /* XXX make sure rpmdb indices are identically named. */
    case RPMTAG_CONFLICTS:
	name = "Conflictname";
	break;
    case RPMTAG_HDRID:
	name = "Sha1header";
	break;

    default:
	t = entryByTag(tag);
	if (t && t->shortname)
	    name = t->shortname;
	break;
    }
    return name;
}

rpmTagType rpmTagGetType(rpmTagVal tag)
{
    const struct headerTagTableEntry_s *t;
    rpmTagType tagtype = RPM_NULL_TYPE;

    pthread_once(&tagsLoaded, loadTags);

    t = entryByTag(tag);
    if (t) {
	/* XXX this is dumb */
	tagtype = (rpmTagType)(t->type | t->retype);
    }
    return tagtype;
}

rpmTagVal rpmTagGetValue(const char * tagstr)
{
    const struct headerTagTableEntry_s *t;
    rpmTagVal tagval = RPMTAG_NOT_FOUND;

    pthread_once(&tagsLoaded, loadTags);

    if (!rstrcasecmp(tagstr, "Packages"))
	return RPMDBI_PACKAGES;

    t = entryByName(tagstr);
    if (t)
	tagval = t->val;
	
    return tagval;
}

rpmTagType rpmTagGetTagType(rpmTagVal tag)
{
    return (rpmTagGetType(tag) & RPM_MASK_TYPE);
}

rpmTagReturnType rpmTagGetReturnType(rpmTagVal tag)
{
    return (rpmTagGetType(tag) & RPM_MASK_RETURN_TYPE);
}

rpmTagClass rpmTagTypeGetClass(rpmTagType type)
{
    rpmTagClass tclass;
    switch (type & RPM_MASK_TYPE) {
    case RPM_CHAR_TYPE:
    case RPM_INT8_TYPE:
    case RPM_INT16_TYPE:
    case RPM_INT32_TYPE:
    case RPM_INT64_TYPE:
	tclass = RPM_NUMERIC_CLASS;
	break;
    case RPM_STRING_TYPE:
    case RPM_STRING_ARRAY_TYPE:
    case RPM_I18NSTRING_TYPE:
	tclass = RPM_STRING_CLASS;
	break;
    case RPM_BIN_TYPE:
	tclass = RPM_BINARY_CLASS;
	break;
    case RPM_NULL_TYPE:
    default:
	tclass = RPM_NULL_CLASS;
	break;
    }
    return tclass;
}

rpmTagClass rpmTagGetClass(rpmTagVal tag)
{
    return rpmTagTypeGetClass(rpmTagGetTagType(tag));
}

int rpmTagGetNames(rpmtd tagnames, int fullname)
{
    const char **names;
    const char *name;

    pthread_once(&tagsLoaded, loadTags);

    if (tagnames == NULL)
	return 0;

    rpmtdReset(tagnames);
    tagnames->count = rpmTagTableSize;
    tagnames->data = names = (const char **)xmalloc(tagnames->count * sizeof(*names));
    tagnames->type = RPM_STRING_ARRAY_TYPE;
    tagnames->flags = RPMTD_ALLOCED | RPMTD_IMMUTABLE;

    for (int i = 0; i < tagnames->count; i++) {
	name = fullname ? tagsByName[i]->name :
			  tagsByName[i]->shortname;
	names[i] = name;
    }
    return tagnames->count;
}
