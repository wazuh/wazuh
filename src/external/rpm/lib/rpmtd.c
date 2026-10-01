#include "system.h"

#include <rpm/rpmtd.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmstrpool.h>
#include "misc.h"		/* format function prototypes */

#include "debug.h"

rpmtd rpmtdNew(void)
{
    rpmtd td = (rpmtd)xmalloc(sizeof(*td));
    rpmtdReset(td);
    return td;
}

rpmtd rpmtdFree(rpmtd td)
{
    /* permit free on NULL td */
    if (td != NULL) {
	rpmtdFreeData(td);
	free(td);
    }
    return NULL;
}

void rpmtdReset(rpmtd td)
{
    if (td) {
	memset(td, 0, sizeof(*td));
	td->ix = -1;
    }
}

void rpmtdFreeData(rpmtd td)
{
    if (td && td->data && td->flags & RPMTD_ALLOCED) {
	if (td->flags & RPMTD_PTR_ALLOCED) {
	    char **data = (char **)td->data;
	    for (int i = 0; i < td->count; i++) {
		free(data[i]);
	    }
	}
	free(td->data);
    }
    rpmtdReset(td);
}

rpm_count_t rpmtdCount(rpmtd td)
{
    rpm_count_t count = 0;
    if (td != NULL) {
	/* fix up for binary type abusing count as data length */
	count = (td->type == RPM_BIN_TYPE) ? 1 : td->count;
    }
    return count;
}

rpm_count_t rpmtdSize(rpmtd td)
{
    return (td != NULL) ? td->size : 0;
}

rpmTagVal rpmtdTag(rpmtd td)
{
    return (td != NULL) ? td->tag : 0;
}

rpmTagType rpmtdType(rpmtd td)
{
    return (td != NULL) ? (rpmTagType)td->type : RPM_NULL_TYPE;
}

rpmTagClass rpmtdClass(rpmtd td)
{
    return (td != NULL) ? rpmTagTypeGetClass(td->type) : RPM_NULL_CLASS;
}

rpmtdFlags rpmtdGetFlags(rpmtd td)
{
    return (td != NULL) ? td->flags : 0;
}

int rpmtdGetIndex(rpmtd td)
{
    return (td != NULL) ? td->ix : -1;
}

int rpmtdSetIndex(rpmtd td, int index)
{
    if (td == NULL || index < 0 || index >= rpmtdCount(td)) {
	return -1;
    }
    td->ix = index;
    return td->ix;
}

int rpmtdInit(rpmtd td)
{
    if (td == NULL)
	return -1;

    /* XXX check that this is an array type? */
    td->ix = -1;
    return 0;
}

int rpmtdNext(rpmtd td)
{
    int i = -1;
    
    if (td != NULL && ++td->ix >= 0) {
	if (td->ix < rpmtdCount(td)) {
	    i = td->ix;
	} else {
	    td->ix = i;
	}
    }
    return i;
}

uint32_t *rpmtdNextUint32(rpmtd td)
{
    uint32_t *res = NULL;
    if (rpmtdNext(td) >= 0) {
	res = rpmtdGetUint32(td);
    }
    return res;
}

uint64_t *rpmtdNextUint64(rpmtd td)
{
    uint64_t *res = NULL;
    if (rpmtdNext(td) >= 0) {
	res = rpmtdGetUint64(td);
    }
    return res;
}

const char *rpmtdNextString(rpmtd td)
{
    const char *res = NULL;
    if (rpmtdNext(td) >= 0) {
	res = rpmtdGetString(td);
    }
    return res;
}

char * rpmtdGetChar(rpmtd td)
{
    char *res = NULL;

    if (td != NULL && td->type == RPM_CHAR_TYPE) {
	int ix = (td->ix >= 0 ? td->ix : 0);
	res = (char *) td->data + ix;
    } 
    return res;
}
uint16_t * rpmtdGetUint16(rpmtd td)
{
    uint16_t *res = NULL;

    if (td != NULL && td->type == RPM_INT16_TYPE) {
	int ix = (td->ix >= 0 ? td->ix : 0);
	res = (uint16_t *) td->data + ix;
    } 
    return res;
}

uint32_t * rpmtdGetUint32(rpmtd td)
{
    uint32_t *res = NULL;

    if (td != NULL && td->type == RPM_INT32_TYPE) {
	int ix = (td->ix >= 0 ? td->ix : 0);
	res = (uint32_t *) td->data + ix;
    } 
    return res;
}

uint64_t * rpmtdGetUint64(rpmtd td)
{
    uint64_t *res = NULL;

    if (td != NULL && td->type == RPM_INT64_TYPE) {
	int ix = (td->ix >= 0 ? td->ix : 0);
	res = (uint64_t *) td->data + ix;
    } 
    return res;
}

const char * rpmtdGetString(rpmtd td)
{
    const char *str = NULL;

    if (td == NULL)
	return NULL;

    if (td->type == RPM_STRING_TYPE) {
	str = (const char *) td->data;
    } else if (td->type == RPM_STRING_ARRAY_TYPE ||
	       td->type == RPM_I18NSTRING_TYPE) {
	/* XXX TODO: check for array bounds */
	int ix = (td->ix >= 0 ? td->ix : 0);
	str = *((const char**) td->data + ix);
    } 
    return str;
}

uint64_t rpmtdGetNumber(rpmtd td)
{
    if (td == NULL)
	return 0;

    uint64_t val = 0;
    int ix = (td->ix >= 0 ? td->ix : 0);

    switch (td->type) {
    case RPM_INT64_TYPE:
	val = *((uint64_t *) td->data + ix);
	break;
    case RPM_INT32_TYPE:
	val = *((uint32_t *) td->data + ix);
	break;
    case RPM_INT16_TYPE:
	val = *((uint16_t *) td->data + ix);
	break;
    case RPM_INT8_TYPE:
    case RPM_CHAR_TYPE:
	val = *((uint8_t *) td->data + ix);
	break;
    default:
	break;
    }
    return val;
}

char *rpmtdFormat(rpmtd td, rpmtdFormats fmt, const char *errmsg)
{
    headerFmt ext = rpmHeaderFormatByValue(fmt);
    const char *err = NULL;
    char *str = NULL;

    if (ext) {
	str = rpmHeaderFormatCall(ext, td);
    } else {
	err = _("Unknown format");
    }
    
    if (err && errmsg) {
	errmsg = err;
    }

    return str;
}

int rpmtdSetTag(rpmtd td, rpmTagVal tag)
{
    rpmTagType newtype = rpmTagGetTagType(tag);
    int rc = 0;

    if (td == NULL)
	goto exit;

    /* 
     * Sanity checks: 
     * - is the new tag valid at all
     * - if changing tag of non-empty container, require matching type 
     */
    if (newtype == RPM_NULL_TYPE)
	goto exit;

    if (td->data || td->count > 0) {
	if (rpmTagGetTagType(td->tag) != rpmTagGetTagType(tag)) {
	    goto exit;
	}
    } 

    td->tag = tag;
    td->type = newtype;
    rc = 1;
    
exit:
    return rc;
}

static inline int rpmtdSet(rpmtd td, rpmTagVal tag, rpmTagType type, 
			    rpm_constdata_t data, rpm_count_t count)
{
    rpmtdReset(td);
    td->tag = tag;
    td->type = type;
    td->count = count;
    /* 
     * Discards const, but we won't touch the data (even rpmtdFreeData()
     * wont free it as allocation flags aren't set) so it's "ok". 
     * XXX: Should there be a separate RPMTD_FOO flag for "user data"?
     */
    td->data = (void *) data;
    return 1;
}

int rpmtdFromUint8(rpmtd td, rpmTagVal tag, uint8_t *data, rpm_count_t count)
{
    rpmTagType type = rpmTagGetTagType(tag);
    rpmTagReturnType retype = rpmTagGetReturnType(tag);
    
    if (count < 1)
	return 0;

    /*
     * BIN type is really just an uint8_t array internally, it's just
     * treated specially otherwise.
     */
    switch (type) {
    case RPM_CHAR_TYPE:
    case RPM_INT8_TYPE:
	if (retype != RPM_ARRAY_RETURN_TYPE && count > 1) 
	    return 0;
	/* fallthrough */
    case RPM_BIN_TYPE:
	break;
    default:
	return 0;
    }
    
    return rpmtdSet(td, tag, type, data, count);
}

int rpmtdFromUint16(rpmtd td, rpmTagVal tag, uint16_t *data, rpm_count_t count)
{
    rpmTagType type = rpmTagGetTagType(tag);
    rpmTagReturnType retype = rpmTagGetReturnType(tag);
    if (type != RPM_INT16_TYPE || count < 1) 
	return 0;
    if (retype != RPM_ARRAY_RETURN_TYPE && count > 1) 
	return 0;
    
    return rpmtdSet(td, tag, type, data, count);
}

int rpmtdFromUint32(rpmtd td, rpmTagVal tag, uint32_t *data, rpm_count_t count)
{
    rpmTagType type = rpmTagGetTagType(tag);
    rpmTagReturnType retype = rpmTagGetReturnType(tag);
    if (type != RPM_INT32_TYPE || count < 1) 
	return 0;
    if (retype != RPM_ARRAY_RETURN_TYPE && count > 1) 
	return 0;
    
    return rpmtdSet(td, tag, type, data, count);
}

int rpmtdFromUint64(rpmtd td, rpmTagVal tag, uint64_t *data, rpm_count_t count)
{
    rpmTagType type = rpmTagGetTagType(tag);
    rpmTagReturnType retype = rpmTagGetReturnType(tag);
    if (type != RPM_INT64_TYPE || count < 1) 
	return 0;
    if (retype != RPM_ARRAY_RETURN_TYPE && count > 1) 
	return 0;
    
    return rpmtdSet(td, tag, type, data, count);
}

int rpmtdFromString(rpmtd td, rpmTagVal tag, const char *data)
{
    rpmTagType type = rpmTagGetTagType(tag);
    int rc = 0;

    if (type == RPM_STRING_TYPE) {
	rc = rpmtdSet(td, tag, type, data, 1);
    } else if (type == RPM_STRING_ARRAY_TYPE) {
	rc = rpmtdSet(td, tag, type, &data, 1);
    }

    return rc;
}

int rpmtdFromStringArray(rpmtd td, rpmTagVal tag, const char **data, rpm_count_t count)
{
    rpmTagType type = rpmTagGetTagType(tag);
    if (type != RPM_STRING_ARRAY_TYPE || count < 1)
	return 0;
    if (type == RPM_STRING_TYPE && count != 1)
	return 0;

    return rpmtdSet(td, tag, type, data, count);
}

int rpmtdFromArgv(rpmtd td, rpmTagVal tag, ARGV_t argv)
{
    int count = argvCount(argv);
    rpmTagType type = rpmTagGetTagType(tag);

    if (type != RPM_STRING_ARRAY_TYPE || count < 1)
	return 0;

    return rpmtdSet(td, tag, type, argv, count);
}

int rpmtdFromArgi(rpmtd td, rpmTagVal tag, ARGI_t argi)
{
    int count = argiCount(argi);
    rpmTagType type = rpmTagGetTagType(tag);
    rpmTagReturnType retype = rpmTagGetReturnType(tag);

    if (type != RPM_INT32_TYPE || retype != RPM_ARRAY_RETURN_TYPE || count < 1)
	return 0;

    return rpmtdSet(td, tag, type, argiData(argi), count);
}

rpmtd rpmtdDup(rpmtd td)
{
    rpmtd newtd = NULL;
    char **data = NULL;
    int i;

    if (td == NULL)
	return NULL;
    
    /* TODO: permit other types too */
    if (td->type != RPM_STRING_ARRAY_TYPE && td->type != RPM_I18NSTRING_TYPE) {
	return NULL;
    }

    /* deep-copy container and data, drop immutable flag */
    newtd = rpmtdNew();
    memcpy(newtd, td, sizeof(*td));
    newtd->flags &= ~(RPMTD_IMMUTABLE);

    newtd->flags |= (RPMTD_ALLOCED | RPMTD_PTR_ALLOCED);
    newtd->data = data = (char **)xmalloc(td->count * sizeof(*data));
    while ((i = rpmtdNext(td)) >= 0) {
	data[i] = xstrdup(rpmtdGetString(td));
    }

    return newtd;
}

rpmsid * rpmtdToPool(rpmtd td, rpmstrPool pool)
{
    rpmsid *sids = NULL;

    if (pool && td) {
	const char **strings = (const char **)td->data;
	switch (td->type) {
	case RPM_STRING_ARRAY_TYPE:
	case RPM_I18NSTRING_TYPE:
	    sids = (rpmsid *)xmalloc(td->count * sizeof(*sids));
	    for (rpm_count_t i = 0; i < td->count; i++)
		sids[i] = rpmstrPoolId(pool, strings[i], 1);
	    break;
	}
    }
    return sids;
}
