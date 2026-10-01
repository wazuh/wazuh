/** \ingroup header
 * \file lib/formats.c
 */

#include "system.h"

#include <inttypes.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmtd.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmbase64.h>

#include "rpmpgpval.h"
#include "manifest.h"
#include "misc.h"
#include "signature.h"

#include "debug.h"

typedef char * (*headerTagFormatFunction) (rpmtd td, char **emsg);

/** \ingroup header
 * Define header tag output formats.
 */

struct headerFmt_s {
    rpmtdFormats fmt;	/*!< Value of extension */
    const char *name;	/*!< Name of extension. */
    rpmTagClass tclass;	/*!< Class of source data (RPM_NULL_CLASS for any) */
    headerTagFormatFunction func;	/*!< Pointer to formatter function. */	
};

static const char *classEr(rpmTagClass tclass)
{
    switch (tclass) {
    case RPM_BINARY_CLASS:	 return _("(not a blob)");
    case RPM_NUMERIC_CLASS:	 return _("(not a number)");
    case RPM_STRING_CLASS:	 return _("(not a string)");
    default:			 break;
    }
    return _("(invalid type)");
}

/* barebones string representation with no extra formatting */
static char * stringFormat(rpmtd td, char **emsg)
{
    char *val = NULL;

    switch (rpmtdClass(td)) {
	case RPM_NUMERIC_CLASS:
	    rasprintf(&val, "%" PRIu64, rpmtdGetNumber(td));
	    break;
	case RPM_STRING_CLASS: {
	    const char *str = rpmtdGetString(td);
	    if (str)
		val = xstrdup(str);
	    break;
	}
	case RPM_BINARY_CLASS:
	    val = rpmhex((uint8_t *)td->data, td->count);
	    break;
	default:
	    *emsg = xstrdup("(unknown type)");
	    break;
    }
    return val;
}

/* arbitrary number format as per format arg */
static char * numFormat(rpmtd td, const char *format)
{
    char * val = NULL;
    rasprintf(&val, format, rpmtdGetNumber(td));
    return val;
}

/* octal number formatting */
static char * octalFormat(rpmtd td, char **emsg)
{
    return numFormat(td, "%o");
}

/* hexadecimal format */
static char * hexFormat(rpmtd td, char **emsg)
{
    return numFormat(td, "%x");
}

/* arbitrary date formatting as per strftimeFormat arg */
static char * realDateFormat(rpmtd td, const char * strftimeFormat, char **emsg)
{
    char * val = NULL;
    struct tm * tstruct, _tm;
    char buf[1024];
    time_t dateint = rpmtdGetNumber(td);
    tstruct = localtime_r(&dateint, &_tm);

    buf[0] = '\0';
    if (tstruct)
	if (strftime(buf, sizeof(buf) - 1, strftimeFormat, tstruct) == 0)
	    *emsg = xstrdup("date output too long");
    val = xstrdup(buf);

    return val;
}

/* date formatting */
static char * dateFormat(rpmtd td, char **emsg)
{
    return realDateFormat(td, "%c", emsg);
}

/* day formatting */
static char * dayFormat(rpmtd td, char **emsg)
{
    return realDateFormat(td, "%a %b %d %Y", emsg);
}

/* shell escape formatting */
static char * shescapeFormat(rpmtd td, char **emsg)
{
    char *result = NULL;

    if (rpmtdClass(td) == RPM_NUMERIC_CLASS) {
	rasprintf(&result, "%" PRIu64, rpmtdGetNumber(td));
    } else if (rpmtdClass(td) == RPM_STRING_CLASS) {
	const char *args[] = { rpmtdGetString(td), NULL };
	rpmExpandThisMacro(NULL, "shescape", (ARGV_const_t)args, &result, 0);
    } else {
	*emsg = xstrdup(_("(invalid type)"));
    }

    return result;
}


/* trigger type formatting (from rpmsense flags) */
static char * triggertypeFormat(rpmtd td, char **emsg)
{
    char * val;
    uint64_t item = rpmtdGetNumber(td);
    if (item & RPMSENSE_TRIGGERPREIN)
	val = xstrdup("prein");
    else if (item & RPMSENSE_TRIGGERIN)
	val = xstrdup("in");
    else if (item & RPMSENSE_TRIGGERUN)
	val = xstrdup("un");
    else if (item & RPMSENSE_TRIGGERPOSTUN)
	val = xstrdup("postun");
    else
	val = xstrdup("");
    return val;
}

/* dependency type formatting (from rpmsense flags) */
static char * deptypeFormat(rpmtd td, char **emsg)
{
    char *val = NULL;
    ARGV_t sdeps = NULL;
    uint64_t item = rpmtdGetNumber(td);

    if (item & RPMSENSE_SCRIPT_PRE)
	argvAdd(&sdeps, "pre");
    if (item & RPMSENSE_SCRIPT_POST)
	argvAdd(&sdeps, "post");
    if (item & RPMSENSE_SCRIPT_PREUN)
	argvAdd(&sdeps, "preun");
    if (item & RPMSENSE_SCRIPT_POSTUN)
	argvAdd(&sdeps, "postun");
    if (item & RPMSENSE_SCRIPT_VERIFY)
	argvAdd(&sdeps, "verify");
    if (item & RPMSENSE_INTERP)
	argvAdd(&sdeps, "interp");
    if (item & RPMSENSE_RPMLIB)
	argvAdd(&sdeps, "rpmlib");
    if ((item & RPMSENSE_FIND_REQUIRES) || (item & RPMSENSE_FIND_PROVIDES))
	argvAdd(&sdeps, "auto");
    if (item & RPMSENSE_PREREQ)
	argvAdd(&sdeps, "prereq");
    if (item & RPMSENSE_PRETRANS)
	argvAdd(&sdeps, "pretrans");
    if (item & RPMSENSE_POSTTRANS)
	argvAdd(&sdeps, "posttrans");
    if (item & RPMSENSE_PREUNTRANS)
	argvAdd(&sdeps, "preuntrans");
    if (item & RPMSENSE_POSTUNTRANS)
	argvAdd(&sdeps, "postuntrans");
    if (item & RPMSENSE_CONFIG)
	argvAdd(&sdeps, "config");
    if (item & RPMSENSE_MISSINGOK)
	argvAdd(&sdeps, "missingok");
    if (item & RPMSENSE_META)
	argvAdd(&sdeps, "meta");

    if (sdeps) {
	val = argvJoin(sdeps, ",");
    } else {
	val = xstrdup("manual");
    }

    argvFree(sdeps);
    return val;
}

/* file permissions formatting */
static char * permsFormat(rpmtd td, char **emsg)
{
    return rpmPermsString(rpmtdGetNumber(td));
}

/* file flags formatting */
static char * fflagsFormat(rpmtd td, char **emsg)
{
    return rpmFFlagsString(rpmtdGetNumber(td));
}

/* pubkey ascii armor formatting */
static char * armorFormat(rpmtd td, char **emsg)
{
    const char * enc;
    const unsigned char * s;
    unsigned char * bs = NULL;
    char *val = NULL;
    size_t ns;
    int atype;

    switch (rpmtdType(td)) {
    case RPM_BIN_TYPE:
	s = (const unsigned char *)td->data;
	/* XXX HACK ALERT: element field abused as no. bytes of binary data. */
	ns = td->count;
	atype = PGPARMOR_SIGNATURE;	/* XXX check pkt for signature */
	break;
    case RPM_STRING_TYPE:
    case RPM_STRING_ARRAY_TYPE:
	enc = rpmtdGetString(td);
	if (rpmBase64Decode(enc, (void **)&bs, &ns)) {
	    *emsg = xstrdup(_("(not base64)"));
	    goto exit;
	}
	s = bs;
	atype = PGPARMOR_PUBKEY;	/* XXX check pkt for pubkey */
	break;
    case RPM_NULL_TYPE:
    case RPM_CHAR_TYPE:
    case RPM_INT8_TYPE:
    case RPM_INT16_TYPE:
    case RPM_INT32_TYPE:
    case RPM_INT64_TYPE:
    case RPM_I18NSTRING_TYPE:
    default:
	*emsg = xstrdup(_("(invalid type)"));
	goto exit;
	break;
    }

    /* XXX this doesn't use padding directly, assumes enough slop in retval. */
    val = pgpArmorWrap(atype, s, ns);
    if (atype == PGPARMOR_PUBKEY) {
    	free(bs);
    }

exit:
    return val;
}

/* base64 encoding formatting */
static char * base64Format(rpmtd td, char **emsg)
{
    char * val = rpmBase64Encode(td->data, td->count, -1);
    if (val == NULL)
	val = xstrdup("");

    return val;
}

/* xml formatting */
static char * xmlFormat(rpmtd td, char **emsg)
{
    const char *xtag = NULL;
    char *val = NULL;
    char *s = NULL;
    headerTagFormatFunction fmt = stringFormat;

    switch (rpmtdClass(td)) {
    case RPM_STRING_CLASS:
	xtag = "string";
	break;
    case RPM_BINARY_CLASS:
	fmt = base64Format;
	xtag = "base64";
	break;
    case RPM_NUMERIC_CLASS:
	xtag = "integer";
	break;
    case RPM_NULL_TYPE:
    default:
	*emsg = xstrdup(_("(invalid xml type)"));
	goto exit;
	break;
    }

    s = fmt(td, emsg);
    if (s == NULL)
	goto exit;

    if (s[0] == '\0') {
	val = rstrscat(NULL, "\t<", xtag, "/>", NULL);
    } else {
	char *new_s = NULL;
	size_t i, s_size = strlen(s);
	
	for (i=0; i<s_size; i++) {
	    switch (s[i]) {
		case '<':	rstrcat(&new_s, "&lt;");	break;
		case '>':	rstrcat(&new_s, "&gt;");	break;
		case '&':	rstrcat(&new_s, "&amp;");	break;
		default: {
		    char c[2] = " ";
		    *c = s[i];
		    rstrcat(&new_s, c);
		    break;
		}
	    }
	}

	val = rstrscat(NULL, "\t<", xtag, ">", new_s, "</", xtag, ">", NULL);
	free(new_s);
    }
    free(s);

exit:
    return val;
}

static char *jsonEscape(const char *s)
{
    char *es = NULL;
    rstrcat(&es, "\"");
    for (const char *c = s; *c != '\0'; c++) {
	const char *ec = NULL;
	switch (*c) {
	case '\b':
	    ec = "\\b";
	    break;
	case '\f':
	    ec = "\\f";
	    break;
	case '\n':
	    ec = "\\n";
	    break;
	case '\r':
	    ec = "\\r";
	    break;
	case '\t':
	    ec = "\\t";
	    break;
	case '"':
	    ec = "\\\"";
	    break;
	case '\\':
	    ec = "\\\\";
	    break;
	default:
	    break;
	}

	if (ec) {
	    rstrcat(&es, ec);
	} else if (*c > 0 && *c < 0x20) {
	    char *uc = NULL;
	    rasprintf(&uc, "\\u%04x", *c);
	    rstrcat(&es, uc);
	    free(uc);
	} else {
	    char t[2] = " ";
	    *t = *c;
	    rstrcat(&es, t);
	}
    }
    rstrcat(&es, "\"");
    return es;
}

static char *jsonFormat(rpmtd td, char **emsg)
{
    int escape = 1;
    char *val = NULL;

    switch (rpmtdClass(td)) {
    case RPM_BINARY_CLASS:
	/* we don't want newlines in the binary output */
	val = rpmBase64Encode(td->data, td->count, 0);
	break;
    case RPM_NUMERIC_CLASS:
	escape = 0;
	/* fallthrough */
    default:
	val = stringFormat(td, emsg);
	break;
    }

    if (escape) {
	char *s = jsonEscape(val);
	free(val);
	val = s;
    }
    return val;
}

/* signature fingerprint and time formatting */
static char * pgpsigFormat(rpmtd td, char **emsg)
{
    char * val = NULL;
    pgpDigParams sigp = NULL;

    if (pgpPrtParams((uint8_t*)td->data, td->count, PGPTAG_SIGNATURE, &sigp)) {
	*emsg = xstrdup(_("(not an OpenPGP signature)"));
    } else {
	char dbuf[BUFSIZ];
	char *keyid = rpmhex(pgpDigParamsSignID(sigp), PGP_KEYID_LEN);
	unsigned int dateint = pgpDigParamsCreationTime(sigp);
	time_t date = dateint;
	struct tm _tm, * tms = localtime_r(&date, &_tm);
	unsigned int key_algo = pgpDigParamsAlgo(sigp, PGPVAL_PUBKEYALGO);
	unsigned int hash_algo = pgpDigParamsAlgo(sigp, PGPVAL_HASHALGO);

	if (!(tms && strftime(dbuf, sizeof(dbuf), "%c", tms) > 0)) {
	    rasprintf(emsg, _("Invalid date %u"), dateint);
	} else {
	    rasprintf(&val, "%s/%s, %s, Key ID %s",
		    pgpValString(PGPVAL_PUBKEYALGO, key_algo),
		    pgpValString(PGPVAL_HASHALGO, hash_algo),
		    dbuf, keyid);
	}

	free(keyid);
	pgpDigParamsFree(sigp);
    }

    return val;
}

/* dependency flags formatting */
static char * depflagsFormat(rpmtd td, char **emsg)
{
    char * val = NULL;
    uint64_t anint = rpmtdGetNumber(td);
    val = (char *)xcalloc(4, 1);

    if (anint & RPMSENSE_LESS)
	strcat(val, "<");
    if (anint & RPMSENSE_GREATER)
	strcat(val, ">");
    if (anint & RPMSENSE_EQUAL)
	strcat(val, "=");

    return val;
}

/* tag container array size */
static char * arraysizeFormat(rpmtd td, char **emsg)
{
    char *val = NULL;
    rasprintf(&val, "%u", rpmtdCount(td));
    return val;
}

/* file state formatting */
static char * fstateFormat(rpmtd td, char **emsg)
{
    char * val = NULL;
    const char * str;
    rpmfileState fstate = (rpmfileState)rpmtdGetNumber(td);
    switch (fstate) {
    case RPMFILE_STATE_NORMAL:
	str = _("normal");
	break;
    case RPMFILE_STATE_REPLACED:
	str = _("replaced");
	break;
    case RPMFILE_STATE_NOTINSTALLED:
	str = _("not installed");
	break;
    case RPMFILE_STATE_NETSHARED:
	str = _("net shared");
	break;
    case RPMFILE_STATE_WRONGCOLOR:
	str = _("wrong color");
	break;
    case RPMFILE_STATE_MISSING:
	str = _("missing");
	break;
    default:
	str = _("(unknown)");
	break;
    }

    val = xstrdup(str);
    return val;
}

/* file verification flags formatting with optional padding */
static char * verifyFlags(rpmtd td, const char *pad)
{
    return rpmVerifyString(rpmtdGetNumber(td), pad);
}

static char * vflagsFormat(rpmtd td, char **emsg)
{
    return verifyFlags(td, "");
}

static char * fstatusFormat(rpmtd td, char **emsg)
{
    return verifyFlags(td, ".");
}

/* macro expansion formatting */
static char * expandFormat(rpmtd td, char **emsg)
{
    return rpmExpand(rpmtdGetString(td), NULL);
}

static char * humanFormat(rpmtd td, char **emsg, int kilo)
{
    const char* units[] = {"", "K", "M", "G", "T", "P", "E", "Z", "Y"};
    int i = 0;
    float number = rpmtdGetNumber(td);
    int decimals = 0;
    char * val = NULL;

    while (number >= kilo) {
	number /= kilo;
	i++;
    }
    if ((number > 0.05) && (number < 9.95))
	decimals = 1;
    rasprintf(&val, "%.*f%s", decimals, number, units[i]);

    return val;
}

static char * humansiFormat(rpmtd td, char **emsg)
{
    return humanFormat(td, emsg, 1000);
}

static char * humaniecFormat(rpmtd td, char **emsg)
{
    return humanFormat(td, emsg, 1024);
}

static char *tagnameFormat(rpmtd td, char **emsg)
{
    return xstrdup(rpmTagGetName(td->tag));
}

static char *tagnumFormat(rpmtd td, char **emsg)
{
    char *num = NULL;
    rasprintf(&num, "%u", td->tag);
    return num;
}

static const struct headerFmt_s rpmHeaderFormats[] = {
    { RPMTD_FORMAT_STRING,	"string",
	RPM_NULL_CLASS,		stringFormat },
    { RPMTD_FORMAT_ARMOR,	"armor",
	RPM_NULL_CLASS,		armorFormat },
    { RPMTD_FORMAT_BASE64,	"base64",
	RPM_BINARY_CLASS,	base64Format },
    { RPMTD_FORMAT_PGPSIG,	"pgpsig",
	RPM_BINARY_CLASS,	pgpsigFormat },
    { RPMTD_FORMAT_DEPFLAGS,	"depflags",
	RPM_NUMERIC_CLASS, depflagsFormat },
    { RPMTD_FORMAT_DEPTYPE,	"deptype",
	RPM_NUMERIC_CLASS,	deptypeFormat },
    { RPMTD_FORMAT_FFLAGS,	"fflags",
	RPM_NUMERIC_CLASS,	fflagsFormat },
    { RPMTD_FORMAT_PERMS,	"perms",
	RPM_NUMERIC_CLASS,	permsFormat },
    { RPMTD_FORMAT_PERMS,	"permissions",
	RPM_NUMERIC_CLASS,	permsFormat },
    { RPMTD_FORMAT_TRIGGERTYPE,	"triggertype",
	RPM_NUMERIC_CLASS,	triggertypeFormat },
    { RPMTD_FORMAT_XML,		"xml",
	RPM_NULL_CLASS,		xmlFormat },
    { RPMTD_FORMAT_OCTAL,	"octal",
	RPM_NUMERIC_CLASS,	octalFormat },
    { RPMTD_FORMAT_HEX,		"hex",
	RPM_NUMERIC_CLASS,	hexFormat },
    { RPMTD_FORMAT_DATE,	"date",
	RPM_NUMERIC_CLASS,	dateFormat },
    { RPMTD_FORMAT_DAY,		"day",
	RPM_NUMERIC_CLASS,	dayFormat },
    { RPMTD_FORMAT_SHESCAPE,	"shescape",
	RPM_NULL_CLASS,		shescapeFormat },
    { RPMTD_FORMAT_ARRAYSIZE,	"arraysize",
	RPM_NULL_CLASS,		arraysizeFormat },
    { RPMTD_FORMAT_FSTATE,	"fstate",
	RPM_NUMERIC_CLASS,	fstateFormat },
    { RPMTD_FORMAT_VFLAGS,	"vflags",
	RPM_NUMERIC_CLASS,	vflagsFormat },
    { RPMTD_FORMAT_EXPAND,	"expand",
	RPM_STRING_CLASS,	expandFormat },
    { RPMTD_FORMAT_FSTATUS,	"fstatus",
	RPM_NUMERIC_CLASS,	fstatusFormat },
    { RPMTD_FORMAT_HUMANSI,	"humansi",
	RPM_NUMERIC_CLASS,	humansiFormat },
    { RPMTD_FORMAT_HUMANIEC,	"humaniec",
	RPM_NUMERIC_CLASS,	humaniecFormat },
    { RPMTD_FORMAT_TAGNAME,	"tagname",
	RPM_NULL_CLASS,		tagnameFormat },
    { RPMTD_FORMAT_TAGNUM,	"tagnum",
	RPM_NULL_CLASS,		tagnumFormat },
    { RPMTD_FORMAT_JSON,	"json",
	RPM_NULL_CLASS,		jsonFormat },
    { RPMTD_FORMAT_STRING,	NULL, 		RPM_NULL_CLASS,	NULL }
};

headerFmt rpmHeaderFormatByName(const char *fmt)
{
    const struct headerFmt_s * ext;

    for (ext = rpmHeaderFormats; ext->name != NULL; ext++) {
	if (rstreq(ext->name, fmt))
	    return ext;
    }
    return NULL;
}

headerFmt rpmHeaderFormatByValue(rpmtdFormats fmt)
{
    const struct headerFmt_s * ext;

    for (ext = rpmHeaderFormats; ext->name != NULL; ext++) {
	if (fmt == ext->fmt)
	    return ext;
    }
    return NULL;
}

char *rpmHeaderFormatCall(headerFmt fmt, rpmtd td)
{
    char *ret = NULL;
    char *err = NULL;

    if (fmt->tclass != RPM_NULL_CLASS && rpmtdClass(td) != fmt->tclass)
	err = xstrdup(classEr(fmt->tclass));
    else
	ret = fmt->func(td, &err);

    if (err) {
	free(ret);
	ret = err;
    }
    return ret;
}
