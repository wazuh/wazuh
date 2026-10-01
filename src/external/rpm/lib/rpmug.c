#include "system.h"

#include <errno.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmmacro.h>

#include "misc.h"
#include "rpmug.h"
#include "debug.h"

struct rpmug_s {
    char *pwpath;
    char *grppath;
    char *lastGname;
    char *lastUname;
    uid_t lastUid;
    gid_t lastGid;
};

static __thread struct rpmug_s *rpmug = NULL;

static const char *getpath(const char *bn, const char *dfl, char **dest)
{
    if (*dest == NULL) {
	char *s = rpmExpand("%{_", bn, "_path}", NULL);
	if (*s == '%' || *s == '\0') {
	    free(s);
	    s = xstrdup(dfl);
	}
	*dest = s;
    }
    return *dest;
}

static const char *pwfile(void)
{
    return getpath("passwd", "/etc/passwd", &rpmug->pwpath);
}

static const char *grpfile(void)
{
    return getpath("group", "/etc/group", &rpmug->grppath);
}

/*
 * Lookup an arbitrary field based on contents of another in a ':' delimited
 * file, such as /etc/passwd or /etc/group.
 */
static int lookup_field(const char *path, const char *val, int vcol, int rcol,
			char **ret)
{
    int rc = -1; /* assume not found */
    char *str, buf[BUFSIZ];
    FILE *f = fopen(path, "r");
    if (f == NULL) {
	rpmlog(RPMLOG_ERR, _("failed to open %s for id/name lookup: %s\n"),
		path, strerror(errno));
	return rc;
    }

    while ((str = fgets(buf, sizeof(buf), f)) != NULL) {
	int nf = vcol > rcol ? vcol : rcol;
	const char *fields[nf + 1];
	char *tok, *save = NULL;
	int col = -1;

	while ((tok = strtok_r(str, ":", &save)) != NULL) {
	    fields[++col] = tok;
	    str = NULL;
	    if (col >= nf)
		break;
	}

	if (col >= nf) {
	    if (rstreq(val, fields[vcol])) {
		*ret = xstrdup(fields[rcol]);
		rc = 0;
	    }
	}
    }

    fclose(f);

    return rc;
}

/* atol() with error handling, return 0/-1 on success/failure */
static int stol(const char *s, long *ret)
{
    int rc = 0;
    char *end = NULL;
    long val = strtol(s, &end, 10);

    /* only accept fully numeric data */
    if (*s == '\0' || *end != '\0')
	rc = -1;

    if ((val == LONG_MIN || val == LONG_MAX) && errno == ERANGE)
	rc = -1;

    if (rc == 0)
	*ret = val;

    return rc;
}

static int lookup_num(const char *path, const char *val, int vcol, int rcol,
			long *ret)
{
    char *buf = NULL;
    int rc = lookup_field(path, val, vcol, rcol, &buf);
    if (rc == 0) {
	rc = stol(buf, ret);
	free(buf);
    }
    return rc;
}

static int lookup_str(const char *path, long val, int vcol, int rcol,
			char **ret)
{
    char *vbuf = NULL;
    rasprintf(&vbuf, "%ld", val);
    int rc = lookup_field(path, vbuf, vcol, rcol, ret);
    free(vbuf);
    return rc;
}

static void rpmugInit(void)
{
    if (rpmug == NULL)
	rpmug = (struct rpmug_s *)xcalloc(1, sizeof(*rpmug));
}

/* 
 * These really ought to use hash tables. I just made the
 * guess that most files would be owned by root or the same person/group
 * who owned the last file. Those two values are cached, everything else
 * is looked up via getpw() and getgr() functions.  If this performs
 * too poorly I'll have to implement it properly :-(
 */

int rpmugUid(const char * thisUname, uid_t * uid)
{
    if (rstreq(thisUname, UID_0_USER)) {
	*uid = 0;
	return 0;
    }

    rpmugInit();

    if (rpmug->lastUname == NULL || !rstreq(thisUname, rpmug->lastUname)) {
	long id;
	if (lookup_num(pwfile(), thisUname, 0, 2, &id))
	    return -1;
	free(rpmug->lastUname);
	rpmug->lastUname = xstrdup(thisUname);
	rpmug->lastUid = id;
    }

    *uid = rpmug->lastUid;

    return 0;
}

int rpmugGid(const char * thisGname, gid_t * gid)
{
    if (rstreq(thisGname, GID_0_GROUP)) {
	*gid = 0;
	return 0;
    }

    rpmugInit();

    if (rpmug->lastGname == NULL || !rstreq(thisGname, rpmug->lastGname)) {
	long id;
	if (lookup_num(grpfile(), thisGname, 0, 2, &id))
	    return -1;
	free(rpmug->lastGname);
	rpmug->lastGname = xstrdup(thisGname);
	rpmug->lastGid = id;
    }

    *gid = rpmug->lastGid;

    return 0;
}

const char * rpmugUname(uid_t uid)
{
    if (uid == (uid_t) 0)
	return UID_0_USER;

    rpmugInit();

    if (uid != rpmug->lastUid) {
	char *uname = NULL;

	if (lookup_str(pwfile(), uid, 2, 0, &uname))
	    return NULL;

	rpmug->lastUid = uid;
	free(rpmug->lastUname);
	rpmug->lastUname = uname;
    }
    return rpmug->lastUname;
}

const char * rpmugGname(gid_t gid)
{
    if (gid == (gid_t) 0)
	return GID_0_GROUP;

    rpmugInit();

    if (gid != rpmug->lastGid) {
	char *gname = NULL;

	if (lookup_str(grpfile(), gid, 2, 0, &gname))
	    return NULL;

	rpmug->lastGid = gid;
	free(rpmug->lastGname);
	rpmug->lastGname = gname;
    }
    return rpmug->lastGname;
}

void rpmugFree(void)
{
    if (rpmug) {
	free(rpmug->lastUname);
	free(rpmug->lastGname);
	free(rpmug->pwpath);
	free(rpmug->grppath);
	rpmug = _free(rpmug);
    }
}
