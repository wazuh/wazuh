/** \ingroup rpmbuild
 * \file build/parseChangelog.c
 *  Parse %changelog section from spec file.
 */

#include "system.h"

#include <rpm/header.h>
#include <rpm/rpmlog.h>
#include "rpmbuild_internal.h"
#include "debug.h"

#define SKIPSPACE(s) { while (*(s) && risspace(*(s))) (s)++; }
#define SKIPNONSPACE(s) { while (*(s) && !risspace(*(s))) (s)++; }

static void addChangelogEntry(Header h, time_t time, const char *name, const char *text)
{
    rpm_time_t mytime = time;	/* XXX convert to header representation */
				
    headerPutUint32(h, RPMTAG_CHANGELOGTIME, &mytime, 1);
    headerPutString(h, RPMTAG_CHANGELOGNAME, name);
    headerPutString(h, RPMTAG_CHANGELOGTEXT, text);
}

static int sameDate(const struct tm *ot, const struct tm *nt)
{
    return (ot->tm_year == nt->tm_year &&
	    ot->tm_mon == nt->tm_mon &&
	    ot->tm_mday == nt->tm_mday &&
	    ot->tm_wday == nt->tm_wday);
}

/**
 * Parse date string to seconds.
 * accepted date formats are "Mon Jun 6 2016" (original one)
 * and "Thu Oct  6 06:48:39 CEST 2016" (extended one)
 * @param datestr	date string (e.g. 'Wed Jan 1 1997')
 * @param[out] secs		secs since the unix epoch
 * @return 		0 on success, -1 on error
 */
static int dateToTimet(const char * datestr, time_t * secs, int * date_words)
{
    int rc = -1; /* assume failure */
    struct tm time, ntime;
    const char * const * idx;
    char *p, *pe, *q, *date, *tz;
    char tz_name[10];               /* name of timezone (if extended format is used) */

    static const char * const days[] =
	{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", NULL };
    static const char * const months[] =
	{ "Jan", "Feb", "Mar", "Apr", "May", "Jun",
 	  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", NULL };
    static const char lengths[] =
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    
    memset(&time, 0, sizeof(time));
    memset(&ntime, 0, sizeof(ntime));

    date = xstrdup(datestr);
    pe = date;

    /* day of week */
    p = pe; SKIPSPACE(p);
    if (*p == '\0') goto exit;
    pe = p; SKIPNONSPACE(pe); if (*pe != '\0') *pe++ = '\0';
    for (idx = days; *idx && !rstreq(*idx, p); idx++)
	{};
    if (*idx == NULL) goto exit;
    time.tm_wday = idx - days;

    /* month */
    p = pe; SKIPSPACE(p);
    if (*p == '\0') goto exit;
    pe = p; SKIPNONSPACE(pe); if (*pe != '\0') *pe++ = '\0';
    for (idx = months; *idx && !rstreq(*idx, p); idx++)
	{};
    if (*idx == NULL) goto exit;
    time.tm_mon = idx - months;

    /* day */
    p = pe; SKIPSPACE(p);
    if (*p == '\0') goto exit;
    pe = p; SKIPNONSPACE(pe); if (*pe != '\0') *pe++ = '\0';

    time.tm_mday = strtol(p, &q, 10);
    if (!(q && *q == '\0')) goto exit;
    if (time.tm_mday < 0 || time.tm_mday > lengths[time.tm_mon]) goto exit;

    /* first part of year entry (original format) / time entry (extended format)*/
    p = pe;
    SKIPSPACE(p);
    if (*p == '\0')
	goto exit;

    /* in the original format here is year record (e.g. 1999),
     * in the extended one here is time stamp (e.g. 10:22:30).
     * Choose the format
     */
    if ((p[1]==':') || ((p[1]!='\0') && ((p[2]==':')))) {
	/* it can be extended format */
	*date_words = 6;

	/* second part of time entry */
	/* hours */
	time.tm_hour = strtol(p, &q, 10);
	if ( (time.tm_hour < 0) || (time.tm_hour > 23) )
	   goto exit;
	if (*q!=':')
	   goto exit;
	p = ++q;
	/* minutes */
	time.tm_min = strtol(p, &q, 10);
	if ( (time.tm_min < 0) || (time.tm_min > 59) )
	   goto exit;
	if (*q != ':')
	   goto exit;
	p = ++q;
	/* time - seconds */
	time.tm_sec = strtol(p, &q, 10);
	if ( (time.tm_sec < 0) || (time.tm_sec > 59) )
	   goto exit;
	p = q;

	/* time zone name */
	SKIPSPACE(p);
	if (*p == '\0')
	   goto exit;
	pe = p;
	SKIPNONSPACE(pe);
	if (*pe != '\0')
	   *pe++ = '\0';
	if (((int)(pe-p) + 1) > 9 )
	   goto exit;
	strncpy(tz_name, p, (int)(pe-p));
	tz_name[(int)(pe-p)] = '\0';

	/* first part of year entry */
	p = pe;
	SKIPSPACE(p);
	if (*p == '\0')
	   goto exit;
    } else {
	*date_words = 4;
	/* the original format */
	/* make this noon so the day is always right (as we make this UTC) */
	time.tm_hour = 12;
   }

    /* year - second part */
    pe = p;
    SKIPNONSPACE(pe);
    if (*pe != '\0')
	*pe = '\0';
    time.tm_year = strtol(p, &q, 10);
    if (!(q && *q == '\0')) goto exit;
    if (time.tm_year < 1990 || time.tm_year >= 3000) goto exit;
    time.tm_year -= 1900;

    /* change time zone and compute calendar time representation */
    tz = getenv("TZ");
    if (tz)
	tz = xstrdup(tz);
    if (*date_words == 6) {
	/* changelog date is in read time zone */
	setenv("TZ", tz_name, 1);
    } else {
	/* changelog date is always in UTC */
	setenv("TZ", "UTC", 1);
    }
    ntime = time; /* struct assignment */
    *secs = mktime(&ntime);
    unsetenv("TZ");
    if (tz) {
	setenv("TZ", tz, 1);
	free(tz);
    }
    tzset();

    if (*secs == -1) goto exit;

    /* XXX Turn this into a hard error in a release or two */
    if (!sameDate(&time, &ntime))
	rpmlog(RPMLOG_WARNING, _("bogus date in %%changelog: %s\n"), datestr);

    rc = 0;

exit:
    free(date);
    return rc;
}

/**
 * Add %changelog section to header.
 * @param h		header
 * @param sb		changelog strings
 * @return		RPMRC_OK on success
 */
static rpmRC addChangelog(Header h, ARGV_const_t sb)
{
    rpmRC rc = RPMRC_FAIL; /* assume failure */
    char *s, *sp;
    int i;
    time_t firstTime = 0;
    time_t lastTime = 0;
    time_t trimtime = rpmExpandNumeric("%{?_changelog_trimtime}");
    time_t trimage = rpmExpandNumeric("%{?_changelog_trimage}");
    char *date, *name, *text, *next;
    int date_words;      /* number of words in date string */

    /* Convert _changelog_trimtime to age for backwards compatibility */
    if (trimtime && !trimage) {
	trimage = time(NULL) - trimtime;
	trimtime = 0;
    }

    s = sp = argvJoin(sb, "");

    /* skip space */
    SKIPSPACE(s);

    while (*s != '\0') {
	time_t time;
	if (*s != '*') {
	    rpmlog(RPMLOG_ERR, _("%%changelog entries must start with *\n"));
	    goto exit;
	}

	/* find end of line */
	date = s;
	while (*s && *s != '\n') s++;
	if (! *s) {
	    rpmlog(RPMLOG_ERR, _("incomplete %%changelog entry\n"));
	    goto exit;
	}
	*s = '\0';
	text = s + 1;
	
	/* 4 fields of date */
	date++;
	s = date;
	SKIPSPACE(date);
	if (dateToTimet(date, &time, &date_words)) {
	    rpmlog(RPMLOG_ERR, _("bad date in %%changelog: %s\n"), date);
	    goto exit;
	}
	/* Changelog trimming is always relative to first entry */
	if (!firstTime) {
	    firstTime = time;
	    if (trimage)
		trimtime = firstTime - trimage;
	}
	if (lastTime && lastTime < time) {
	    rpmlog(RPMLOG_ERR,
		     _("%%changelog not in descending chronological order\n"));
	    goto exit;
	}
	for (i = 0; i < date_words; i++) {
	    SKIPSPACE(s);
	    SKIPNONSPACE(s);
	}
	lastTime = time;

	/* skip space to the name */
	SKIPSPACE(s);
	if (! *s) {
	    rpmlog(RPMLOG_ERR, _("missing name in %%changelog\n"));
	    goto exit;
	}

	/* name */
	name = s;
	while (*s != '\0') s++;
	while (s > name && risspace(*s)) {
	    *s-- = '\0';
	}
	if (s == name) {
	    rpmlog(RPMLOG_ERR, _("missing name in %%changelog\n"));
	    goto exit;
	}

	/* text */
	SKIPSPACE(text);
	if (! *text) {
	    rpmlog(RPMLOG_ERR, _("no description in %%changelog\n"));
	    goto exit;
	}
	    
	/* find the next leading '*' (or eos) */
	s = text;
	do {
	   s++;
	} while (*s && (*(s-1) != '\n' || *s != '*'));
	next = s;
	s--;

	/* backup to end of description */
	while ((s > text) && risspace(*s)) {
	    *s-- = '\0';
	}
	
	if ( !trimtime || time >= trimtime ) {
	    addChangelogEntry(h, time, name, text);
	} else break;
	
	s = next;
    }
    rc = RPMRC_OK;

exit:
    free(sp);

    return rc;
}

int parseChangelog(rpmSpec spec)
{
    int res = PART_ERROR;
    ARGV_t sb = NULL;

    if (headerIsEntry(spec->packages->header, RPMTAG_CHANGELOGTIME)) {
	rpmlog(RPMLOG_ERR, _("line %d: second %%changelog\n"), spec->lineNum);
	goto exit;
    }
    
    if ((res = parseLines(spec, STRIP_COMMENTS, &sb, NULL)) == PART_ERROR)
	goto exit;

    if (sb && addChangelog(spec->packages->header, sb)) {
	goto exit;
    }

exit:
    argvFree(sb);

    return res;
}
