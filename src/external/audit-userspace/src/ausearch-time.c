/* ausearch-time.c - time handling utility functions
 * Copyright 2006-08,2011,2016-17 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */

#define _XOPEN_SOURCE
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "ausearch-time.h"

#define SECONDS_IN_DAY 24*60*60
static void clear_tm(struct tm *t);
static void replace_time(struct tm *t1, struct tm *t2);
static void replace_date(struct tm *t1, struct tm *t2);


time_t start_time = 0, end_time = 0;

struct nv_pair {
    int        value;
    const char *name;
};

static struct nv_pair timetab[] = {
        { T_NOW, "now" },
        { T_RECENT, "recent" },
	{ T_BOOT, "boot" },
        { T_TODAY, "today" },
        { T_YESTERDAY, "yesterday" },
        { T_THIS_WEEK, "this-week" },
        { T_WEEK_AGO, "week-ago" },
        { T_THIS_MONTH, "this-month" },
        { T_THIS_YEAR, "this-year" },
};

#define TIME_NAMES (sizeof(timetab)/sizeof(timetab[0]))

int lookup_time(const char *name)
{
        unsigned int i;

        for (i = 0; i < TIME_NAMES; i++) {
                if (strcmp(timetab[i].name, name) == 0) {
                        return timetab[i].value;
		}
	}
        return -1;

}

static void clear_tm(struct tm *t)
{
        t->tm_sec = 0;         /* seconds */
        t->tm_min = 0;         /* minutes */
        t->tm_hour = 0;        /* hours */
        t->tm_mday = 0;        /* day of the month */
        t->tm_mon = 0;         /* month */
        t->tm_year = 0;        /* year */
        t->tm_isdst = 0;       /* DST flag */
}

static void set_tm_now(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
	replace_time(d, tv);
	replace_date(d, tv);
}

static void set_tm_today(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
}

static void set_tm_yesterday(struct tm *d)
{
        time_t t = time(NULL) - (time_t)(SECONDS_IN_DAY);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
}

static void set_tm_recent(struct tm *d)
{
        time_t t = time(NULL) - (time_t)(10*60); /* 10 minutes ago */
        struct tm *tv = localtime(&t);
	replace_time(d, tv);
	replace_date(d, tv);
}

static int set_tm_boot(struct tm *d)
{
	char buf[128];
        time_t t;
	int rc, fd = open("/proc/uptime", O_RDONLY);
	if (fd < 0) {
error_out:
		fprintf(stderr, "Can't read uptime (%s)\n", strerror(errno));
		return -1;
	}

        t = time(NULL);
	rc = read(fd, buf, sizeof(buf)-1);
	close(fd);
	if (rc > 0) {
		struct tm *tv;
		float f_uptime;
		unsigned long uptime;
		char *ptr;

		buf[rc] = 0;
		ptr = strchr(buf, ' '); // Accurate only to the second
		if (ptr)
			*ptr = 0;

		errno = 0;
		f_uptime = strtof(buf, NULL);
		uptime = f_uptime + 0.5;
		if (errno)
			goto error_out;

		t -= uptime;
        	tv = localtime(&t);
		replace_time(d, tv);
		replace_date(d, tv);
	} else
		goto error_out;

	return 0;
}

static void set_tm_this_week(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	t -= (time_t)(tv->tm_wday*(time_t)SECONDS_IN_DAY);
        tv = localtime(&t);
	replace_date(d, tv);
}

static void set_tm_week_ago(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv;
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	t -= (time_t)(7*SECONDS_IN_DAY);
        tv = localtime(&t);
	replace_date(d, tv);
}

static void set_tm_this_month(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
        d->tm_mday = 1;         /* override day of month */
}

static void set_tm_this_year(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
        d->tm_mday = 1;         /* override day of month */
        d->tm_mon = 0;          /* override month */
	d->tm_isdst = 0;
}

/* The time in t1 is replaced by t2 */
static void replace_time(struct tm *t1, struct tm *t2)
{
        t1->tm_sec = t2->tm_sec;	/* seconds */
        t1->tm_min = t2->tm_min;	/* minutes */
        t1->tm_hour = t2->tm_hour;	/* hours */
}

/* The date in t1 is replaced by t2 */
static void replace_date(struct tm *t1, struct tm *t2)
{
        t1->tm_mday = t2->tm_mday;	/* day */
        t1->tm_mon = t2->tm_mon;	/* month */
        t1->tm_year = t2->tm_year;	/* year */
        t1->tm_isdst = t2->tm_isdst;	/* daylight savings time */
}

static int lookup_and_set_time(const char *da, struct tm *d)
{
	int retval = lookup_time(da);
	if (retval >= 0) {
		switch (retval)
		{
			case T_NOW:
				set_tm_now(d);
				break;
			case T_RECENT:
				set_tm_recent(d);
				break;
			case T_BOOT:
				if (set_tm_boot(d))
					return -2;
				break;
			case T_TODAY:
				set_tm_today(d);
				break;
			case T_YESTERDAY:
				set_tm_yesterday(d);
				break;
			case T_THIS_WEEK:
				set_tm_this_week(d);
				break;
			case T_WEEK_AGO:
				set_tm_week_ago(d);
				break;
			case T_THIS_MONTH:
				set_tm_this_month(d);
				break;
			case T_THIS_YEAR:
				set_tm_this_year(d);
				break;
		}
		return 0;
	} else
		return -1;
}

/* static void print_time(struct tm *d)
{
	char outstr[200];
	strftime(outstr, sizeof(outstr), "%c", d);
	printf("%s\n", outstr);
} */

int ausearch_time_start(const char *da, const char *ti)
{
/* If da == NULL, use current date */
/* If ti == NULL, then use midnight 00:00:00 */
	int rc = 0;
	struct tm d;
	char *ret;

	clear_tm(&d);
	if (da == NULL)
		set_tm_now(&d);
	else {
		if (lookup_and_set_time(da, &d) < 0) {
			ret = strptime(da, "%x", &d);
			if (ret == NULL) {
				fprintf(stderr,
		"Invalid start date (%s). Month, Day, and Year are required.\n",
					da);
				return 1;
			}
			if (*ret != 0) {
				fprintf(stderr,
					"Error parsing start date (%s)\n", da);
				return 1;
			}
			// FIX DST flag
			start_time = mktime(&d);
		} else {
			int keyword=lookup_time(da);
			if (keyword == T_RECENT || keyword == T_NOW ||
				keyword == T_BOOT) {
				if (ti == NULL || strcmp(ti, "00:00:00") == 0)
					goto set_it;
			}
		}
	}

	if (ti != NULL) {
		char tmp_t[64];

		if (strlen(ti) <= 5) {
			snprintf(tmp_t, sizeof(tmp_t), "%s:00", ti);
		} else {
			tmp_t[0]=0;
			strncat(tmp_t, ti, sizeof(tmp_t)-1);
		}
		ret = strptime(tmp_t, "%X", &d);
		if (ret == NULL) {
			fprintf(stderr,
	"Invalid start time (%s). Hour, Minute, and Second are required.\n",
				ti);
			return 1;
		}
		if (*ret != 0) {
			fprintf(stderr, "Error parsing start time (%s)\n", ti);
			return 1;
		}
	} else
		clear_tm(&d);

	if (d.tm_year < 104) {
		fprintf(stderr, "Error - year is %d\n", d.tm_year+1900);
		return -1;
	}
set_it:
	start_time = mktime(&d);
	// printf("start is: %s\n", ctime(&start_time));
	if (start_time == -1) {
		fprintf(stderr, "Error converting start time\n");
		rc = -1;
	}
	return rc;
}

int ausearch_time_end(const char *da, const char *ti)
{
/* If date == NULL, use current date */
/* If ti == NULL, use current time */
	int rc = 0;
	struct tm d;
	char *ret;

	clear_tm(&d);
	if (da == NULL)
		set_tm_now(&d);
	else {
		if (lookup_and_set_time(da, &d) < 0) {
			ret = strptime(da, "%x", &d);
			if (ret == NULL) {
				fprintf(stderr,
		 "Invalid end date (%s). Month, Day, and Year are required.\n",
					da);
				return 1;
			}
			if (*ret != 0) {
				fprintf(stderr,
					"Error parsing end date (%s)\n", da);
				return 1;
			}
			// FIX DST flag
			end_time = mktime(&d);
		} else {
			int keyword=lookup_time(da);
			if (keyword == T_RECENT || keyword == T_NOW ||
				keyword == T_BOOT) {
				if (ti == NULL || strcmp(ti, "00:00:00") == 0)
					goto set_it;
			}
			// Special case today
			if (keyword == T_TODAY) {
				set_tm_now(&d);
				if (ti == NULL || strcmp(ti, "00:00:00") == 0)
					goto set_it;
			}
		}
	}

	if (ti != NULL) {
		char tmp_t[64];

		if (strlen(ti) <= 5) {
			snprintf(tmp_t, sizeof(tmp_t), "%s:00", ti);
		} else {
			tmp_t[0]=0;
			strncat(tmp_t, ti, sizeof(tmp_t)-1);
		}
		ret = strptime(tmp_t, "%X", &d);
		if (ret == NULL) {
			fprintf(stderr,
	     "Invalid end time (%s). Hour, Minute, and Second are required.\n",
				ti);
			return 1;
		}
		if (*ret != 0) {
			fprintf(stderr, "Error parsing end time (%s)\n", ti);
			return 1;
		}
	} else {
		time_t tt = time(NULL);
		struct tm *tv = localtime(&tt);
		d.tm_hour = tv->tm_hour;
		d.tm_min = tv->tm_min;
		d.tm_sec = tv->tm_sec;
		d.tm_isdst = tv->tm_isdst;
	}
	if (d.tm_year < 104) {
		fprintf(stderr, "Error - year is %d\n", d.tm_year+1900);
		return -1;
	}
set_it:
	end_time = mktime(&d);
	// printf("end is: %s\n", ctime(&end_time));
	if (end_time == -1) {
		fprintf(stderr, "Error converting end time\n");
		rc = -1;
	}
	return rc;
}

