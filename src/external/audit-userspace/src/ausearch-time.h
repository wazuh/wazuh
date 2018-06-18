/* ausearch-time.h - header file for ausearch-time.c
 * Copyright 2006-07,2016-17 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUSEARCH_TIME_HEADERS
#define AUSEARCH_TIME_HEADERS

#include "ausearch-common.h"

enum {  T_NOW, T_RECENT, T_BOOT, T_TODAY, T_YESTERDAY, T_THIS_WEEK, T_WEEK_AGO, 
	T_THIS_MONTH, T_THIS_YEAR };

int lookup_time(const char *name);
int ausearch_time_start(const char *da, const char *ti);
int ausearch_time_end(const char *da, const char *ti);

#endif

