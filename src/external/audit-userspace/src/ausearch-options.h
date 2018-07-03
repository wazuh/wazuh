/* ausearch-options.h -- 
 * Copyright 2005,2008,2010 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 * 
 */

#ifndef AUSEARCH_OPTIONS_H
#define AUSEARCH_OPTIONS_H

#include <time.h>
#include <sys/types.h>
#include <stdint.h>
#include "ausearch-common.h"
#include "ausearch-int.h"

/* Global variables that describe what search is to be performed */
extern const char *event_key;
extern const char *event_subject;
extern const char *event_object;
extern int event_se;
extern int just_one;
extern int line_buffered;
extern int event_debug;
extern pid_t event_ppid;
extern uint32_t event_session_id;
extern ilist *event_type;

/* Data type to govern output format */
extern report_t report_format;

/* Function to process commandline options */
extern int check_params(int count, char *vars[]);

#endif

