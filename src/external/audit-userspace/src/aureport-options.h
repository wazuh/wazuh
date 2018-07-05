/* aureport-options.h -- 
 * Copyright 2005-06, 2008,2014 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUREPORT_OPTIONS_H
#define AUREPORT_OPTIONS_H

#include <time.h>
#include <sys/types.h>
#include "ausearch-common.h"

/* Global variables that describe what search is to be performed */
extern const char *event_context;

typedef enum { RPT_UNSET, RPT_TIME, RPT_SUMMARY, RPT_AVC, RPT_MAC,
	RPT_CONFIG, RPT_EVENT, RPT_FILE, RPT_HOST, RPT_LOGIN,
	RPT_ACCT_MOD, RPT_PID, RPT_SYSCALL, RPT_TERM, RPT_USER,
	RPT_EXE, RPT_ANOMALY, RPT_RESPONSE, RPT_CRYPTO, 
	RPT_AUTH, RPT_KEY, RPT_TTY, RPT_COMM, RPT_VIRT,
	RPT_INTEG } report_type_t;

typedef enum { D_UNSET, D_SUM, D_DETAILED, D_SPECIFIC } report_det_t;

extern report_type_t report_type;
extern report_det_t report_detail;
extern report_t report_format;


/* Function to process commandline options */
extern int check_params(int count, char *vars[]);

#include <stdlib.h>
#define UNIMPLEMENTED { fprintf(stderr,"Unimplemented option\n"); exit(1); }

#endif

