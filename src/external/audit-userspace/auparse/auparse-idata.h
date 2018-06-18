/*
* idata.h - Header file for ausearch-lookup.c
* Copyright (c) 2013,2016-17 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved.
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#ifndef IDATA_HEADER
#define IDATA_HEADER

#include "config.h"
#include "dso.h"
#include "auparse-defs.h"

typedef struct _idata {
	unsigned int machine;	// The machine type for the event
	int syscall;		// The syscall for the event
	unsigned long long a0;	// arg 0 to the syscall
	unsigned long long a1;	// arg 1 to the syscall
	const char *cwd;	// The current working directory
	const char *name;	// name of field being interpretted
	const char *val;	// value of field being interpretted
} idata;


int auparse_interp_adjust_type(int rtype, const char *name, const char *val);
char *auparse_do_interpretation(int type, const idata *id,
	auparse_esc_t escape_mode);
void _auparse_load_interpretations(const char *buf);
void _auparse_free_interpretations(void);
const char *_auparse_lookup_interpretation(const char *name);

#endif

