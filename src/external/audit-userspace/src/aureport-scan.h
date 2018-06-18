/* aureport-scan.h -- 
 * Copyright 2005-06,2008,2014 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUREPORT_SCAN_H
#define AUREPORT_SCAN_H

#include "ausearch-llist.h"
#include "ausearch-int.h"

typedef struct sdata {
	slist users;
	slist terms;
	slist files;
	slist hosts;
	slist exes;
	slist comms;
	slist avc_objs;
	slist keys;
	ilist pids;
	slist sys_list;
	ilist anom_list;
	ilist resp_list;
	ilist mac_list;
	ilist crypto_list;
	ilist virt_list;
	ilist integ_list;
	unsigned long changes;
	unsigned long crypto;
	unsigned long acct_changes;
	unsigned long good_logins;
	unsigned long bad_logins;
	unsigned long good_auth;
	unsigned long bad_auth;
	unsigned long events;
	unsigned long avcs;
	unsigned long mac;
	unsigned long failed_syscalls;
	unsigned long anomalies;
	unsigned long responses;
	unsigned long virt;
	unsigned long integ;
} summary_data;

void reset_counters(void);
void destroy_counters(void);
int scan(llist *l);
int per_event_processing(llist *l);

void print_title(void);
void print_per_event_item(llist *l);
void print_wrap_up(void);

extern summary_data sd;

#endif

