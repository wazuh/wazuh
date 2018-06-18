/*
* auditctl-listing.h - Header file for ausearch-llist.c
* Copyright (c) 2014 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved.
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
* Boston, MA 02110-1335, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#ifndef CTLLISTING_HEADER
#define CTLLISTING_HEADER

#include "config.h"
#include "libaudit.h"

void audit_print_init(void);
int audit_print_reply(struct audit_reply *rep, int fd);
int key_match(const struct audit_rule_data *r);

#endif
