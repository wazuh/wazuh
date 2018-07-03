/*
* ausearch-lookup.h - Header file for ausearch-lookup.c
* Copyright (c) 2005-06,2014,2017 Red Hat Inc., Durham, North Carolina.
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

#ifndef AULOOKUP_HEADER
#define AULOOKUP_HEADER

#include "config.h"
#include <pwd.h>
#include <grp.h>
#include "libaudit.h"
#include "ausearch-llist.h"


const char *aulookup_result(avc_t result);
const char *aulookup_success(int s);
const char *aulookup_syscall(llist *l, char *buf, size_t size);
const char *aulookup_uid(uid_t uid, char *buf, size_t size);
void aulookup_destroy_uid_list(void);
char *unescape(const char *buf);
int is_hex_string(const char *str);
void print_tty_data(const char *val);
void safe_print_string_n(const char *s, unsigned int len, int ret);
void safe_print_string(const char *s, int ret);

#endif

