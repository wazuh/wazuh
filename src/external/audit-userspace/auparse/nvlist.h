/*
* nvlist.h - Header file for nvlist.c
* Copyright (c) 2006-07,2016 Red Hat Inc., Durham, North Carolina.
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

#ifndef NVLIST_HEADER
#define NVLIST_HEADER

#include "config.h"
#include "private.h"
#include <sys/types.h>
#include "rnode.h"
#include "ellist.h"


static inline unsigned int nvlist_get_cnt(nvlist *l) { return l->cnt; }
static inline void nvlist_first(nvlist *l) { l->cur = l->head; }
static inline nvnode *nvlist_get_cur(const nvlist *l) { return l->cur; }
static inline const char *nvlist_get_cur_name(const nvlist *l) {if (l->cur) return l->cur->name; else return NULL;}
static inline const char *nvlist_get_cur_val(const nvlist *l) {if (l->cur) return l->cur->val; else return NULL;}
static inline const char *nvlist_get_cur_val_interp(const nvlist *l) {if (l->cur) return l->cur->interp_val; else return NULL;}

AUDIT_HIDDEN_START

void nvlist_create(nvlist *l);
void nvlist_clear(nvlist* l);
nvnode *nvlist_next(nvlist *l);
int nvlist_get_cur_type(const rnode *r);
const char *nvlist_interp_cur_val(const rnode *r, auparse_esc_t escape_mode);
void nvlist_append(nvlist *l, nvnode *node);
void nvlist_interp_fixup(nvlist *l);

/* Given a numeric index, find that record. */
nvnode *nvlist_goto_rec(nvlist *l, unsigned int i);
/* Given a name, find that record */
int nvlist_find_name(nvlist *l, const char *name);

AUDIT_HIDDEN_END

#endif

