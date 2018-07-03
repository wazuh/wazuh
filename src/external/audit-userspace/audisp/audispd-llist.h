/*
* audispd-llist.h - Header file for ausearch-conf_llist.c
* Copyright (c) 2007,2013 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUDISP_LIST_HEADER
#define AUDISP_LIST_HEADER

#include "config.h"
#include <sys/types.h>
#include "audispd-pconfig.h"

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lnode{
  plugin_conf_t *p;     // The rule from the kernel
  struct _lnode *next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} conf_llist;

void plist_create(conf_llist *l);
static inline void plist_first(conf_llist *l) { l->cur = l->head; }
static inline unsigned int plist_count(conf_llist *l) { return l->cnt; }
unsigned int plist_count_active(const conf_llist *l);
void plist_last(conf_llist *l);
lnode *plist_next(conf_llist *l);
static inline lnode *plist_get_cur(conf_llist *l) { return l->cur; }
void plist_append(conf_llist *l, plugin_conf_t *p);
void plist_clear(conf_llist* l);
void plist_mark_all_unchecked(conf_llist* l);
lnode *plist_find_unchecked(conf_llist* l);
lnode *plist_find_name(conf_llist* l, const char *name);

#endif

