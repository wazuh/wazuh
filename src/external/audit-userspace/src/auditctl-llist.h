/*
* auditctl-llist.h - Header file for ausearch-llist.c
* Copyright (c) 2005 Red Hat Inc., Durham, North Carolina.
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

#ifndef CTLLIST_HEADER
#define CTLLIST_HEADER

#include "config.h"
#include <sys/types.h>
#include "libaudit.h"

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lnode{
  struct audit_rule_data *r; // The rule from the kernel
  size_t size;		// Size of the rule struct
  struct _lnode *next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} llist;

void list_create(llist *l);
void list_first(llist *l);
void list_last(llist *l);
lnode *list_next(llist *l);
static inline lnode *list_get_cur(llist *l) { return l->cur; }
void list_append(llist *l, struct audit_rule_data *r, size_t sz);
void list_clear(llist* l);

#endif

