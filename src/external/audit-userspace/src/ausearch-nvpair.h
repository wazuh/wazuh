/*
* ausearch-nvpair.h - Header file for ausearch-nvpair.c
* Copyright (c) 2006-08 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUNVPAIR_HEADER
#define AUNVPAIR_HEADER

#include "config.h"
#include <sys/types.h>

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _nvnode{
  char *name;		// The name string
  long val;		// The value field
  struct _nvnode* next;	// Next nvpair node pointer
} nvnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  nvnode *head;		// List head
  nvnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} nvlist;

void nvlist_create(nvlist *l);
static inline void nvlist_first(nvlist *l) { l->cur = l->head; }
nvnode *nvlist_next(nvlist *l);
static inline nvnode *nvlist_get_cur(nvlist *l) { return l->cur; }
void nvlist_append(nvlist *l, nvnode *node);
void nvlist_clear(nvlist* l);

/* Given a numeric index, find that record. */
int nvlist_find_val(nvlist *l, long val);

#endif

