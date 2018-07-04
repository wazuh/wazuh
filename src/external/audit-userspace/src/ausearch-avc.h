/*
* ausearch-avc.h - Header file for ausearch-string.c
* Copyright (c) 2006,2008 Red Hat Inc., Durham, North Carolina.
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

#ifndef AU_AVC_HEADER
#define AU_AVC_HEADER

#include "config.h"
#include <sys/types.h>
#include "libaudit.h"

typedef enum { AVC_UNSET, AVC_DENIED, AVC_GRANTED } avc_t;

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _anode{
  char *scontext;       // se linux subject context
  char *tcontext;       // se linux object context
  avc_t avc_result;     // se linux avc denied/granted
  char *avc_perm;       // se linux avc permission mentioned
  char *avc_class;      // se linux class mentioned
  struct _anode* next;	// Next string node pointer
} anode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  anode *head;		// List head
  anode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} alist;

void alist_create(alist *l);
static inline void alist_first(alist *l) { l->cur = l->head; }
anode *alist_next(alist *l);
static inline anode *alist_get_cur(alist *l) { return l->cur; }
void alist_append(alist *l, anode *node);
void anode_init(anode *an);
void anode_clear(anode *an);
void alist_clear(alist* l);

/* See if any subj exists in list */
int alist_find_subj(alist *l);
anode *alist_next_subj(alist *l);
/* See if any obj exists in list */
int alist_find_obj(alist *l);
anode *alist_next_obj(alist *l);
/* See if any avc exists in list */
int alist_find_avc(alist *l);
anode *alist_next_avc(alist *l);

#endif

