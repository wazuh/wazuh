/*
* aulastlog-llist.h - Header file for aulastlog-llist.c
* Copyright (c) 2008 Red Hat Inc., Durham, North Carolina.
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

#ifndef AULASTLIST_HEADER
#define AULASTLIST_HEADER

#include <sys/types.h>


/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lnode{
  time_t sec;		// last time uid logged in
  uid_t uid;            // user ID
  char *name;		// users name
  char *host;		// host where logging in from
  char *term;		// terminal name
  unsigned int item;	// Which item of the same event
  struct _lnode* next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} llist;

void list_create(llist *l);
static inline void list_first(llist *l) { l->cur = l->head; }
lnode *list_next(llist *l);
static inline lnode *list_get_cur(llist *l) { return l->cur; }
static inline unsigned int list_get_cnt(llist *l) { return l->cnt; }
void list_append(llist *l, lnode *node);
void list_clear(llist* l);
int list_update_login(llist* l, time_t t);
int list_update_host(llist* l, const char *h);
int list_update_term(llist* l, const char *t);

/* Given a uid, find that record. */
lnode *list_find_uid(llist *l, uid_t uid);

#endif

