/*
* aulast-llist.h - Header file for aulastlog-llist.c
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


typedef enum { LOG_IN, SESSION_START, LOG_OUT, DOWN, CRASH, GONE } status_t; 

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lnode{
  unsigned int session; // The kernel login session id
  time_t start;		// first time uid logged in
  time_t end;		// last time uid logged in
  uid_t auid;           // user ID
  int pid;		// pid of program logging in
  const char *name;	// user name
  const char *term;	// terminal name
  const char *host;	// host where logging in from
  int result;		// login results
  status_t status;	// Current status of this session
  unsigned long loginuid_proof;	// audit serial number for loginuid change
  unsigned long user_login_proof; // audit serial number for user login event
  unsigned long  user_end_proof; // audit serial number for user log out event
  struct _lnode* next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
} llist;

void list_create(llist *l);
static inline void list_first(llist *l) { l->cur = l->head; }
lnode *list_next(llist *l);
static inline lnode *list_get_cur(llist *l) { return l->cur; }
void list_clear(llist* l);
int list_create_session_simple(llist* l, lnode *n);
int list_create_session(llist *l, uid_t auid, int pid, int session,
			unsigned long serial);
int list_update_start(llist* l, const char *host, const char *term,
			int res, unsigned long serial);
int list_update_logout(llist* l, time_t t, unsigned long serial);
lnode *list_delete_cur(llist *l);

/* Given a uid, find that record. */
lnode *list_find_auid(llist *l, uid_t auid, int pid, unsigned int session);
lnode *list_find_session(llist *l, unsigned int session);

#endif

