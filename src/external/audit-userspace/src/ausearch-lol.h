/*
* ausearch-lol.h - linked list of linked lists library header
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

#ifndef AUSEARCH_LOL_HEADER
#define AUSEARCH_LOL_HEADER

#include "config.h"
#include "ausearch-llist.h"

typedef enum { L_EMPTY, L_BUILDING, L_COMPLETE } lol_t;
 
/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lolnode{
  llist *l;			// The linked list
  int status;			// 0 = empty, 1 in use, 2 complete
} lolnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lolnode *array;
  int maxi;		// Largest index used
  int limit;		// Number of nodes in the array
} lol;

void lol_create(lol *lo);
void lol_clear(lol *lo);
int lol_add_record(lol *lo, char *buff);
void terminate_all_events(lol *lo);
llist* get_ready_event(lol *lo);

#endif

