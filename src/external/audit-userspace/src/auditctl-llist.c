/*
* ausearch-llist.c - Minimal linked list library
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

#include <stdlib.h>
#include <string.h>
#include "auditctl-llist.h"

void list_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void list_first(llist *l)
{
	l->cur = l->head;
}

void list_last(llist *l)
{
        register lnode* node;
	
	if (l->head == NULL)
		return;

        node = l->head;
	while (node->next)
		node = node->next;
	l->cur = node;
}

lnode *list_next(llist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void list_append(llist *l, struct audit_rule_data *r, size_t sz)
{
	lnode* newnode;

	newnode = malloc(sizeof(lnode));

	if (r) {
		void *rr = malloc(sz);
		if (rr) 
			memcpy(rr, r, sz);
		newnode->r = rr;
	} else
		newnode->r = NULL;

	newnode->size = sz;
	newnode->next = 0;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

void list_clear(llist* l)
{
	lnode* nextnode;
	register lnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->r);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

