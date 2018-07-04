/*
* ausearch-nvpair.c - Minimal linked list library for name-value pairs
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

#include "config.h"
#include <stdlib.h>
#include "ausearch-nvpair.h"


void nvlist_create(nvlist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

nvnode *nvlist_next(nvlist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void nvlist_append(nvlist *l, nvnode *node)
{
	nvnode* newnode = malloc(sizeof(nvnode));

	newnode->name = node->name;
	newnode->val = node->val;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Add pointer to newnode and make sure we are at the end
		while (l->cur->next)
			l->cur = l->cur->next;
		l->cur->next = newnode;
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

int nvlist_find_val(nvlist *l, long val)
{
        register nvnode* node = l->head;

	while (node) {
		if (node->val == val) {
			l->cur = node;
			return 1;
		}
		else
			node = node->next;
	}
	return 0;
}

void nvlist_clear(nvlist* l)
{
	nvnode* nextnode;
	register nvnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->name);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

