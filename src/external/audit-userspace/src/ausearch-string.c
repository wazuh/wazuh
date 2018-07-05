/*
* ausearch-string.c - Minimal linked list library for strings
* Copyright (c) 2005,2008,2014 Red Hat Inc., Durham, North Carolina.
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

#include "ausearch-string.h"
#include <stdlib.h>
#include <string.h>


void slist_create(slist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void slist_last(slist *l)
{
        register snode* cur;
	
	if (l->head == NULL)
		return;

	// Try using cur so that we don't have to start at beginnning
	if (l->cur)
		cur = l->cur;
	else
	        cur = l->head;

	// Loop until no next value
	while (cur->next)
		cur = cur->next;
	l->cur = cur;
}

snode *slist_next(slist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void slist_append(slist *l, snode *node)
{
	snode* newnode;

	newnode = malloc(sizeof(snode));

	if (node->str)
		newnode->str = node->str;
	else
		newnode->str = NULL;

	if (node->key)
		newnode->key = node->key;
	else
		newnode->key = NULL;

	newnode->hits = node->hits;
	newnode->next = NULL;

	// Make sure cursor is at the end
	slist_last(l);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

void slist_clear(slist* l)
{
	snode* nextnode;
	register snode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->str);
		free(current->key);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

/* This function dominates the timing of aureport. Needs to be more efficient */
int slist_add_if_uniq(slist *l, const char *str)
{
	snode sn;
        register snode *cur;

       	cur = l->head;
	while (cur) {
		if (strcmp(str, cur->str) == 0) {
			cur->hits++;
			l->cur = cur;
			return 0;
		} else 
			cur = cur->next;
	}

	/* No matches, append to the end */
	sn.str = strdup(str);
	sn.key = NULL;
	sn.hits = 1;
	slist_append(l, &sn);
	return 1;
}

// If lprev would be NULL, use l->head
static void swap_nodes(snode *lprev, snode *left, snode *right)
{
	snode *t = right->next;
	if (lprev)
		lprev->next = right;
	right->next = left;
	left->next = t;
}

// This will sort the list from most hits to least
void slist_sort_by_hits(slist *l)
{
	register snode* cur, *prev;

	if (l->cnt <= 1)
		return;

	prev = cur = l->head;

	while (cur && cur->next) {
		/* If the next node is bigger */
		if (cur->hits < cur->next->hits) {
			if (cur == l->head) {
				// Update the actual list head
				l->head = cur->next;
				prev = NULL;
			}
			swap_nodes(prev, cur, cur->next);

			// start over
			prev = cur = l->head;
			continue;
		}
		prev = cur;
		cur = cur->next;
	}
	// End with cur pointing at first record
	l->cur = l->head;
}

