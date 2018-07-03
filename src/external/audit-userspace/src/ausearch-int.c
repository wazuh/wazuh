/*
* ausearch-int.c - Minimal linked list library for integers
* Copyright (c) 2005,2008 Red Hat Inc., Durham, North Carolina.
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
#include "ausearch-int.h"

void ilist_create(ilist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int_node *ilist_next(ilist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void ilist_append(ilist *l, int num, unsigned int hits, int aux)
{
	int_node* newnode;

	newnode = malloc(sizeof(int_node));

	newnode->num = num;
	newnode->hits = hits;
	newnode->aux1 = aux;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

void ilist_clear(ilist* l)
{
	int_node* nextnode;
	register int_node* current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int ilist_add_if_uniq(ilist *l, int num, int aux)
{
	register int_node *cur, *prev;

	prev = cur = l->head;
	while (cur) {
		if (cur->num == num) {
			cur->hits++;
			return 0;
		} else if (num > cur->num) {
			prev = cur;
			cur = cur->next;
		} else {
			int head = 0;

			// Insert so list is from low to high
			if (cur == l->head) {
				l->head = NULL;
				head = 1;
			} else
				l->cur = prev;
			ilist_append(l, num, 1, aux);
			if (head)
				l->cur->next = prev;
			else
				l->cur->next = cur;
			return 1;
		}
	}

	if (prev)
		l->cur = prev;

	/* No matches, append to the end */
	ilist_append(l, num, 1, aux);
	return 1;
}

// If lprev would be NULL, use l->head
static void swap_nodes(int_node *lprev, int_node *left, int_node *right)
{
	int_node *t = right->next;
	if (lprev)
		lprev->next = right;
	right->next = left;
	left->next = t;
}

// This will sort the list from most hits to least
void ilist_sort_by_hits(ilist *l)
{
	register int_node* cur, *prev;

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

