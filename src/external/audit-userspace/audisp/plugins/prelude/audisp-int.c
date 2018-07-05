/*
* audisp-int.c - Minimal linked list library for integers
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

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "audisp-int.h"

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

void ilist_append(ilist *l, int num)
{
	int_node* newnode;

	newnode = malloc(sizeof(int_node));

	newnode->num = num;
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

int ilist_find_num(ilist *l, unsigned int num)
{
        register int_node* node = l->head;

	while (node) {
		if (node->num == num) {
			l->cur = node;
			return 1;
		}
		else
			node = node->next;
	}
	return 0;
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

int ilist_add_if_uniq(ilist *l, int num)
{
	register int_node* cur;

	cur = l->head;
	while (cur) {
		if (cur->num == num) 
			return 0;
		else
			cur = cur->next;
	}

	/* No matches, append to the end */
	ilist_append(l, num);
	return 1;
}

