/*
* nvlist.c - Minimal linked list library for name-value pairs
* Copyright (c) 2006-07,2016 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "nvlist.h"
#include "interpret.h"
#include "auparse-idata.h"


void nvlist_create(nvlist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

static void nvlist_last(nvlist *l)
{
        register nvnode* node;

	if (l->head == NULL)
		return;

	node = l->head;
	while (node->next)
		node = node->next;
	l->cur = node;
}

nvnode *nvlist_next(nvlist *l)
{
	if (l->cur)
		l->cur = l->cur->next;
	return l->cur;
}

void nvlist_append(nvlist *l, nvnode *node)
{
	nvnode* newnode = malloc(sizeof(nvnode));

	newnode->name = node->name;
	newnode->val = node->val;
	newnode->interp_val = NULL;
	newnode->item = l->cnt; 
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Otherwise add pointer to newnode
		if (l->cnt == (l->cur->item+1)) {
			l->cur->next = newnode;
		}
		else {
			nvlist_last(l);
			l->cur->next = newnode;
		}
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

/*
 * Its less code to make a fixup than a new append.
 */
void nvlist_interp_fixup(nvlist *l)
{
	if (l->cur) {
		l->cur->interp_val = l->cur->val;
		l->cur->val = NULL;
	}
}

nvnode *nvlist_goto_rec(nvlist *l, unsigned int i)
{
	register nvnode* node;

	node = l->head;       /* start at the beginning */
	while (node) {
		if (node->item == i) {
			l->cur = node;
			return node;
		} else
			node = node->next;
	}
	return NULL;
}

/*
 * This function will start at current index and scan for a name
 */
int nvlist_find_name(nvlist *l, const char *name)
{
        register nvnode* node = l->cur;

	while (node) {
		if (strcmp(node->name, name) == 0) {
			l->cur = node;
			return 1;
		}
		else
			node = node->next;
	}
	return 0;
}

extern int interp_adjust_type(int rtype, const char *name, const char *val);
int nvlist_get_cur_type(const rnode *r)
{
	const nvlist *l = &r->nv;
	return auparse_interp_adjust_type(r->type, l->cur->name, l->cur->val);
}

const char *nvlist_interp_cur_val(const rnode *r, auparse_esc_t escape_mode)
{
	const nvlist *l = &r->nv;
	if (l->cur->interp_val)
		return l->cur->interp_val;
	return interpret(r, escape_mode);
}

void nvlist_clear(nvlist* l)
{
	nvnode* nextnode;
	register nvnode* current;

	if (l->head == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->name);
		free(current->val);
		free(current->interp_val);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}
