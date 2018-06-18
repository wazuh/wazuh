/*
* audispd-llist.c - Minimal linked list library
* Copyright (c) 2007,2013 Red Hat Inc., Durham, North Carolina.
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
#include "audispd-llist.h"

void plist_create(conf_llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void plist_last(conf_llist *l)
{
        register lnode* node;
	
	if (l->head == NULL)
		return;

        node = l->head;
	while (node->next)
		node = node->next;
	l->cur = node;
}

lnode *plist_next(conf_llist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

unsigned int plist_count_active(const conf_llist *l)
{
	register lnode* current;
	unsigned int cnt = 0;

	current = l->head;
	while (current) {
		if (current->p && current->p->active == A_YES)
			cnt++;
		current=current->next;
	}
	return cnt;
}

void plist_append(conf_llist *l, plugin_conf_t *p)
{
	lnode* newnode;

	newnode = malloc(sizeof(lnode));

	if (p) {
		void *pp = malloc(sizeof(struct plugin_conf));
		if (pp) 
			memcpy(pp, p, sizeof(struct plugin_conf));
		newnode->p = pp;
	} else
		newnode->p = NULL;

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

void plist_clear(conf_llist* l)
{
	lnode* nextnode;
	register lnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->p);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void plist_mark_all_unchecked(conf_llist* l)
{
	register lnode* current;

	current = l->head;
	while (current) {
		if (current->p)
			current->p->checked = 0;
		current=current->next;
	}
}

lnode *plist_find_unchecked(conf_llist* l)
{
	register lnode* current;

	current = l->head;
	while (current) {
		if (current->p && current->p->checked == 0)
			return current;
		current=current->next;
	}
	return NULL;
}

lnode *plist_find_name(conf_llist* l, const char *name)
{
	register lnode* current;

	if (name == NULL)
		return NULL;

	current = l->head;
	while (current) {
		if (current->p && current->p->name) {
			if (strcmp(current->p->name, name) == 0)
				return current;
		}
		current=current->next;
	}
	return NULL;
}

