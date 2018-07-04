/*
* aulastlog-llist.c - Minimal linked list library
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

#include <stdlib.h>
#include <string.h>
#include "aulastlog-llist.h"

void list_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

lnode *list_next(llist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void list_append(llist *l, lnode *node)
{
	lnode* newnode;

	newnode = malloc(sizeof(lnode));

	newnode->sec = node->sec;
	newnode->uid = node->uid;
	newnode->name = strdup(node->name);
	if (node->host)
		newnode->host = strdup(node->host);
	else
		newnode->host = NULL;
	if (node->term)
		newnode->term = strdup(node->term);
	else
		newnode->term = NULL;
	newnode->item = l->cnt; 
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

void list_clear(llist* l)
{
	lnode* nextnode;
	register lnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->name);
		free(current->host);
		free(current->term);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int list_update_login(llist* l, time_t t)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	cur->sec = t;
	return 1;
}

int list_update_host(llist* l, const char *h)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	if (h) {
		free(cur->host);
		cur->host = strdup(h);
	} else
		cur->host = NULL;
	return 1;
}

int list_update_term(llist* l, const char *t)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	if (t) {
		free(cur->term);
		cur->term = strdup(t);
	} else
		cur->term = NULL;
	return 1;
}

lnode *list_find_uid(llist *l, uid_t uid)
{
        register lnode* node;
                                                                                
       	node = l->head;	/* start at the beginning */
	while (node) {
		if (node->uid == uid) {
			l->cur = node;
			return node;
		} else
			node = node->next;
	}
	return NULL;
}

