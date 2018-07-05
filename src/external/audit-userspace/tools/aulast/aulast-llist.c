/*
* aulast-llist.c - Minimal linked list library
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
#include "aulast-llist.h"

void list_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
}

lnode *list_next(llist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

static void list_append(llist *l, lnode *node)
{
	node->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = node;
	else if (l->cur) {
		// Make sure we are at the end
		while (l->cur->next)
			l->cur = l->cur->next;

		l->cur->next = node;
	}

	// make newnode current
	l->cur = node;
}

void list_clear(llist* l)
{
	lnode* nextnode;
	register lnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free((void *)current->name);
		free((void *)current->term);
		free((void *)current->host);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
}

int list_create_session_simple(llist *l, lnode *n)
{
	list_append(l, n);
	return 1;
}

int list_create_session(llist *l, uid_t auid, int pid, int session,
	unsigned long serial)
{
	lnode *n = malloc(sizeof(lnode));
	if (n == NULL)
		return 0;
	n->session = session;
	n->start = 0;
	n->end = 0;
	n->auid = auid;
	n->pid = pid;
	n->result = -1;
	n->name = NULL;
	n->term = NULL;
	n->host = NULL;
	n->status = LOG_IN;
	n->loginuid_proof = serial;
	n->user_login_proof = 0;
	n->user_end_proof = 0;
	list_append(l, n);
	return 1;
}

int list_update_start(llist* l, const char *host, const char *term,
	int res, unsigned long serial)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	cur->status = SESSION_START;
	if (term)
		cur->term = strdup(term);
	if (host)
		cur->host = strdup(host);
	cur->result = res;
	cur->user_login_proof = serial;
	return 1;
}

int list_update_logout(llist* l, time_t t, unsigned long serial)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	cur->end = t;
	cur->status = LOG_OUT;
	cur->user_end_proof = serial;
	return 1;
}

lnode *list_delete_cur(llist *l)
{
        register lnode *cur, *prev;
                                                                                
       	prev = cur = l->head;	/* start at the beginning */
	while (cur) {
		if (cur == l->cur) {
			if (cur == prev && cur == l->head) {
				l->head = cur->next;
				l->cur = cur->next;
				free((void *)cur->name);
				free((void *)cur->term);
				free((void *)cur->host);
				free(cur);
				prev = NULL;
			} else {
				prev->next = cur->next;
				free((void *)cur->name);
				free((void *)cur->term);
				free((void *)cur->host);
				free(cur);
				l->cur = prev;
			}
			return prev;
		} else {
			prev = cur;
			cur = cur->next;
		}
	}
	return NULL;
}

lnode *list_find_auid(llist *l, uid_t auid, int pid, unsigned int session)
{
        register lnode* cur;
                                                                                
       	cur = l->head;	/* start at the beginning */
	while (cur) {
		if (cur->pid == pid && cur->auid == auid &&
					cur->session == session) {
			l->cur = cur;
			return cur;
		} else
			cur = cur->next;
	}
	return NULL;
}

lnode *list_find_session(llist *l, unsigned int session)
{
        register lnode* cur;
                                                                                
       	cur = l->head;	/* start at the beginning */
	while (cur) {
		if (cur->session == session) {
			l->cur = cur;
			return cur;
		} else
			cur = cur->next;
	}
	return NULL;
}

