/*
* ausearch-avc.c - Minimal linked list library for avcs
* Copyright (c) 2006,2008,2014 Red Hat Inc., Durham, North Carolina.
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
#include "ausearch-avc.h"


void alist_create(alist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

anode *alist_next(alist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

static void alist_last(alist *l)
{
	register anode* cur;

	if (l->head == NULL)
		return;

	// Start with cur in hopes that we don't start at beginning
	if (l->cur)
		cur = l->cur;
	else
		cur = l->head;

	// Loop until no next value
	while (cur->next)
		cur = cur->next;
	l->cur = cur;
}

void alist_append(alist *l, anode *node)
{
	anode* newnode;

	newnode = malloc(sizeof(anode));

	if (node->scontext)
		newnode->scontext = node->scontext;
	else
		newnode->scontext = NULL;

	if (node->tcontext)
		newnode->tcontext = node->tcontext;
	else
		newnode->tcontext = NULL;

	newnode->avc_result = node->avc_result;

	if (node->avc_perm)
		newnode->avc_perm = node->avc_perm;
	else
		newnode->avc_perm = NULL;

	if (node->avc_class)
		newnode->avc_class = node->avc_class;
	else
		newnode->avc_class = NULL;

	newnode->next = NULL;

	// Make sure cursor is at the end
	alist_last(l);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

int alist_find_subj(alist *l)
{
        register anode* node = l->head;

	while (node) {
		if (node->scontext) {
			l->cur = node;
			return 1;
		}
		else
			node = node->next;
	}
	return 0;
}

anode *alist_next_subj(alist *l)
{
	if (l->cur == NULL)
		return NULL;
	while (l->cur->next) {
		l->cur=l->cur->next;
		if (l->cur->scontext)
			return l->cur;
	}
	return NULL;
}

int alist_find_obj(alist *l)
{
        register anode* node = l->head;

	while (node) {
		if (node->tcontext) {
			l->cur = node;
			return 1;
		}
		else
			node = node->next;
	}
	return 0;
}

anode *alist_next_obj(alist *l)
{
	if (l->cur == NULL)
		return NULL;
	while (l->cur->next) {
		l->cur=l->cur->next;
		if (l->cur->tcontext)
			return l->cur;
	}
	return NULL;
}

int alist_find_avc(alist *l)
{
        register anode* node = l->head;

	while (node) {
		if (node->avc_result != AVC_UNSET) {
			l->cur = node;
			return 1;
		}
		else
			node = node->next;
	}
	return 0;
}

anode *alist_next_avc(alist *l)
{
	if (l->cur == NULL)
		return NULL;
	while (l->cur->next) {
		l->cur=l->cur->next;
		if (l->cur->avc_result != AVC_UNSET)
			return l->cur;
	}
	return NULL;
}

void alist_clear(alist* l)
{
	anode* nextnode;
	register anode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		anode_clear(current);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void anode_init(anode *an)
{
	an->scontext = NULL;
	an->tcontext = NULL;
	an->avc_result = AVC_UNSET;
	an->avc_perm = NULL;
	an->avc_class = NULL;
}

void anode_clear(anode *an)
{
	free(an->scontext);
	free(an->tcontext);
	free(an->avc_perm);
	free(an->avc_class);
}

