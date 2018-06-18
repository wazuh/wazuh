/*
 * normalize-llist.h - Header file for normalize-llist.c
 * Copyright (c) 2016-17 Red Hat Inc., Durham, North Carolina.
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

#ifndef NORMALIZE_LLIST_HEADER
#define NORMALIZE_LLIST_HEADER

#include "config.h"
#include <stdint.h>
#include "private.h"

/* This is the node of the linked list. Number & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _data_node {
  uint32_t num;		// The number
  void *data;		// Extra spot for data
  struct _data_node *next;	// Next string node pointer
} data_node;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  data_node *head;		// List head
  data_node *cur;		// Pointer to current node
  void (*cleanup)(void *); // Function to call when releasing memory
  unsigned int cnt;	// How many items in this list
} cllist;

static inline void cllist_first(cllist *l) { l->cur = l->head; }
static inline data_node *cllist_get_cur(cllist *l) { return l->cur; }

AUDIT_HIDDEN_START

void cllist_create(cllist *l, void (*cleanup)(void *));
void cllist_clear(cllist* l);
data_node *cllist_next(cllist *l);
void cllist_append(cllist *l, uint32_t num, void *data);

AUDIT_HIDDEN_END

#endif

