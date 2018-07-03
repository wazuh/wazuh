/*
 * lru.h - Header file for lru.c
 * Copyright (c) 2016.2017 Red Hat Inc., Durham, North Carolina.
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

#ifndef LRU_HEADER
#define LRU_HEADER
#include "dso.h"

/* Make these hidden to prevent conflicts */
AUDIT_HIDDEN_START


// Queue is implemented using double linked list
typedef struct QNode
{
	struct QNode *prev;
	struct QNode *next;
	unsigned long uses;
	unsigned int id;
	void *str;        // the data in the cache
} QNode;

// Collection of pointers to Queue Nodes
typedef struct Hash
{
	unsigned int size; // how many entries
	QNode **array;     // an array of queue nodes
} Hash;

// FIFO of Queue Nodes
typedef struct Queue
{
	unsigned int count;  // Number of filled slots
	unsigned int total;  // total number of slots
	unsigned long hits;  // Number of times object was in cache
	unsigned long misses;// number of times object was not in cache
	unsigned long evictions;// number of times cached object was not usable
	QNode *front;
	QNode *end;
	Hash *hash;
	const char *name;	// Used for reporting
	void (*cleanup)(void *); // Function to call when releasing memory
} Queue;

Queue *init_lru(unsigned int qsize, void (*cleanup)(void *),
		const char *name);
void destroy_lru(Queue *queue);
void lru_evict(Queue *queue, unsigned int key);
QNode *check_lru_cache(Queue *q, unsigned int key);
unsigned int compute_subject_key(const Queue *queue, unsigned int uid);

AUDIT_HIDDEN_END

#endif
