
/* rnode.h --
 * Copyright 2007,2016-17 Red Hat Inc., Durham, North Carolina.
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
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef RNODE_HEADER
#define RNODE_HEADER

/* This is the node of the linked list. Any data elements that are
 * per field goes here. */
typedef struct _nvnode{
  char *name;           // The name string
  char *val;            // The value field
  char *interp_val;     // The value field interpretted
  unsigned int item;    // Which item of the same event
  struct _nvnode* next; // Next nvpair node pointer
} nvnode;

/* This is the field linked list head. */
typedef struct {
  nvnode *head;         // List head
  nvnode *cur;          // Pointer to current node
  unsigned int cnt;     // How many items in this list
} nvlist;


/* This is the node of the linked list. Only data elements that are per
 * record goes here. */
typedef struct _rnode{
	char *record;           // The whole unparsed record
	char *interp;		// The interpretations that go with record
	const char *cwd;	// This is pass thru for ellist
	int type;               // record type (KERNEL, USER, LOGIN, etc)
	int machine;            // The machine type for the event
	int syscall;            // The syscall for the event
	unsigned long long a0;  // arg 0 to the syscall
	unsigned long long a1;  // arg 1 to the syscall
	nvlist nv;              // name-value linked list of parsed elements
	unsigned int item;      // Which item of the same event
	int list_idx;		// The index into the source list, points to where record was found
	unsigned int line_number; // The line number where record was found
	struct _rnode* next;    // Next record node pointer
} rnode;

#endif

