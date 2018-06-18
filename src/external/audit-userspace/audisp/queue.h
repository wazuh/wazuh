/* queue.h --
 * Copyright 2007 Red Hat Inc., Durham, North Carolina.
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

#ifndef QUEUE_HEADER
#define QUEUE_HEADER

#include "libaudit.h"
#include "audispd-config.h"

typedef struct event
{
	struct audit_dispatcher_header hdr;
	char data[MAX_AUDIT_MESSAGE_LENGTH];
} event_t;


void reset_suspended(void);
int init_queue(unsigned int size);
void enqueue(event_t *e, struct daemon_conf *config);
event_t *dequeue(void);
void nudge_queue(void);
void increase_queue_depth(unsigned int size);
void destroy_queue(void);

#endif

