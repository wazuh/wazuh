/* auditd-event.h -- 
 * Copyright 2004,2005,2008,2016,2018 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 * 
 */

#ifndef AUDITD_EVENT_H
#define AUDITD_EVENT_H

#include <stdio.h>
#include "libaudit.h"

typedef void (*ack_func_type)(void *ack_data, const unsigned char *header, const char *msg);

struct auditd_event {
	struct audit_reply reply;
	ack_func_type ack_func;
	void *ack_data;
	unsigned long sequence_id;
};

#include "auditd-config.h"

int dispatch_network_events(void);
void write_logging_state(FILE *f);
void shutdown_events(void);
int init_event(struct daemon_conf *config);
void resume_logging(void);
void cleanup_event(struct auditd_event *e);
void format_event(struct auditd_event *e);
void enqueue_event(struct auditd_event *e);
void handle_event(struct auditd_event *e);
struct auditd_event *create_event(char *msg, ack_func_type ack_func,
			void *ack_data, uint32_t sequence_id);

#endif

