/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef STATE_WRAPPERS_H
#define STATE_WRAPPERS_H

void __wrap_rem_inc_tcp();
void __wrap_rem_dec_tcp();
void __wrap_rem_inc_evt();
void __wrap_rem_inc_ctrl_msg();
void __wrap_rem_inc_msg_queued();
void __wrap_rem_add_send(unsigned long bytes);
void __wrap_rem_inc_discarded();
void __wrap_rem_add_recv(unsigned long bytes);
void __wrap_rem_inc_dequeued();

#endif
