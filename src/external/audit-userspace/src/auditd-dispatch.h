/* auditd-dispatch.h -- 
 * Copyright 2005,2007,2013,2017 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUDITD_DISPATCH_H
#define AUDITD_DISPATCH_H

#include "auditd-config.h"

int dispatcher_pid(void);
void dispatcher_reaped(void);
int make_dispatcher_fd_private(void);
int init_dispatcher(const struct daemon_conf *config, int config_dir_set);
void shutdown_dispatcher(void);
void reconfigure_dispatcher(const struct daemon_conf *config);
int dispatch_event(const struct audit_reply *rep, int is_err, int protocol_ver);

#endif

