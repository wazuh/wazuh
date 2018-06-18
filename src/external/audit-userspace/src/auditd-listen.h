/* auditd-config.h -- 
 * Copyright 2004-2007 Red Hat Inc., Durham, North Carolina.
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
 *   DJ Delorie <dj@redhat.com>
 * 
 */

#ifndef AUDITD_LISTEN_H
#define AUDITD_LISTEN_H

#include "ev.h"

#ifdef USE_LISTENER
int auditd_tcp_listen_init ( struct ev_loop *loop, struct daemon_conf *config );
void auditd_tcp_listen_uninit ( struct ev_loop *loop,
				struct daemon_conf *config );
void auditd_tcp_listen_reconfigure ( struct daemon_conf *nconf,
				     struct daemon_conf *oconf );
#else
static inline int auditd_tcp_listen_init ( struct ev_loop *loop,
					   struct daemon_conf *config )
{
	return 0;
}

static inline void auditd_tcp_listen_uninit ( struct ev_loop *loop,
					      struct daemon_conf *config )
{
	return;
}

static inline void auditd_tcp_listen_reconfigure ( struct daemon_conf *nconf,
						   struct daemon_conf *oconf )
{
	return;
}
#endif /* USE_LISTENER */

#endif
