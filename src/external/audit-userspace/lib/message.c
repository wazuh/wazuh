/* message.c --
 * Copyright 2004,2005,2016 Red Hat Inc., Durham, North Carolina.
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

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include "libaudit.h"
#include "private.h"

/* The message mode refers to where informational messages go
   0 - stderr, 1 - syslog, 2 - quiet. The default is quiet. */
static message_t message_mode = MSG_QUIET;
static debug_message_t debug_message = DBG_NO;

void set_aumessage_mode(message_t mode, debug_message_t debug)
{
        message_mode = mode;
	debug_message = debug;
}

void audit_msg(int priority, const char *fmt, ...)
{
        va_list   ap;

	if (message_mode == MSG_QUIET)
		return;

	if (priority == LOG_DEBUG && debug_message == DBG_NO)
		return;

        va_start(ap, fmt);
        if (message_mode == MSG_SYSLOG)
                vsyslog(priority, fmt, ap);
        else {
                vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	}
        va_end( ap );
}
