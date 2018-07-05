/* deprecated.c -- This file is the trash heap of things about to leave 
 * Copyright 2006-07,2009,2016 Red Hat Inc., Durham, North Carolina.
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
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "libaudit.h"
#include "private.h"

/*
 * This function will send a user space message to the kernel.
 * It returns the sequence number which is > 0 on success  
 * or <= 0 on error. (pam uses this) This is the main audit sending
 * function now.
 */
int audit_send_user_message(int fd, int type, hide_t hide_error,
	const char *message)
{
	int retry_cnt = 0;
	int rc;
retry:
	rc = audit_send(fd, type, message, strlen(message)+1);
	if (rc == -ECONNREFUSED) {
		/* This is here to let people that build their own kernel
		   and disable the audit system get in. ECONNREFUSED is
		   issued by the kernel when there is "no on listening". */
		return 0;
	} else if (rc == -EPERM && !audit_can_write() && hide_error == HIDE_IT) {
		/* If we get this, then the kernel supports auditing
		 * but we don't have enough privilege to write to the
		 * socket. Therefore, we have already been authenticated
		 * and we are a common user. Just act as though auditing
		 * is not enabled. Any other error we take seriously.
		 * This is here basically to satisfy Xscreensaver. */
		return 0;
	} else if (rc == -EINVAL) {
		/* If we get this, the kernel doesn't understand the
		 * netlink message type. This is most likely due to
		 * being an old kernel. Use the old message type. */
		if (type >= AUDIT_FIRST_USER_MSG && 
				type <= AUDIT_LAST_USER_MSG && !retry_cnt) {

			/* do retry */
			type = AUDIT_USER;
			retry_cnt++;
			goto retry;
		} 
	}
	return rc;
}

