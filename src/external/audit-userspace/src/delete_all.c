/* delete_all.c --
 * Copyright 2005-06, 2008-09,2014 Red Hat Inc., Durham, North Carolina.
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
#include <string.h>
#include <errno.h>

#include "libaudit.h"
#include "private.h"

#include "auditctl-llist.h"

extern int key_match(const struct audit_rule_data *r);

/* Returns 0 for success and -1 for failure */
int delete_all_rules(int fd)
{
	int seq, i, rc;
	int timeout = 40; /* tenths of seconds */
	struct audit_reply rep;
	fd_set read_mask;
	llist l;
	lnode *n;

	/* list the rules */
	seq = audit_request_rules_list_data(fd);
	if (seq <= 0) 
		return -1;

	FD_ZERO(&read_mask);
	FD_SET(fd, &read_mask);
	list_create(&l);

	for (i = 0; i < timeout; i++) {
		struct timeval t;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		do {
			rc = select(fd+1, &read_mask, NULL, NULL, &t);
		} while (rc < 0 && errno == EINTR);
		// We'll try to read just in case
		rc = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
		if (rc > 0) {
			/* Reset timeout */
			i = 0;

			/* Don't make decisions based on wrong packet */
			if (rep.nlh->nlmsg_seq != seq)
				continue;

			/* If we get done or error, break out */
			if (rep.type == NLMSG_DONE)
				break;

			if (rep.type == NLMSG_ERROR && rep.error->error) {
				audit_msg(LOG_ERR, 
					"Error receiving rules list (%s)", 
					strerror(-rep.error->error));
				return -1;
			}

			/* If its not what we are expecting, keep looping */
			if (rep.type != AUDIT_LIST_RULES)
				continue;

			if (key_match(rep.ruledata))
				list_append(&l, rep.ruledata, 
					sizeof(struct audit_rule_data) +
					rep.ruledata->buflen);

		}
	}
	list_first(&l);
	n = l.cur;
	while (n) {
		/* Bounce it right back with delete */
		rc = audit_send(fd, AUDIT_DEL_RULE, n->r, n->size);
		if (rc < 0) {
			audit_msg(LOG_ERR, "Error deleting rule (%s)",
				strerror(-rc)); 
			return -1;
		}
		n = list_next(&l);
	}
	list_clear(&l);

	return 0;
}

