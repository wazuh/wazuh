/*
 * aulastlog.c - A lastlog program based on audit logs 
 * Copyright (c) 2008-2009,2011 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include "auparse.h"
#include "aulastlog-llist.h"

void usage(void)
{
	fprintf(stderr, "usage: aulastlog [--stdin] [--user name]\n");
}

int main(int argc, char *argv[])
{
	int i, use_stdin = 0;
	char *user = NULL;
	struct passwd *p;
        auparse_state_t *au;
	llist l;

        setlocale (LC_ALL, "");
	for (i=1; i<argc; i++) {
		if ((strcmp(argv[i], "--user") == 0) || 
				(strcmp(argv[i], "-u") == 0)) {
			i++;
			if (i<argc)
				user = argv[i];
			else {
				usage();
				return 1;
			}
		} else if (strcmp(argv[i], "--stdin") == 0) {
			use_stdin = 1;
		} else {
			usage();
			return 1;
		}
	}

	list_create(&l);

	// Stuff linked lists with all users
	// This use is OK because docs say local machine only 
	while ((p = getpwent()) != NULL) {
		lnode n;

		n.sec = 0;
		n.uid = p->pw_uid;
		n.name = p->pw_name;
		n.host = NULL;
		n.term = NULL;
		if (user == NULL)
			list_append(&l, &n);
		else if (strcmp(user, p->pw_name) == 0)
			list_append(&l, &n);
	}
	endpwent();

	if (user && list_get_cnt(&l) == 0) {
		printf("Unknown User: %s\n", user);
		return 1;
	}

	// Search for successful user logins
	if (use_stdin)
		au = auparse_init(AUSOURCE_FILE_POINTER, stdin);
	else
		au = auparse_init(AUSOURCE_LOGS, NULL);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		goto error_exit_1;
	}
	if (ausearch_add_item(au, "type", "=", "USER_LOGIN",
						 AUSEARCH_RULE_CLEAR)){
		printf("ausearch_add_item error - %s\n", strerror(errno));
		goto error_exit_2;
	}
	if (ausearch_add_item(au, "res", "=", "success",
						 AUSEARCH_RULE_AND)){
		printf("ausearch_add_item error - %s\n", strerror(errno));
		goto error_exit_2;
	}
	if (ausearch_set_stop(au, AUSEARCH_STOP_RECORD)){
		printf("ausearch_set_stop error - %s\n", strerror(errno));
		goto error_exit_2;
        }

	// Now scan the logs and append events
	while (ausearch_next_event(au) > 0) {
		const au_event_t *e = auparse_get_timestamp(au);
		if (auparse_find_field(au, "auid")) {
			uid_t u = auparse_get_field_int(au);
			list_first(&l);
			if (list_find_uid(&l, u)) {
				const char *str;

				list_update_login(&l, e->sec);
				str = auparse_find_field(au, "hostname");
				if (str) 
					list_update_host(&l, str);
				str = auparse_find_field(au, "terminal");
				if (str)
					list_update_term(&l, str);
			}
		}
		if (auparse_next_event(au) < 0)
			break;
	}
        auparse_destroy(au);

	// Now output the report
	printf( "Username         Port         From"
		"                       Latest\n");
	list_first(&l);
	do {
		char tmp[48];
		const char *c, *h, *t;
		lnode *cur = list_get_cur(&l);
		if (cur->sec == 0)
			c = "**Never logged in**";
		else {
			struct tm *btm;

			btm = localtime(&cur->sec);
			strftime(tmp, sizeof(tmp), "%x %T", btm);
			c = tmp;
		}
		h = cur->host;
		if (h == NULL)
			h = "";
		t = cur->term;
		if (t == NULL)
			t = "";
		printf("%-16s %-12.12s %-26.26s %s\n", cur->name, t, h, c);
	} while (list_next(&l));
	
	list_clear(&l);
	return 0;

error_exit_2:
        auparse_destroy(au);
error_exit_1:
	list_clear(&l);
	return 1;
}

