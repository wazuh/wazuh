/* prelude-config.h -- 
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
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

#ifndef PRELUDE_CONFIG_H
#define PRELUDE_CONFIG_H

#include "audisp-int.h"

typedef enum { E_NO, E_YES  } enable_t;
typedef enum { A_IGNORE, A_IDMEF=1, A_KILL=2, A_SESSION=4, A_SINGLE=8,
	A_HALT=16  } action_t;

typedef struct prelude_conf
{
	const char *profile;
	enable_t avcs;
	action_t avcs_act;
	enable_t logins;
	action_t logins_act;
	enable_t login_failure_max;
	action_t login_failure_max_act;
	enable_t login_session_max;
	action_t login_session_max_act;
	enable_t login_location;
	action_t login_location_act;
	enable_t login_time;
	action_t login_time_act;
	enable_t abends;
	action_t abends_act;
	enable_t promiscuous;
	action_t promiscuous_act;
	enable_t mac_status;
	action_t mac_status_act;
	enable_t group_auth;
	action_t group_auth_act;
	enable_t watched_acct;
	action_t watched_acct_act;
	ilist watched_accounts;
	enable_t watched_syscall;
	action_t watched_syscall_act;
	enable_t watched_file;
	action_t watched_file_act;
	enable_t watched_exec;
	action_t watched_exec_act;
	enable_t watched_mk_exe;
	action_t watched_mk_exe_act;
	enable_t tty;
	action_t tty_act;
} prelude_conf_t;

void clear_config(prelude_conf_t *config);
int  load_config(prelude_conf_t *config, const char *file);
void free_config(prelude_conf_t *config);

#endif

