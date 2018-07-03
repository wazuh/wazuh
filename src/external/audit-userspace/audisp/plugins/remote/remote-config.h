/* remote-config.h -- 
 * Copyright 2008,2009,2011,2016 Red Hat Inc., Durham, North Carolina.
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

#ifndef REMOTE_CONFIG_H
#define REMOTE_CONFIG_H

typedef enum { M_IMMEDIATE, M_STORE_AND_FORWARD  } rmode_t;
typedef enum { T_TCP, T_SSL, T_GSSAPI, T_LABELED } transport_t;
typedef enum { F_ASCII, F_MANAGED } format_t;
typedef enum { FA_IGNORE, FA_SYSLOG, FA_WARN_ONCE_CONT, FA_WARN_ONCE,
	       FA_EXEC, FA_RECONNECT, FA_SUSPEND,
	       FA_SINGLE, FA_HALT, FA_STOP } failure_action_t;
typedef enum { OA_IGNORE, OA_SYSLOG, OA_SUSPEND, OA_SINGLE,
	       OA_HALT } overflow_action_t;

typedef struct remote_conf
{
	const char *remote_server;
	unsigned int port;
	unsigned int local_port;
	transport_t transport;
	rmode_t mode;
	const char *queue_file;
	unsigned int queue_depth;
	format_t format;
	unsigned int network_retry_time;
	unsigned int max_tries_per_record;
	unsigned int max_time_per_record;
	unsigned int heartbeat_timeout;
	int enable_krb5;
	const char *krb5_principal;
	const char *krb5_client_name;
	const char *krb5_key_file;

	failure_action_t network_failure_action;
	const char *network_failure_exe;
	failure_action_t disk_low_action;
	const char *disk_low_exe;
	failure_action_t disk_full_action;
	const char *disk_full_exe;
	failure_action_t disk_error_action;
	const char *disk_error_exe;
	failure_action_t remote_ending_action;
	const char *remote_ending_exe;
	failure_action_t generic_error_action;
	const char *generic_error_exe;
	failure_action_t generic_warning_action;
	const char *generic_warning_exe;
	failure_action_t queue_error_action;
	const char *queue_error_exe;
	overflow_action_t overflow_action;
} remote_conf_t;

void clear_config(remote_conf_t *config);
int  load_config(remote_conf_t *config, const char *file);
void free_config(remote_conf_t *config);

#endif

