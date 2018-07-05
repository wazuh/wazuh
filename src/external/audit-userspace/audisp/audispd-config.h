/* audispd-config.h -- 
 * Copyright 2007-08 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUDISPD_CONFIG_H
#define AUDISPD_CONFIG_H

#include "libaudit.h"

typedef enum { O_IGNORE, O_SYSLOG, O_SUSPEND, O_SINGLE,
		O_HALT } overflow_action_t;
typedef enum { N_NONE, N_HOSTNAME, N_FQD, N_NUMERIC, N_USER } node_t;

typedef struct daemon_conf
{
	unsigned int q_depth;
	overflow_action_t overflow_action;
	unsigned int priority_boost;
	unsigned int max_restarts;
	node_t node_name_format;
	const char *name;
	char *plugin_dir;
} daemon_conf_t;

void clear_config(daemon_conf_t *config);
int  load_config(daemon_conf_t *config, const char *file);
void free_config(daemon_conf_t *config);

#endif

