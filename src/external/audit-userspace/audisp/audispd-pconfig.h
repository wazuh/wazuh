/* audispd-pconfig.h -- 
 * Copyright 2007,2013 Red Hat Inc., Durham, North Carolina.
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

#ifndef AUDISPD_PCONFIG_H
#define AUDISPD_PCONFIG_H

#include <sys/types.h>
#include "libaudit.h"
#define MAX_PLUGIN_ARGS 2

typedef enum { A_NO, A_YES } active_t;
typedef enum { D_UNSET, D_IN, D_OUT } direction_t;
typedef enum { S_ALWAYS, S_BUILTIN, S_AF_UNIX, S_SYSLOG } service_t;
typedef enum { F_BINARY, F_STRING } format_t;

typedef struct plugin_conf
{
	active_t active;	/* Current state - active or not */
	direction_t direction;	/* in or out kind of plugin */
	const char *path;	/* path to binary */
	service_t type;		/* builtin or always */
	char *args[MAX_PLUGIN_ARGS+2];	/* args to be passed to plugin */
	format_t format;	/* Event format */
	int plug_pipe[2];	/* Communication pipe for events */
	pid_t pid;		/* Used to signal children */
	ino_t inode;		/* Use to see if new binary was installed */
	int checked;		/* Used for internal housekeeping on HUP */
	char *name;		/* Used to distinguish plugins for HUP */
	unsigned restart_cnt;	/* Number of times its crashed */
} plugin_conf_t;

void clear_pconfig(plugin_conf_t *config);
int  load_pconfig(plugin_conf_t *config, char *file);
void free_pconfig(plugin_conf_t *config);

#endif

