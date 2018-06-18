/***************************************************************************
 *   Copyright (C) 2007 International Business Machines  Corp.             *
 *   All Rights Reserved.                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 * Authors:                                                                *
 *   Klaus Heinrich Kiwi <klausk@br.ibm.com>                               *
 *   based on code by Steve Grubb <sgrubb@redhat.com>                      *
 ***************************************************************************/

#ifndef _ZOS_REMOTE_CONFIG_H
#define _ZOS_REMOTE_CONFIG_H


/***************************************************************************
 *   z/OS Remote-services Plugin configuration                             *
 ***************************************************************************/
typedef struct plugin_conf
{
        char *name;
        char *server;
        unsigned int port;
        char *user;
        char *password;
        long timeout;
        unsigned int q_depth;
        unsigned int counter;
} plugin_conf_t;

void plugin_clear_config(plugin_conf_t *);
int plugin_load_config(plugin_conf_t *, const char *);
void plugin_free_config(plugin_conf_t *);

#endif                          /* _ZOS_REMOTE_CONFIG_H */
