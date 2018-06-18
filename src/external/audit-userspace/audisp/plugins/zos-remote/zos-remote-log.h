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
 ***************************************************************************/

#ifndef _ZOS_REMOTE_LOG_H
#define _ZOS_REMOTE_LOG_H

#include "zos-remote-ldap.h"

#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <lber.h>

extern pid_t mypid;

void log_err(const char *, ...);
void log_warn(const char *, ...);
void log_info(const char *, ...);
void _log_debug(const char *, ...);
void _debug_bv(struct berval *);
void _debug_ber(BerElement *);

#ifdef DEBUG

#define log_debug(fmt, ...)        _log_debug(fmt, ## __VA_ARGS__)
#define debug_bv(bv)               _debug_bv(bv)
#define debug_ber(ber)             _debug_ber(ber)

#else

#define log_debug(fmt, ...)
#define debug_bv(bv)
#define debug_ber(ber)

#endif                 /* DEBUG */


#endif                          /* _ZOS_REMOTE_LOG_H */
