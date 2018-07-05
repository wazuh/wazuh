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
#include "zos-remote-log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "auparse.h"


static void vlog_prio(int prio, const char *fmt, va_list ap)
{
        char *str;

        if (asprintf(&str, "pid=%d: %s", mypid, fmt) != -1) {
                vsyslog(LOG_DAEMON | prio, str, ap);
                free(str);
        }
}

void log_err(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vlog_prio(LOG_ERR, fmt, ap);
        va_end(ap);
}

void log_warn(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vlog_prio(LOG_WARNING, fmt, ap);
        va_end(ap);
}

void log_info(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vlog_prio(LOG_INFO, fmt, ap);
        va_end(ap);
}

void _log_debug(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vlog_prio(LOG_INFO, fmt, ap);
        va_end(ap);
}

void _debug_ber(BerElement * ber)
{
        struct berval bv;

        if (ber_flatten2(ber, &bv, 0) != -1) {
                debug_bv(&bv);
        }
}

void _debug_bv(struct berval *bv)
{
        char *out;
        char octet[4];
        ber_len_t i;

        log_debug("---BER value HEX dump (size %u bytes)",
                  (unsigned int) bv->bv_len);
                  
        if (bv->bv_len > 0) {
                out = (char *) calloc((3 * (bv->bv_len)) + 1, sizeof(char));
                if (!out) return;

                for (i = 1; i <= bv->bv_len; i++) {
                        snprintf(octet, 4, "%02x ",
                                 (unsigned char) bv->bv_val[i - 1]);
                        strcat(out, octet);
                }
                log_debug(out);
                free(out);
        }
}


