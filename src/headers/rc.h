/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Remote Control shared headers */

#ifndef __RC_H
#define __RC_H

/* Global headers */
#define CONTROL_HEADER      "#!-"

#define IsValidHeader(str)  ((str[0] == '#') && \
                             (str[1] == '!') && \
                             (str[2] == '-') && \
                             (str+=3) )

#define EXECD_HEADER        "execd "
#define FILE_UPDATE_HEADER  "up file "
#define FILE_CLOSE_HEADER   "close file "
#define HC_STARTUP          "agent startup "
#define HC_ACK              "agent ack "
#define HC_SK_DB_COMPLETED  "syscheck-db-completed"
#define HC_SK_RESTART       "syscheck restart"

#endif

