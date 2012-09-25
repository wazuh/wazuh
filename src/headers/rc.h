/* @(#) $Id: ./src/headers/rc.h, 2011/09/08 dcid Exp $
 */

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


/* Exec message */
#define EXECD_HEADER        "execd "

/* File update message */
#define FILE_UPDATE_HEADER  "up file "

/* File closing message */
#define FILE_CLOSE_HEADER   "close file "

/* Agent startup */
#define HC_STARTUP          "agent startup "

/* Agent startup ack */
#define HC_ACK              "agent ack "

/* Syscheck database completed */
#define HC_SK_DB_COMPLETED  "syscheck-db-completed"

/* Syscheck restart msg. */
#define HC_SK_RESTART       "syscheck restart"


#endif

/* EOF */
