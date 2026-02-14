/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic error codes */

#ifndef OS_ERR
#define OS_ERR

#define OS_SUCCESS      0   /* Success                  */
#define OS_INVALID      -1  /* Invalid entry            */
#define OS_NOTFOUND     -2  /* Entry not found          */
#define OS_FILERR       -3  /* Error in the file        */
#define OS_SIZELIM      -4  /* Size limit problem       */
#define OS_CFGERR       -5  /* Configuration error      */
#define OS_SOCKTERR     -6  /* Socket error             */
#define OS_MISVALUE     -7  /* There are values missing */
#define OS_CONNERR      -8  /* Connection failed        */
#define OS_UNDEF        -9  /* Uknown error             */
#define OS_MEMERR       -10 /* Memory Error             */
#define OS_SOCKBUSY     -11 /* Socket busy -- try again */
#define OS_MAXLEN       -12 /* Max length               */
#define OS_TIMEOUT      -13 /* Timeout error            */

#define OS_ENDFILE      -20 /* End of file              */
#define OS_FINISH       -21 /* Finished this task       */

typedef int w_err_t;

#endif /* OS_ERR */
