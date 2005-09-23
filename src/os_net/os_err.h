/*   $OSSEC, os_err.h, v0.1, 2004/07/08, Daniel B. Cid$   */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* Basic err codes
 *
 */

#ifndef __OS_ERR /* Definition of the __OS_ERR */
#define __OS_ERR

#define OS_SUCESS  	 0      /* Sucess */
#define OS_INVALID	-1	/* Invalid entry */
#define OS_NOTFOUND	-2	/* Entry not found */
#define	OS_FILERR	-3	/* Error in the file */
#define OS_SIZELIM	-4	/* Size limit problem */
#define OS_CFGERR	-5	/* Configuration error */
#define OS_SOCKTERR	-6	/* Socket error */
#define OS_MISVALUE	-7	/* There are values missing */
#define OS_CONNERR	-8	/* Connection failed */
#define OS_UNDEF	-9	/* Uknown error */
#define OS_MEMERR	-10	/* Memory Error */

#define OS_ENDFILE	-20	/* End of file */
#define OS_FINISH	-21	/* Finished this task */

#endif /* __OS_ERR */
