/*   $OSSEC, defs.h, v0.1, 2004/07/22, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Global definitions
 */

#ifndef __OS_HEADERS /* Definition of the headers */
#define __OS_HEADERS


/* Basic SUCESS/ERROR definitions */
#define ERROR 		1	
#define SUCESS 		0	

/* Whenever whe need to speficy r/w permissions */
#define READ 		1
#define	WRITE		2

/* Size limit control */
#define OS_MAXSTR 	1024	/* Maximum size to be read */
#define OS_MAXMSG	512	    /* Maximum msg to be passed */
#define OS_RULESIZE	256	    /* Maximum size for a rule */	 	
#define OS_FLSIZE	256	    /* Maximum size whenever reading a file */		
#define OS_DEFSIZE	128	    /* Default size */
#define OS_KEYSIZE	32	    /* Maximum size for a key */

#define HIGHLEVEL       8	/* Maximum level for a rule */
#define LOWLEVEL        0	/* Lowest level for a rule */

/* Users Configuration */
#ifndef MAILUSER
    #define MAILUSER        "ossecm"
#endif

#ifndef USER
    #define USER            "ossec"
#endif
    
#ifndef EXECUSER
    #define EXECUSER        "ossece"
#endif
    
#ifndef REMUSER
    #define REMUSER         "ossecr"
#endif
    
#ifndef GROUPGLOBAL
    #define GROUPGLOBAL     "ossec"
#endif    
                    
#ifndef DEFAULTDIR		
	#define DEFAULTDIR	"/var/ossec"
#endif

/* queues configuration */
#ifndef DEFAULTQUEUE
	#define DEFAULTQUEUE	"/queue/ossec/queue"
#endif

/* Used by analysisd to get the decoders plugins.
 * Only read from CHROOT.
 * Should not be changed by the user.
 */
#ifndef XML_DECODER
    #define XML_DECODER     "/etc/decoder.xml"
#endif
        
#ifndef KEYS_FILE
	#define KEYS_FILE "/etc/client.keys"
#endif

#ifndef DEFAULTQPATH
	#define DEFAULTQPATH	"/var/ossec/queue/ossec/queue"
#endif

#ifndef DEFAULTCPATH
	#define DEFAULTCPATH	"/var/ossec/etc/ossec.conf"
#endif

#ifndef DEFAULT_SECURE
	#define DEFAULT_SECURE 1514 /* Default UDP port- secure */
#endif

#ifndef DEFAULT_SYSLOG
	#define DEFAULT_SYSLOG 514 /* Default syslog port - udp */
#endif


#endif /* __OS_HEADERS */
