/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Global definitions
 */

#ifndef __OS_HEADERS
#define __OS_HEADERS


/* Read / Write definitions
 */
#define READ 		1
#define	WRITE		2


/* Size limit control */
#define OS_SIZE_8192    8192
#define OS_SIZE_6144    6144
#define OS_SIZE_4096    4096
#define OS_SIZE_2048    2048
#define OS_SIZE_1024    1024
#define OS_SIZE_256     256
#define OS_SIZE_128     128

#define OS_MAXSTR       OS_SIZE_6144    /* Size for logs, sockets, etc */
#define OS_BUFFER_SIZE  OS_SIZE_2048    /* Size of general buffers */
#define OS_FLSIZE	    OS_SIZE_256     /* Maximum file size */
#define OS_HEADER_SIZE  OS_SIZE_128     /* Maximum header size */
#define OS_LOG_HEADER   OS_SIZE_256     /* Maximum log header size */
#define IPSIZE          16              /* IP Address size */


/* Some Global names */
#define __name      "OSSEC HIDS"
#define __version   "v0.9-2"
#define __author    "Daniel B. Cid"
#define __contact   "contact@ossec.net"
#define __site      "http://www.ossec.net"
#define __license   "\
This program is free software; you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License (version 2) as \n\
published by the Free Software Foundation.\n"

/* Maximum allowed PID */
#ifdef SOLARIS
    #define MAX_PID 29999
#else
    #define MAX_PID 32768
#endif

    
/* Max limit of 256 agents */
#define MAX_AGENTS  256


/* manager notification */
#define NOTIFY_TIME     600     /* every 10 minutes */

        
/* User Configuration */
#ifndef MAILUSER
    #define MAILUSER        "ossecm"
#endif

#ifndef USER
    #define USER            "ossec"
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


/* Default queue */
#define DEFAULTQUEUE	"/queue/ossec/queue"


/* Active response files */
#define DEFAULTAR       "/etc/shared/ar.conf"
#define AR_BINDIR       "/active-response/bin"


/* Exec queue */
#define EXECQUEUE	    "/queue/alerts/execq"


/* Active response queue */
#define ARQUEUE         "/queue/alerts/ar"


/* Decoder file */
#define XML_DECODER     "/etc/decoder.xml"

        
/* Agent information location */
#define AGENTINFO_DIR    "/queue/agent-info"


/* Wait file */
#ifndef WIN32
    #define WAIT_FILE       "/queue/.wait"
#else
    #define WAIT_FILE       ".wait"
#endif
    
        
/* Internal definitions files */
#ifndef WIN32
    #define OSSEC_DEFINES   "/etc/internal_options.conf"
#else
    #define OSSEC_DEFINES   "internal_options.conf"
#endif


/* Log directories */
#define EVENTS          "/logs/archives"
#define EVENTS_DAILY    "/logs/archives/archives.log"
#define ALERTS          "/logs/alerts"
#define ALERTS_DAILY    "/logs/alerts/alerts.log"
#define FWLOGS          "/logs/firewall"
#define FWLOGS_DAILY    "/logs/firewall/firewall.log"


/* Stats directories */
#define STATWQUEUE  "/stats/weekly-average"
#define STATQUEUE   "/stats/hourly-average"
#define STATSAVED   "/stats/totals"


/* Authentication keys file */
#ifndef WIN32
#define KEYS_FILE       "/etc/client.keys"
#else
#define KEYS_FILE       "client.keys"
#endif
#define AUTH_FILE       KEYS_FILE


/* Shared config directory */
#ifndef WIN32
    #define SHAREDCFG_DIR   "/etc/shared"
#else
    #define SHAREDCFG_DIR   "shared"       
#endif    

/* Built in defines */
#define DEFAULTQPATH	DEFAULTDIR DEFAULTQUEUE
#ifndef WIN32
#define DEFAULTCPATH    DEFAULTDIR "/etc/ossec.conf"
#else
#define DEFAULTCPATH "ossec.conf"
#endif
#define DEFAULTARPATH   DEFAULTDIR DEFAULTAR
#define AR_BINDIRPATH   DEFAULTDIR AR_BINDIR
#define EXECQUEUEPATH   DEFAULTDIR EXECQUEUE

#ifdef WIN32
    #define SHAREDCFG_DIRPATH   SHAREDCFG_DIR
#else
    #define SHAREDCFG_DIRPATH   DEFAULTDIR SHAREDCFG_DIR
#endif

#define WAIT_FILE_PATH  DEFAULTDIR WAIT_FILE


/* Default ports */
#ifndef DEFAULT_SECURE
	#define DEFAULT_SECURE 1514 /* Default encrypted */
#endif

#ifndef DEFAULT_SYSLOG
	#define DEFAULT_SYSLOG 514 /* Default syslog port - udp */
#endif



/* Xml global elements */
#ifndef xml_global
#define xml_global "global"
#endif

#ifndef xml_alerts
#define xml_alerts "alerts"
#endif

#ifndef xml_rules
#define xml_rules "rules"
#endif

#ifndef xml_localfile
#define xml_localfile "localfile"
#endif

#ifndef xml_remote
#define xml_remote "remote"
#endif

#ifndef xml_client
#define xml_client "client"
#endif

#ifndef xml_execd
#define xml_execd "execd"
#endif

#ifndef xml_syscheck
#define xml_syscheck "syscheck"
#endif

#ifndef xml_rootcheck
#define xml_rootcheck "rootcheck"
#endif

#ifndef xml_command
#define xml_command  "command"
#endif

#ifndef xml_ar
#define xml_ar      "active-response"
#endif

#endif /* __OS_HEADERS */
