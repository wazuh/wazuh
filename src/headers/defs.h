/* @(#) $Id: ./src/headers/defs.h, 2012/08/11 dcid Exp $
 */

/* Copyright (C) 2009-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */



/* Global definitions
 */

#ifndef __OS_HEADERS
#define __OS_HEADERS


/* TRUE / FALSE definitions
 */
#define TRUE            1
#define FALSE           0

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
#define IPSIZE          INET6_ADDRSTRLEN    /* IP Address size */


/* Some Global names */
#define __name      "OSSEC HIDS"
#define __version   "v2.7.1"
#define __author    "Trend Micro Inc."
#define __contact   "contact@ossec.net"
#define __site      "http://www.ossec.net"
#define __license   "\
This program is free software; you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License (version 2) as \n\
published by the Free Software Foundation. For more details, go to \n\
http://www.ossec.net/main/license/\n"

/* Maximum allowed PID */
#ifdef SOLARIS
    #define MAX_PID 29999
#else
    #define MAX_PID 32768
#endif


/* Max limit of 256 agents */
#ifndef MAX_AGENTS
    #define MAX_AGENTS  256
#endif


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
#ifndef WIN32
    #define DEFAULTAR       "/etc/shared/ar.conf"
    #define AR_BINDIR       "/active-response/bin"
    #define AGENTCONFIGINT  "/etc/shared/agent.conf"
    #define AGENTCONFIG     DEFAULTDIR "/etc/shared/agent.conf"
#else
    #define DEFAULTAR           "shared/ar.conf"
    #define AR_BINDIR           "active-response/bin"
    #define AGENTCONFIG         "shared/agent.conf"
    #define AGENTCONFIGINT      "shared/agent.conf"
#endif


/* Exec queue */
#define EXECQUEUE	    "/queue/alerts/execq"


/* Active response queue */
#define ARQUEUE         "/queue/alerts/ar"


/* Decoder file */
#define XML_DECODER     "/etc/decoder.xml"
#define XML_LDECODER    "/etc/local_decoder.xml"


/* Agent information location */
#define AGENTINFO_DIR    "/queue/agent-info"


/* Syscheck directory */
#define SYSCHECK_DIR    "/queue/syscheck"

/* Rootcheck directory */
#define ROOTCHECK_DIR    "/queue/rootcheck"

/* Diff queue */
#define DIFF_DIR        "/queue/diff"
#define DIFF_DIR_PATH   DEFAULTDIR DIFF_DIR
#define DIFF_NEW_FILE  "new-entry"
#define DIFF_LAST_FILE "last-entry"


/* Syscheck data */
#define SYSCHECK        "syscheck"
#define SYSCHECK_REG    "syscheck-registry"


/* Rule path */
#define RULEPATH        "/rules"


/* Wait file */
#ifndef WIN32
    #define WAIT_FILE       "/queue/ossec/.wait"
#else
    #define WAIT_FILE       ".wait"
#endif


/* Agent information file */
#ifndef WIN32
    #define AGENT_INFO_FILE "/queue/ossec/.agent_info"
    #define AGENT_INFO_FILEP DEFAULTDIR AGENT_INFO_FILE
#else
    #define AGENT_INFO_FILE ".agent_info"
    #define AGENT_INFO_FILEP AGENT_INFO_FILE
#endif


/* Syscheck restart */
#ifndef WIN32
    #define SYSCHECK_RESTART        "/var/run/.syscheck_run"
    #define SYSCHECK_RESTART_PATH   DEFAULTDIR SYSCHECK_RESTART
#else
    #define SYSCHECK_RESTART        "syscheck/.syscheck_run"
    #define SYSCHECK_RESTART_PATH   "syscheck/.syscheck_run"
#endif


/* Agentless directories. */
#define AGENTLESSDIR    "/agentless"
#define AGENTLESSPASS   "/agentless/.passlist"
#define AGENTLESS_ENTRYDIR  "/queue/agentless"


/* Internal definitions files */
#ifndef WIN32
    #define OSSEC_DEFINES   "/etc/internal_options.conf"
    #define OSSEC_LDEFINES   "/etc/local_internal_options.conf"
#else
    #define OSSEC_DEFINES   "internal_options.conf"
    #define OSSEC_LDEFINES   "local_internal_options.conf"
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
#define KEYSFILE_PATH   DEFAULTDIR KEYS_FILE
#else
#define KEYS_FILE       "client.keys"
#define KEYSFILE_PATH   KEYS_FILE
#endif

#ifndef AUTH_FILE
#define AUTH_FILE       KEYS_FILE
#endif


/* Shared config directory */
#ifndef WIN32
    #define SHAREDCFG_DIR   "/etc/shared"
#else
    #define SHAREDCFG_DIR   "shared"
#endif

/* Built in defines */
#define DEFAULTQPATH	DEFAULTDIR DEFAULTQUEUE

#ifndef WIN32
#define OSSECCONF       "/etc/ossec.conf"
#define DEFAULTCPATH    DEFAULTDIR OSSECCONF
#else
#define OSSECCONF       "ossec.conf"
#define DEFAULTCPATH "ossec.conf"
#endif

#ifndef WIN32
    #define DEFAULTARPATH   DEFAULTDIR DEFAULTAR
    #define AR_BINDIRPATH   DEFAULTDIR AR_BINDIR
    #define AGENTLESSDIRPATH    DEFAULTDIR AGENTLESSDIR
    #define AGENTLESSPASSPATH   DEFAULTDIR AGENTLESSPASS
    #define AGENTLESS_ENTRYDIRPATH  DEFAULTDIR AGENTLESS_ENTRYDIR
#else
    #define DEFAULTARPATH   "shared/ar.conf"
    #define AR_BINDIRPATH   "active-response/bin"
    #define AGENTLESSDIRPATH    AGENTLESSDIR
    #define AGENTLESSPASSPATH   AGENTLESSPASS
    #define AGENTLESS_ENTRYDIRPATH  AGENTLESS_ENTRYDIR
#endif
#define EXECQUEUEPATH   DEFAULTDIR EXECQUEUE

#ifdef WIN32
    #define SHAREDCFG_DIRPATH   SHAREDCFG_DIR
#else
    #define SHAREDCFG_DIRPATH   DEFAULTDIR SHAREDCFG_DIR
#endif

#define SHAREDCFG_FILE      SHAREDCFG_DIR "/merged.mg"
#define SHAREDCFG_FILEPATH  SHAREDCFG_DIRPATH "/merged.mg"
#define SHAREDCFG_FILENAME  "merged.mg"


#define WAIT_FILE_PATH  DEFAULTDIR WAIT_FILE


/* Default ports */
#ifndef DEFAULT_SECURE
	#define DEFAULT_SECURE "1514" /* Default encrypted */
#endif

#ifndef DEFAULT_SYSLOG
	#define DEFAULT_SYSLOG "514" /* Default syslog port - udp */
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
