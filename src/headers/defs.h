/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Global Definitions */

#ifndef __OS_HEADERS
#define __OS_HEADERS

#define TRUE            1
#define FALSE           0

#define READ    1
#define WRITE   2

#define OS_BINARY  0
#define OS_TEXT    1

/* Size limit control */
#define OS_SIZE_65536   65536
#define OS_SIZE_61440   61440
#define OS_SIZE_20480   20480
#define OS_SIZE_8192    8192
#define OS_SIZE_6144    6144
#define OS_SIZE_4096    4096
#define OS_SIZE_2048    2048
#define OS_SIZE_1024    1024
#define OS_SIZE_256     256
#define OS_SIZE_128     128

/* Level of log messages */
#define LOGLEVEL_CRITICAL 4
#define LOGLEVEL_ERROR 3
#define LOGLEVEL_WARNING 2
#define LOGLEVEL_INFO 1
#define LOGLEVEL_DEBUG 0

#define OS_MAXSTR       OS_SIZE_65536    /* Size for logs, sockets, etc  */
#define OS_BUFFER_SIZE  OS_SIZE_2048    /* Size of general buffers      */
#define OS_FLSIZE       OS_SIZE_256     /* Maximum file size            */
#define OS_HEADER_SIZE  OS_SIZE_128     /* Maximum header size          */
#define OS_LOG_HEADER   OS_SIZE_256     /* Maximum log header size      */
#define OS_SK_HEADER    OS_SIZE_6144    /* Maximum syscheck header size */
#define IPSIZE          16              /* IP Address size              */
#define AUTH_POOL       1000            /* Max number of connections    */
#define BACKLOG         128             /* Socket input queue length    */
#define MAX_EVENTS      1024            /* Max number of epoll events   */
#define EPOLL_MILLIS    -1              /* Epoll wait time              */
#define MAX_TAG_COUNTER 256             /* Max retrying counter         */
#define SOCK_RECV_TIME0 300             /* Socket receiving timeout (s) */
#define MIN_ORDER_SIZE  10              /* Minimum size of orders array */
#define KEEPALIVE_SIZE  700             /* Random keepalive string size */
#define MAX_DYN_STR     4194304         /* Max message size received 4MiB */

/* Some global names */
#define __ossec_name    "Wazuh"
#define __ossec_version "v3.8.0"
#define __author        "Wazuh Inc."
#define __contact       "info@wazuh.com"
#define __site          "http://www.wazuh.com"
#define __license       "\
This program is free software; you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License (version 2) as \n\
published by the Free Software Foundation. For more details, go to \n\
https://www.gnu.org/licenses/gpl.html\n"

/* Maximum allowed PID */
#ifdef SOLARIS
#define MAX_PID 29999
#else
#define MAX_PID 32768
#endif

/* Limit of 256 agents */
#ifndef MAX_AGENTS
#define MAX_AGENTS  256
#endif

/* First ID assigned by authd */
#ifndef AUTHD_FIRST_ID
#define AUTHD_FIRST_ID  1024
#endif

/* Notify the manager */
#define NOTIFY_TIME     10      // ... every 10 seconds
#define RECONNECT_TIME  60      // Time to reconnect
#define DISCON_TIME     1800    // Take agent as disconnected

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

#ifndef ROOTUSER
#define ROOTUSER        "root"
#endif

#ifndef GROUPGLOBAL
#define GROUPGLOBAL     "ossec"
#endif

#ifndef DEFAULTDIR
#define DEFAULTDIR      "/var/ossec"
#endif

/* Default queue */
#define DEFAULTQUEUE    "/queue/ossec/queue"

// Authd local socket
#define AUTH_LOCAL_SOCK "/queue/ossec/auth"
#define AUTH_LOCAL_SOCK_PATH DEFAULTDIR AUTH_LOCAL_SOCK

// Remote requests socket
#define REMOTE_REQ_SOCK "/queue/ossec/request"

// Local requests socket
#define COM_LOCAL_SOCK  "/queue/ossec/com"
#define LC_LOCAL_SOCK  "/queue/ossec/logcollector"
#define SYS_LOCAL_SOCK  "/queue/ossec/syscheck"
#define WM_LOCAL_SOCK  "/queue/ossec/wmodules"
#define ANLSYS_LOCAL_SOCK  "/queue/ossec/analysis"
#define MAIL_LOCAL_SOCK "/queue/ossec/mail"
#define LESSD_LOCAL_SOCK "/queue/ossec/agentless"
#define INTG_LOCAL_SOCK "/queue/ossec/integrator"
#define CSYS_LOCAL_SOCK  "/queue/ossec/csyslog"
#define MON_LOCAL_SOCK  "/queue/ossec/monitor"
#define CLUSTER_SOCK "/queue/cluster/c-internal.sock"

// Database socket
#define WDB_LOCAL_SOCK "/queue/db/wdb"
#ifndef WIN32
#define WDB_LOCAL_SOCK_PATH DEFAULTDIR WDB_LOCAL_SOCK
#endif

#define WM_DOWNLOAD_SOCK "/queue/ossec/download"
#define WM_DOWNLOAD_SOCK_PATH DEFAULTDIR WM_DOWNLOAD_SOCK

#define WM_KEY_REQUEST_SOCK "/queue/ossec/krequest"
#define WM_KEY_REQUEST_SOCK_PATH DEFAULTDIR WM_KEY_REQUEST_SOCK

/* Active Response files */
#define DEFAULTAR_FILE  "ar.conf"

#ifndef WIN32
#define DEFAULTAR       "/etc/shared/" DEFAULTAR_FILE
#define AR_BINDIR       "/active-response/bin"
#define AGENTCONFIGINT  "/etc/shared/agent.conf"
#define AGENTCONFIG     DEFAULTDIR "/etc/shared/agent.conf"
#define DEF_CA_STORE    DEFAULTDIR "/etc/wpk_root.pem"
#else
#define DEFAULTAR       "shared/" DEFAULTAR_FILE
#define AR_BINDIR       "active-response/bin"
#define AGENTCONFIG     "shared/agent.conf"
#define AGENTCONFIGINT  "shared/agent.conf"
#define DEF_CA_STORE    "wpk_root.pem"
#endif

/* Exec queue */
#define EXECQUEUE       "/queue/alerts/execq"

/* Active Response queue */
#define ARQUEUE         "/queue/alerts/ar"

/* Decoder file */
#define XML_LDECODER    "/etc/decoders/local_decoder.xml"

/* Agent information location */
#define AGENTINFO_DIR    "/queue/agent-info"
#define AGENTINFO_DIR_PATH DEFAULTDIR "/queue/agent-info"

/* Agent groups location */
#define GROUPS_DIR    "/queue/agent-groups"

/* Default group name */
#define DEFAULT_GROUP "default"

/* Syscheck directory */
#define SYSCHECK_DIR    "/queue/syscheck"

/* Rootcheck directory */
#define ROOTCHECK_DIR    "/queue/rootcheck"

/* Backup directory for agents */
#define AGNBACKUP_DIR    "/backup/agents"

/* Wazuh Database */
#define WDB_DIR         "var/db"
#define WDB2_DIR        "queue/db"
#define WDB_GLOB_NAME   "global.db"
#define WDB_PROF_NAME   ".template.db"

/* Diff queue */
#ifndef WIN32
#define DIFF_DIR        "/queue/diff"
#define DIFF_DIR_PATH   DEFAULTDIR DIFF_DIR
#else
#define DIFF_DIR_PATH "queue/diff"
#endif
#define DIFF_NEW_FILE  "new-entry"
#define DIFF_LAST_FILE "last-entry"
#define DIFF_GZ_FILE "last-entry.gz"
#define DIFF_TEST_HOST "__test"

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
#define AGENT_INFO_FILEF DEFAULTDIR AGENTINFO_DIR "/%s-%s"
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

/* Agentless directories */
#define AGENTLESSDIR        "/agentless"
#define AGENTLESSPASS       "/agentless/.passlist"
#define AGENTLESS_ENTRYDIR  "/queue/agentless"

/* Integration directory. */
#define INTEGRATORDIR "/integrations"
#define INTEGRATORDIRPATH    DEFAULTDIR INTEGRATORDIR


/* Internal definitions files */
#ifndef WIN32
#define OSSEC_DEFINES   "/etc/internal_options.conf"
#define OSSEC_LDEFINES   "/etc/local_internal_options.conf"
#else
#define OSSEC_DEFINES   "internal_options.conf"
#define OSSEC_LDEFINES   "local_internal_options.conf"
#endif

/* Log directories */
#define EVENTS            "/logs/archives"
#define EVENTS_DAILY      "/logs/archives/archives.log"
#define ALERTS            "/logs/alerts"
#define ALERTS_PATH       DEFAULTDIR ALERTS
#define ALERTS_DAILY      "/logs/alerts/alerts.log"
#define ALERTSJSON_DAILY  "/logs/alerts/alerts.json"
#define FWLOGS            "/logs/firewall"
#define FWLOGS_DAILY      "/logs/firewall/firewall.log"
#define EVENTSJSON_DAILY  "/logs/archives/archives.json"

/* Stats directories */
#define STATWQUEUE  "/stats/weekly-average"
#define STATQUEUE   "/stats/hourly-average"
#define STATSAVED   "/stats/totals"

/* Authentication keys file */
#ifndef WIN32
#define KEYS_FILE       "/etc/client.keys"
#define AUTHD_PASS      "/etc/authd.pass"
#define KEYSFILE_PATH   DEFAULTDIR KEYS_FILE
#define AUTHDPASS_PATH  DEFAULTDIR AUTHD_PASS
#else
#define KEYS_FILE       "client.keys"
#define KEYSFILE_PATH   KEYS_FILE
#define AUTHD_PASS      "authd.pass"
#define AUTHDPASS_PATH  AUTHD_PASS
#endif

#ifndef AUTH_FILE
#define AUTH_FILE       KEYS_FILE
#endif

/* Timestamp file */
#define TIMESTAMP_FILE  "/queue/agents-timestamp"

/* Shared config directory */
#ifndef WIN32
#define SHAREDCFG_DIR   "/etc/shared"
#else
#define SHAREDCFG_DIR   "shared"
#endif

/* Multi-groups directory */
#define MULTIGROUPS_DIR   "/var/multigroups"
#define MAX_GROUP_NAME 255
#define MULTIGROUP_SEPARATOR ','
#define MAX_GROUPS_PER_MULTIGROUP 256

// Incoming directory
#ifndef WIN32
#define INCOMING_DIR   "/var/incoming"
#else
#define INCOMING_DIR   "incoming"
#endif

// Upgrade directory
#ifndef WIN32
#define UPGRADE_DIR   "/var/upgrade"
#else
#define UPGRADE_DIR   "upgrade"
#endif

// Download directory
#define DOWNLOAD_DIR  "/var/download"

/* Built-in defines */
#define DEFAULTQPATH    DEFAULTDIR DEFAULTQUEUE

#ifndef WIN32
#define OSSECCONF       "/etc/ossec.conf"
#define DEFAULTCPATH    DEFAULTDIR OSSECCONF
#else
#define OSSECCONF       "ossec.conf"
#define DEFAULTCPATH    "ossec.conf"
#endif

#ifndef WIN32
#define DEFAULTARPATH           DEFAULTDIR DEFAULTAR
#define AR_BINDIRPATH           DEFAULTDIR AR_BINDIR
#define AGENTLESSDIRPATH        DEFAULTDIR AGENTLESSDIR
#define AGENTLESSPASSPATH       DEFAULTDIR AGENTLESSPASS
#define AGENTLESS_ENTRYDIRPATH  DEFAULTDIR AGENTLESS_ENTRYDIR
#else
#define DEFAULTARPATH           "shared/ar.conf"
#define AR_BINDIRPATH           "active-response/bin"
#define AGENTLESSDIRPATH        AGENTLESSDIR
#define AGENTLESSPASSPATH       AGENTLESSPASS
#define AGENTLESS_ENTRYDIRPATH  AGENTLESS_ENTRYDIR
#endif
#define EXECQUEUEPATH           DEFAULTDIR EXECQUEUE

#ifdef WIN32
#define SHAREDCFG_DIRPATH   SHAREDCFG_DIR
#else
#define SHAREDCFG_DIRPATH   DEFAULTDIR SHAREDCFG_DIR
#endif

#define SHAREDCFG_FILE      SHAREDCFG_DIR "/merged.mg"
#define SHAREDCFG_FILEPATH  SHAREDCFG_DIRPATH "/merged.mg"
#define SHAREDCFG_FILENAME  "merged.mg"

#define WAIT_FILE_PATH  DEFAULTDIR WAIT_FILE

#define MAX_QUEUED_EVENTS_PATH "/proc/sys/fs/inotify/max_queued_events"

#define TMP_DIR "tmp"
#define TMP_PATH DEFAULTDIR "/" TMP_DIR

/* Windows COMSPEC */
#define COMSPEC "C:\\Windows\\System32\\cmd.exe"

/* Default ports */
#ifndef DEFAULT_SECURE
#define DEFAULT_SECURE 1514 /* Default encrypted */
#endif

#ifndef DEFAULT_SYSLOG
#define DEFAULT_SYSLOG 514 /* Default syslog port - udp */
#endif

/* XML global elements */
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

#define CLOCK_LENGTH 256

#endif /* __OS_HEADERS */
