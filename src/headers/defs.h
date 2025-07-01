/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Global Definitions */

#ifndef OS_HEADERS
#define OS_HEADERS

#define TRUE            1
#define FALSE           0

#define READ    1
#define WRITE   2

#define OS_BINARY  0
#define OS_TEXT    1

/* Size limit control */
#define OS_SIZE_1048576 1048576
#define OS_SIZE_65536   65536
#define OS_SIZE_61440   61440
#define OS_SIZE_32768   32768
#define OS_SIZE_20480   20480
#define OS_SIZE_8192    8192
#define OS_SIZE_6144    6144
#define OS_SIZE_4096    4096
#define OS_SIZE_2048    2048
#define OS_SIZE_1024    1024
#define OS_SIZE_512     512
#define OS_SIZE_256     256
#define OS_SIZE_128     128
#define OS_SIZE_64      64
#define OS_SIZE_32      32
#define OS_SIZE_16      16

/* Level of log messages */
#define LOGLEVEL_DEBUG_VERBOSE 5
#define LOGLEVEL_CRITICAL 4
#define LOGLEVEL_ERROR 3
#define LOGLEVEL_WARNING 2
#define LOGLEVEL_INFO 1
#define LOGLEVEL_DEBUG 0

#define OS_MAXSTR       OS_SIZE_65536               /* Size for logs, sockets, etc      */
#define OS_BUFFER_SIZE  OS_SIZE_2048                /* Size of general buffers          */
#define OS_FLSIZE       OS_SIZE_256                 /* Maximum file size                */
#define OS_HEADER_SIZE  OS_SIZE_128                 /* Maximum header size              */
#define OS_LOG_HEADER   OS_SIZE_256                 /* Maximum log header size          */
#define OS_SK_HEADER    OS_SIZE_6144                /* Maximum syscheck header size     */
#define IPSIZE          INET6_ADDRSTRLEN            /* IP Address size                  */
#define AUTH_POOL       1000                        /* Max number of connections        */
#define BACKLOG         128                         /* Socket input queue length        */
#define MAX_EVENTS      1024                        /* Max number of epoll events       */
#define EPOLL_MILLIS    -1                          /* Epoll wait time                  */
#define MAX_TAG_COUNTER 256                         /* Max retrying counter             */
#define SOCK_RECV_TIME0 300                         /* Socket receiving timeout (s)     */
#define MIN_ORDER_SIZE  32                          /* Minimum size of orders array     */
#define KEEPALIVE_SIZE  700                         /* Random keepalive string size     */
#define MAX_DYN_STR     4194304                     /* Max message size received 4MiB   */
#define DATE_LENGTH     64                          /* Format date time %D %T           */
#define OS_MAX_LOG_SIZE OS_MAXSTR - OS_LOG_HEADER   /* Maximum log size with a header protection */

/* Some global names */
#define __ossec_name    "Wazuh"
#define __ossec_version "v4.99.0"
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

/* First ID assigned by authd */
#ifndef AUTHD_FIRST_ID
#define AUTHD_FIRST_ID  1024
#endif

/* Notify the manager */
#define NOTIFY_TIME     10      // ... every 10 seconds
#define RECONNECT_TIME  60      // Time to reconnect

/* User Configuration */
#ifndef USER
#define USER            "wazuh"
#endif

#ifndef ROOTUSER
#define ROOTUSER        "root"
#endif

#ifndef GROUPGLOBAL
#define GROUPGLOBAL     "wazuh"
#endif

// Standard super user UID and GID
#define ROOT_UID (0)

#define ROOT_GID (0)

// Wazuh home environment variable
#define WAZUH_HOME_ENV  "WAZUH_HOME"

/* Default queue */
#define DEFAULTQUEUE    "queue/sockets/queue"

// Authd local socket
#define AUTH_LOCAL_SOCK "queue/sockets/auth"

// Key request socket
#define KEY_REQUEST_SOCK "queue/sockets/krequest"

// Local requests socket
#define COM_LOCAL_SOCK  "queue/sockets/com"
#define LC_LOCAL_SOCK  "queue/sockets/logcollector"
#define SYS_LOCAL_SOCK  "queue/sockets/syscheck"
#define WM_LOCAL_SOCK  "queue/sockets/wmodules"
#define REMOTE_LOCAL_SOCK  "queue/sockets/remote"
#define ANLSYS_LOCAL_SOCK  "queue/sockets/analysis"
#define MAIL_LOCAL_SOCK "queue/sockets/mail"
#define LESSD_LOCAL_SOCK "queue/sockets/agentless"
#define INTG_LOCAL_SOCK "queue/sockets/integrator"
#define CSYS_LOCAL_SOCK  "queue/sockets/csyslog"
#define MON_LOCAL_SOCK  "queue/sockets/monitor"
#define CLUSTER_SOCK "queue/cluster/c-internal.sock"
#define CONTROL_SOCK "queue/sockets/control"
#define LOGTEST_SOCK "queue/sockets/logtest"
#define AGENT_UPGRADE_SOCK "queue/sockets/upgrade"

// Tasks socket
#define TASK_QUEUE "queue/tasks/task"

// Attempts to check sockets availability
#define SOCK_ATTEMPTS   10

// Database socket
#define WDB_LOCAL_SOCK "queue/db/wdb"

#define WM_DOWNLOAD_SOCK "queue/sockets/download"

// Tasks socket
#define WM_UPGRADE_SOCK "queue/tasks/upgrade"

#define WM_TASK_MODULE_SOCK "queue/tasks/task"

/* Active Response files */
#define DEFAULTAR_FILE  "ar.conf"
#define AR_BINDIR       "active-response/bin"
#ifndef WIN32
#define DEFAULTAR       "etc/shared/" DEFAULTAR_FILE
#define AGENTCONFIG     "etc/shared/agent.conf"
#define DEF_CA_STORE    "etc/wpk_root.pem"
#else
#define DEFAULTAR       "shared/" DEFAULTAR_FILE
#define AGENTCONFIG     "shared/agent.conf"
#define DEF_CA_STORE    "wpk_root.pem"
#endif

/* Exec queue */
#define EXECQUEUE       "queue/alerts/execq"

/* Security configuration assessment module queue */
#define CFGAQUEUE       "queue/alerts/cfgaq"

/* Security configuration assessment remoted queue */
#define CFGARQUEUE       "queue/alerts/cfgarq"

/* Active Response queue */
#define ARQUEUE         "queue/alerts/ar"

/* Decoder file */
#define XML_LDECODER    "etc/decoders/local_decoder.xml"

/* Agent groups location */
#define GROUPS_DIR    "queue/agent-groups"

/* Default group name */
#define DEFAULT_GROUP "default"

/* Syscollector normalization configs */
#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#define SYSCOLLECTOR_NORM_CONFIG_DISK_PATH    ".\\norm_config.json"
#else
#define SYSCOLLECTOR_NORM_CONFIG_DISK_PATH    "./norm_config.json"
#endif // WIN32
#else
#define SYSCOLLECTOR_NORM_CONFIG_DISK_PATH "queue/syscollector/norm_config.json"
#endif // WAZUH_UNIT_TESTING

#if defined(__MACH__)
#define SYSCOLLECTOR_NORM_TYPE "macos"
#elif defined(WIN32)
#define SYSCOLLECTOR_NORM_TYPE "windows"
#else
#define SYSCOLLECTOR_NORM_TYPE "linux"
#endif // __MACH__


/* Syscollector db directory */
#ifndef WAZUH_UNIT_TESTING
#define SYSCOLLECTOR_DB_DISK_PATH "queue/syscollector/db/local.db"
#else
#ifndef WIN32
#define SYSCOLLECTOR_DB_DISK_PATH    "./local.db"
#else
#define SYSCOLLECTOR_DB_DISK_PATH    ".\\local.db"
#endif // WIN32
#endif // WAZUH_UNIT_TESTING

/* Wazuh Database */
#define WDB_DIR                "var/db"
#define WDB2_DIR               "queue/db"
#define WDB_GLOB_NAME          "global"
#define WDB_MITRE_NAME         "mitre"
#define WDB_PROF_NAME          ".template.db"
#define WDB_PROF_PATH          WDB2_DIR "/" WDB_PROF_NAME
#define WDB_TASK_DIR           "queue/tasks"
#define WDB_TASK_NAME          "tasks"
#define WDB_BACKUP_FOLDER      "backup/db"
#define WDB_GLOB_BACKUP_NAME   WDB_GLOB_NAME".db-backup"

/* Diff queue */
#define DIFF_DIR        "queue/diff"
#define DIFF_NEW_FILE   "new-entry"
#define DIFF_LAST_FILE  "last-entry"
#define DIFF_GZ_FILE    "last-entry.gz"
#define DIFF_TEST_HOST  "__test"

/* Syscheck data */
#define SYSCHECK        "syscheck"
#define SYSCHECK_REG    "syscheck-registry"

/* Rule path */
#define RULEPATH        "rules"

/* Wait file */
#ifndef WIN32
#define WAIT_FILE       "queue/sockets/.wait"
#else
#define WAIT_FILE       ".wait"
#endif

/* Agent information file */
#ifndef WIN32
#define AGENT_INFO_FILE "queue/sockets/.agent_info"
#else
#define AGENT_INFO_FILE ".agent_info"
#endif

/* Agentless directories */
#define AGENTLESSDIR        "agentless"
#define AGENTLESS_ENTRYDIR  "queue/agentless"

/* Integration directory. */
#define INTEGRATORDIR "integrations"


/* Internal definitions files */
#ifndef WIN32
#define OSSEC_DEFINES   "etc/internal_options.conf"
#define OSSEC_LDEFINES   "etc/local_internal_options.conf"
#else
#define OSSEC_DEFINES   "internal_options.conf"
#define OSSEC_LDEFINES   "local_internal_options.conf"
#endif

/* Log directories */
#define EVENTS            "logs/archives"
#define EVENTS_DAILY      "logs/archives/archives.log"
#define ALERTS            "logs/alerts"
#define ALERTS_DAILY      "logs/alerts/alerts.log"
#define ALERTSJSON_DAILY  "logs/alerts/alerts.json"
#define FWLOGS            "logs/firewall"
#define FWLOGS_DAILY      "logs/firewall/firewall.log"
#define EVENTSJSON_DAILY  "logs/archives/archives.json"

/* Stats directories */
#define STATWQUEUE  "stats/weekly-average"
#define STATQUEUE   "stats/hourly-average"
#define STATSAVED   "stats/totals"

/* Authentication keys file */
#ifndef WIN32
#define KEYS_FILE       "etc/client.keys"
#define AUTHD_PASS      "etc/authd.pass"
#else
#define KEYS_FILE       "client.keys"
#define AUTHD_PASS      "authd.pass"
#endif

/* Timestamp file */
#define TIMESTAMP_FILE  "queue/agents-timestamp"

/* Shared config directory */
#ifndef WIN32
#define SHAREDCFG_DIR   "etc/shared"
#else
#define SHAREDCFG_DIR   "shared"
#endif

/* Multi-groups directory */
#define MULTIGROUPS_DIR   "var/multigroups"
#define MAX_GROUP_NAME 255
#define MULTIGROUP_SEPARATOR ','
#define MAX_GROUPS_PER_MULTIGROUP 128

// Incoming directory
#ifndef WIN32
#define INCOMING_DIR   "var/incoming"
#else
#define INCOMING_DIR   "incoming"
#endif

// Upgrade directory
#ifndef WIN32
#define UPGRADE_DIR   "var/upgrade"
#else
#define UPGRADE_DIR   "upgrade"
#endif

// Download directory
#define DOWNLOAD_DIR  "var/download"

/* Built-in defines */

#ifndef WIN32
#define OSSECCONF       "etc/ossec.conf"
#else
#define OSSECCONF       "ossec.conf"
#endif

#define SHAREDCFG_FILE      SHAREDCFG_DIR "/merged.mg"
#define SHAREDCFG_FILENAME  "merged.mg"

#define MAX_QUEUED_EVENTS_PATH "/proc/sys/fs/inotify/max_queued_events"

#define TMP_DIR "tmp"

/* Windows COMSPEC */
#define COMSPEC "C:\\Windows\\System32\\cmd.exe"

/* Default ports */
#ifndef DEFAULT_SECURE
#define DEFAULT_SECURE 1514 /* Default encrypted */
#endif

#ifndef DEFAULT_SYSLOG
#define DEFAULT_SYSLOG 514 /* Default syslog port - udp */
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
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

#define SECURITY_CONFIGURATION_ASSESSMENT_DIR       "ruleset/sca"

#define SECURITY_CONFIGURATION_ASSESSMENT_DIR_WIN   "ruleset\\sca"

#ifdef WIN32
#define FTELL_TT "%lld"
#define FTELL_INT64 (int64_t)
#else
#define FTELL_TT "%ld"
#define FTELL_INT64 (long)
#endif

#endif /* OS_HEADERS */
