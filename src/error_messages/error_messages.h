/* @(#) $Id: ./src/error_messages/error_messages.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of OSSEC HIDS ( http://www.ossec.net )
 * Error/debug messages
 */


#ifndef _ERROR_MESSAGES__H

#define _ERROR_MESSAGES__H


	/***  Error messages - English ***/


/* SYSTEM ERRORS */
#define FORK_ERROR	  "%s(1101): ERROR: Unable to fork. Exiting."
#define MEM_ERROR	  "%s(1102): ERROR: Not enough Memory. Exiting."
#define FOPEN_ERROR   "%s(1103): ERROR: Unable to open file '%s'."
#define SIZE_ERROR    "%s(1104): ERROR: Maximum string size reached for: %s."
#define NULL_ERROR    "%s(1105): ERROR: Attempted to use null string. "
#define FORMAT_ERROR  "%s(1106): ERROR: String not correctly formatted."
#define MKDIR_ERROR   "%s(1107): ERROR: Unable to create directory: '%s'"
#define PERM_ERROR    "%s(1108): ERROR: Permission error. Operation not completed."
#define THREAD_ERROR  "%s(1109): ERROR: Unable to create new pthread."
#define READ_ERROR    "%s(1110): ERROR: Unable to read from socket."
#define WAITPID_ERROR "%s(1111): ERROR: Unable to Waitpid()."
#define SETSID_ERROR  "%s(1112): ERROR: Unable to Setsid()."
#define MUTEX_ERROR   "%s(1113): ERROR: Unable to set pthread mutex."
#define SELECT_ERROR  "%s(1114): ERROR: Unable to select()."
#define FREAD_ERROR   "%s(1115): ERROR: Error reading file '%s'."
#define FSEEK_ERROR   "%s(1116): ERROR: Error handling file '%s' (fseek)."
#define FILE_ERROR    "%s(1117): ERROR: Error handling file '%s' (date)."
#define SYSTEM_ERROR  "%s(1118): ERROR: Internal error. Exiting.."
#define FGETS_ERROR   "%s(1119): ERROR: Invalid line on file '%s': %s."
#define PIPE_ERROR    "%s(1120): ERROR: Pipe error."
#define GLOB_ERROR    "%s(1121): ERROR: Glob error. Invalid pattern: '%s'."
#define GLOB_NFOUND   "%s(1122): ERROR: No file found by pattern: '%s'."
#define UNLINK_ERROR  "%s(1123): ERROR: Unable to delete file: '%s'."
#define RENAME_ERROR  "%s(1124): ERROR: Unable to rename file: '%s'."
#define INT_ERROR     "%s(1125): ERROR: Internal error (undefined)."
#define OPEN_ERROR    "%s(1126): ERROR: Unable to open file '%s' reason '%s'"


/* COMMON ERRORS */
#define CONN_ERROR 	    "%s(1201): ERROR: No remote connection configured."
#define CONFIG_ERROR	"%s(1202): ERROR: Configuration error at '%s'. Exiting."
#define USER_ERROR	    "%s(1203): ERROR: Invalid user '%s' or group '%s' given."
#define CONNTYPE_ERROR 	"%s(1204): ERROR: Invalid connection type: '%s'."
#define PORT_ERROR	    "%s(1205): INFO: No port specified. Using default: '%d'."
#define BIND_ERROR	    "%s(1206): ERROR: Unable to Bind port '%s'"
#define SETGID_ERROR	"%s(1207): ERROR: Unable to switch to group: '%s'."
#define SETUID_ERROR	"%s(1208): ERROR: Unable to switch to user: '%s'."
#define CHROOT_ERROR	"%s(1209): ERROR: Unable to chroot to directory: '%s'."
#define QUEUE_ERROR	    "%s(1210): ERROR: Queue '%s' not accessible: '%s'."
#define QUEUE_FATAL	    "%s(1211): ERROR: Unable to access queue: '%s'. Giving up.."
#define PID_ERROR	    "%s(1212): ERROR: Unable to create PID file."
#define DENYIP_WARN 	"%s(1213): WARN: Message from %s not allowed."
#define MSG_ERROR	    "%s(1214): WARN: Problem receiving message from %s."
#define CLIENT_ERROR	"%s(1215): ERROR: No client configured. Exiting."
#define CONNS_ERROR	    "%s(1216): ERROR: Unable to connect to '%s'."
#define UNABLE_CONN     "%s(1242): ERROR: Unable to connect to server. Exausted all options."
#define SEC_ERROR	    "%s(1217): ERROR: Error creating encrypted message."
#define SEND_ERROR	    "%s(1218): ERROR: Unable to send message to %s."
#define RULESLOAD_ERROR	"%s(1219): ERROR: Unable to access the rules directory."
#define RULES_ERROR	    "%s(1220): ERROR: Error loading the rules: '%s'."
#define LISTS_ERROR     "%s(1221): ERROR: Error loading the list: '%s'."
#define QUEUE_SEND      "%s(1224): ERROR: Error sending message to queue."
#define SIGNAL_RECV     "%s(1225): INFO: SIGNAL Received. Exit Cleaning..."
#define XML_ERROR       "%s(1226): ERROR: Error reading XML file '%s': %s (line %d)."
#define XML_ERROR_VAR   "%s(1227): ERROR: Error applying XML variables '%s': %s."
#define XML_NO_ELEM     "%s(1228): ERROR: Element '%s' without any option."
#define XML_INVALID     "%s(1229): ERROR: Invalid element '%s' on the '%s' config."
#define XML_INVELEM     "%s(1230): ERROR: Invalid element in the configuration: '%s'."
#define XML_INVATTR     "%s(1243): ERROR: Invalid attribute '%s' in the configuration: '%s'."
#define XML_ELEMNULL    "%s(1231): ERROR: Invalid NULL element in the configuration."
#define XML_READ_ERROR  "%s(1232): ERROR: Error reading XML. Unknown cause."
#define XML_VALUENULL   "%s(1234): ERROR: Invalid NULL content for element: %s."
#define XML_VALUEERR    "%s(1235): ERROR: Invalid value for element '%s': %s."
#define XML_MAXREACHED  "%s(1236): ERROR: Maximum number of elements reached for: %s."
#define INVALID_IP      "%s(1237): ERROR: Invalid ip address: '%s'."
#define INVALID_ELEMENT "%s(1238): ERROR: Invalid value for element '%s': %s"
#define NO_CONFIG       "%s(1239): ERROR: Configuration file not found: '%s'."
#define INVALID_TIME    "%s(1240): ERROR: Invalid time format: '%s'."
#define INVALID_DAY     "%s(1241): ERROR: Invalid day format: '%s'."

#define MAILQ_ERROR	    "%s(1221): ERROR: No Mail queue at %s"
#define IMSG_ERROR	    "%s(1222): ERROR: Invalid msg: %s"
#define SNDMAIL_ERROR	"%s(1223): ERROR: Error Sending email to %s (smtp server)"
#define XML_INV_GRAN_MAIL "%s(1224): ERROR: Invalid 'email_alerts' config (missing parameters)."
#define CHLDWAIT_ERROR  "%s(1261): ERROR: Waiting for child process. (status: %d)."
#define TOOMANY_WAIT_ERROR "%s(1262): ERROR: Too many errors waiting for child process(es)."


/* rootcheck */
#define MAX_RK_MSG        "%s(1250): ERROR: Maximum number of global files reached: %d"
#define INVALID_RKCL_NAME  "%s(1251): ERROR: Invalid rk configuration name: '%s'."
#define INVALID_RKCL_VALUE "%s(1252): ERROR: Invalid rk configuration value: '%s'."
#define INVALID_ROOTDIR    "%s(1253): ERROR: Invalid rootdir (unable to retrieve)."
#define INVALID_RKCL_VAR   "%s(1254): ERROR: Invalid rk variable: '%s'."


/* syscheck */
#define SYSCHECK_NO_OPT "%s(1701): WARN: No option provided for directories: '%s', ignoring it."
#define SK_NO_DIR       "%s(1702): INFO: No directory provided for syscheck to monitor."
#define SK_INV_ATTR     "%s(1703): ERROR: Invalid attribute '%s' for directory option."
#define SK_INV_OPT      "%s(1704): ERROR: Invalid option '%s' for attribute '%s'"
#define SK_NO_DB        "%s(1705): ERROR: No integrity database found at '%s'."
#define SK_INV_MSG      "%s(1755): ERROR: Invalid syscheck message received."
#define SK_DUP          "%s(1756): ERROR: Duplicated directory given: '%s'."
#define SK_INV_REG      "%s(1757): ERROR: Invalid syscheck registry entry: '%s'."
#define SK_REG_OPEN     "%s(1758): ERROR: Unable to open registry key: '%s'."


/* Analysisd */
#define FTS_LIST_ERROR   "%s(1260): ERROR: Error initiating FTS list"
#define CRAFTED_IP       "%s(1271): WARN: Invalid IP Address '%s'. Possible logging attack."
#define CRAFTED_USER     "%s(1272): WARN: Invalid username '%s'. Possible logging attack."
#define INVALID_CAT      "%s(1273): ERROR: Invalid category '%s' chosen."
#define INVALID_CONFIG   "%s(1274): ERROR: Invalid configuration. Element '%s': %s."
#define INVALID_HOSTNAME "%s(1275): ERROR: Invalid hostname in syslog message: '%s'."
#ifdef GEOIP
#define INVALID_GEOIP_DB "%s(1276): ERROR: Cannot open GeoIP database: '%s'."
#endif


/* Log collector */


/* Remoted */
#define NO_REM_CONN     "%s(1750): ERROR: No remote connection configured. Exiting."


/* 1760 - 1769 -- reserver for maild */


/* Active response */
#define AR_CMD_MISS     "%s(1280): ERROR: Missing command options. " \
                        "You must specify a 'name', 'executable' and 'expect'."
#define AR_MISS         "%s(1281): ERROR: Missing options in the active response " \
                        "configuration. "
#define ARQ_ERROR       "%s(1301): ERROR: Unable to connect to active response queue."
#define AR_INV_LOC      "%s(1302): ERROR: Invalid active response location: '%s'."
#define AR_INV_CMD      "%s(1303): ERROR: Invalid command '%s' in the active response."
#define AR_DEF_AGENT    "%s(1304): ERROR: No agent defined for response."
#define AR_NO_TIMEOUT   "%s(1305): ERROR: Timeout not allowed for command: '%s'."


#define EXECD_INV_MSG   "%s(1310): WARN: Invalid active response (execd) message '%s'."
#define EXEC_INV_NAME   "%s(1311): ERROR: Invalid command name '%s' provided."
#define EXEC_CMDERROR   "%s(1312): ERROR: Error executing '%s': %s"
#define EXEC_INV_CONF   "%s(1313): ERROR: Invalid active response config: '%s'."
#define EXEC_DISABLED   "%s(1350): INFO: Active response disabled. Exiting."
#define EXEC_SHUTDOWN   "%s(1314): INFO: Shutdown received. Deleting responses."

#define AR_NOAGENT_ERROR    "%s(1320): ERROR: Agent '%s' not found."


/* List operations */
#define LIST_ERROR      "%s(1290): ERROR: Unable to create a new list (calloc)."
#define LIST_ADD_ERROR  "%s(1291): ERROR: Error adding nodes to list."
#define LIST_SIZE_ERROR "%s(1292): ERROR: Error setting error size."
#define LIST_FREE_ERROR "%s(1293): ERROR: Error setting data free pointer."


/* Log collector messages */
#define MISS_LOG_FORMAT "%s(1901): ERROR: Missing 'log_format' element."
#define MISS_FILE       "%s(1902): ERROR: Missing 'location' element."
#define INV_EVTLOG      "%s(1903): ERROR: Invalid event log: '%s'."
#define NSTD_EVTLOG     "%s(1907): INFO: Non-standard event log set: '%s'."
#define LOGC_FILE_ERROR "%s(1904): INFO: File not available, ignoring it: '%s'."
#define NO_FILE         "%s(1905): INFO: No file configured to monitor."
#define PARSE_ERROR     "%s(1906): ERROR: Error parsing file: '%s'."
#define READING_FILE    "%s(1950): INFO: Analyzing file: '%s'."
#define READING_EVTLOG  "%s(1951): INFO: Analyzing event log: '%s'."
#define VAR_LOG_MON     "%s(1952): INFO: Monitoring variable log file: '%s'."
#define INV_MULTILOG    "%s(1953): ERROR: Invalid DJB multilog file: '%s'."


/* Encryption/ auth errors */
#define INVALID_KEY     "%s(1401): ERROR: Error reading authentication key: '%s'."
#define NO_AUTHFILE     "%s(1402): ERROR: Authentication key file '%s' not found."
#define ENCFORMAT_ERROR "%s(1403): ERROR: Incorrectly formatted message from '%s'."
#define ENCKEY_ERROR    "%s(1404): ERROR: Authentication error. Wrong key from '%s'."
#define ENCSIZE_ERROR   "%s(1405): ERROR: Message size not valid: '%s'."
#define ENCSUM_ERROR    "%s(1406): ERROR: Checksum mismatch on message from '%s'."
#define ENCTIME_ERROR   "%s(1407): ERROR: Duplicated counter for '%s'."
#define ENC_IP_ERROR    "%s(1408): ERROR: Invalid ID for the source ip: '%s'."
#define ENCFILE_CHANGED "%s(1409): INFO: Authentication file changed. Updating."
#define ENC_READ        "%s(1410): INFO: Reading authentication keys file."


/* Regex errors */
#define REGEX_COMPILE   "%s(1450): ERROR: Syntax error on regex: '%s': %d."
#define REGEX_SUBS      "%s(1451): ERROR: Missing sub_strings on regex: '%s'."


/* Mail errors */
#define INVALID_SMTP    "%s(1501): ERROR: Invalid SMTP Server: %s"
#define INVALID_MAIL    "%s(1502): ERROR: Invalid Email Address: %s"


/* Decoders */
#define PPLUGIN_INV     "%s(2101): ERROR: Parent decoder name invalid: '%s'."
#define PDUP_INV        "%s(2102): ERROR: Duplicated decoder with prematch: '%s'."
#define PDUPFTS_INV     "%s(2103): ERROR: Duplicated decoder with fts set: '%s'."
#define DUP_INV         "%s(2104): ERROR: Invalid duplicated decoder: '%s'."
#define DEC_PLUGIN_ERR  "%s(2105): ERROR: Error loading decoder options."
#define DECODER_ERROR   "%s(2106): ERROR: Error adding decoder plugin."
#define DEC_REGEX_ERROR "%s(2107): ERROR: Decoder configuration error: '%s'."
#define DECODE_NOPRE    "%s(2108): ERROR: No 'prematch' found in decoder: '%s'."
#define DUP_REGEX       "%s(2109): ERROR: Duplicated offsets for same regex: '%s'."
#define INV_DECOPTION   "%s(2110): ERROR: Invalid decoder argument for %s: '%s'."
#define DECODE_ADD      "%s(2111): ERROR: Additional data to plugin decoder: '%s'."

#define INV_OFFSET      "%s(2120): ERROR: Invalid offset value: '%s'"
#define INV_ATTR        "%s(2121): ERROR: Invalid decoder attribute: '%s'"


/* os_zlib */
#define COMPRESS_ERR    "%s(2201): ERROR: Error compressing string: '%s'."
#define UNCOMPRESS_ERR  "%s(2202): ERROR: Error uncompressing string."


/* read defines */
#define DEF_NOT_FOUND   "%s(2301): ERROR: Definition not found for: '%s.%s'."
#define INV_DEF         "%s(2302): ERROR: Invalid definition for %s.%s: '%s'."


/* Agent errors */
#define AG_WAIT_SERVER  "%s(4101): WARN: Waiting for server reply (not started). Tried: '%s'."
#define AG_CONNECTED    "%s(4102): INFO: Connected to the server (%s:%s)."
#define AG_USINGIP      "%s(4103): INFO: Server IP address already set. Trying that before the hostname."
#define AG_INV_HOST     "%s(4104): ERROR: Invalid hostname: '%s'."
#define AG_INV_IP       "%s(4105): ERROR: No valid server IP found."
#define EVTLOG_OPEN     "%s(4106): ERROR: Unable to open event log: '%s'."
#define EVTLOG_GETLAST  "%s(4107): ERROR: Unable to query last event log from: '%s'."
#define EVTLOG_DUP      "%s(4108): ERROR: Duplicated event log entry: '%s'."
#define AG_NOKEYS_EXIT "%s(4109): ERROR: Unable to start without auth keys. Exiting."
#define AG_MAX_ERROR    "%s(4110): ERROR: Maximum number of agents '%d' reached."
#define AG_AX_AGENTS     "%s(4111): INFO: Maximum number of agents allowed: '%d'."


/* Rules reading errors */
#define RL_INV_ROOT     "%s(5101): ERROR: Invalid root element: '%s'."
#define RL_INV_RULE     "%s(5102): ERROR: Invalid rule element: '%s'."
#define RL_INV_ENTRY    "%s(5103): ERROR: Invalid rule on '%s'. Missing id/level."
#define RL_EMPTY_ATTR   "%s(5104): ERROR: Rule attribute '%s' empty."
#define RL_INV_ATTR     "%s(5105): ERROR: Invalid rule attributes inside file: '%s'."
#define RL_NO_OPT       "%s(5106): ERROR: Rule '%d' without any options. "\
                        "It may lead to false positives. Exiting. "


/* Syslog output */
#define XML_INV_CSYSLOG "%s(5301): ERROR: Invalid client-syslog configuration."


/* Agentless */
#define XML_INV_AGENTLESS   "%s(7101): ERROR: Invalid agentless configuration."
#define XML_INV_MISSFREQ    "%s(7102): ERROR: Frequency not set for the periodic option."
#define XML_INV_MISSOPTS    "%s(7103): ERROR: Missing agentless options."


/* Database messages */
#define DBINIT_ERROR    "%s(5201): ERROR: Error initializing database handler."
#define DBCONN_ERROR    "%s(5202): ERROR: Error connecting to database '%s'(%s): ERROR: %s."
#define DBQUERY_ERROR   "%s(5203): ERROR: Error executing query '%s'. Error: '%s'."
#define DB_GENERROR     "%s(5204): ERROR: Database error. Unable to run query."
#define DB_MISS_CONFIG  "%s(5205): ERROR: Missing database configuration. "\
                        "It requires host, user, pass and database."
#define DB_CONFIGERR    "%s(5206): ERROR: Database configuration error."
#define DB_COMPILED     "%s(5207): ERROR: OSSEC not compiled with support for '%s'."
#define DB_MAINERROR    "%s(5208): ERROR: Multiple database errors. Exiting."
#define DB_CLOSING      "%s(5209): INFO: Closing connection to database."
#define DB_ATTEMPT      "%s(5210): INFO: Attempting to reconnect to database."



/* Verbose messages */
#define STARTUP_MSG	"%s: INFO: Started (pid: %d)."
#define PRIVSEP_MSG	"%s: INFO: Chrooted to directory: %s, using user: %s"
#define MSG_SOCKET_SIZE "%s: INFO: (unix_domain) Maximum send buffer set to: '%d'."

#define NO_SYSLOG       "%s(1501): ERROR: No IP or network allowed in the access list" \
                        " for syslog. No reason for running it. Exiting."
#define CONN_TO     "%s: INFO: Connected to '%s' (%s queue)"
#define MAIL_DIS    "%s: INFO: E-Mail notification disabled. Clean Exit."


/* Debug Messages */
#define STARTED_MSG "%s: DEBUG: Starting ..."
#define FOUND_USER  "%s: DEBUG: Found user/group ..."
#define ASINIT      "%s: DEBUG: Active response initialized ..."
#define READ_CONFIG "%s: DEBUG: Read configuration ..."


/* Wait operations */
#define WAITING_MSG     "%s: WARN: Process locked. Waiting for permission..."
#define WAITING_FREE    "%s: INFO: Lock free. Continuing..."
#define SERVER_UNAV     "%s: WARN: Server unavailable. Setting lock."
#define SERVER_UP       "%s: INFO: Server responded. Releasing lock."

/* Ossec alert messages */
#define OS_AD_STARTED   "ossec: Ossec started."
#define OS_AG_STARTED   "ossec: Agent started: '%s->%s'."
#define OS_AG_DISCON    "ossec: Agent disconnected: '%s'."


#endif /* _ERROR_MESSAGES__H */

