/*   $OSSEC, error_messages.h, v0.1, 2005/03/22, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of OSSEC HIDS (http://www.ossec.net/ossec/)
 * Error/debug messages
 */


#ifndef _ERROR_MESSAGES__H

#define _ERROR_MESSAGES__H


	/***  Error messages - English ***/

/* SYSTEM ERRORS */
#define FORK_ERROR	 "%s(1101): Impossible to fork. Exiting."
#define MEM_ERROR	 "%s(1102): Memory error. Exiting."
#define FOPEN_ERROR  "%s(1103): Impossible to open file %s."
#define SIZE_ERROR   "%s(1104): Maximum string size reached for: %s"
#define NULL_ERROR   "%s(1105): Null string used. Ignoring."
#define FORMAT_ERROR "%s(1106): String not correctly formated. Crafted?"  
#define MKDIR_ERROR  "%s(1107): Impossible to create directory: '%s'"
#define PERM_ERROR   "%s(1108): Permission error. Operation not completed."

/* COMMON ERRORS */
#define CONN_ERROR 	"%s(1201): No remote connection configured. Exiting."
#define CONFIG_ERROR	"%s(1202): Configuration problem. Exiting."
#define USER_ERROR	"%s(1203): Invalid user \"%s\" or group \"%s\" given"
#define CONNTYPE_ERROR 	"%s(1204): Invalid connection type: %s"
#define PORT_ERROR	"%s(1205): No port specified. Using default: %d"
#define BIND_ERROR	"%s(1206): Impossible to Bind port %d"
#define SETGID_ERROR	"%s(1207): Impossible to switch to group: %s"	
#define SETUID_ERROR	"%s(1208): Impossible to switch to user: %s"
#define CHROOT_ERROR	"%s(1209): Impossible to chroot to directory: %s"
#define QUEUE_ERROR	"%s(1210): Queue \"%s\" not accessible"
#define QUEUE_FATAL	"%s(1211): Impossible to access queue: %s. Giving up.."
#define PID_ERROR	"%s(1212): Impossible to create PID file"
#define DENYIP_ERROR	"%s(1213): Message from %s not allowed"
#define MSG_ERROR	"%s(1214): Problem receiving message from %s"
#define CLIENT_ERROR	"%s(1215): No client configured. Exiting."
#define CONNS_ERROR	"%s(1216): Connection error to %s"
#define SEC_ERROR	"%s(1217): Error creating encrypted message"
#define SEND_ERROR	"%s(1218): Impossible to send message to server"
#define RULESLOAD_ERROR	"%s(1219): Impossible to access the rules directory"
#define RULES_ERROR	"%s(1220): Error loading the rules"

#define MAILQ_ERROR	"%s(1221): No Mail queue at %s"
#define IMSG_ERROR	"%s(1222): Invalid msg: %s"
#define SNDMAIL_ERROR	"%s(1223): Error Sending email to %s (smtp server)"

#define EXECQ_ERROR "%s(1301): No Execd queue at %s"

/* Verbose messages */
#define STARTED_MSG	"%s: Starting ..."
#define PRIVSEP_MSG	"%s: Chrooted to directory: %s, using user: %s"


#endif /* _ERROR_MESSAGES__H */

