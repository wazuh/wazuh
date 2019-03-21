/*
 * Copyright (C) 2015-2019
 * January 17
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #ifndef _INFO_MESSAGES__H
 #define _INFO_MESSAGES__H

/* File integrity monitoring info messages*/
#define SK_NO_DIR
#define FIM_RT_RESUMED                  STARTUP_MSG
#define FIM_RT_RESUMED                  SK_NO_DIR
#define FIM_RT_RESUMED                  SK_NO_DIR
#define FIM_RT_RESUMED                  STARTUP_MSG


#define FIM_FREQUENCY_STARTED           "File integrity monitoring scan started."
#define FIM_FREQUENCY_ENDED             "File integrity monitoring scan ended. Database completed."
#define FIM_DAEMON_STARTED              "Starting daemon..."
#define FIM_FREQUENCY_TIME              "File integrity monitoring scan frequency: %d seconds"

#define FIM_RT_STARTING                 "Initializing real-time file integrity monitoring engine."
#define FIM_RT_STARTED                  "Real-time file integrity monitoring started."
#define FIM_RT_PAUSED                   "Real-time file integrity monitoring paused."
#define FIM_RT_RESUMED                  "Real-time file integrity monitoring resumed."

#define FIM_WHODATA_START               "Whodata auditing engine started."
#define FIM_WHODATA_STARTING            "Starting file integrity monitoring real-time Whodata engine."
#define FIM_WHODATA_STARTED             "File integrity monitoring real-time Whodata engine started."

#define FIM_AUDIT_NOSOCKET              "No socket found at '%s'. Restarting Auditd service."
#define FIM_AUDIT_SOCKET                "Generating Auditd socket configuration file: %s"
#define FIM_AUDIT_                      "Audit plugin configuration (%s) was modified. Restarting Auditd service."
#define FIM_AUDIT_                      "Audit health check is disabled. Real-time Whodata could not work correctly."
#define FIM_AUDIT_REMOVE_RULE           "Monitored directory '%s' was removed: Audit rule removed."
#define FIM_AUDIT_INVALID_AUID          "Audit: Invalid 'auid' value readed. Check Audit configuration (PAM)."
#define FIM_AUDIT_RECONNECT             "Audit: reconnecting... (%i)"
#define FIM_AUDIT_CONNECT               "Audit: connected."

#define FIM_DISABLED                    "File integrity monitoring disabled."
#define FIM_RT_INCOPATIBLE              "Real-time Whodata mode is not compatible with this version of Windows."
#define FIM_MONITORING_REGISTRY         "Monitoring registry entry: '%s%s'."
#define FIM_MONITORING_DIRECTORY        "Monitoring directory: '%s'
#define FIM_FILE_IGNORE                 "Ignoring: '%s'"
#define FIM_FILE_REGEX_IGNORE           "Ignoring sregex: '%s'"
#define FIM_REGISTRY_IGNORE             "Ignoring registry: '%s'"
#define FIM_REGISTRY_REGEX_IGNORE       "Ignoring registry sregex: '%s'"
#define FIM_NO_DIFF                     "No diff for file: '%s'"
#define FIM_WAITING_QUEUE               "Cannot connect to queue '%s' (%d)'%s'. Waiting %d seconds to reconnect."
#define FIM_RT_MONITORING_DIRECTORY     "Directory set for real time monitoring: '%s'."

#define FIM_WD_READDED                  "'%s' has been re-added. It will be monitored in real-time Whodata mode."
#define FIM_WD_SACL_CHANGED             "The SACL of '%s' has been modified and it is not valid for the real-time Whodata mode. Whodata will not be available for this file."
#define FIM_WD_DELETE                   "'%s' has been deleted. It will not be monitored in real-time Whodata mode."

#endif
