/*
 * Copyright (C) 2015-2019
 * January 17
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #ifndef _WARN_MESSAGES__H
 #define _WARN_MESSAGES__H

/* File integrity monitoring warning messages*/
#define FIM_WARN_ACCESS                         "Accessing to '%s': [(%d) - (%s)]"
#define FIM_WARN_DELETE                         "Could not delete of filesystem '%s'"
#define FIM_WARN_DELETE_HASH_TABLE              "Could not delete from hash table '%s'"
#define FIM_WARN_SYMLINKS_UNSUPPORTED           "Links are not supported: '%s'"
#define FIM_WARN_STAT_BROKEN_LINK               "Error in stat() function: %s. This may be caused by a broken symbolic link (%s)."
#define FIM_WARN_REALTIME_UNSUPPORTED           "The realtime monitoring request on unsupported system for '%s'"

#define FIM_WARN_REALTIME_OVERFLOW              "Real time process: no data. Probably buffer overflow."
#define FIM_WARN_REALTIME_OPENFAIL              "'%s' does not exist. Monitoring discarded."
#define FIM_WARN_REALTIME_DISABLED              "Ignoring flag for real time monitoring on directory: '%s'."

#define FIM_WARN_AUDIT_SOCKET_NOEXIST           "Audit socket (%s) does not exist. You need to restart Auditd. Who-data will be disabled."
#define FIM_WARN_AUDIT_CONFIGURATION_MODIFIED   "Audit plugin configuration was modified. You need to restart Auditd. Who-data will be disabled."
#define FIM_WARN_AUDIT_RULES_MODIFIED           "Detected Audit rules manipulation: Audit rules removed."
#define FIM_WARN_AUDIT_CONNECTION_CLOSED        "Audit: connection closed."
#define FIM_WARN_AUDIT_THREAD_NOSTARTED         "Audit events reader thread not started."

#define FIM_WARN_GENDIFF_SNAPSHOT               "Cannot create a snapshot of file '%s'"

#define FIM_WARN_WHODATA_AUTOCONF               "Audit policies could not be auto-configured due to the Windows version. Check if they are correct for whodata mode."
#define FIM_WARN_WHODATA_LOCALPOLICIES          "Local audit policies could not be configured."
#define FIM_WARN_WHODATA_EVENT_OVERFLOW         "Real-time Whodata events queue for Windows has more than %d elements."

#endif

