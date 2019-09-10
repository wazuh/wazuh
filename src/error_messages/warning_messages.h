/*
 * Copyright (C) 2015-2019
 * January 17
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #ifndef _WARN_MESSAGES__H
 #define _WARN_MESSAGES__H

/* File integrity monitoring warning messages*/
#define FIM_WARN_ACCESS                         "(6900): Accessing to '%s': [(%d) - (%s)]"
#define FIM_WARN_DELETE                         "(6901): Could not delete of filesystem '%s'"
#define FIM_WARN_DELETE_HASH_TABLE              "(6902): Could not delete from hash table '%s'"
#define FIM_WARN_SYMLINKS_UNSUPPORTED           "(6903) Links are not supported: '%s'"
#define FIM_WARN_STAT_BROKEN_LINK               "(6904): Error in stat() function: %s. This may be caused by a broken symbolic link (%s)."
#define FIM_WARN_REALTIME_UNSUPPORTED           "(6905): The realtime monitoring request on unsupported system."

#define FIM_WARN_REALTIME_OVERFLOW              "(6906): Real time process: no data. Probably buffer overflow."
#define FIM_WARN_REALTIME_OPENFAIL              "(6907): '%s' does not exist. Monitoring discarded."
#define FIM_WARN_REALTIME_DISABLED              "(6908): Ignoring flag for real time monitoring on directory: '%s'."

#define FIM_WARN_AUDIT_SOCKET_NOEXIST           "(6909): Audit socket (%s) does not exist. You need to restart Auditd. Who-data will be disabled."
#define FIM_WARN_AUDIT_CONFIGURATION_MODIFIED   "(6910): Audit plugin configuration was modified. You need to restart Auditd. Who-data will be disabled."
#define FIM_WARN_AUDIT_RULES_MODIFIED           "(6911): Detected Audit rules manipulation: Audit rules removed."
#define FIM_WARN_AUDIT_CONNECTION_CLOSED        "(6912): Audit: connection closed."
#define FIM_WARN_AUDIT_THREAD_NOSTARTED         "(6913): Audit events reader thread not started."

#define FIM_WARN_GENDIFF_SNAPSHOT               "(6914): Cannot create a snapshot of file '%s'"

#define FIM_WARN_WHODATA_AUTOCONF               "(6915): Audit policies could not be auto-configured due to the Windows version. Check if they are correct for whodata mode."
#define FIM_WARN_WHODATA_LOCALPOLICIES          "(6916): Local audit policies could not be configured."
#define FIM_WARN_WHODATA_EVENT_OVERFLOW         "(6917): Real-time Whodata events queue for Windows has more than %d elements."

#define FIM_WARN_NFS_INOTIFY                    "(6918): '%s' NFS Directories do not support iNotify."

#endif
