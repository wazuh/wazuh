/*
 * Copyright (C) 2015-2020
 * January 17
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WARN_MESSAGES_H
#define WARN_MESSAGES_H

/* File integrity monitoring warning messages*/
#define FIM_WARN_ACCESS                         "(6900): Accessing  '%s': [(%d) - (%s)]"
#define FIM_WARN_DELETE                         "(6901): Could not delete from filesystem '%s'"
#define FIM_WARN_DELETE_HASH_TABLE              "(6902): Could not delete from hash table '%s'"
#define FIM_WARN_SYMLINKS_UNSUPPORTED           "(6903) Links are not supported: '%s'"
#define FIM_WARN_STAT_BROKEN_LINK               "(6904): Error in stat() function: %s. This may be caused by a broken symbolic link (%s)."
#define FIM_WARN_ALLOW_PREFILTER                "(6905): Ignoring prefilter option '%s'. Enable <%s> to use it."
#define FIM_WARN_REALTIME_OVERFLOW              "(6906): Real time process: no data. Probably buffer overflow."
#define FIM_WARN_REALTIME_OPENFAIL              "(6907): '%s' does not exist. Monitoring discarded."
#define FIM_WARN_REALTIME_DISABLED              "(6908): Ignoring flag for real time monitoring on directory: '%s'."
#define FIM_WARN_AUDIT_SOCKET_NOEXIST           "(6909): Audit socket (%s) does not exist. You need to restart Auditd. Who-data will be disabled."
#define FIM_WARN_AUDIT_CONFIGURATION_MODIFIED   "(6910): Audit plugin configuration was modified. You need to restart Auditd. Who-data will be disabled."
#define FIM_WARN_AUDIT_RULES_MODIFIED           "(6911): Detected Audit rules manipulation: Audit rules removed."
#define FIM_WARN_AUDIT_CONNECTION_CLOSED        "(6912): Audit: connection closed."
#define FIM_WARN_AUDIT_THREAD_NOSTARTED         "(6913): Who-data engine could not start. Switching who-data to real-time."
#define FIM_WARN_GENDIFF_SNAPSHOT               "(6914): Cannot create a snapshot of file '%s'"
#define FIM_WARN_WHODATA_AUTOCONF               "(6915): Audit policies could not be auto-configured due to the Windows version. Check if they are correct for whodata mode."
#define FIM_WARN_WHODATA_LOCALPOLICIES          "(6916): Local audit policies could not be configured."
#define FIM_WARN_WHODATA_EVENT_OVERFLOW         "(6917): Real-time Whodata events queue for Windows has more than %d elements."
#define FIM_WARN_NFS_INOTIFY                    "(6918): '%s' NFS Directories do not support iNotify."
#define FIM_INV_REG                             "(6919): Invalid syscheck registry entry: '%s' arch: '%s'."
#define FIM_REG_OPEN                            "(6920): Unable to open registry key: '%s' arch: '%s'."
#define FIM_WARN_FILE_REALTIME                  "(6921): Unable to configure real-time option for file: '%s'"
#define FIM_PATH_NOT_OPEN                       "(6922): Cannot open '%s': %s"
#define FIM_WARN_SKIP_EVENT                     "(6923): Unable to process file '%s'"
#define FIM_AUDIT_NORUNNING                     "(6924): Who-data engine cannot start because Auditd is not running."
#define FIM_INVALID_OPTION_SKIP                 "(6925): Invalid option '%s' for attribute '%s'. The paths '%s' will not be monitored."
#define FIM_WARN_WHODATA_ADD_RULE               "(6926): Unable to add audit rule for '%s'"
#define FIM_DB_FULL_ALERT                       "(6927): Sending DB 100%% full alert."
#define FIM_WARN_WHODATA_GETID                  "(6928): Couldn't get event ID from Audit message. Line: '%s'."
#define FIM_WARN_WHODATA_EVENT_TOOLONG          "(6929): Caching Audit message: event too long. Event with ID: '%s' will be discarded."
#define FIM_WARN_MAX_DIR_REACH                  "(6930): Maximum number of directories to be monitored in the same tag reached (%d) Excess are discarded: '%s'"
#define FIM_WARN_MAX_REG_REACH                  "(6931): Maximum number of registries to be monitored in the same tag reached (%d) Excess are discarded: '%s'"
#define FIM_WHODATA_PARAMETER                   "(6932): Invalid parameter type (%ld) for '%s'."
#define FIM_WHODATA_RENDER_EVENT                "(6933): Error rendering the event. Error %lu."
#define FIM_WHODATA_RENDER_PARAM                "(6934): Invalid number of rendered parameters."


/* Monitord warning messages */
#define ROTATE_LOG_LONG_PATH                    "(7500): The path of the rotated log is too long."
#define ROTATE_JSON_LONG_PATH                   "(7501): The path of the rotated json is too long."
#define COMPRESSED_LOG_LONG_PATH                "(7502): The path of the compressed log is too long."
#define COMPRESSED_JSON_LONG_PATH               "(7503): The path of the compressed json is too long."

/* Ruleset reading warnings */
#define ANALYSISD_INV_VALUE_RULE                "(7600): Invalid value '%s' for attribute '%s' in rule %d"
#define ANALYSISD_INV_VALUE_DEFAULT             "(7601): Invalid value for attribute '%s' in '%s' option " \
                                                "(decoder `%s`). Default value will be taken"

#endif /* WARN_MESSAGES_H */
