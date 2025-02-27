/*
 * Copyright (C) 2015
 * January 17
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef INFO_MESSAGES_H
#define INFO_MESSAGES_H

/* File integrity monitoring info messages*/
#define FIM_DAEMON_STARTED                  "(6000): Starting daemon..."
#define FIM_DISABLED                        "(6001): File integrity monitoring disabled."
#define FIM_MONITORING_REGISTRY             "(6002): Monitoring registry entry: '%s%s', with options '%s'"
#define FIM_MONITORING_DIRECTORY            "(6003): Monitoring path: '%s', with options '%s'."
#define FIM_MONITORING_LDIRECTORY           "(6003): Monitoring path: '%s' (%s), with options '%s'."
#define FIM_NO_DIFF                         "(6004): No diff for file: '%s'"
#define FIM_WAITING_QUEUE                   "(6005): Cannot connect to queue '%s' (%d)'%s'. Waiting %d seconds to reconnect."
#define FIM_PRINT_IGNORE_ENTRY              "(6206): Ignore '%s' entry '%s'"
#define FIM_PRINT_IGNORE_SREGEX             "(6207): Ignore '%s' sregex '%s'"
#define FIM_FREQUENCY_STARTED               "(6008): File integrity monitoring scan started."
#define FIM_FREQUENCY_ENDED                 "(6009): File integrity monitoring scan ended."
#define FIM_FREQUENCY_TIME                  "(6010): File integrity monitoring scan frequency: %d seconds"
#define FIM_REALTIME_STARTING               "(6011): Initializing real time file monitoring engine."
#define FIM_REALTIME_STARTED                "(6012): Real-time file integrity monitoring started."
#define FIM_REALTIME_PAUSED                 "(6013): Real-time file integrity monitoring paused."
#define FIM_REALTIME_RESUMED                "(6014): Real-time file integrity monitoring resumed."
#define FIM_REALTIME_INCOMPATIBLE           "(6015): Real-time Whodata mode is not compatible with this version of Windows."
#define FIM_REALTIME_MONITORING_DIRECTORY   "(6016): Directory set for real time monitoring: '%s'."

#define FIM_WHODATA_STARTING                "(6018): Initializing file integrity monitoring real-time Whodata engine."
#define FIM_WHODATA_STARTED                 "(6019): File integrity monitoring real-time Whodata engine started."
#define FIM_WHODATA_READDED                 "(6020): '%s' has been re-added. It will be monitored in real-time Whodata mode."
#define FIM_WHODATA_SACL_CHANGED            "(6021): The SACL of '%s' has been modified and it is not valid for the real-time Whodata mode. Whodata will not be available for this file."
#define FIM_WHODATA_DELETE                  "(6022): '%s' has been deleted. It will not be monitored in real-time Whodata mode."
#define FIM_AUDIT_NOSOCKET                  "(6023): No socket found at '%s'. Restarting Auditd service."
#define FIM_AUDIT_SOCKET                    "(6024): Generating Auditd socket configuration file: '%s'"
#define FIM_AUDIT_RESTARTING                "(6025): Audit plugin configuration (%s) was modified. Restarting Auditd service."
#define FIM_AUDIT_HEALTHCHECK_DISABLE       "(6026): Audit health check is disabled. Real-time Whodata could not work correctly."
#define FIM_AUDIT_REMOVE_RULE               "(6027): Monitored directory '%s' was removed: Audit rule removed."

#define FIM_AUDIT_RECONNECT                 "(6029): Audit: reconnecting... (%i)"
#define FIM_AUDIT_CONNECT                   "(6030): Audit: connected."
#define FIM_WINREGISTRY_START               "(6031): Registry integrity monitoring scan started"
#define FIM_WINREGISTRY_ENDED               "(6032): Registry integrity monitoring scan ended"
#define FIM_LINKCHECK_START                 "(6033): Starting symbolic link updater. Interval '%d'."
#define FIM_LINKCHECK_CHANGED               "(6034): Updating symbolic link '%s': from '%s' to '%s'."
#define FIM_WHODATA_VOLUMES                 "(6035): Analyzing Windows volumes"

#define FIM_DB_NORMAL_ALERT_FILE            "(6036): The file database status returns to normal."
#define FIM_DB_NORMAL_ALERT_REG             "(6037): The registry database status returns to normal."
#define FIM_DB_80_PERCENTAGE_ALERT_FILE     "(6038): File database is 80%% full."
#define FIM_DB_80_PERCENTAGE_ALERT_REG      "(6039): Registry database is 80%% full."
#define FIM_DB_90_PERCENTAGE_ALERT_FILE     "(6040): File database is 90%% full."
#define FIM_DB_90_PERCENTAGE_ALERT_REG      "(6041): Registry database is 90%% full."

#define FIM_FILE_SIZE_LIMIT_DISABLED        "(6042): File size limit disabled."
#define FIM_DISK_QUOTA_LIMIT_DISABLED       "(6043): Disk quota limit disabled."
#define FIM_NO_DIFF_REGISTRY                "(6044): Option nodiff enabled for %s '%s'."
#define FIM_AUDIT_CREATED_RULE_FILE         "(6045): Created audit rules file, due to audit immutable mode rules will be loaded in the next reboot."
#define FIM_AUDIT_QUEUE_SIZE                "(6046): Internal audit queue size set to '%d'."

/* wazuh-logtest information messages */
#define LOGTEST_INITIALIZED                 "(7200): Logtest started"
#define LOGTEST_DISABLED                    "(7201): Logtest disabled"
#define LOGTEST_INFO_TOKEN_SESSION          "(7202): Session initialized with token '%s'"
#define LOGTEST_INFO_LOG_EMPTY              "(7203): Empty log for check alert level"
#define LOGTEST_INFO_LOG_NOALERT            "(7204): Output without rule"
#define LOGTEST_INFO_LOG_NOLEVEL            "(7205): Rule without alert level"
#define LOGTEST_INFO_SESSION_REMOVE         "(7206): The session '%s' was closed successfully"

/* Logcollector info messages */
#define LOGCOLLECTOR_INVALID_HANDLE_VALUE   "(9200): File '%s' can not be handled."
#define LOGCOLLECTOR_ONLY_MACOS             "(9201): 'macos' log format is only supported on macOS."
#define LOGCOLLECTOR_JOURNALD_ONLY_LINUX    "(9202): 'Journald' log format is only available on Linux."
#define LOGCOLLECTOR_JOURNALD_MONITORING    "(9203): Monitoring journal entries."
#define LOGCOLLECTOR_ROTATION_DETECTED      "(9204): 'Journald' files rotation detected."
#define LOGCOLLECTOR_CONTEXT_RECREATION     "(9205): 'Journald' context was recreated."

/* Agent info messages */
#define AG_UNINSTALL_VALIDATION_START       "(9500): Starting user validation to uninstall the Wazuh agent package."
#define AG_UNINSTALL_VALIDATION_GRANTED     "(9501): Validation of the uninstallation of the Wazuh agent package granted."
#define AG_UNINSTALL_VALIDATION_DENIED      "(9502): Validation of the uninstallation of the Wazuh agent package denied."

#endif /* INFO_MESSAGES_H */
