/*
 * Copyright (C) 2015-2020
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
#define FIM_MONITORING_REGISTRY             "(6002): Monitoring registry entry: '%s%s'."
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
#define FIM_WHODATA_VOLUMES                 "(6036): Analyzing Windows volumes"

#define FIM_DB_NORMAL_ALERT                 "(6038): Sending DB back to normal alert."
#define FIM_DB_80_PERCENTAGE_ALERT          "(6039): Sending DB 80%% full alert."
#define FIM_DB_90_PERCENTAGE_ALERT          "(6039): Sending DB 90%% full alert."


#define FIM_FILE_SIZE_LIMIT_DISABLED        "(6042): File size limit disabled."
#define FIM_DISK_QUOTA_LIMIT_DISABLED       "(6043): Disk quota limit disabled."

#endif /* INFO_MESSAGES_H */
