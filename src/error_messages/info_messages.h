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

#define FIM_DAEMON_STARTED                         "(6001): Starting daemon..."
#define FIM_DISABLED                               "(6002): File integrity monitoring disabled."
#define FIM_MONITORING_REGISTRY                    "(6003): Monitoring registry entry: '%s%s'."
#define FIM_MONITORING_DIRECTORY                   "(6004): Monitoring directory: '%s'"
#define FIM_FILE_IGNORE                            "(6005): Ignoring: '%s'"
#define FIM_FILE_REGEX_IGNORE                      "(6006): Ignoring sregex: '%s'"
#define FIM_REGISTRY_IGNORE                        "(6007): Ignoring registry: '%s'"
#define FIM_REGISTRY_REGEX_IGNORE                  "(6008): Ignoring registry sregex: '%s'"
#define FIM_NO_DIFF                                "(6009): No diff for file: '%s'"
#define FIM_WAITING_QUEUE                          "(6010): Cannot connect to queue '%s' (%d)'%s'. Waiting %d seconds to reconnect."

#define FIM_FREQUENCY_STARTED                      "(6011): File integrity monitoring scan started."
#define FIM_FREQUENCY_ENDED                        "(6012): File integrity monitoring scan ended. Database completed."
#define FIM_FREQUENCY_TIME                         "(6013): File integrity monitoring scan frequency: %d seconds"

#define FIM_REALTIME_STARTING                      "(6014): Initializing real-time file integrity monitoring engine."
#define FIM_REALTIME_STARTED                       "(6015): Real-time file integrity monitoring started."
#define FIM_REALTIME_PAUSED                        "(6016): Real-time file integrity monitoring paused."
#define FIM_REALTIME_RESUMED                       "(6017): Real-time file integrity monitoring resumed."
#define FIM_REALTIME_INCOMPATIBLE                  "(6018): Real-time Whodata mode is not compatible with this version of Windows."
#define FIM_REALTIME_MONITORING_DIRECTORY          "(6019): Directory set for real time monitoring: '%s'."

#define FIM_WHODATA_START                          "(6020): Whodata auditing engine started."
#define FIM_WHODATA_STARTING                       "(6021): Starting file integrity monitoring real-time Whodata engine."
#define FIM_WHODATA_STARTED                        "(6022): File integrity monitoring real-time Whodata engine started."
#define FIM_WHODATA_READDED                        "(6023): '%s' has been re-added. It will be monitored in real-time Whodata mode."
#define FIM_WHODATA_SACL_CHANGED                   "(6024): The SACL of '%s' has been modified and it is not valid for the real-time Whodata mode. Whodata will not be available for this file."
#define FIM_WHODATA_DELETE                         "(6025): '%s' has been deleted. It will not be monitored in real-time Whodata mode."

#define FIM_AUDIT_NOSOCKET                         "(6026): No socket found at '%s'. Restarting Auditd service."
#define FIM_AUDIT_SOCKET                           "(6027): Generating Auditd socket configuration file: %s"
#define FIM_AUDIT_RESTARTING                       "(6028): Audit plugin configuration (%s) was modified. Restarting Auditd service."
#define FIM_AUDIT_HEALTHCHECK_DISABLE              "(6029): Audit health check is disabled. Real-time Whodata could not work correctly."
#define FIM_AUDIT_REMOVE_RULE                      "(6030): Monitored directory '%s' was removed: Audit rule removed."
#define FIM_AUDIT_INVALID_AUID                     "(6031): Audit: Invalid 'auid' value readed. Check Audit configuration (PAM)."
#define FIM_AUDIT_RECONNECT                        "(6032): Audit: reconnecting... (%i)"
#define FIM_AUDIT_CONNECT                          "(6033): Audit: connected."


#endif
