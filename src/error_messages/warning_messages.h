/*
 * Copyright (C) 2015
 * January 17
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WARN_MESSAGES_H
#define WARN_MESSAGES_H

/* Active Response */
#define AR_SERVER_AGENT "(1306): Invalid agent ID. Use location=server to run AR on the manager."

/* File integrity monitoring warning messages*/
#define FIM_WARN_ACCESS                         "(6900): Accessing  '%s': [(%d) - (%s)]"
#define FIM_WARN_DELETE                         "(6901): Could not delete from filesystem '%s'"
#define FIM_WARN_DELETE_HASH_TABLE              "(6902): Could not delete from hash table '%s'"
#define FIM_WARN_SYMLINKS_UNSUPPORTED           "(6903) Links are not supported: '%s'"
#define FIM_WARN_STAT_BROKEN_LINK               "(6904): Error in w_stat() function: %s. This may be caused by a broken symbolic link (%s)."
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

#define FIM_AUDIT_NORUNNING                     "(6923): Who-data engine cannot start because Auditd is not running."
#define FIM_INVALID_OPTION_SKIP                 "(6924): Invalid option '%s' for attribute '%s'. The paths '%s' will not be monitored."
#define FIM_WARN_WHODATA_ADD_RULE               "(6925): Unable to add audit rule for '%s'"
#define FIM_DB_FULL_ALERT_FILE                  "(6926): File database is 100%% full."
#define FIM_DB_FULL_ALERT_REG                   "(6927): Registry database is 100%% full."
#define FIM_WARN_WHODATA_GETID                  "(6928): Couldn't get event ID from Audit message. Line: '%s'."
#define FIM_WARN_WHODATA_EVENT_TOOLONG          "(6929): Caching Audit message: event too long. Event with ID: '%s' will be discarded."
#define FIM_WARN_MAX_DIR_REACH                  "(6930): Maximum number of directories to be monitored in the same tag reached (%d) Excess are discarded: '%s'"
#define FIM_WARN_MAX_REG_REACH                  "(6931): Maximum number of registries to be monitored in the same tag reached (%d) Excess are discarded: '%s'"
#define FIM_WHODATA_PARAMETER                   "(6932): Invalid parameter type (%ld) for '%s'."
#define FIM_WHODATA_RENDER_EVENT                "(6933): Error rendering the event. Error %lu."
#define FIM_WHODATA_RENDER_PARAM                "(6934): Invalid number of rendered parameters."
#define FIM_DB_TEMPORARY_FILE_POSITION          "(6935): Unable to reposition temporary file to beginning. Error[%d]: '%s'"
#define FIM_REG_VAL_WRONG_TYPE                  "(6936): Wrong registry value type processed for report_changes."
#define FIM_INVALID_REG_OPTION_SKIP             "(6937): Invalid option '%s' for attribute '%s'. The registry '%s' not be monitored."
#define FIM_REGISTRY_EVENT_NULL_ENTRY           "(6938): Invalid null registry event."
#define FIM_REGISTRY_EVENT_NULL_ENTRY_KEY       "(6939): Invalid registry event with a null key was detected."
#define FIM_REGISTRY_EVENT_WRONG_ENTRY_TYPE     "(6940): Invalid registry event with a type different than registry was detected."
#define FIM_REGISTRY_EVENT_WRONG_SAVED_TYPE     "(6941): Invalid registry event with a saved type different than registry was detected."
#define FIM_REGISTRY_UNSCANNED_KEYS_FAIL        "(6942): Failed to get unscanned registry keys."
#define FIM_REGISTRY_UNSCANNED_VALUE_FAIL       "(6943): Failed to get unscanned registry values."
#define FIM_REGISTRY_FAIL_TO_INSERT_VALUE       "(6944): Failed to insert value '%s %s\\%s'"
#define FIM_REGISTRY_FAIL_TO_GET_KEY_ID         "(6945): Unable to get id for registry key '%s %s'"
#define FIM_AUDIT_DISABLED                      "(6946): Audit is disabled."
#define FIM_WARN_FORMAT_PATH                    "(6947): Error formatting path: '%s'"
#define FIM_DATABASE_NODES_COUNT_FAIL           "(6948): Unable to get the number of entries in database."
#define FIM_CJSON_ERROR_CREATE_ITEM             "(6949): Cannot create a cJSON item"
#define FIM_REGISTRY_ACC_SID                    "(6950): Error in LookupAccountSid getting %s. (%ld): %s"
#define FIM_WHODATA_ERROR_CHECKING_POL          "(6951): Unable to check the necessary policies for whodata: %s (%lu)."
#define FIM_WHODATA_POLICY_CHANGE_CHECKER       "(6952): Audit policy change detected. Switching directories to realtime."
#define FIM_WHODATA_POLICY_CHANGE_CHANNEL       "(6953): Event 4719 received due to changes in audit policy. Switching directories to realtime."
#define FIM_EMPTY_CHANGED_ATTRIBUTES            "(6954): Entry '%s' does not have any modified fields. No event will be generated."
#define FIM_INVALID_FILE_NAME                   "(6955): Ignoring file '%s' due to unsupported name (non-UTF8)."
#define FIM_FULL_AUDIT_QUEUE                    "(6956): Internal audit queue is full. Some events may be lost. Next scheduled scan will recover lost data."
#define FIM_REALTIME_FILE_NOT_SUPPORTED         "(6957): Realtime mode only supports directories, not files. Switching to scheduled mode. File: '%s'"
#define FIM_FULL_EBPF_KERNEL_QUEUE              "(6958): Internal ebpf queue for kernel events is full. Too many eBPF events from system files. Next scheduled scan will recover lost data."
#define FIM_ERROR_EBPF_HEALTHCHECK              "(6959): The eBPF healthcheck has failed. Switching all whodata eBPF configuration to audit."
#define FIM_WARN_INODE_WRONG_TYPE               "(6960): Inode field received with a wrong type, it must be a string."

/* Monitord warning messages */
#define ROTATE_LOG_LONG_PATH                    "(7500): The path of the rotated log is too long."
#define ROTATE_JSON_LONG_PATH                   "(7501): The path of the rotated json is too long."
#define COMPRESSED_LOG_LONG_PATH                "(7502): The path of the compressed log is too long."
#define COMPRESSED_JSON_LONG_PATH               "(7503): The path of the compressed json is too long."

/* Wazuh-logtest warning messages*/
#define LOGTEST_INV_NUM_THREADS                 "(7000): Number of logtest threads too high. Only creates %d threads"
#define LOGTEST_INV_NUM_USERS                   "(7001): Number of maximum users connected in logtest too high. Only allows %d users"
#define LOGTEST_INV_NUM_TIMEOUT                 "(7002): Number of maximum user timeouts in logtest too high. Only allows %ds maximum timeouts"
#define LOGTEST_WARN_TOKEN_EXPIRED              "(7003): '%s' token expires"
#define LOGTEST_WARN_SESSION_NOT_FOUND          "(7004): No session found for token '%s'"
#define LOGTEST_WARN_FIELD_NOT_OBJECT_IGNORE    "(7005): '%s' field must be a JSON object. The parameter will be ignored"
#define LOGTEST_WARN_FIELD_NOT_BOOLEAN_IGNORE   "(7006): '%s' field must be a boolean. The parameter will be ignored"


/* Ruleset reading warnings */
#define ANALYSISD_INV_VALUE_RULE                "(7600): Invalid value '%s' for attribute '%s' in rule %d."
#define ANALYSISD_INV_VALUE_DEFAULT             "(7601): Invalid value for attribute '%s' in '%s' option " \
                                                        "(decoder `%s`). Default value will be used."
#define ANALYSISD_INV_OPT_VALUE_DEFAULT         "(7602): Invalid value '%s' in '%s' option " \
                                                        "(decoder `%s`). Default value will be used."
#define ANALYSISD_DEC_DEPRECATED_OPT_VALUE      "(7603): Deprecated value '%s' in '%s' option " \
                                                        "(decoder `%s`). Default value will be used."
#define ANALYSISD_IGNORE_RULE                   "(7604): Rule '%d' will be ignored."
#define ANALYSISD_INV_OVERWRITE                 "(7605): It is not possible to overwrite '%s' value " \
                                                        "in rule '%d'. The original value is retained."
#define ANALYSISD_INV_SIG_ID                    "(7607): Invalid '%s'. Signature ID must be an integer. " \
                                                        "Rule '%d' will be ignored."
#define ANALYSISD_LEVEL_NOT_FOUND               "(7608): Level ID '%d' was not found. Invalid 'if_level'. " \
                                                        "Rule '%d' will be ignored."
#define ANALYSISD_INV_IF_LEVEL                  "(7609): Invalid 'if_level' value: '%s'. Rule '%d' will be ignored."
#define ANALYSISD_GROUP_NOT_FOUND               "(7610): Group '%s' was not found. Invalid 'if_group'. " \
                                                        "Rule '%d' will be ignored."
#define ANALYSISD_CATEGORY_NOT_FOUND            "(7611): Category was not found. Invalid 'category'. " \
                                                        "Rule '%d' will be ignored."
#define ANALYSISD_DUPLICATED_SIG_ID             "(7612): Rule ID '%d' is duplicated. Only the first occurrence will be "\
                                                        "considered."
#define ANALYSISD_OVERWRITE_MISSING_RULE        "(7613): Rule ID '%d' does not exist but 'overwrite' is set to 'yes'. "\
                                                        "Still, the rule will be loaded."
#define ANALYSISD_NULL_RULE                     "(7614): Rule pointer is NULL. Skipping."
#define ANALYSISD_INV_IF_MATCHED_SID            "(7615): Invalid 'if_matched_sid' value: '%s'. Rule '%d' will be ignored."
#define ANALYSISD_LIST_NOT_LOADED               "(7616): List '%s' could not be loaded. Rule '%d' will be ignored."
#define ANALYSISD_SIG_ID_NOT_FOUND              "(7617): Signature ID '%d' was not found and will be ignored "\
                                                        "in the 'if_sid' option of rule '%d'."
#define ANALYSISD_INVALID_IF_SID                "(7618): Invalid 'if_sid' value: '%s'. Rule '%d' will be ignored."
#define ANALYSISD_EMPTY_SID                     "(7619): Empty 'if_sid' value. Rule '%d' will be ignored."
#define ANALYSISD_SIG_ID_NOT_FOUND_MID          "(7620): Signature ID '%d' was not found. Invalid 'if_matched_sid'."\
                                                         "Rule '%d' will be ignored."

/* Logcollector */
#define LOGCOLLECTOR_INV_VALUE_DEFAULT          "(8000): Invalid value '%s' for attribute '%s' in '%s' option. " \
                                                "Default value will be used."
#define LOGCOLLECTOR_MULTILINE_SUPPORT          "(8001): log_format '%s' does not support multiline_regex option." \
                                                " Will be ignored."
#define LOGCOLLECTOR_MULTILINE_AGE_TIMEOUT      "(8002): 'age' cannot be less than 'timeout' in multiline_regex option."\
                                                " 'age' will be ignored."
#define LOGCOLLECTOR_INV_VALUE_IGNORE           "(8003): Invalid value '%s' for attribute '%s' in '%s' option. " \
                                                "Attribute will be ignored."
#define LOGCOLLECTOR_OPTION_IGNORED             "(8004): log_format '%s' does not support '%s' option." \
                                                " Option will be ignored."
#define LOGCOLLECTOR_INV_MACOS                  "(8005): Invalid location value '%s' when using 'macos' as " \
                                                "'log_format'. Default value will be used."
#define LOGCOLLECTOR_MISSING_LOCATION_MACOS     "(8006): Missing 'location' element when using 'macos' as " \
                                                "'log_format'. Default value will be used."
#define LOGCOLLECTOR_DEFAULT_REGEX_TYPE         "(8007): Invalid type in '%s' regex '%s', setting by default PCRE2 regex."

#define LOGCOLLECTOR_JOURNAL_LOG_LIB_FAIL_LOAD      "(8008): Failed to load '%s': '%s'."
#define LOGCOLLECTOR_JOURNAL_LOG_LIB_FAIL_OWN       "(8009): The library '%s' is not owned by the root user."
#define LOGCOLLECTOR_JOURNAL_LOG_FAIL_OPEN          "(8010): Failed open journal log: '%s'."
#define LOGCOLLECTOR_JOURNAL_LOG_FAIL_READ_TS       "(8011): Failed to read timestamp from journal log: '%s'. Using current time."
#define LOGCOLLECTOR_JOURNAL_LOG_FUTURE_TS          "(8012): The timestamp '%" PRIu64 "' is in the future or invalid. Using the most recent entry."
#define LOGCOLLECTOR_JOURNAL_LOG_FAIL_READ_OLD_TS   "(8013): Failed to read oldest timestamp from journal log: '%s'."
#define LOGCOLLECTOR_JOURNAL_LOG_CHANGE_TS          "(8014): The timestamp '%" PRIu64 "' is older than the oldest available in journal. Using the oldest entry."

#define LOGCOLLECTOR_JOURNAL_CONFG_FAIL_FILTER      "(8015): Cannot add filter, the block will be ignored."
#define LOGCOLLECTOR_JOURNAL_CONFG_MISSING_LOC      "(8016): Missing 'location' element when using '%s' as 'log_format'. Default value will be used."
#define LOGCOLLECTOR_JOURNAL_CONFG_INVALID_LOC      "(8017): Invalid location value '%s' when using '%s' as 'log_format'. Default value will be used."
#define LOGCOLLECTOR_JOURNAL_CONFG_NOT_JOURNAL_FILTER "(8018): log_format '%s' does not support filter option. Will be ignored."
#define LOGCOLLECTOR_JOURNAL_CONFG_EMPTY_FILTER_FIELD "(8019): The field for the journal filter cannot be empty."
#define LOGCOLLECTOR_JOURNAL_CONFG_EMPTY_FILTER_EXPR  "(8020): The expression for the journal filter cannot be empty."
#define LOGCOLLECTOR_JOURNAL_CONFG_FILTER_EXP_FAIL    "(8021): Error compiling the PCRE2 expression '%s' for field '%s' in journal filter."
#define LOGCOLLECTOR_JOURNAL_CONFG_DISABLE_FILTER    "(8022): The filters of the journald log will be disabled in the merge, because one of the configuration does not have filters."

/* Remoted */
#define REMOTED_NET_PROTOCOL_ERROR              "(9000): Error getting protocol. Default value (%s) will be used."
#define REMOTED_INV_VALUE_IGNORE                "(9001): Ignored invalid value '%s' for '%s'."
#define REMOTED_NET_PROTOCOL_ONLY_SECURE        "(9002): Only secure connection supports TCP and UDP at the same time."\
                                                " Default value (%s) will be used."
#define REMOTED_INV_VALUE_DEFAULT               "(9004): Invalid value '%s' in '%s' option. " \
                                                "Default value will be used."

/* Other */
#define NETWORK_PATH_EXECUTED           "(9800): File access denied. Network path usage is not allowed: '%s'."
#define NETWORK_PATH_CONFIGURED         "(9801): Network path not allowed in configuration. '%s': %s."

#endif /* WARN_MESSAGES_H */
