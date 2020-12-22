/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYSCHECK_H
#define SYSCHECK_H

#include "config/syscheck-config.h"
#include "syscheck_op.h"
#include "external/cJSON/cJSON.h"

#define MAX_LINE PATH_MAX+256

/* Notify list size */
#define NOTIFY_LIST_SIZE    32

#define WDATA_DEFAULT_INTERVAL_SCAN 300

#ifdef WIN32
#define FIM_REGULAR _S_IFREG
#define FIM_DIRECTORY _S_IFDIR
#else
#define FIM_REGULAR S_IFREG
#define FIM_DIRECTORY S_IFDIR
#define FIM_LINK S_IFLNK
#endif

/* Global config */
extern syscheck_config syscheck;
extern int sys_debug_level;

typedef enum fim_event_type {
    FIM_ADD,
    FIM_DELETE,
    FIM_MODIFICATION
} fim_event_type;

typedef enum fim_scan_event {
    FIM_SCAN_START,
    FIM_SCAN_END
} fim_scan_event;

typedef enum fim_state_db {
    FIM_STATE_DB_EMPTY,
    FIM_STATE_DB_NORMAL,
    FIM_STATE_DB_80_PERCENTAGE,
    FIM_STATE_DB_90_PERCENTAGE,
    FIM_STATE_DB_FULL
} fim_state_db;

typedef struct fim_element {
    struct stat statbuf;
    int index;
    int configuration;
    int mode;
} fim_element;

typedef struct fim_tmp_file {
    union { //type_storage
        FILE *fd;
        W_Vector *list;
    };
    char *path;
    int elements;
} fim_tmp_file;

typedef struct diff_data {
    int file_size;
    int size_limit;

    char *compress_folder;
    char *compress_file;

    char *tmp_folder;
    char *file_origin;
    char *uncompress_file;
    char *compress_tmp_file;
    char *diff_file;
} diff_data;

#ifdef WIN32
/* Flags to know if a directory/file's watcher has been removed */
#define FIM_RT_HANDLE_CLOSED 0
#define FIM_RT_HANDLE_OPEN 1
#endif

/* Win32 does not have lstat */
#ifdef WIN32
    #define w_stat(x, y) stat(x, y)
#else
    #define w_stat(x, y) lstat(x, y)
#endif

/** Function Prototypes **/

/**
 * @brief Check the integrity of the files against the saved database
 *
 */
void run_check(void);


/**
 * @brief Start the file integrity monitoring daemon
 *
 */
void start_daemon(void);

/**
 * @brief Read Syscheck configuration from the XML configuration file
 *
 * @param cfgfile Path of the XML configuration file
 * @return 1 if there are no configured directories or registries, 0 on success, -1 on error
 */
int Read_Syscheck_Config(const char *cfgfile) __attribute__((nonnull));

/**
 * @brief Get the Syscheck Config object
 *
 * @return JSON format configuration
 */
cJSON *getSyscheckConfig(void);

/**
 * @brief Get the Syscheck Internal Options object
 *
 * @return JSON format configuration
 */
cJSON *getSyscheckInternalOptions(void);

/**
 * @brief Read the syscheck internal options (to be deprecated)
 *
 * @param debug_level Debug level to be set in the syscheck daemon
 */
void read_internal(int debug_level);

/**
 * @brief Performs an integrity monitoring scan
 *
 */
void fim_scan();


/**
 * @brief
 *
 * @param [in] path Path of the file to check
 * @param [out] item FIM item
 * @param [in] w_evt Whodata event
 * @param [in] report 0 Dont report alert in the scan, otherwise an alert is generated
 */
void fim_checker(char *path, fim_element *item, whodata_evt *w_evt, int report);

/**
 * @brief Check file integrity monitoring on a specific folder
 *
 * @param [in] dir
 * @param [out] item FIM item
 * @param [in] w_evt Whodata event
 * @param [in] report 0 Dont report alert in the scan, otherwise an alert is generated
 * @return 0 on success, -1 on failure
 */
int fim_directory (char *dir, fim_element *item, whodata_evt *w_evt, int report);

/**
 * @brief Check file integrity monitoring on a specific file
 *
 * @param [in] file
 * @param [in] item FIM item
 * @param [in] w_evt Whodata event
 * @param [in] report 0 Dont report alert in the scan, otherwise an alert is generated
 * @return 0 on success, -1 on failure
 */
int fim_file(char *file, fim_element *item, whodata_evt *w_evt, int report);

/**
 * @brief Process FIM realtime event
 *
 * @param [in] file Path of the file to check
 */
void fim_realtime_event(char *file);

/**
 * @brief Process FIM whodata event
 *
 * @param w_evt Whodata event
 */
void fim_whodata_event(whodata_evt *w_evt);

/**
 * @brief Process a path that has possibly been deleted
 *
 * @note On Windows, calls function fim_checker meanwhile, on Linux, calls function fim_audit_inode_event. It's because Windows haven't got inodes.
 * @param pathname Name of path
 * @param mode Monitoring FIM mode
 * @param w_evt Pointer to whodata information
 */
void fim_process_missing_entry(char * pathname, fim_event_mode mode, whodata_evt * w_evt);

/**
 * @brief Search the position of the path in directories array
 *
 * @param path Path to seek in the directories array
 * @param entry "file", for file checking or "registry" for registry checking
 * @return Returns the position of the path in the directories array, -1 if the path is not found
 */
int fim_configuration_directory(const char *path, const char *entry);

/**
 * @brief Evaluates the depth of the directory or file to check if it exceeds the configured max_depth value
 *
 * @param path File name of the file/directory to check
 * @param dir_position Position of the file to check in the directories array
 * @return Depth of the directory/file, -1 on error
 */
int fim_check_depth(char *path, int dir_position);

/**
 * @brief Get data from file
 *
 * @param file_name Name of the file to get the data from
 * @param item FIM item asociated with the file
 *
 * @return A fim_file_data structure with the data from the file
 */
fim_file_data * fim_get_data(const char *file_name, fim_element *item);

/**
 * @brief Initialize a fim_file_data structure
 *
 * @param [out] data Data to initialize
 */
void init_fim_data_entry(fim_file_data *data);

/**
 * @brief Calculate checksum of a FIM entry data
 *
 * @param data FIM entry data to calculate the checksum with
 */
void fim_get_checksum(fim_file_data *data);

/**
 * @brief Prints the scan information
 *
 */
void fim_print_info(struct timespec start, struct timespec end, clock_t cputime_start);

/**
 * @brief Sleep during rt_delay milliseconds
 *
 */
void fim_rt_delay();

/**
 * @brief Checks for deleted files, deletes them from the agent's database and sends a deletion event on scheduled scans
 */
void check_deleted_files();


/**
 * @brief Produce a file change JSON event
 *
 * {
 *   type:                  "event"
 *   data: {
 *     path:                string
 *     mode:                "scheduled"|"real-time"|"whodata"
 *     type:                "added"|"deleted"|"modified"
 *     timestamp:           number
 *     tags:                string
 *     content_changes:     string
 *     changed_attributes:  array   fim_json_compare_attrs()    [Only if old_data]
 *     old_attributes:      object  fim_attributes_json()       [Only if old_data]
 *     attributes:          object  fim_attributes_json()
 *     audit:               object  fim_audit_json()
 *   }
 * }
 *
 * @param file_name File path.
 * @param old_data Previous file state.
 * @param new_data Current file state.
 * @param dir_position Index of the related configuration stanza.
 * @param type Type of event: added, deleted or modified.
 * @param mode Event source.
 * @param w_evt Audit data structure.
 * @param diff File diff if applicable.
 * @return File event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON *fim_json_event(char *file_name, fim_file_data *old_data, fim_file_data *new_data, int pos, unsigned int type, fim_event_mode mode, whodata_evt *w_evt, const char *diff);

/**
 * @brief Frees the memory of a FIM entry data structure
 *
 * @param [out] data The FIM entry data to be freed
 */
void free_file_data(fim_file_data *data);

/**
 * @brief Deallocates fim_entry struct.
 *
 * @param entry Entry to be deallocated.
 */
void free_entry(fim_entry * entry);

/**
 * @brief Frees the memory of a FIM inode data structure
 *
 * @param [out] data The FIM inode data to be freed
 */
void free_inode_data(fim_inode_data **data);

/**
 * @brief Start real time monitoring
 *
 * @return 0 on success, -1 on error
 */
int realtime_start(void);

/**
 * @brief Add a directory to real time monitoring
 *
 * @param dir Path to file or directory
 * @param whodata If the path is configured with whodata option
 * @param followsl If the path is configured with follow sym link option
 * @return 1 on success, -1 on realtime_start failure, -2 on set_winsacl failure, and 0 on other errors
 */
int realtime_adddir(const char *dir, int whodata, int followsl) __attribute__((nonnull(1)));

/**
 * @brief Process events in the real time queue
 *
 */
void realtime_process(void);

/**
 * @brief Delete data form dir_tb hash table
 *
 * @param [out] data
 */
void free_syscheck_dirtb_data(char *data);

/**
 * @brief Deletes subdirectories watches when a folder changes its name
 *
 * @param dir Directory whose subdirectories need to delete their watches
 */

void delete_subdirectories_watches(char *dir);

/**
 * @brief Remove stale watches from the realtime hashmap
 */
void realtime_sanitize_watch_map();

/**
 * @brief Frees the memory of a Whodata event structure
 *
 * @param [out] w_evt
 */
void free_whodata_event(whodata_evt *w_evt);

/**
 * @brief Send a message related to syscheck change/addition
 *
 * @param msg The message to be sent
 */
void send_syscheck_msg(const char *msg) __attribute__((nonnull));

/**
 * @brief Send a data synchronization control message
 *
 * @param location Specifies if the synchronization message is for files or registries.
 * @param msg The message to be sent
 */
void fim_send_sync_msg(const char *location, const char * msg);

// TODO
/**
 * @brief
 *
 * @param msg
 * @return int
 */
int send_log_msg(const char *msg);

#ifdef __linux__
#define READING_MODE 0
#define HEALTHCHECK_MODE 1

/**
 * @brief Initialize Audit events reader thread
 *
 * @return 1 on success, -1 on error
 */
int audit_init(void);

/**
 * @brief Retrieves the id of an audit event
 *
 * @param event An audit event
 * @return The string id of the event
 */
char *audit_get_id(const char * event);

/**
 * @brief Initialize regular expressions
 *
 * @return 0 on success, -1 on error
 */
int init_regex(void);

/**
 * @brief Adds audit rules to configured directories
 *
 * @param first_time Indicates if it's the first time the rules are being added
 * @return The number of rules added
 */
int add_audit_rules_syscheck(bool first_time);

/**
 * @brief Read an audit event from socket
 *
 * @param [out] audit_sock The audit socket to read the events from
 * @param [in] reading_mode READING_MODE or HEALTHCHECK_MODE
 */
void audit_read_events(int *audit_sock, int reading_mode);

/**
 * @brief Makes Audit thread to wait for audit healthcheck to be performed
 *
 */
void audit_set_db_consistency(void);

/**
 * @brief Check if the Audit daemon is installed and running
 *
 * @return The PID of Auditd
 */
int check_auditd_enabled(void);

/**
 * @brief Set all directories that don't have audit rules and have whodata enabled to realtime.
 *
*/
void audit_no_rules_to_realtime();

/**
 * @brief Set Auditd socket configuration
 *
 * @return 0 on success, -1 on error
 */
int set_auditd_config(void);

/**
 * @brief Initialize Audit evsents socket
 *
 * @return File descriptor of the socket, -1 on error
 */
int init_auditd_socket(void);

/**
 * @brief Creates the necessary threads to process audit events
 *
 * @param [out] audit_sock The audit socket to read the events from
 */
void *audit_main(int *audit_sock);

/**
 * @brief Reloads audit rules every RELOAD_RULES_INTERVAL seconds
 *
 */
void *audit_reload_thread();

/**
 * @brief Thread that performs a healthcheck on audit
 * It reads an event from audit socket to check if it's running
 *
 * @param [out] audit_sock The audit socket to read the events from
 */
void *audit_healthcheck_thread(int *audit_sock);

// TODO
/**
 * @brief
 *
 * @param cwd
 * @param path0
 * @param path1
 * @return A string with generated path
 */
char *gen_audit_path(char *cwd, char *path0, char *path1);

/**
 * @brief Add cwd and exe of parent process
 *
 * @param ppid ID of parent process
 * @param parent_name String where save the parent name (exe)
 * @param parent_cwd String where save the parent working directory (cwd)
 */
void get_parent_process_info(char *ppid, char ** const parent_name, char ** const parent_cwd);

/**
 * @brief Reloads audit rules to configured directories
 * This is necessary to include audit rules for hot added directories in the configuration
 *
 */
void audit_reload_rules(void);

/**
 * @brief Parses an audit event and sends the corresponding alert message
 *
 * @param buffer The audit event to parse
 */
void audit_parse(char *buffer);

/**
 * @brief Generate the audit event that the healthcheck thread should read
 *
 * @param audit_socket The audit socket to read the events from
 * @return 0 on success, -1 on error
 */
int audit_health_check(int audit_socket);

/**
 * @brief Deletes all the existing audit rules added by FIM
 *
 */
void clean_rules(void);

/**
 * @brief
 *
 * @param buffer
 * @return 0 if no key is found, 1 if AUDIT_KEY is found, 2 if an existing key is found, 3 if AUDIT_HEALTHCHECK_KEY is found
 */
int filterkey_audit_events(char *buffer);
extern W_Vector *audit_added_dirs;
extern volatile int audit_thread_active;
extern volatile int whodata_alerts;
extern volatile int audit_db_consistency_flag;
extern pthread_mutex_t audit_mutex;
extern pthread_cond_t audit_thread_started;
extern pthread_cond_t audit_hc_started;
extern pthread_cond_t audit_db_consistency;

#elif WIN32
/**
 * @brief Initializes the whodata scan mode
 *
 * @return 0 on success, 1 on error
 */
int run_whodata_scan(void);

/**
 * @brief
 *
 * @return 0 on success, 1 on error
 */
int whodata_audit_start();

/**
 * @brief Configure the SACL in a configured folder for Whodata auditing
 *
 * @param dir The name of the folder to configure
 * @param position The position of the folder in the configuration array
 * @return 0 on success, 1 on error
 */
int set_winsacl(const char *dir, int position);

/**
 * @brief In case SACLs and policies have been set, restore them
 */
void audit_restore();

/**
 * @brief Thread that checks the status of the whodata configured folders
 * It checks if the folder has ben re-added, if its SACL has been changed or if it has been deleted.
 *
 */

long unsigned int WINAPI state_checker(__attribute__((unused)) void *_void);

/**
 * @brief Function that generates the diff file of a Windows registry when the option report_changes is activated
 * It creates a file with the content of the value, to compute differences
 *
 * @param key_name Path of the registry key monitored
 * @param value_name Name of the value that has generated the alert
 * @param value_data Content of the value to be checked
 * @param data_type The type of value we are checking
 * @param registry Config of the registry key
 * @return String with the changes to add to the alert
 */

char *fim_registry_value_diff(const char *key_name,
                              const char *value_name,
                              const char *value_data,
                              DWORD data_type,
                              const registry *configuration);
#endif

/**
 * @brief Function that generates the diff file of a file monitored when the option report_changes is activated
 *
 * @param filename Path of file monitored
 * @return String with the diff to add to the alert
 */

char * fim_file_diff(const char *filename);

/**
 * @brief Deletes the filename diff folder and modify diff_folder_size if disk_quota enabled
 *
 * @param filename Path of the file that has been deleted
 * @return 0 if success, -1 on error
 */
int fim_diff_process_delete_file(const char *filename);

/**
 * @brief Deletes the registry diff folder and modify diff_folder_size if disk_quota enabled
 *
 * @param key_name Path of the registry that has been deleted
 * @param arch Arch type of the registry
 * @return 0 if success, -1 on error
 */
int fim_diff_process_delete_registry(const char *key_name, int arch);

/**
 * @brief Deletes the value diff folder and modifies diff_folder_size if disk_quota enabled
 *
 * @param key_name Path of the registry that contains the deleted value
 * @param value_name Path of the value that has been deleted
 * @param arch Arch type of the registry
 * @return 0 if success, -1 on error
 */
int fim_diff_process_delete_value(const char *key_name, const char *value_name, int arch);

/**
 * @brief Initializes all syscheck data
 *
 */
void fim_initialize();
int fim_whodata_initialize();

/**
 * @brief Checks if a specific file has been configured to be ignored
 *
 * @param file_name The name of the file to check
 * @return 1 if it has been configured to be ignored, 0 if not
 */
int fim_check_ignore(const char *file_name);

/**
 * @brief Checks if a specific folder has been configured to be checked with a specific restriction
 *
 * @param file_name The name of the file to check
 * @param restriction The regex restriction to be checked
 * @return 1 if the folder has been configured with the specified restriction, 0 if not
 */
int fim_check_restrict(const char *file_name, OSMatch *restriction);

#ifndef WIN32

/**
 * @brief Thread that creates a socket for communication with the API
 * Com request thread dispatcher
 *
 * @param Argument to be passed to the thread
 */
void *syscom_main(void *arg);
#endif

/**
 * @brief Dispatches messages from API directed to syscheck module
 *
 * @param [in] command The input command sent from the API
 * @param [out] output The output buffer to be filled (answer for the API)
 * @return The size of the output buffer
 */
size_t syscom_dispatch(char *command, char **output);

/**
 * @brief
 *
 * @param [in] section The specific section to be checked sent from the API
 * @param [out] output The output buffer to be filled (answer for the API)
 * @return The size of the output buffer
 */
size_t syscom_getconfig(const char *section, char **output);

#ifdef WIN_WHODATA
/**
 * @brief Updates the SACL of an specific file
 *
 * @param obj_path The path of the file to update the SACL of
 * @return 0 on success, -1 on error
 */
int w_update_sacl(const char *obj_path);
#endif

#ifdef WIN32
#define check_removed_file(x) ({ strstr(x, ":\\$recycle.bin") ? 1 : 0; })
#endif

/**
 * @brief Thread that performs the syscheck data synchronization
 *
 * @param args To be used with NULL value
 */
#ifdef WIN32
DWORD WINAPI fim_run_integrity(void __attribute__((unused)) * args);
#else
void *fim_run_integrity(void *args);
#endif

/**
 * @brief Calculates the checksum of the FIM entry files and sends it to the database for integrity checking
 *
 * @param type Must be FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param mutex A mutex associated with the DB tables to be synchronized.
 */
void fim_sync_checksum(fim_type type, pthread_mutex_t *mutex);

/**
 * @brief Calculates the checksum of the FIM entry files starting from `start` letter and finishing at `top` letter
 * It also sends it to the database for integrity checking
 *
 * @param start The letter to start checking from
 * @param top The letter to finish checking to
 * @param id
 */
void fim_sync_checksum_split(const char *start, const char *top, long id);

// TODO
/**
 * @brief
 *
 * @param start
 * @param top
 */
void fim_sync_send_list(const char *start, const char *top);

/**
 * @brief Dispatches a message coming to the syscheck queue
 *
 * @param payload The message to dispatch
 */
void fim_sync_dispatch(char *payload);

/**
 * @brief Push a message to the syscheck queue
 *
 * @param msg The specific message to be pushed
 */
void fim_sync_push_msg(const char *msg);

/**
 * @brief Create file attribute set JSON from a FIM entry structure
 *
 * Format:
 * {
 *   type:        "file"|"registry"
 *   size:        number
 *   perm:        string
 *   user_name:   string
 *   group_name:  string
 *   uid:         string
 *   gid:         string
 *   inode:       number
 *   mtime:       number
 *   hash_md5:    string
 *   hash_sha1:   string
 *   hash_sha256: string
 *   checksum:    string
 * }
 *
 * @param data Pointer to a FIM entry structure.
 * @pre data is mutex-blocked.
 * @return Pointer to cJSON structure.
 */
cJSON * fim_attributes_json(const fim_file_data * data);

/**
 * @brief Create file entry JSON from a FIM entry structure
 *
 * Format:
 * {
 *   path:              string
 *   timestamp:         number
 *   attributes: {
 *     type:            "file"|"registry"
 *     size:            number
 *     perm:            string
 *     user_name:       string
 *     group_name:      string
 *     uid:             string
 *     gid:             string
 *     inode:           number
 *     mtime:           number
 *     hash_md5:        string
 *     hash_sha1:       string
 *     hash_sha256:     string
 *     win_attributes:  string
 *     symlink_path:    string
 *     checksum:        string
 *   }
 * }
 *
 * @param key Pointer to the key used in the manager fim_entry DB.
 * @param entry Pointer to a FIM entry structure.
 * @pre entry is mutex-blocked.
 * @return Pointer to cJSON structure.
 */
cJSON *fim_entry_json(const char *key, fim_entry *entry);

/**
 * @brief Create file attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - size
 * - permission
 * - uid
 * - user_name
 * - gid
 * - group_name
 * - mtime
 * - inode (UNIX only)
 * - md5
 * - sha1
 * - sha256
 *
 * @param old_data
 * @param new_data
 * @return cJSON*
 */
cJSON * fim_json_compare_attrs(const fim_file_data * old_data, const fim_file_data * new_data);

/**
 * @brief Create file audit data JSON object
 *
 * Format:
 * {
 *   user_id:        string
 *   user_name:      string
 *   group_id:       string
 *   group_name:     string
 *   process_name:   string
 *   audit_uid:      string
 *   audit_name:     string
 *   effective_uid:  string
 *   effective_name: string
 *   ppid:           number
 *   process_id:     number
 * }
 *
 * @param w_evt Pointer to event whodata structure
 * @return cJSON object pointer.
 */
cJSON * fim_audit_json(const whodata_evt * w_evt);

/**
 * @brief Create scan info JSON event
 *
 * Format:
 * {
 *   type:          "scan_start"|"scan_end"
 *   data: {
 *     timestamp:   number
 *   }
 * }
 *
 * @param event Event type (start or end).
 * @param timestamp Datetime in UNIX epoch.
 * @return cJSON object pointer.
 */

cJSON * fim_scan_info_json(fim_scan_event event, long timestamp);

/**
 * @brief Send a scan info event
 *
 * @param event Event type (start or end).
 */
void fim_send_scan_info(fim_scan_event event);

/**
 * @brief Checks the DB state, sends a message alert if necessary
 *
 */
void fim_check_db_state();

/**
 * @brief Checks the size of the queue/diff/local folder
 *
 */
void fim_diff_folder_size();

/**
 * @brief Get path from syscheck.dir or syscheck.symbolic_links, depending on whether there is a resolved path
 * configured in syscheck.symbolic_links or not.
 *
 * @param position Position of the directory in the structure
 * @return syscheck.symbolic_links[position] if not NULL, syscheck.dir[position] otherwise
 */
char *fim_get_real_path(int position);

#endif /* SYSCHECK_H */
