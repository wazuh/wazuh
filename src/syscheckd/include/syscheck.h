/* Copyright (C) 2015, Wazuh Inc.
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

#include "../../config/syscheck-config.h"
#include "commonDefs.h"
#include "syscheck_op.h"
#include <cJSON.h>

#define MAX_LINE PATH_MAX + 256

/* Notify list size */
#define NOTIFY_LIST_SIZE 32

/* Audit defs */
#define WDATA_DEFAULT_INTERVAL_SCAN 300
#define AUDIT_SOCKET                "queue/sockets/audit"
#define AUDIT_CONF_FILE             "etc/af_wazuh.conf"
#define AUDIT_HEALTHCHECK_DIR       "tmp"
#define AUDIT_HEALTHCHECK_KEY       "wazuh_hc"
#define AUDIT_HEALTHCHECK_FILE      "tmp/audit_hc"

#ifdef WIN32
#define FIM_REGULAR   _S_IFREG
#define FIM_DIRECTORY _S_IFDIR
#else
#define FIM_REGULAR   S_IFREG
#define FIM_DIRECTORY S_IFDIR
#define FIM_LINK      S_IFLNK
#endif

/* Win32 does not have lstat */
#ifdef WIN32
#define w_lstat(x, y) w_stat64(x, y)
#define stat          _stat64
#else
#define w_lstat(x, y) lstat(x, y)
#endif

/* Global config */
extern syscheck_config syscheck;
extern int sys_debug_level;
extern int audit_queue_full_reported;
extern int ebpf_kernel_queue_full_reported;

typedef enum fim_event_type
{
    FIM_ADD,
    FIM_DELETE,
    FIM_MODIFICATION
} fim_event_type;

typedef enum fim_scan_event
{
    FIM_SCAN_START,
    FIM_SCAN_END
} fim_scan_event;

typedef enum fim_state_db
{
    FIM_STATE_DB_EMPTY,
    FIM_STATE_DB_NORMAL,
    FIM_STATE_DB_80_PERCENTAGE,
    FIM_STATE_DB_90_PERCENTAGE,
    FIM_STATE_DB_FULL
} fim_state_db;

typedef struct _event_data_s
{
    int report_event;
    fim_event_mode mode;
    fim_event_type type;
    struct stat statbuf;
    whodata_evt* w_evt;
} event_data_t;

typedef struct fim_tmp_file
{
    union
    { // type_storage
        FILE* fd;
        W_Vector* list;
    };
    char* path;
    int elements;
} fim_tmp_file;

typedef struct diff_data
{
    int file_size;
    int size_limit;

    char* compress_folder;
    char* compress_file;

    char* tmp_folder;
    char* file_origin;
    char* uncompress_file;
    char* compress_tmp_file;
    char* diff_file;
} diff_data;

typedef struct callback_ctx
{
    event_data_t* event;
    const directory_t* config;
} callback_ctx;

typedef struct fim_txn_context_s
{
    event_data_t* evt_data;
    fim_entry* latest_entry;
} fim_txn_context_t;

#ifdef WIN32
/* Flags to know if a directory/file's watcher has been removed */
#define FIM_RT_HANDLE_CLOSED 0
#define FIM_RT_HANDLE_OPEN   1

/* Default value type for cases where type is undefined.
   0x0000000C is the one after the last defined type, REG_QWORD (0x0000000B) */
#define REG_UNKNOWN 0x0000000C
#endif

/** Function Prototypes **/

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
int Read_Syscheck_Config(const char* cfgfile) __attribute__((nonnull));

/**
 * @brief Get the Syscheck Config object
 *
 * @return JSON format configuration
 */
cJSON* getSyscheckConfig(void);

/**
 * @brief Get the Syscheck Internal Options object
 *
 * @return JSON format configuration
 */
cJSON* getSyscheckInternalOptions(void);

/**
 * @brief Read the syscheck internal options (to be deprecated)
 *
 * @param debug_level Debug level to be set in the syscheck daemon
 */
void read_internal(int debug_level);

/**
 * @brief Performs an integrity monitoring scan
 *
 * @return A timestamp taken as soons as the scan ends.
 */
time_t fim_scan();

/**
 * @brief Stop scanning files for one second if the max number of files scanned has been reached.
 *
 */
void check_max_fps();

/**
 * @brief
 *
 * @param [in] path Path of the file to check
 * @param [in] evt_data Information associated to the triggered event
 * @param [in] configuration Configuration block associated with a previous event.
 * @param [in] dbsync_txn Handle to an active dbsync transaction.
 */
void fim_checker(const char* path,
                 event_data_t* evt_data,
                 const directory_t* parent_configuration,
                 TXN_HANDLE dbsync_txn,
                 fim_txn_context_t* ctx);

/**
 * @brief Check file integrity monitoring on a specific folder
 *
 * @param [in] dir
 * @param [in] evt_data Information associated to the triggered event
 * @param [in] configuration Configuration block associated with the directory.
 * @param [in] txn_handle DBSync transaction handler. Can be NULL.
 *
 * @return 0 on success, -1 on failure
 */

int fim_directory(const char* dir,
                  event_data_t* evt_data,
                  const directory_t* configuration,
                  TXN_HANDLE dbsync_txn,
                  fim_txn_context_t* ctx);

/**
 * @brief Check file integrity monitoring on a specific file
 *
 * @param [in] path Path of the file to check
 * @param [in] configuration Configuration block associated with a previous event.
 * @param [in] evt_data Information associated to the triggered event
 * @param [in] txn_handle DBSync transaction handler. Can be NULL.
 * @param [in] ctx DBSync transaction context.
 */
void fim_file(const char* path,
              const directory_t* configuration,
              event_data_t* evt_data,
              TXN_HANDLE txn_handle,
              fim_txn_context_t* ctx);

/**
 * @brief Process FIM realtime event
 *
 * @param [in] file Path of the file to check
 */
void fim_realtime_event(char* file);

/**
 * @brief Process FIM whodata event
 *
 * @param w_evt Whodata event
 */
void fim_whodata_event(whodata_evt* w_evt);

/**
 * @brief Process a path that has possibly been deleted
 *
 * @note On Windows, calls function fim_checker meanwhile, on Linux, calls function fim_audit_inode_event. It's because
 * Windows haven't got inodes.
 * @param pathname Name of path
 * @param mode Monitoring FIM mode
 * @param w_evt Pointer to whodata information
 */
void fim_process_missing_entry(char* pathname, fim_event_mode mode, whodata_evt* w_evt);

/**
 * @brief Search the position of the path in directories array
 *
 * @param path Path to seek in the directories array
 * @return Returns a pointer to the configuration associated with the provided path, NULL if the path is not found
 */
directory_t* fim_configuration_directory(const char* path);

/**
 * @brief Update directories configuration with the wildcard list, at runtime
 *
 */
void update_wildcards_config();

/**
 * @brief Evaluates the depth of the directory or file to check if it exceeds the configured max_depth value
 *
 * @param path File name of the file/directory to check
 * @param configuration Configuration associated with the file
 * @return Depth of the directory/file, -1 on error
 */
int fim_check_depth(const char* path, const directory_t* configuration);

/**
 * @brief Get data from file
 *
 * @param file Name of the file to get the data from
 * @param [in] configuration Configuration block associated with a previous event.
 * @param [in] statbuf Buffer acquired from a stat command with information linked to 'path'
 *
 * @return A fim_file_data structure with the data from the file
 */
fim_file_data* fim_get_data(const char* file, const directory_t* configuration, const struct stat* statbuf);

/**
 * @brief Initialize a fim_file_data structure
 *
 * @param [out] data Data to initialize
 */
void init_fim_data_entry(fim_file_data* data);

/**
 * @brief Calculate checksum of a FIM entry data
 *
 * @param data FIM entry data to calculate the checksum with
 */
void fim_get_checksum(fim_file_data* data);

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
 * @param new_data Current file state.
 * @param old_data Previous file state.
 * @param configuration Pointer to the related configuration stanza.
 * @param evt_data Information associated to the triggered event
 * @param diff File diff if applicable.
 * @return File event JSON object.
 * @retval NULL No changes detected. Do not send an event.
 */
cJSON* fim_json_event(const fim_entry* new_data,
                      const fim_file_data* old_data,
                      const directory_t* configuration,
                      const event_data_t* evt_data,
                      const char* diff);

/**
 * @brief Frees the memory of a FIM entry data structure
 *
 * @param [out] data The FIM entry data to be freed
 */
void free_file_data(fim_file_data* data);

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
 * @param configuration Configuration associated with the file or directory
 * @return 1 on success, -1 on realtime_start failure, -2 on set_winsacl failure, and 0 on other errors
 */
int realtime_adddir(const char* dir, directory_t* configuration);

#ifdef INOTIFY_ENABLED
/**
 * @brief Add an inotify watch to monitoring directory
 *
 * @param dir Path to file or directory
 * @param configuration Configuration associated with the file or directory
 * @return 1 on success, -1 on failure
 */
int fim_add_inotify_watch(const char* dir, const directory_t* configuration);
#endif

/**
 * @brief Remove an inotify watch
 *
 * @param configuration Configuration associated with the file or directory
 */
void fim_realtime_delete_watches(const directory_t* configuration);

/**
 * @brief Check whether the realtime event queue has overflown.
 *
 * @return 0 if the queue hasn't overflown, 1 otherwise.
 */
int fim_realtime_get_queue_overflow();

/**
 * @brief Set the value of the queue overflown flag.
 *
 * @param value The new value to set the queue overflow flag.
 */
void fim_realtime_set_queue_overflow(int value);

/**
 * @brief Log the number of realtime watches currently set.
 */
void fim_realtime_print_watches();

/**
 * @brief Process events in the real time queue
 *
 */
void realtime_process(void);

/**
 * @brief Deletes subdirectories watches when a folder changes its name
 *
 * @param dir Directory whose subdirectories need to delete their watches
 */

void delete_subdirectories_watches(char* dir);

/**
 * @brief Remove stale watches from the realtime hashmap
 */
void realtime_sanitize_watch_map();

/**
 * @brief Frees the memory of a Whodata event structure
 *
 * @param [out] w_evt
 */
void free_whodata_event(whodata_evt* w_evt);

/**
 * @brief Send a message related to syscheck change/addition
 *
 * @param msg The message to be sent
 */
void send_syscheck_msg(const cJSON* msg) __attribute__((nonnull));

// TODO
/**
 * @brief
 *
 * @param msg
 * @return int
 */
int send_log_msg(const char* msg);

#ifdef __linux__
#define READING_MODE     0
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
char* audit_get_id(const char* event);

/**
 * @brief Initialize regular expressions
 *
 * @return 0 on success, -1 on error
 */
int init_regex(void);

/**
 * @brief Adds audit rules to directories
 *
 * @param path Path of the configured rule
 */
void add_whodata_directory(const char* path);

/**
 * @brief Function the delete the audit rule for a specfic path
 *
 * @param path: Path of the configured rule.
 */
void remove_audit_rule_syscheck(const char* path);

/**
 * @brief Read an audit event from socket
 *
 * @param [out] audit_sock The audit socket to read the events from
 * @param [in] running atomic_int that holds the status of the running thread.
 */
void audit_read_events(int* audit_sock, atomic_int_t* running);

/**
 * @brief Thread in charge of pulling messages from the audit queue and parse them to generate events.
 */
void* audit_parse_thread();

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
 * @brief Create the necessary file to store the audit rules to be loaded by the immutable mode.
 *
 */
void audit_create_rules_file();

/**
 * @brief Set all directories that don't have audit rules and have whodata enabled to realtime.
 *
 */
void audit_rules_to_realtime();

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
 * @brief Reloads audit rules every RELOAD_RULES_INTERVAL seconds
 *
 */
void* audit_reload_thread();

/**
 * @brief Thread that performs a healthcheck on audit
 * It reads an event from audit socket to check if it's running
 *
 * @param [out] audit_sock The audit socket to read the events from
 */
void* audit_healthcheck_thread(int* audit_sock);

// TODO
/**
 * @brief
 *
 * @param cwd
 * @param path0
 * @param path1
 * @return A string with generated path
 */
char* gen_audit_path(char* cwd, char* path0, char* path1);

/**
 * @brief Add cwd and exe of parent process
 *
 * @param ppid ID of parent process
 * @param parent_name String where save the parent name (exe)
 * @param parent_cwd String where save the parent working directory (cwd)
 */
void get_parent_process_info(char* ppid, char** const parent_name, char** const parent_cwd);

/**
 * @brief Reloads audit rules to configured directories
 * This is necessary to include audit rules for hot added directories in the configuration
 *
 */
void fim_audit_reload_rules(void);

/**
 * @brief Parses an audit event and sends the corresponding alert message
 *
 * @param buffer The audit event to parse
 */
void audit_parse(char* buffer);

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
 * @param configuration The configuration associated with the folder.
 * @return 0 on success, 1 on error
 */
int set_winsacl(const char* dir, directory_t* configuration);

/**
 * @brief In case SACLs and policies have been set, restore them
 */
void audit_restore();

/**
 * @brief Thread that checks the status of the whodata configured folders
 * It checks if the folder has ben re-added, if its SACL has been changed or if it has been deleted.
 *
 */

long unsigned int WINAPI state_checker(__attribute__((unused)) void* _void);

/**
 * @brief Function that generates the diff file of a Windows registry when the option report_changes is activated
 * It creates a file with the content of the value, to compute differences
 *
 * @param key_name Path of the registry key monitored
 * @param value_name Name of the value that has generated the alert
 * @param value_data Content of the value to be checked
 * @param data_type The type of value we are checking
 * @param configuration Config of the registry key
 * @return String with the changes to add to the alert
 */

char* fim_registry_value_diff(const char* key_name,
                              const char* value_name,
                              const char* value_data,
                              DWORD data_type,
                              const registry_t* configuration);
#endif

/**
 * @brief Function that generates the diff file of a file monitored when the option report_changes is activated
 *
 * @param filename Path of file monitored
 * @param configuration Configuration associated with the given path.
 * @return String with the diff to add to the alert
 */

char* fim_file_diff(const char* filename, const directory_t* configuration);

/**
 * @brief Deletes the filename diff folder and modify diff_folder_size if disk_quota enabled
 *
 * @param filename Path of the file that has been deleted
 */
void fim_diff_process_delete_file(const char* filename);

#ifdef WIN32
/**
 * @brief Deletes the registry diff folder and modify diff_folder_size if disk_quota enabled
 *
 * @param key_name Path of the registry that has been deleted
 * @param arch Arch type of the registry
 */
void fim_diff_process_delete_registry(const char* key_name, int arch);

/**
 * @brief Deletes the value diff folder and modifies diff_folder_size if disk_quota enabled
 *
 * @param key_name Path of the registry that contains the deleted value
 * @param value_name Path of the value that has been deleted
 * @param arch Arch type of the registry
 */
void fim_diff_process_delete_value(const char* key_name, const char* value_name, int arch);
#endif

/**
 * @brief Initializes all syscheck data
 *
 */
void fim_initialize();

/**
 * @brief Initializes Windows whodata thread, or send signal to start audit threat in Linux
 *
 */
int fim_whodata_initialize();

/**
 * @brief Checks if a specific file has been configured to be ignored
 *
 * @param file_name The name of the file to check
 * @return 1 if it has been configured to be ignored, 0 if not
 */
int fim_check_ignore(const char* file_name);

/**
 * @brief Checks if a specific folder has been configured to be checked with a specific restriction
 *
 * @param file_name The name of the file to check
 * @param restriction The regex restriction to be checked
 * @return 1 if the folder has been configured with the specified restriction, 0 if not
 */
int fim_check_restrict(const char* file_name, OSMatch* restriction);

#ifndef WIN32

/**
 * @brief Thread that creates a socket for communication with the API
 * Com request thread dispatcher
 *
 * @param Argument to be passed to the thread
 */
void* syscom_main(void* arg);
#endif

/**
 * @brief Dispatches messages from API directed to syscheck module
 *
 * @param [in] command The input command sent from the API
 * @param [out] output The output buffer to be filled (answer for the API)
 * @return The size of the output buffer
 */
size_t syscom_dispatch(char* command, char** output);

/**
 * @brief
 *
 * @param [in] section The specific section to be checked sent from the API
 * @param [out] output The output buffer to be filled (answer for the API)
 * @return The size of the output buffer
 */
size_t syscom_getconfig(const char* section, char** output);

#ifdef WIN_WHODATA
/**
 * @brief Updates the SACL of an specific file
 *
 * @param obj_path The path of the file to update the SACL of
 * @return 0 on success, -1 on error
 */
int w_update_sacl(const char* obj_path);
#endif

#ifdef WIN32
#define check_removed_file(x) ({ strstr(x, ":\\$recycle.bin") ? 1 : 0; })

/**
 * @brief Get the number of realtime watches opened by FIM.
 *
 * @return Number of realtime watches.
 */
unsigned int get_realtime_watches();
#endif

/**
 * @brief Create file attribute set JSON from a FIM entry structure
 *
 * Format:
 * {
 *   type:        "file"|"registry"
 *   size:        number
 *   permissions: string
 *   owner:       string
 *   group_:      string
 *   uid:         string
 *   gid:         string
 *   inode:       number
 *   mtime:       number
 *   hash_md5:    string
 *   hash_sha1:   string
 *   hash_sha256: string
 *   attributes:  string
 *   checksum:    string
 * }
 *
 * @param dbsync_event Pointer to event dbsync JSON structure.
 * @param data Pointer to a FIM entry structure.
 * @param configuration Pointer to the configuration structure.
 * @pre data is mutex-blocked.
 * @return Pointer to cJSON structure.
 */
cJSON* fim_attributes_json(const cJSON* dbsync_event, const fim_file_data* data, const directory_t* configuration);

/**
 * @brief Create file attribute comparison JSON object
 *
 * Format: array of strings, with the following possible strings:
 * - size
 * - permissions
 * - attributes
 * - uid
 * - owner
 * - gid
 * - group_
 * - mtime
 * - inode (UNIX only)
 * - md5
 * - sha1
 * - sha256
 *
 * @param old_data
 * @param new_data
 * @param configuration
 * @return cJSON*
 */
cJSON*
fim_json_compare_attrs(const fim_file_data* old_data, const fim_file_data* new_data, const directory_t* configuration);

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
cJSON* fim_audit_json(const whodata_evt* w_evt);

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
 * @brief Get the directory that will be effectively monitored depending on configuration the entry configuration and
 * physical object in the filesystem
 *
 * @param dir Pointer to the configuration associated with the directory
 * @return A string holding the element being monitored. It must be freed after it's usage.
 */
char* fim_get_real_path(const directory_t* dir);

/**
 * @brief Create a delete event and removes the entry from the database.
 *
 * @param file_path path data to be removed.
 * @param evt_data Information associated to the triggered event.
 * @param configuration Directory configuration to be deleted.
 *
 */
int fim_generate_delete_event(const char* file_path, const void* evt_data, const void* configuration);

/**
 * @brief Get shutdown process flag.
 *
 * @return Process shutdown flag.
 */
bool fim_shutdown_process_on();

#ifdef __linux__
#ifdef ENABLE_AUDIT
/**
 * @brief Initializes eBPF and does the healthcheck to check availability.
 */
void check_ebpf_availability();
#endif /* ENABLE_AUDIT */
#endif
#endif /* SYSCHECK_H */
