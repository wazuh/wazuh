/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYSCHECKC_H
#define SYSCHECKC_H

typedef enum fim_event_mode {
    FIM_SCHEDULED,
    FIM_REALTIME,
    FIM_WHODATA
} fim_event_mode;

typedef enum fdb_stmt {
    // Files
    FIMDB_STMT_REPLACE_ENTRY,
    FIMDB_STMT_GET_PATH,
    FIMDB_STMT_GET_LAST_PATH,
    FIMDB_STMT_GET_FIRST_PATH,
    FIMDB_STMT_GET_ALL_CHECKSUMS,
    FIMDB_STMT_GET_NOT_SCANNED,
    FIMDB_STMT_SET_ALL_UNSCANNED,
    FIMDB_STMT_GET_COUNT_RANGE,
    FIMDB_STMT_GET_PATH_RANGE,
    FIMDB_STMT_DELETE_PATH,
    FIMDB_STMT_GET_PATHS_INODE,
    FIMDB_STMT_SET_SCANNED,
    FIMDB_STMT_GET_COUNT_PATH,
    FIMDB_STMT_GET_COUNT_INODE,
    FIMDB_STMT_GET_PATH_FROM_PATTERN,
    // Registries
#ifdef WIN32
    FIMDB_STMT_REPLACE_REG_DATA,
    FIMDB_STMT_REPLACE_REG_KEY,
    FIMDB_STMT_GET_REG_KEY,
    FIMDB_STMT_GET_REG_DATA,
    FIMDB_STMT_GET_REG_KEY_NOT_SCANNED,
    FIMDB_STMT_GET_REG_DATA_NOT_SCANNED,
    FIMDB_STMT_SET_ALL_REG_KEY_UNSCANNED,
    FIMDB_STMT_SET_REG_KEY_UNSCANNED,
    FIMDB_STMT_SET_ALL_REG_DATA_UNSCANNED,
    FIMDB_STMT_SET_REG_DATA_UNSCANNED,
    FIMDB_STMT_GET_REG_ROWID,
    FIMDB_STMT_DELETE_REG_KEY_PATH,
    FIMDB_STMT_DELETE_REG_DATA,
    FIMDB_STMT_DELETE_REG_DATA_PATH,
    FIMDB_STMT_GET_COUNT_REG_KEY,
    FIMDB_STMT_GET_COUNT_REG_DATA,
    FIMDB_STMT_GET_COUNT_REG_KEY_AND_DATA,
    FIMDB_STMT_GET_LAST_REG_KEY,
    FIMDB_STMT_GET_FIRST_REG_KEY,
    FIMDB_STMT_SET_REG_DATA_SCANNED,
    FIMDB_STMT_SET_REG_KEY_SCANNED,
    FIMDB_STMT_GET_REG_KEY_ROWID,
    FIMDB_STMT_GET_REG_DATA_ROWID,
#endif
    FIMDB_STMT_GET_REG_PATH_RANGE,
    FIMDB_STMT_GET_REG_LAST_PATH,
    FIMDB_STMT_GET_REG_FIRST_PATH,
    FIMDB_STMT_GET_REG_ALL_CHECKSUMS,
    FIMDB_STMT_GET_REG_COUNT_RANGE,
    FIMDB_STMT_COUNT_DB_ENTRIES,

    FIMDB_STMT_SIZE
} fdb_stmt;

#define FIM_MODE(x) (x & WHODATA_ACTIVE ? FIM_WHODATA : x & REALTIME_ACTIVE ? FIM_REALTIME : FIM_SCHEDULED)

#if defined(WIN32) && defined(EVENTCHANNEL_SUPPORT)
#define WIN_WHODATA 1
#endif

#define MAX_DIR_SIZE    64
#define MAX_DIR_ENTRY   128
#define SYSCHECK_WAIT   1
#define MAX_FILE_LIMIT  INT_MAX
#define MIN_COMP_ESTIM  0.4         // Minimum value to be taken by syscheck.comp_estimation_perc

/* Checking options */
#define CHECK_SIZE          00000001
#define CHECK_PERM          00000002
#define CHECK_OWNER         00000004
#define CHECK_GROUP         00000010
#define CHECK_MTIME         00000020
#define CHECK_INODE         00000040
#define CHECK_MD5SUM        00000100
#define CHECK_SHA1SUM       00000200
#define CHECK_SHA256SUM     00000400
// 0001000 0002000 0004000 Reserved for future hash functions
#define CHECK_ATTRS         00010000
#define CHECK_SEECHANGES    00020000
#define CHECK_FOLLOW        00040000
#define REALTIME_ACTIVE     00100000
#define WHODATA_ACTIVE      00200000
#define SCHEDULED_ACTIVE    00400000
#define CHECK_TYPE          01000000
#define EBPF_PROVIDER       00000000
#define AUDIT_PROVIDER      00000001

#ifdef WIN32
#define REGISTRY_CHECK_ALL                                                                                  \
    (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_SIZE | CHECK_OWNER | CHECK_GROUP | CHECK_PERM | \
     CHECK_MTIME | CHECK_TYPE)
#define CHECK_SUM (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM)
#endif

#define ARCH_32BIT          0
#define ARCH_64BIT          1
#define ARCH_BOTH           2

#ifdef WIN32
/* Whodata  states */
#define WD_STATUS_FILE_TYPE 1
#define WD_STATUS_DIR_TYPE  2
#define WD_STATUS_UNK_TYPE  3
#define WD_SETUP_AUTO       0
#define WD_SETUP_SUCC       1
#define WD_SETUP_SUCC_FAIL  2
#define WD_STATUS_EXISTS    0x0000001
#define WD_CHECK_WHODATA    0x0000002
#define WD_CHECK_REALTIME   0x0000004
#define WD_IGNORE_REST      0x0000008
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

#define SK_CONF_UNPARSED    -2
#define SK_CONF_UNDEFINED   -1

#define FIM_DB_MEMORY       1
#define FIM_DB_DISK         0

//Max allowed value for recursion
#define MAX_DEPTH_ALLOWED 320
#ifdef WIN32
#define MAX_REGISTRY_DEPTH 512
#endif

#include "../os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"
#include "integrity_op.h"
#include "../external/sqlite/sqlite3.h"
#include "../headers/list_op.h"

#ifdef WIN32
typedef struct whodata_dir_status whodata_dir_status;
#endif

#ifndef WIN32
typedef struct _rtfim {
    unsigned int queue_overflow:1;
    OSHash *dirtb;
    int fd;
} rtfim;

#else

typedef struct _rtfim {
    unsigned int queue_overflow:1;
    OSHash *dirtb;
    HANDLE evt;
} rtfim;

typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    TCHAR buffer[65536];
    unsigned int watch_status;
} win32rtfim;

#endif

typedef enum fim_type {FIM_TYPE_FILE, FIM_TYPE_REGISTRY} fim_type;

#ifdef WIN32

typedef struct whodata_dir_status {
    int status;
    char object_type;
    SYSTEMTIME last_check;
} whodata_dir_status;

typedef ULARGE_INTEGER whodata_directory;

typedef struct whodata {
    OSHash *fd;          // Open file descriptors
    OSHash *directories; // Directories checked by whodata mode
    int interval_scan;   // Time interval between scans of the checking thread
    char **device;        // Hard disk devices
    char **drive;         // Drive letter
} whodata;

#endif /* End WIN32*/

typedef struct _directory_s {
    char *path;
    int options;
    int diff_size_limit; /* Apply the file size limit option in a specific directory */
    char *symbolic_links;
    OSMatch *filerestrict;
    int recursion_level;
    char *tag; /* array of tags for each directory */
#ifdef WIN32
    // Windows specific fields
    whodata_dir_status dirs_status; // Status list
#endif
    unsigned int is_wildcard:1; // 1 if it is a wildcard, 0 if it is a directory
    unsigned int is_expanded:1; // Indicates if the wilcard has been expanded in this scan
} directory_t;

typedef struct whodata_evt {
    char *user_id;
    char *user_name;
    char *process_name;
    char *path;
#ifndef WIN32
    char *group_id;  // Linux
    char *group_name;  // Linux
    char *audit_uid;  // Linux
    char *audit_name;  // Linux
    char *effective_uid;  // Linux
    char *effective_name;  // Linux
    char *inode;  // Linux
    char *dev;  // Linux
    char *parent_name; // Linux
    char *parent_cwd;
    int ppid;  // Linux
    char *cwd; // Linux
    unsigned int process_id;
#else
    unsigned __int64 process_id;
    unsigned int mask;
    char scan_directory;
#endif
} whodata_evt;

#ifdef WIN32

typedef struct _registry_s {
    char *entry;
    int arch;
    int opts;
    int recursion_level;
    int diff_size_limit;
    OSMatch *restrict_key;
    OSMatch *restrict_value;
    char *tag;
} registry_t;

typedef struct registry_ignore {
    char *entry;
    int arch;
} registry_ignore;

typedef struct registry_ignore_regex {
    OSMatch *regex;
    int arch;
} registry_ignore_regex;

#endif

typedef struct fim_file_data {
#ifdef WIN32
    cJSON * perm_json;
#endif
    char * permissions;
    char * attributes;
    char * uid;
    char * gid;
    char * owner;
    char * group;
    time_t mtime;
    unsigned long long int size;
    unsigned long long int inode;
    unsigned long int device;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;

    // Checksum
    os_sha1 checksum;
} fim_file_data;

typedef struct fim_registry_key {
    char* path;
#ifdef WIN32
    cJSON* perm_json;
#endif
    char* permissions;
    char* uid;
    char* gid;
    char* owner;
    char* group;
    time_t mtime;
    int architecture;

    // Checksum
    os_sha1 checksum;
} fim_registry_key;

typedef struct fim_registry_value_data {
    char* path;
    char* value;
    unsigned int type;
    unsigned long long int size;
    os_md5 hash_md5;
    os_sha1 hash_sha1;
    os_sha256 hash_sha256;
    int architecture;

    // Checksum
    os_sha1 checksum;
} fim_registry_value_data;

typedef struct fim_entry {
    fim_type type;
    union {
        struct {
            char *path;
            fim_file_data *data;
        } file_entry;
        struct {
            fim_registry_key *key;
            fim_registry_value_data *value;
        } registry_entry;
    };

} fim_entry;


typedef struct fdb_transaction_t
{
    time_t last_commit;
    time_t interval;
} fdb_transaction_t;

typedef struct fdb_t {
    sqlite3 *db;
    sqlite3_stmt *stmt[FIMDB_STMT_SIZE];
    fdb_transaction_t transaction;
    volatile bool full;
    pthread_mutex_t mutex;
} fdb_t;

typedef struct _config {
    int rootcheck;                                     /* set to 0 when rootcheck is disabled */
    int disabled;                                      /* is syscheck disabled? */
    int scan_on_start;
    int max_depth;                                     /* max level of recursivity allowed */
    size_t file_max_size;                              /* max file size for calculating hashes */

    fs_set skip_fs;
    int rt_delay;                                      /* Delay before real-time dispatching (ms) */

    int time;                                          /* frequency (secs) for syscheck to run */
    int queue;                                         /* file descriptor of socket to write to queue */
    unsigned int restart_audit:1;                      /* Allow Syscheck restart Auditd */
    unsigned int enable_whodata:1;                     /* At least one directory configured with whodata */
    unsigned int whodata_provider:1;                   /* Select the whodata provider */
    unsigned int realtime_change:1;                    /* Variable to activate the change to realtime from a whodata monitoring*/

    OSList *directories;                               /* List of directories to be monitored */
    OSList *wildcards;                                 /* List of wildcards to be monitored */

    char *scan_day;                                    /* run syscheck on this day */
    char *scan_time;                                   /* run syscheck at this time */

    unsigned int file_limit_enabled;                   /* Enable FIM file entry max limits */
    int file_entry_limit;                              /* maximum number of files to monitor */

    char **ignore;                                     /* list of files/dirs to ignore */
    OSMatch **ignore_regex;                            /* regex of files/dirs to ignore */

    int disk_quota_enabled;                            /* Enable diff disk quota limit */
    int disk_quota_limit;                              /* Controls the increase of the size of the queue/diff/local folder (in KB) */
    int file_size_enabled;                             /* Enable diff file size limit */
    int file_size_limit;                               /* Avoids generating a backup from a file bigger than this limit (in KB) */
    float diff_folder_size;                            /* Save size of queue/diff/local folder */
    float comp_estimation_perc;                        /* Estimation of the percentage of compression each file will have */
    uint16_t disk_quota_full_msg;                      /* Specify if the full disk_quota message can be written (Once per scan) */

    unsigned int max_files_per_second;                 /* Max number of files read per second. */

    char **nodiff;                                     /* list of files/dirs to never output diff */
    OSMatch **nodiff_regex;                            /* regex of files/dirs to never output diff */

    int max_eps;                                       /* Maximum events per second. */

    /* Windows only registry checking */
#ifdef WIN32
    unsigned int registry_limit_enabled;               /* Enable FIM registry entry max limits */
    int db_entry_registry_limit;                       /* maximum number of registries to monitor */
    registry_ignore *key_ignore;                       /* List of registry keys to ignore */
    registry_ignore_regex *key_ignore_regex;           /* Regex of registry keys to ignore */
    registry_ignore *value_ignore;                     /* List of registry values to ignore*/
    registry_ignore_regex *value_ignore_regex;         /* Regex of registry values to ignore */
    registry_t *registry;                              /* array of registry entries to be scanned */
    unsigned int max_fd_win_rt;                        /* Maximum number of descriptors in realtime */
    whodata wdata;                                     /* Whodata struct */
    registry_t *registry_nodiff;                       /* list of values/registries to never output diff */
    registry_ignore_regex *registry_nodiff_regex;      /* regex of values/registries to never output diff */
#endif
    int max_audit_entries;                             /* Maximum entries for Audit (whodata) */
    char **audit_key;                                  /* Listen audit keys */
    int audit_healthcheck;                             /* Startup health-check for whodata */
    int sym_checker_interval;

    pthread_rwlock_t directories_lock;
    pthread_mutex_t fim_scan_mutex;
    pthread_mutex_t fim_realtime_mutex;
#ifndef WIN32
    pthread_mutex_t fim_symlink_mutex;
    unsigned int queue_size;                           /* Linux Audit message queue size for whodata */
#endif
    rtfim *realtime;
    fdb_t *database;
    int database_store;

    char **prefilter_cmd;
    int process_priority; // Adjusts the priority of the process (or threads in Windows)
    bool allow_remote_prefilter_cmd;
} syscheck_config;


/**
 * @brief Initializes the default configuration for syscheck.
 *
 * @param syscheck Configuration structure to initizalize. If NULL, the function will return OS_INVALID.
 * @retval OS_SUCCESS if the default configuration was loaded successfully.
 * @retval OS_INVALID if there is a problem allocating resources.
 */
int initialize_syscheck_configuration(syscheck_config *syscheck);

/**
 * @brief Converts the value written in the configuration to a determined data unit in KB
 *
 * @param content Read content from the configuration
 *
 * @return Read value on success, -1 on failure
 */
int read_data_unit(const char *content);

/**
 * @brief Read diff configuration
 *
 * Read disk_quota, file_size and nodiff options
 *
 * @param xml XML structure containing Wazuh's configuration
 * @param syscheck Syscheck configuration structure
 * @param node XML node to continue reading the configuration file
 */
void parse_diff(const OS_XML *xml, syscheck_config * syscheck, XML_NODE node);

/**
 * @brief Change sysnative directory to system32.
 *
 * @param path Directory path read from configuration file
 */
void fim_adjust_path(char** path);

/**
 * @brief Creates a directory_t object from defined values
 *
 * @param path Path to be dumped
 * @param options Indicates the attributes for folders or registries to be set
 * @param filerestrict The restrict string to be set
 * @param recursion_level The recursion level to be set
 * @param tag The tag to be set
 * @param diff_size_limit Maximum size to calculate diff for files in the directory
 * @param is_wildcard Boolean that indicates if this is a wildcard or not
 */
directory_t *fim_create_directory(const char *path,
                                  int options,
                                  const char *filerestrict,
                                  int recursion_level,
                                  const char *tag,
                                  int diff_size_limit,
                                  unsigned int is_wildcard);

/**
 * @brief Inserts the directory_t 'config_object' into the directory_t OSList 'config_list'
 *
 * @param config_list directory_t OSList from the syscheck configuration, passed by reference
 * @param config_object directory_t object to be inserted
 */
void fim_insert_directory(OSList *config_list,
                          directory_t *config_object);

/**
 * @brief Copies a given directory_t object and returns a reference to the copy.
 *
 * @param _dir directory_t object to be copied
 */
directory_t *fim_copy_directory(const directory_t *_dir);

/**
 * @brief Expands wildcards in the given path
 *
 * @param path Path to be expanded
 */
char **expand_wildcards(const char *path);

#ifdef WIN32
/**
 * @brief Adds (or overwrite if exists) an entry to the syscheck configuration structure
 *
 * @param syscheck Syscheck configuration structure
 * @param entry Entry to be dumped
 * @param opts Indicates the attributes for registries to be set
 * @param restrict_key The restrict regex to be set for keys.
 * @param restrict_key The restrict regex to be set for values.
 * @param recursion_level The recursion level to be set
 * @param tag The tag to be set
 * @param arch Indicates whether to monitor the 64 or 32 version of the registry
 * @param diff_size Maximum size to calculate diff for files in the directory
 */
void dump_syscheck_registry(syscheck_config *syscheck,
                            char *entry,
                            int opts,
                            const char *restrict_key,
                            const char *restrict_value,
                            int recursion_level,
                            const char *tag,
                            int arch,
                            int diff_size);
#endif

/**
 * @brief Converts a bit mask with syscheck options to a human readable format
 *
 * @param [out] buf The buffer to write the check options in
 * @param [in] buflen The size of the buffer
 * @param [in] opts The bit mask of the options
 * @return A text version of the directory check option bits
 */
char *syscheck_opts2str(char *buf, int buflen, int opts);

/**
 * @brief Frees the memory of a syscheck configuration structure
 *
 * @param [out] config The syscheck configuration to free
 */
void Free_Syscheck(syscheck_config *config);

/**
 * @brief Frees the memory of a directory_t structure
 *
 * @param dir The directory to be free'd
 */
void free_directory(directory_t *dir);

/**
 * @brief Logs the real time engine status
 *
 */
void log_realtime_status(int);

#endif /* SYSCHECKC_H */
