/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"
#include "state.h"
#include <math.h>
#include <pthread.h>
#include "sysinfo_utils.h"
#include <openssl/evp.h>

// Remove STATIC qualifier from tests
#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#define MAX_ASCII_LINES 10
#define MAX_UTF8_CHARS 1400
#define OFFSET_SIZE     21  ///< Maximum 64-bit integer is 20-char long, plus 1 because of the '\0'

/* Prototypes */
static int update_fname(int i, int j);
static int update_current(logreader **current, int *i, int *j);
static void set_read(logreader *current, int i, int j);
static IT_control remove_duplicates(logreader *current, int i, int j);
static int find_duplicate_inode(logreader * lf);
static void set_sockets();
static void files_lock_init(void);
static void check_text_only();
static int check_pattern_expand(int do_seek);
static void check_pattern_expand_excluded();
static void set_can_read(int value);

/**
 * @brief Releases the data structure stored in the hash table 'files_status'.
 * @param data Structure of the data to be released
 */
STATIC void free_files_status_data(os_file_status_t *data);

/**
 * @brief Create files_status hash and load the previous estatus from JSON file
 */
STATIC void w_initialize_file_status();

/**
 * @brief Before stop logcollector save the files_status hash on JSON file
 */
STATIC void w_save_file_status();

/**
 * @brief Load files_status data to hash
 * @param global_json json wich contains the previous files_status hash
 */
STATIC void w_load_files_status(cJSON *global_json);

/**
 * @brief Parse the hash files_status to JSON
 * @return json of all read status files in a string
 */
STATIC char * w_save_files_status_to_cJSON();

/**
 * @brief Set file on the last line read or on the end in case the status hasn't been saved.
 * @param lf logreader to set
 * @return 0 on success, otherwise -1
 */
STATIC int w_set_to_last_line_read(logreader *lf);

/**
 * @brief Set file on the end
 * @param lf logreader to set
 * @return 0 on success, otherwise -1
 */
STATIC int64_t w_set_to_pos(logreader *lf, int64_t pos, int mode);

/**
 * @brief Update or add (if it not exit) hash node
 * @param path Hash key
 * @param pos Offset of hash
 * @return 0 on success, otherwise -1
 */
STATIC int w_update_hash_node(char * path, int64_t pos);

/* Global variables */
int loop_timeout;
int logr_queue;
int open_file_attempts;
logreader *logff;
logreader_glob *globs;
socket_forwarder *logsk;
int vcheck_files;
int maximum_lines;
int sample_log_length;
int force_reload;
int reload_interval;
int reload_delay;
int free_excluded_files_interval;
int state_interval;
OSHash * msg_queues_table;

///< To asociate the path, the position to read, and the hash key of lines read.
OSHash * files_status;
///< Use for log messages
char *files_status_name = "file_status";
static int _cday = 0;
int N_INPUT_THREADS = N_MIN_INPUT_THREADS;
int OUTPUT_QUEUE_SIZE = OUTPUT_MIN_QUEUE_SIZE;
socket_forwarder default_agent = { .name = "agent" };
logtarget default_target[2] = { { .log_socket = &default_agent } };

/* Output thread variables */
static pthread_mutex_t mutex;
#ifdef WIN32
static pthread_mutex_t win_el_mutex;
static pthread_mutexattr_t win_el_mutex_attr;
#endif

/* can read synchronization */
static int _can_read = 0;
static rwlock_t can_read_rwlock;

/* Multiple readers / one write mutex */
static rwlock_t files_update_rwlock;

static OSHash *excluded_files = NULL;
static OSHash *excluded_binaries = NULL;

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))

STATIC w_macos_log_procceses_t * macos_processes = NULL;

#endif

int check_ignore_and_restrict(OSList * ignore_exp_list, OSList * restrict_exp_list, const char *log_line) {
    OSListNode *node_it;
    w_expression_t *exp_it;

    if (ignore_exp_list) {
        OSList_foreach(node_it, ignore_exp_list) {
            exp_it = node_it->data;
            /* Check ignore regex, if it matches, do not process the log */
            if (w_expression_match(exp_it, log_line, NULL, NULL)) {
                mdebug2(LF_MATCH_REGEX, log_line, "ignore", w_expression_get_regex_pattern(exp_it));
                return true;
            }
        }
    }

    if (restrict_exp_list) {
        OSList_foreach(node_it, restrict_exp_list) {
            exp_it = node_it->data;
            /* Check restrict regex, only if match every log is processed */
            if (!w_expression_match(exp_it, log_line, NULL, NULL)) {
                mdebug2(LF_MATCH_REGEX, log_line, "restrict", w_expression_get_regex_pattern(exp_it));
                return true;
            }
        }
    }

    return false;
}

/* Handle file management */
void LogCollectorStart()
{
    int i = 0, j = -1, tg;
    int f_check = 0;
    int f_reload = 0;
    int f_free_excluded = 0;
    IT_control f_control = 0;
    IT_control duplicates_removed = 0;
    logreader *current;

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
    w_sysinfo_helpers_t * sysinfo = NULL;
    os_calloc(1, sizeof(w_sysinfo_helpers_t), sysinfo);
    if (!w_sysinfo_init(sysinfo)) {
        merror(SYSINFO_DYNAMIC_INIT_ERROR);
    }
#endif

    /* Create store data */
    excluded_files = OSHash_Create();
    if (!excluded_files) {
        merror_exit(LIST_ERROR);
    }

    /* Create store for binaries data */
    excluded_binaries = OSHash_Create();
    if (!excluded_binaries) {
        merror_exit(LIST_ERROR);
    }

    /* Initialize status file struct (files_status) and set w_save_file_status at the process exit */
    w_initialize_file_status();

    if (atexit(w_save_file_status)) {
        merror(ATEXIT_ERROR);
    }

    /* Initialize state component */
    if (state_interval == 0) {
        w_logcollector_state_init(LC_STATE_GLOBAL, false);
    } else if (state_interval > 0) {
        w_logcollector_state_init(LC_STATE_GLOBAL | LC_STATE_INTERVAL, true);
    }


    /* Create the state thread */
#ifndef WIN32
    w_create_thread(w_logcollector_state_main, (void *) &state_interval);
#else
    w_create_thread(NULL,
                    0,
                    w_logcollector_state_main,
                    (void *) &state_interval,
                    0,
                    NULL);
#endif

    set_sockets();
    files_lock_init();

    // Check for expanded files
    check_pattern_expand(1);
    check_pattern_expand_excluded();

    w_mutex_init(&mutex, NULL);
#ifndef WIN32
    /* To check for inode changes */
    struct stat tmp_stat;

    /* Check for ASCII, UTF-8 */
    check_text_only();

    /* Set the files mutexes */
    w_set_file_mutexes();
#else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;
    memset(&lpFileInformation, 0, sizeof(BY_HANDLE_FILE_INFORMATION));
    const char *m_uname;

    m_uname = getuname();

    /* Check if we are on Windows Vista */
    if (!checkVista()) {
        minfo("Windows version is older than 6.0. (%s).", m_uname);
    } else {
        minfo("Windows version is 6.0 or newer. (%s).", m_uname);
    }

    /* Read vista descriptions */
    if (isVista) {
        win_read_vista_sec();
    }

    /* Check for ASCII, UTF-8 */
    check_text_only();

    w_mutexattr_init(&win_el_mutex_attr);
    w_mutexattr_settype(&win_el_mutex_attr, PTHREAD_MUTEX_ERRORCHECK);
#endif

    mdebug1("Entering LogCollectorStart().");

    /* Initialize each file and structure */
    for (i = 0;; i++) {
        if (f_control = update_current(&current, &i, &j), f_control) {
            if (f_control == NEXT_IT) {
                continue;
            } else {
                break;
            }
        }

        /* Remove duplicate entries */
        /* Returns NEXT_IT if duplicates were removed, LEAVE_IT if an error occurred
           or CONTINUE_IT to continue with the current iteration */
        duplicates_removed = remove_duplicates(current, i, j);
        if (duplicates_removed == NEXT_IT) {
            i--;
            continue;
        }

        if (!current->file) {
            /* Do nothing, duplicated entry */
        } else if (!strcmp(current->logformat, "eventlog")) {
#ifdef WIN32

            minfo(READING_EVTLOG, current->file);
            os_strdup(current->file, current->channel_str);
            win_startel(current->file);

            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#else
            free(current->file);
#endif
            current->file = NULL;
            current->command = NULL;
            current->fp = NULL;
        } else if (!strcmp(current->logformat, "eventchannel")) {
#ifdef WIN32

#ifdef EVENTCHANNEL_SUPPORT
            minfo(READING_EVTLOG, current->file);
            os_strdup(current->file, current->channel_str);
            win_start_event_channel(current->file, current->future, current->query, current->reconnect_time);
#else
            mwarn("eventchannel not available on this version of Windows");
#endif

            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#else
            free(current->file);
#endif
            current->file = NULL;
            current->command = NULL;
            current->fp = NULL;
        } else if (strcmp(current->logformat, "command") == 0) {
            current->file = NULL;
            current->fp = NULL;
            current->size = 0;

#ifdef WIN32
            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#endif
            if (current->command) {
                current->read = read_command;

                minfo("Monitoring output of command(%d): %s", current->ign, current->command);
                tg = 0;
                if (current->target) {
                    while (current->target[tg]) {
                        mdebug1("Socket target for '%s' -> %s", current->command, current->target[tg]);
                        tg++;
                    }
                }

                if (!current->alias) {
                    os_strdup(current->command, current->alias);
                }
            } else {
                merror("Missing command argument. Ignoring it.");
            }
        } else if (strcmp(current->logformat, "full_command") == 0) {
            current->file = NULL;
            current->fp = NULL;
            current->size = 0;

#ifdef WIN32
            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#endif

            if (current->command) {
                current->read = read_fullcommand;

                minfo("Monitoring full output of command(%d): %s", current->ign, current->command);
                tg = 0;
                if (current->target){
                    while (current->target[tg]) {
                        mdebug1("Socket target for '%s' -> %s", current->command, current->target[tg]);
                        tg++;
                    }
                }

                if (!current->alias) {
                    os_strdup(current->command, current->alias);
                }
            } else {
                merror("Missing command argument. Ignoring it.");
            }
        }

        else if (strcmp(current->logformat, MACOS) == 0) {
#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
            /* Get macOS version */
            w_macos_create_log_env(current, sysinfo);
            current->read = read_macos;
            if (current->macos_log->state != LOG_NOT_RUNNING) {
                if (atexit(w_macos_release_log_execution)) {
                    merror(ATEXIT_ERROR);
                }
                /* macOS log's resources need to be globally reachable to be released */
                macos_processes = &current->macos_log->processes;

                for (int tg_idx = 0; current->target[tg_idx]; tg_idx++) {
                    mdebug1("Socket target for '%s' -> %s", MACOS_LOG_NAME, current->target[tg_idx]);
                    w_logcollector_state_add_target(MACOS_LOG_NAME, current->target[tg_idx]);
                }
            }
#else
            minfo(LOGCOLLECTOR_ONLY_MACOS);
#endif
            os_free(current->file);
            current->command = NULL;
            os_free(current->fp);
        }

        else if (strcmp(current->logformat, JOURNALD_LOG) == 0) {
#ifdef __linux__
            current->read = read_journald;
            w_journald_set_ofe(current->future);

            if (current->target != NULL) {
                for (int tg_idx = 0; current->target[tg_idx]; tg_idx++) {
                    mdebug1(LOGCOLLECTOR_SOCKET_TARGET, JOURNALD_LOG, current->target[tg_idx]);
                    w_logcollector_state_add_target(JOURNALD_LOG, current->target[tg_idx]);
                }
            }
#else
            minfo(LOGCOLLECTOR_JOURNALD_ONLY_LINUX);
            w_journal_log_config_free(&(current->journal_log));
#endif
            os_free(current->file);
            current->command = NULL;
            os_free(current->fp);
        }

        else if (j < 0) {
            set_read(current, i, j);
            if (current->file) {
                minfo(READING_FILE, current->file);
            }
            /* More tweaks for Windows. For some reason IIS places
             * some weird characters at the end of the files and getc
             * always returns 0 (even after clearerr).
             */
#ifdef WIN32
            if (current->fp) {
                if (current->future == 0) {
                    w_set_to_last_line_read(current);
                } else {
                    int64_t offset = w_set_to_pos(current, 0, SEEK_END);
                    w_update_hash_node(current->file, offset);
                }
            }

            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#endif
        } else {
            if (current->file) {
                minfo(READING_FILE, current->file);
            }

        /* On Windows we need to forward the seek for wildcard files */
#ifdef WIN32
            if (current->fp) {
                if (current->future == 0) {
                    w_set_to_last_line_read(current);
                } else {
                    int64_t offset = w_set_to_pos(current, 0, SEEK_END);
                    w_update_hash_node(current->file, offset);
                }
            }
#endif
        }
    }

    //Save status localfiles to disk
    w_save_file_status();

    // Initialize message queue's log builder
    mq_log_builder_init();

    /* Create the output threads */
    w_create_output_threads();

    /* Create the input threads */
    w_create_input_threads();

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());
    mdebug1(CURRENT_FILES, current_files, maximum_files);

#ifndef WIN32
    // Start com request thread
    w_create_thread(lccom_main, NULL);
#endif
    set_can_read(1);
    /* Daemon loop */
    while (1) {

        /* Free hash table content for excluded files */
        if (f_free_excluded >= free_excluded_files_interval) {
            set_can_read(0); // Stop reading threads
            rwlock_lock_write(&files_update_rwlock);
            set_can_read(1); // Clean signal once we have the lock
            mdebug1("Refreshing excluded files list.");

            OSHash_Free(excluded_files);
            excluded_files = OSHash_Create();

            if (!excluded_files) {
                merror_exit(LIST_ERROR);
            }

            OSHash_Free(excluded_binaries);
            excluded_binaries = OSHash_Create();

            if (!excluded_binaries) {
                merror_exit(LIST_ERROR);
            }

            f_free_excluded = 0;

            rwlock_unlock(&files_update_rwlock);
        }

        if (f_check >= vcheck_files) {
            set_can_read(0); // Stop reading threads
            rwlock_lock_write(&files_update_rwlock);
            set_can_read(1); // Clean signal once we have the lock
            int i;
            int j = -1;
            f_reload += f_check;

            mdebug1("Performing file check.");

            // Force reload, if enabled

            if (force_reload && f_reload >= reload_interval) {
                struct timespec delay = { reload_delay / 1000, (reload_delay % 1000) * 1000000 };

                // Close files

                for (i = 0, j = -1;; i++) {
                    if (f_control = update_current(&current, &i, &j), f_control) {
                        if (f_control == NEXT_IT) {
                            continue;
                        } else {
                            break;
                        }
                    }

                    if (current->file && current->fp) {
                        close_file(current);
                    }
                }

                // Delay: yield mutex

                rwlock_unlock(&files_update_rwlock);

                if (reload_delay) {
                    nanosleep(&delay, NULL);
                }

                set_can_read(0); // Stop reading threads
                rwlock_lock_write(&files_update_rwlock);
                set_can_read(1); // Clean signal once we have the lock

                // Open files again, and restore position

                for (i = 0, j = -1;; i++) {
                    if (f_control = update_current(&current, &i, &j), f_control) {
                        if (f_control == NEXT_IT) {
                            continue;
                        } else {
                            break;
                        }
                    }

                    if (current->file && current->exists) {
                        if (reload_file(current) == -1) {
                            minfo(FORGET_FILE, current->file);
                            os_file_status_t * old_file_status = OSHash_Delete_ex(files_status, current->file);
                            free_files_status_data(old_file_status);
                            w_logcollector_state_delete_file(current->file);
                            current->exists = 0;
                            current->ign++;

                            // Only expanded files that have been deleted will be forgotten

                            if (j >= 0) {
                                if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0,&globs[j])) {
                                    merror(REM_ERROR, current->file);
                                } else {
                                    mdebug1(CURRENT_FILES, current_files, maximum_files);
                                    i--;
                                    continue;
                                }
                            } else if (open_file_attempts) {
                                mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                            } else {
                                mdebug1(OPEN_UNABLE, current->file);
                            }
                        }
                    }
                }
            }

            /* Check if any file has been renamed/removed */
            for (i = 0, j = -1;; i++) {
                if (f_control = update_current(&current, &i, &j), f_control) {
                    if (f_control == NEXT_IT) {
                        continue;
                    } else {
                        break;
                    }
                }

                /* These are the windows logs or ignored files */
                if (!current->file) {
                    continue;
                }

                /* Files with date -- check for day change */
                if (current->ffile) {
                    if (update_fname(i, j)) {
                        if (current->fp) {
                            fclose(current->fp);
                        }
                        current->fp = NULL;
                        current->exists = 1;

                        handle_file(i, j, 0, 1);
                        continue;
                    }

                    /* Variable file name */
                    else if (!current->fp && open_file_attempts - current->ign > 0) {
                        handle_file(i, j, 1, 1);
                        continue;
                    }
                }

                /* Check for file change -- if the file is open already */
                if (current->fp) {
#ifndef WIN32

                    /* To help detect a file rollover, temporarily open the file a second time.
                     * Previously the fstat would work on "cached" file data, but this should
                     * ensure it's fresh when hardlinks are used (like alerts.log).
                     */
                    FILE *tf;
                    tf = wfopen(current->file, "r");
                    if(tf == NULL) {
                        if (errno == ENOENT) {
                            if(current->exists==1){
                                minfo(FORGET_FILE, current->file);
                                os_file_status_t * old_file_status = OSHash_Delete_ex(files_status, current->file);
                                free_files_status_data(old_file_status);
                                w_logcollector_state_delete_file(current->file);
                                current->exists = 0;
                            }
                            current->ign++;

                            // Only expanded files that have been deleted will be forgotten
                            if (j >= 0) {
                                if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0,&globs[j])) {
                                    merror(REM_ERROR, current->file);
                                } else {
                                    mdebug1(CURRENT_FILES, current_files, maximum_files);
                                    i--;
                                    continue;
                                }
                            } else if (open_file_attempts) {
                                mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                            } else {
                                mdebug1(OPEN_UNABLE, current->file);
                            }
                        } else {
                            merror(FOPEN_ERROR, current->file, errno, strerror(errno));
                        }
                    }

                    else if ((fstat(fileno(tf), &tmp_stat)) == -1) {
                        fclose(current->fp);
                        fclose(tf);
                        current->fp = NULL;

                        merror(FSTAT_ERROR, current->file, errno, strerror(errno));
                    }
                    else if (fclose(tf) == EOF) {
                        merror("Closing the temporary file %s did not work (%d): %s", current->file, errno, strerror(errno));
                    }
#else
                    HANDLE h1;

                    h1 = wCreateFile(current->file, GENERIC_READ,
                                    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (h1 == INVALID_HANDLE_VALUE) {
                        fclose(current->fp);
                        current->fp = NULL;
                        minfo(LOGCOLLECTOR_INVALID_HANDLE_VALUE, current->file);
                    } else if (GetFileInformationByHandle(h1, &lpFileInformation) == 0) {
                        fclose(current->fp);
                        CloseHandle(h1);
                        current->fp = NULL;
                        minfo(LOGCOLLECTOR_INVALID_HANDLE_VALUE, current->file);
                    }

                    if (!current->fp) {
                        if(current->exists==1){
                            minfo(FORGET_FILE, current->file);
                            os_file_status_t * old_file_status = OSHash_Delete_ex(files_status, current->file);
                            free_files_status_data(old_file_status);
                            w_logcollector_state_delete_file(current->file);
                            current->exists = 0;
                        }
                        current->ign++;

                        // Only expanded files that have been deleted will be forgotten
                        if (j >= 0) {
                            if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0,&globs[j])) {
                                merror(REM_ERROR, current->file);
                            } else {
                                mdebug2(CURRENT_FILES, current_files, maximum_files);
                                i--;
                                continue;
                            }
                        } else if (open_file_attempts) {
                            mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                        } else {
                            mdebug1(OPEN_UNABLE, current->file);
                        }
                    }
#endif

#ifdef WIN32
                    else if (current->fd != (lpFileInformation.nFileIndexLow + lpFileInformation.nFileIndexHigh))
#else
                    else if (current->fd != tmp_stat.st_ino)
#endif
                    {
                        current->exists = 1;

                        char msg_alert[512 + 1];

                        snprintf(msg_alert, 512, "ossec: File rotated (inode "
                                 "changed): '%s'.",
                                 current->file);

                        /* Send message about log rotated */
                        w_msg_hash_queues_push(msg_alert, "logcollector", strlen(msg_alert) + 1, default_target, LOCALFILE_MQ);

                        mdebug1("File inode changed. %s",
                               current->file);

                        os_file_status_t * old_file_status = OSHash_Delete_ex(files_status, current->file);
                        free_files_status_data(old_file_status);
                        w_logcollector_state_delete_file(current->file);

                        fclose(current->fp);

#ifdef WIN32
                        CloseHandle(h1);
#endif

                        current->fp = NULL;
                        handle_file(i, j, 0, 1);
                        continue;
                    }
#ifdef WIN32
                    else if ((DWORD)current->size > (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow))
#else
                    else if (current->size > tmp_stat.st_size)
#endif
                    {
                        current->exists = 1;
                        char msg_alert[512 + 1];

                        snprintf(msg_alert, 512, "ossec: File size reduced "
                                 "(inode remained): '%s'.",
                                 current->file);

                        /* Send message about log rotated */
                        w_msg_hash_queues_push(msg_alert, "logcollector", strlen(msg_alert) + 1, default_target, LOCALFILE_MQ);

                        mdebug1("File size reduced. %s",
                                current->file);

                        /* Get new file */
                        os_file_status_t * old_file_status = OSHash_Delete_ex(files_status, current->file);
                        free_files_status_data(old_file_status);
                        w_logcollector_state_delete_file(current->file);

                        fclose(current->fp);

#ifdef WIN32
                        CloseHandle(h1);
#endif
                        current->fp = NULL;
                        handle_file(i, j, 0, 1);
                    } else {
#ifdef WIN32
                        CloseHandle(h1);

                        /* Update file size */
                        current->size = lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow;
#else
                        current->exists = 1;
                        current->size = tmp_stat.st_size;
#endif
                    }
                } else {
#ifdef WIN32
                    if (!current->command && strcmp(current->logformat,EVENTCHANNEL) && strcmp(current->logformat,EVENTLOG)) {

                        int file_exists = 1;
                        HANDLE h1;

                        h1 = wCreateFile(current->file, GENERIC_READ,
                                        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (h1 == INVALID_HANDLE_VALUE) {
                            mdebug1(LOGCOLLECTOR_INVALID_HANDLE_VALUE, current->file);
                            file_exists = 0;
                            w_logcollector_state_delete_file(current->file);
                        } else if (GetFileInformationByHandle(h1, &lpFileInformation) == 0) {
                            mdebug1(LOGCOLLECTOR_INVALID_HANDLE_VALUE, current->file);
                            file_exists = 0;
                            w_logcollector_state_delete_file(current->file);
                        }

                        CloseHandle(h1);

                        // Only expanded files that have been deleted will be forgotten
                        if (j >= 0) {
                            if (!file_exists) {
                                if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0, &globs[j])) {
                                    merror(REM_ERROR, current->file);
                                } else {
                                    mdebug2(CURRENT_FILES, current_files, maximum_files);
                                    i--;
                                    continue;
                                }
                            }
                        } else if (open_file_attempts) {
                            mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                        } else {
                            mdebug1(OPEN_UNABLE, current->file);
                        }
                    }
#endif
                }

                /* If open_file_attempts is at 0 the files aren't forgotted ever*/
                if(open_file_attempts == 0){
                    current->ign = -1;
                }
                /* Too many errors for the file */
                if (current->ign >= open_file_attempts) {
                    /* 999 Maximum ignore */
                    if (current->ign == 999) {
                        continue;
                    }

                    if(!strcmp(current->logformat, "eventchannel")){
                        mdebug1(LOGC_FILE_ERROR, current->file);
                    } else {
                        minfo(LOGC_FILE_ERROR, current->file);
                    }

                    if (current->fp) {
                        fclose(current->fp);
                    }

                    current->fp = NULL;
                    current->ign = 999;

                    if (j >= 0) {
#ifndef WIN32
                        struct stat stat_fd;
                        if (w_stat(current->file, &stat_fd) == -1 && ENOENT == errno) {
#else
                        if (!PathFileExists(current->file)) {
#endif
                            os_file_status_t * old_file_status = OSHash_Delete_ex(files_status, current->file);
                            free_files_status_data(old_file_status);
                            w_logcollector_state_delete_file(current->file);

                            if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0,&globs[j])) {
                                merror(REM_ERROR, current->file);
                            } else {
                                mdebug1(CURRENT_FILES, current_files, maximum_files);
                                i--;
                            }
                        } else {
#ifndef WIN32
                            merror(FSTAT_ERROR, current->file, errno, strerror(errno));
#endif
                        }
                    }
                    continue;
                }

                /* File not open */
                if (!current->fp) {
                    if (current->ign >= 999) {
                        continue;
                    } else {
                        /* Try for a few times to open the file */
                        handle_file(i, j, 1, 1);
                        continue;
                    }
                }
            }

            // Check for new files to be expanded
            if (check_pattern_expand(1)) {
                /* Remove duplicate entries */
                for (i = 0, j = -1;; i++) {
                    if (f_control = update_current(&current, &i, &j), f_control) {
                        if (f_control == NEXT_IT) {
                            continue;
                        } else {
                            break;
                        }
                    }

                    duplicates_removed = remove_duplicates(current, i, j);
                    if (duplicates_removed == NEXT_IT) {
                        i--;
                        continue;
                    }
                }
            }

            /* Check for excluded files */
            check_pattern_expand_excluded();

            /* Check for ASCII, UTF-8 */
            check_text_only();


            rwlock_unlock(&files_update_rwlock);

            if (f_reload >= reload_interval) {
                f_reload = 0;
            }

            //Save status localfiles to disk
            w_save_file_status();

            f_check = 0;

            if (mq_log_builder_update() == -1) {
                mdebug1("Output log pattern data could not be updated.");
            }
        }

        sleep(1);

        f_check++;
        f_free_excluded++;
    }
}

int update_fname(int i, int j)
{
    time_t __ctime = time(0);
    char lfile[OS_FLSIZE + 1];
    size_t ret;
    logreader *lf;
    struct tm tm_result = { .tm_sec = 0 };

    if (j < 0) {
        lf = &logff[i];
    } else {
        lf = &globs[j].gfiles[i];
    }

    localtime_r(&__ctime, &tm_result);

    /* Handle file */
    if (tm_result.tm_mday == _cday) {
        return (0);
    }

    lfile[OS_FLSIZE] = '\0';
    ret = strftime(lfile, OS_FLSIZE, lf->ffile, &tm_result);
    if (ret == 0) {
        merror_exit(PARSE_ERROR, lf->ffile);
    }

    /* Update the filename */
    if (strcmp(lfile, lf->file)) {
        os_free(lf->file);
        os_strdup(lfile, lf->file);
        minfo(VAR_LOG_MON, lf->file);

        /* Setting cday to zero because other files may need
         * to be changed.
         */
        _cday = 0;
        return (1);
    }

    _cday = tm_result.tm_mday;
    return (0);
}

/* Open, get the fileno, seek to the end and update mtime */
int handle_file(int i, int j, __attribute__((unused)) int do_fseek, int do_log)
{
    logreader *lf;

    if (j < 0) {
        lf = &logff[i];
    } else {
        lf = &globs[j].gfiles[i];
    }

    /* We must be able to open the file, fseek and get the
     * time of change from it.
     */

    /* TODO: Support text mode on Windows */
    lf->fp = wfopen(lf->file, "rb");
    if (!lf->fp) {
        if (do_log == 1 && lf->exists == 1) {
            merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
            lf->exists = 0;
        }
        goto error;
    }

#ifndef WIN32
    struct stat stat_fd = { .st_mode = 0 };
    int fd;

    /* Get inode number for fp */
    fd = fileno(lf->fp);
    if (fstat(fd, &stat_fd) == -1) {
        merror(FSTAT_ERROR, lf->file, errno, strerror(errno));
        fclose(lf->fp);
        lf->fp = NULL;
        goto error;
    }

    lf->fd = stat_fd.st_ino;
    lf->size =  stat_fd.st_size;
    lf->dev =  stat_fd.st_dev;

#else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;
    memset(&lpFileInformation, 0, sizeof(BY_HANDLE_FILE_INFORMATION));

    /* On windows, we also need the real inode, which is the combination
     * of the index low + index high numbers.
     */
    if (!get_fp_file_information(lf->fp, &lpFileInformation)) {
        merror("Unable to get file information by handle.");
        fclose(lf->fp);
        lf->fp = NULL;
        goto error;
    }

    lf->fd = (lpFileInformation.nFileIndexLow + lpFileInformation.nFileIndexHigh);
    lf->size = (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow);

#endif

    if (find_duplicate_inode(lf)) {
        mdebug1(DUP_FILE_INODE, lf->file);
        close_file(lf);
        return 0;
    }

/* Windows and fseek causes some weird issues */
#ifndef WIN32
    if (do_fseek == 1 && S_ISREG(stat_fd.st_mode)) {
        if (lf->future == 0) {
            if (w_set_to_last_line_read(lf) < 0) {
                goto error;
            }
        } else {
            int64_t offset;
            if (offset = w_set_to_pos(lf, 0, SEEK_END), offset < 0) {
                goto error;
            }
            w_update_hash_node(lf->file, offset);
        }
    }
#endif

    /* Set ignore to zero */
    lf->ign = 0;
    lf->exists = 1;
    return (0);

error:
    lf->ign++;

    if (open_file_attempts && j < 0) {
        mdebug1(OPEN_ATTEMPT, lf->file, open_file_attempts - lf->ign);
    } else {
        mdebug1(OPEN_UNABLE, lf->file);
    }

    return -1;
}

/* Reload file: open after close, and restore position */
int reload_file(logreader * lf) {

    /* TODO: Support text mode on Windows */
    lf->fp = wfopen(lf->file, "rb");

    if (!lf->fp) {
        return -1;
    }

    fsetpos(lf->fp, &lf->position);
    return 0;
}

/* Close file and save position */
void close_file(logreader * lf) {
    if (!(lf && lf->fp)) {
        // This should not occur.
        return;
    }

    fgetpos(lf->fp, &lf->position);
    fclose(lf->fp);
    lf->fp = NULL;

#ifdef WIN32
    lf->h = NULL;
#endif
}

#ifdef WIN32

/* Remove newlines and replace tabs in the argument fields with spaces */
void win_format_event_string(char *string)
{
    if (string == NULL) {
        return;
    }

    while (*string != '\0') {
        if (*string == '\n' || *string == '\r' || *string == ':') {
            if (*string == '\n' || *string == '\r') {
                *string = ' ';
            }

            string++;

            while (*string == '\t') {
                *string = ' ';
                string++;
            }

            continue;
        }

        string++;
    }
}

#endif /* WIN32 */

int update_current(logreader **current, int *i, int *j)
{
    if (*j < 0) {
        /* Check for normal files */
        *current = &logff[*i];
        if(!(*current)->logformat) {
            if (globs && globs->gfiles) {
                *i = -1;
                *j = 0;
                return NEXT_IT;
            } else {
                return LEAVE_IT;
            }
        }
    } else {

        /* Check boundaries */
        if ( *i > globs[*j].num_files) {
            *i=-1;
            (*j)++;
             if(!globs[*j].gpath) {
                return LEAVE_IT;
            } else {
                return NEXT_IT;
            }
        }

        /* Check expanded files */
        *current = &globs[*j].gfiles[*i];
        if (!(*current)->file) {
            *i=-1;
            (*j)++;
            if(!globs[*j].gpath) {
                return LEAVE_IT;
            } else {
                return NEXT_IT;
            }
        }
    }
    return CONTINUE_IT;
}

void set_read(logreader *current, int i, int j) {
    int tg;
    current->command = NULL;
    current->ign = 0;
    w_logcollector_state_add_file(current->file);
    /* Initialize the files */
    if (current->ffile) {

        /* Day must be zero for all files to be initialized */
        _cday = 0;
        if (update_fname(i, j)) {
            handle_file(i, j, 1, 1);
        } else {
            merror_exit(PARSE_ERROR, current->ffile);
        }

    } else {
        handle_file(i, j, 1, 1);
    }

    tg = 0;
    if (current->target) {
        while (current->target[tg]) {
            mdebug1("Socket target for '%s' -> %s", current->file, current->target[tg]);
            w_logcollector_state_add_target(current->file, current->target[tg]);
            tg++;
        }
    }

    /* Get the log type */
    if (strcmp("snort-full", current->logformat) == 0) {
        current->read = read_snortfull;
    }
#ifndef WIN32
    if (strcmp("ossecalert", current->logformat) == 0) {
        current->read = read_ossecalert;
    }
#endif
    else if (strcmp("nmapg", current->logformat) == 0) {
        current->read = read_nmapg;
    } else if (strcmp("json", current->logformat) == 0) {
        current->read = read_json;
    } else if (strcmp("mysql_log", current->logformat) == 0) {
        current->read = read_mysql_log;
    } else if (strcmp("mssql_log", current->logformat) == 0) {
        current->read = read_mssql_log;
    } else if (strcmp("postgresql_log", current->logformat) == 0) {
        current->read = read_postgresql_log;
    } else if (strcmp("djb-multilog", current->logformat) == 0) {
        if (!init_djbmultilog(current)) {
            merror(INV_MULTILOG, current->file);
            if (current->fp) {
                fclose(current->fp);
                current->fp = NULL;
            }
            current->file = NULL;
        }
        current->read = read_djbmultilog;
    } else if (strncmp(current->logformat, "multi-line:", 11) == 0) {
        current->read = read_multiline;
    } else if (strcmp("audit", current->logformat) == 0) {
        current->read = read_audit;
    } else if (strcmp(MULTI_LINE_REGEX, current->logformat) == 0) {
        current->read = read_multiline_regex;
    } else {
#ifdef WIN32
        if (current->filter_binary) {
            /* If the file is empty, set it to UCS-2 LE */
            if (FileSizeWin(current->file) == 0) {
                current->ucs2 = UCS2_LE;
                current->read = read_ucs2_le;
                mdebug2("File '%s' is empty. Setting encoding to UCS-2 LE.",current->file);
                return;
            }
        }

        if(current->ucs2 == UCS2_LE){
            mdebug1("File '%s' is UCS-2 LE",current->file);
            current->read = read_ucs2_le;
            return;
        }

        if(current->ucs2 == UCS2_BE){
            mdebug1("File '%s' is UCS-2 BE",current->file);
            current->read = read_ucs2_be;
            return;
        }
#endif
        current->read = read_syslog;
    }
}

#ifndef WIN32
int check_pattern_expand(int do_seek) {
    glob_t g;
    int err;
    int glob_offset;
    int found;
    int i, j;
    int retval = 0;

    pthread_mutexattr_t attr;
    w_mutexattr_init(&attr);
    w_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);

    if (globs) {
        for (j = 0; globs[j].gpath; j++) {
            if (current_files >= maximum_files) {
                break;
            }
            glob_offset = 0;
            if (err = glob(globs[j].gpath, 0, NULL, &g), err) {
                if (err == GLOB_NOMATCH) {
                    mdebug1(GLOB_NFOUND, globs[j].gpath);
                } else {
                    mdebug1(GLOB_ERROR, globs[j].gpath);
                }
                continue;
            }
            while (g.gl_pathv[glob_offset] != NULL) {
                if (current_files >= maximum_files) {
                    mwarn(FILE_LIMIT, maximum_files);
                    break;
                }

                struct stat statbuf;
                if (lstat(g.gl_pathv[glob_offset], &statbuf) < 0) {
                    merror("Error on lstat '%s' due to [(%d)-(%s)]", g.gl_pathv[glob_offset], errno, strerror(errno));
                    glob_offset++;
                    continue;
                }

                if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
                    mdebug1("File %s is not a regular file. Skipping it.", g.gl_pathv[glob_offset]);
                    glob_offset++;
                    continue;
                }

                found = 0;
                for (i = 0; globs[j].gfiles[i].file; i++) {
                    if (!strcmp(globs[j].gfiles[i].file, g.gl_pathv[glob_offset])) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    retval = 1;
                    char *ex_file = OSHash_Get(excluded_files,g.gl_pathv[glob_offset]);
                    int added = 0;

                    if(!ex_file) {
                        minfo(NEW_GLOB_FILE, globs[j].gpath, g.gl_pathv[glob_offset]);

                        os_realloc(globs[j].gfiles, (i +2)*sizeof(logreader), globs[j].gfiles);

                        /* Copy the current item to the end mark as it should be a pattern */
                        memcpy(globs[j].gfiles + i + 1, globs[j].gfiles + i, sizeof(logreader));
                        // Clone the multiline configuration if it exists
                        globs[j].gfiles[i + 1].multiline = w_multiline_log_config_clone(globs[j].gfiles[i].multiline);

                        os_strdup(g.gl_pathv[glob_offset], globs[j].gfiles[i].file);
                        w_mutex_init(&globs[j].gfiles[i].mutex, &attr);
                        globs[j].gfiles[i].fp = NULL;
                        globs[j].gfiles[i].exists = 1;
                        globs[j].gfiles[i + 1].file = NULL;
                        globs[j].gfiles[i + 1].target = NULL;
                        current_files++;
                        globs[j].num_files++;
                        mdebug2(CURRENT_FILES, current_files, maximum_files);
                        if  (!globs[j].gfiles[i].read) {
                            set_read(&globs[j].gfiles[i], i, j);
                        } else {
                            handle_file(i, j, do_seek, 1);
                        }

                        added = 1;
                    }

                    char *file_excluded_binary = OSHash_Get(excluded_binaries,g.gl_pathv[glob_offset]);

                    /* This file could have to non binary file */
                    if (file_excluded_binary && !added) {
                        os_realloc(globs[j].gfiles, (i +2)*sizeof(logreader), globs[j].gfiles);

                        /* Copy the current item to the end mark as it should be a pattern */
                        memcpy(globs[j].gfiles + i + 1, globs[j].gfiles + i, sizeof(logreader));
                        // Clone the multiline configuration if it exists
                        globs[j].gfiles[i + 1].multiline = w_multiline_log_config_clone(globs[j].gfiles[i].multiline);

                        os_strdup(g.gl_pathv[glob_offset], globs[j].gfiles[i].file);
                        w_mutex_init(&globs[j].gfiles[i].mutex, &attr);
                        globs[j].gfiles[i].fp = NULL;
                        globs[j].gfiles[i].exists = 1;
                        globs[j].gfiles[i + 1].file = NULL;
                        globs[j].gfiles[i + 1].target = NULL;
                        current_files++;
                        globs[j].num_files++;
                        mdebug2(CURRENT_FILES, current_files, maximum_files);
                        if  (!globs[j].gfiles[i].read) {
                            set_read(&globs[j].gfiles[i], i, j);
                        } else {
                            handle_file(i, j, do_seek, 1);
                        }
                    }
                }
                glob_offset++;
            }
            globfree(&g);
        }
    }

    w_mutexattr_destroy(&attr);

    return retval;
}

static void check_pattern_expand_excluded() {
    glob_t g;
    int err;
    int glob_offset;
    int found;
    int j;

    if (globs) {
        for (j = 0; globs[j].gpath; j++) {

            if (!globs[j].exclude_path) {
                continue;
            }

            /* Check for files to exclude */
            glob_offset = 0;
            if (err = glob(globs[j].exclude_path, 0, NULL, &g), err) {
                if (err == GLOB_NOMATCH) {
                    mdebug1(GLOB_NFOUND, globs[j].exclude_path);
                } else {
                    mdebug1(GLOB_ERROR, globs[j].exclude_path);
                }
                continue;
            }
            while (g.gl_pathv[glob_offset] != NULL) {
                found = 0;
                int k;
                for (k = 0; globs[j].gfiles[k].file; k++) {
                    if (!strcmp(globs[j].gfiles[k].file, g.gl_pathv[glob_offset])) {
                        found = 1;
                        break;
                    }
                }

                /* Excluded file found, remove it completely */
                if(found) {
                    int result;

                    result = Remove_Localfile(&(globs[j].gfiles), k, 1, 0,&globs[j]);

                    if (result) {
                        merror_exit(REM_ERROR,g.gl_pathv[glob_offset]);
                    } else {

                        /* Add the excluded file to the hash table */
                        char *file = OSHash_Get(excluded_files,g.gl_pathv[glob_offset]);

                        if(!file) {
                            OSHash_Add(excluded_files,g.gl_pathv[glob_offset],(void *)1);
                            minfo(EXCLUDE_FILE,g.gl_pathv[glob_offset]);
                        }

                        mdebug2(CURRENT_FILES, current_files, maximum_files);
                    }
                }
                glob_offset++;
            }
            globfree(&g);
        }
    }
}

#else
int check_pattern_expand(int do_seek) {
    int found;
    int i, j;
    int retval = 0;

    if (globs) {
        for (j = 0; globs[j].gpath; j++) {

            if (current_files >= maximum_files) {
                mwarn(FILE_LIMIT, maximum_files);
                break;
            }

            char** result = expand_win32_wildcards(globs[j].gpath);

            if (result) {

                int file;
                char *full_path = NULL;

                for (file = 0; result[file] != NULL; file++) {

                    if (current_files >= maximum_files) {
                        mwarn(FILE_LIMIT, maximum_files);
                        for (int f = file; result[f] != NULL; f++) {
                            os_free(result[f]);
                        }
                        break;
                    }

                    os_strdup(result[file], full_path);
                    os_free(result[file]);

                    found = 0;
                    for (i = 0; globs[j].gfiles[i].file; i++) {
                        if (!strcmp(globs[j].gfiles[i].file, full_path)) {
                            found = 1;
                            break;
                        }
                    }

                    if (!found) {
                        retval = 1;
                        int added = 0;

                        char *ex_file = OSHash_Get(excluded_files, full_path);

                        if (!ex_file) {

                            /*  Because Windows cache's files, we need to check if the file
                                exists. Deleted files can still appear due to caching */
                            HANDLE h1;

                            h1 = wCreateFile(full_path, GENERIC_READ,
                                            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

                            if (h1 == INVALID_HANDLE_VALUE) {
                                os_free(full_path);
                                continue;
                            }

                            CloseHandle(h1);

                            minfo(NEW_GLOB_FILE, globs[j].gpath, full_path);
                            os_realloc(globs[j].gfiles, (i + 2) * sizeof(logreader), globs[j].gfiles);
                            /* Copy the current item to the end mark as it should be a pattern */
                            memcpy(globs[j].gfiles + i + 1, globs[j].gfiles + i, sizeof(logreader));
                            // Clone the multiline configuration if it exists
                            globs[j].gfiles[i + 1].multiline = w_multiline_log_config_clone(globs[j].gfiles[i].multiline);

                            os_strdup(full_path, globs[j].gfiles[i].file);
                            w_mutex_init(&globs[j].gfiles[i].mutex, &win_el_mutex_attr);
                            globs[j].gfiles[i].fp = NULL;
                            globs[j].gfiles[i].exists = 1;
                            globs[j].gfiles[i + 1].file = NULL;
                            globs[j].gfiles[i + 1].target = NULL;
                            current_files++;
                            globs[j].num_files++;
                            mdebug2(CURRENT_FILES, current_files, maximum_files);

                            if (!globs[j].gfiles[i].read) {
                                set_read(&globs[j].gfiles[i], i, j);
                            } else {
                                handle_file(i, j, do_seek, 1);
                            }

                            added = 1;
                        }

                        char *file_excluded_binary = OSHash_Get(excluded_binaries, full_path);

                        /* This file could have to non binary file */
                        if (file_excluded_binary && !added) {
                            os_realloc(globs[j].gfiles, (i + 2) * sizeof(logreader), globs[j].gfiles);

                            /* Copy the current item to the end mark as it should be a pattern */
                            memcpy(globs[j].gfiles + i + 1, globs[j].gfiles + i, sizeof(logreader));
                            // Clone the multiline configuration if it exists
                            globs[j].gfiles[i + 1].multiline = w_multiline_log_config_clone(globs[j].gfiles[i].multiline);

                            os_strdup(full_path, globs[j].gfiles[i].file);
                            w_mutex_init(&globs[j].gfiles[i].mutex, &win_el_mutex_attr);
                            globs[j].gfiles[i].fp = NULL;
                            globs[j].gfiles[i].exists = 1;
                            globs[j].gfiles[i + 1].file = NULL;
                            globs[j].gfiles[i + 1].target = NULL;
                            current_files++;
                            globs[j].num_files++;
                            mdebug2(CURRENT_FILES, current_files, maximum_files);

                            if (!globs[j].gfiles[i].read) {
                                set_read(&globs[j].gfiles[i], i, j);
                            } else {
                                handle_file(i, j, do_seek, 1);
                            }
                        }
                    }
                    os_free(full_path);
                }
                os_free(result);
            }
        }
    }
    return retval;
}
#endif

static IT_control remove_duplicates(logreader *current, int i, int j) {
    IT_control d_control = CONTINUE_IT;
    IT_control f_control;
    int r, k;
    logreader *dup;

    if (current->file && !current->command) {
        for (r = 0, k = -1;; r++) {
            if (f_control = update_current(&dup, &r, &k), f_control) {
                if (f_control == NEXT_IT) {
                    continue;
                } else {
                    break;
                }
            }

            if (current != dup && dup->file && !strcmp(current->file, dup->file)) {
                mwarn(DUP_FILE, current->file);
                int result;

                if (j < 0) {
                    result = Remove_Localfile(&logff, i, 0, 1,NULL);
                } else {
                    result = Remove_Localfile(&(globs[j].gfiles), i, 1, 0,&globs[j]);
                }
                if (result) {
                    merror_exit(REM_ERROR, current->file);
                } else {
                    mdebug1(CURRENT_FILES, current_files, maximum_files);
                }
                d_control = NEXT_IT;
                break;
            }
        }
    }

    return d_control;
}

int find_duplicate_inode(logreader * lf) {
    if (lf->file == NULL && lf->command != NULL) {
        return 0;
    }

    int r;
    int k;
    logreader * dup;
    IT_control f_control;

    for (r = 0, k = -1;; r++) {
        if (f_control = update_current(&dup, &r, &k), f_control) {
            if (f_control == NEXT_IT) {
                continue;
            } else {
                break;
            }
        }

        /* If the entry is different, the file is open,
         * and both inode and device match,
         * then the link is a duplicate.
         */

        if (lf != dup && dup->fp != NULL && lf->fd == dup->fd && lf->dev == dup->dev) {
            return 1;
        }
    }

    return 0;
}

static void set_sockets() {
    int i, j, k, t;
    logreader *current;
    char *file;

    // List read sockets
    unsigned int sk;
    for (sk=0; logsk && logsk[sk].name; sk++) {
        mdebug1("Socket '%s' (%s) added. Location: %s", logsk[sk].name, logsk[sk].mode == IPPROTO_UDP ? "udp" : "tcp", logsk[sk].location);
    }

    for (i = 0, t = -1;; i++) {
        if (t == -1 && logff && logff[i].file) {
            current = &logff[i];
            file = logff[i].file;
        } else if (globs && globs[++t].gpath){
            current = globs[t].gfiles;
            file = globs[t].gpath;
        } else {
            break;
        }

        os_malloc(sizeof(logtarget), current->log_target);

        for (j = 0; current->target[j]; j++) {
            os_realloc(current->log_target, (j + 2) * sizeof(logtarget), current->log_target);
            memset(current->log_target + j, 0, 2 * sizeof(logtarget));

            if (strcmp(current->target[j], "agent") == 0) {
                current->log_target[j].log_socket = &default_agent;
                w_msg_hash_queues_add_entry("agent");
                continue;
            }
            int found = -1;
            for (k = 0; logsk && logsk[k].name; k++) {
                found = strcmp(logsk[k].name, current->target[j]);
                if (found == 0) {
                    break;
                }
            }
            if (found != 0) {
                merror_exit("Socket '%s' for '%s' is not defined.", current->target[j], file);
            } else {
                current->log_target[j].log_socket = &logsk[k];
                w_msg_hash_queues_add_entry(logsk[k].name);
            }
        }

        memset(current->log_target + j, 0, sizeof(logtarget));

        // Add output formats

        if (current->out_format) {
            for (j = 0; current->out_format[j]; ++j) {
                if (current->out_format[j]->target) {
                    // Fill the corresponding target

                    for (k = 0; current->target[k]; ++k) {
                        if (strcmp(current->target[k], current->out_format[j]->target) == 0) {
                            current->log_target[k].format = current->out_format[j]->format;
                            break;
                        }
                    }

                    if (!current->target[k]) {
                        mwarn("Log target '%s' not found for the output format of localfile '%s'.", current->out_format[j]->target, current->file);
                    }
                } else {
                    // Fill the targets that don't yet have a format

                    for (k = 0; current->target[k]; k++) {
                        if (!current->log_target[k].format) {
                            current->log_target[k].format = current->out_format[j]->format;
                        }
                    }
                }
            }
        }
    }
}

void w_set_file_mutexes(){
    logreader *current;
    IT_control f_control;
    int r,k;

    pthread_mutexattr_t attr;
    w_mutexattr_init(&attr);
    w_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);

    for (r = 0, k = -1;; r++) {
        if (f_control = update_current(&current, &r, &k), f_control) {
            if (f_control == NEXT_IT) {
                continue;
            } else {
                break;
            }
        }

        if (k < 0) {
            w_mutex_init(&current->mutex, &attr);
        }
    }

    w_mutexattr_destroy(&attr);
}

void free_msg_queue(w_msg_queue_t *msg) {
    if (msg->msg_queue) queue_free(msg->msg_queue);
    free(msg);
}

void w_msg_hash_queues_init(){

    OUTPUT_QUEUE_SIZE = getDefine_Int("logcollector", "queue_size", OUTPUT_MIN_QUEUE_SIZE, 220000);
    msg_queues_table = OSHash_Create();

    if(!msg_queues_table){
        merror_exit("Failed to create hash table for queue threads");
    }

    OSHash_SetFreeDataPointer(msg_queues_table, (void (*)(void *))free_msg_queue);
}

int w_msg_hash_queues_add_entry(const char *key){
    int result;
    w_msg_queue_t *msg;

    os_calloc(1,sizeof(w_msg_queue_t), msg);
    msg->msg_queue = queue_init(OUTPUT_QUEUE_SIZE);
    w_mutex_init(&msg->mutex, NULL);
    w_cond_init(&msg->available, NULL);

    if (result = OSHash_Add(msg_queues_table, key, msg), result != 2) {
        queue_free(msg->msg_queue);
        w_mutex_destroy(&msg->mutex);
        w_cond_destroy(&msg->available);
        free(msg);
    }

    return result;
}

int w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget * targets, char queue_mq) {
    w_msg_queue_t *msg;
    int i;
    char *file_cpy;
    int result;

    w_logcollector_state_update_file(file, size);

    for (i = 0; targets[i].log_socket; i++)
    {
        w_mutex_lock(&mutex);

        msg = (w_msg_queue_t *)OSHash_Get(msg_queues_table, targets[i].log_socket->name);

        w_mutex_unlock(&mutex);

        if (msg) {
            os_strdup(file, file_cpy);
            result = w_msg_queue_push(msg, str, file_cpy, size, &targets[i], queue_mq);

            if (result < 0) {
                w_logcollector_state_update_target(file,targets[i].log_socket->name, true);
            }
        }
    }

    return 0;
}

int w_msg_queue_push(w_msg_queue_t * msg, const char * buffer, char *file, unsigned long size, logtarget * log_target, char queue_mq) {
    w_message_t *message;
    static int reported = 0;
    int result;

    w_mutex_lock(&msg->mutex);

    os_calloc(1,sizeof(w_message_t),message);
    os_calloc(size,sizeof(char),message->buffer);
    memcpy(message->buffer,buffer,size);
    message->size = size;
    message->file = file;
    message->log_target = log_target;
    message->queue_mq = queue_mq;


    if (result = queue_push(msg->msg_queue, message), result == 0) {
        w_cond_signal(&msg->available);
    }

    if ((result < 0) && !reported) {
        #ifndef WIN32
            mwarn("Target '%s' message queue is full (%zu). Log lines may be lost.", log_target->log_socket->name, msg->msg_queue->size);
        #else
            mwarn("Target '%s' message queue is full (%u). Log lines may be lost.", log_target->log_socket->name, msg->msg_queue->size);
        #endif
            reported = 1;
    }

    w_mutex_unlock(&msg->mutex);

    if (result < 0) {
        free(message->file);
        free(message->buffer);
        free(message);
        mdebug2("Discarding log line for target '%s'", log_target->log_socket->name);
    }

    return result;
}

w_message_t * w_msg_queue_pop(w_msg_queue_t * msg){
    w_message_t *message;
    w_mutex_lock(&msg->mutex);

    while (message = (w_message_t *)queue_pop(msg->msg_queue), !message) {
        w_cond_wait(&msg->available, &msg->mutex);
    }

    w_mutex_unlock(&msg->mutex);
    return message;
}

#ifdef WIN32
DWORD WINAPI w_output_thread(void * args) {
#else
void * w_output_thread(void * args){
#endif
    char *queue_name = args;
    w_message_t *message;
    w_msg_queue_t *msg_queue;
    int result;

    if (msg_queue = OSHash_Get(msg_queues_table, queue_name), !msg_queue) {
        mwarn("Could not found the '%s'.", queue_name);
    #ifdef WIN32
        exit(1);
    #else
        return NULL;
    #endif
    }

    while(1)
    {
        int sleep_time = 5;
        /* Pop message from the queue */
        message = w_msg_queue_pop(msg_queue);

        if (strcmp(message->log_target->log_socket->name, "agent") == 0) {
            // When dealing with this type of messages we don't want any of them to be lost
            // Continuously attempt to reconnect to the queue and send the message.
            result = SendMSGtoSCK(logr_queue, message->buffer, message->file,
                                  message->queue_mq, message->log_target);
            if (result != 0) {
                if (result != 1) {
#ifdef CLIENT
                    merror("Unable to send message to '%s' (wazuh-agentd might be down). Attempting to reconnect.", DEFAULTQUEUE);
#else
                    merror("Unable to send message to '%s' (wazuh-analysisd might be down). Attempting to reconnect.", DEFAULTQUEUE);
#endif
                }
                // Retry to connect infinitely.
                logr_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

                minfo("Successfully reconnected to '%s'", DEFAULTQUEUE);

                if (result = SendMSGtoSCK(logr_queue, message->buffer, message->file, message->queue_mq, message->log_target),
                    result != 0) {
                    // We reconnected but are still unable to send the message, notify it and go on.
                    if (result != 1) {
                        merror("Unable to send message to '%s' after a successfull reconnection...", DEFAULTQUEUE);
                    }
                    result = 1;
                }
            }

            w_logcollector_state_update_target(message->file,
                                               message->log_target->log_socket->name,
                                               result == 1);

        } else {
            const int MAX_RETRIES = 3;
            int retries = 0;
            result = 1;
            while (retries < MAX_RETRIES) {
                result = SendMSGtoSCK(logr_queue, message->buffer, message->file,
                                      message->queue_mq, message->log_target);
                if (result < 0) {
                    merror(QUEUE_SEND);

                    sleep(sleep_time);

                    // If we failed, we will wait longer before reattempting to connect
                    sleep_time += 5;
                    retries++;
                } else {
                    break;
                }
            }

            w_logcollector_state_update_target(message->file,
                                               message->log_target->log_socket->name,
                                               result == 1);

            if (retries == MAX_RETRIES) {
                merror(SEND_ERROR, message->log_target->log_socket->location, message->buffer);
            }
        }
        free(message->file);
        free(message->buffer);
        free(message);
    }

#ifndef WIN32
    return NULL;
#endif
}

void w_create_output_threads(){
    unsigned int i;
    const OSHashNode *curr_node;

    for(i = 0; i <= msg_queues_table->rows; i++){
        if(msg_queues_table->table[i]){
            curr_node = msg_queues_table->table[i];

            /* Create one thread per valid hash entry */
            if(curr_node->key){
#ifndef WIN32
                w_create_thread(w_output_thread, curr_node->key);
#else
                w_create_thread(NULL,
                    0,
                    w_output_thread,
                    curr_node->key,
                    0,
                    NULL);
#endif
            }
        }
    }
}

#ifdef WIN32
DWORD WINAPI w_input_thread(__attribute__((unused)) void * t_id) {
#else
void * w_input_thread(__attribute__((unused)) void * t_id){
#endif
    logreader *current;
    int i = 0, r = 0, j = -1;
    IT_control f_control = 0;
    time_t curr_time = 0;
#ifdef __linux__
    unsigned long thread_id = (unsigned long) pthread_self();
#endif
#ifndef WIN32
    struct stat tmp_stat;
#else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;
    memset(&lpFileInformation, 0, sizeof(BY_HANDLE_FILE_INFORMATION));
#endif

    /* Daemon loop */
    while (1) {
        sleep(loop_timeout);

#ifdef WIN32
        /* Check for messages in the event viewer */

        if (pthread_mutex_trylock(&win_el_mutex) == 0) {
            win_readel();
            w_mutex_unlock(&win_el_mutex);
        }
#endif

        /* Check which file is available */
        for (i = 0, j = -1;; i++) {

            rwlock_lock_read(&files_update_rwlock);
            if (f_control = update_current(&current, &i, &j), f_control) {
                rwlock_unlock(&files_update_rwlock);

                if (f_control == NEXT_IT) {
                    continue;
                } else {
                    break;
                }
            }

            if (pthread_mutex_trylock(&current->mutex) == 0){

                if (!current->fp) {
                    /* Run the command */
                    if (current->command) {
                        curr_time = time(0);
                        if ((curr_time - current->size) >= current->ign) {
                            current->size = curr_time;
                            current->read(current, &r, 0);
                        }
                    }
#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
                    /* Read the macOS `log` process output */
                    else if (current->macos_log != NULL && current->macos_log->state != LOG_NOT_RUNNING) {
                        current->read(current, &r, 0);
                    }
#endif
#ifdef __linux__
                    /* Read the journald logs */
                    else if (current->journal_log != NULL) {
                        if (w_journald_can_read(thread_id)) {
                            current->read(current, &r, 0);
                        } else {
                            mdebug2(LOGCOLLECTOR_JOURNAL_LOG_NOT_OWNER);
                        }
                    }
#endif
                    w_mutex_unlock(&current->mutex);
                    rwlock_unlock(&files_update_rwlock);
                    continue;
                }

                /* Windows with IIS logs is very strange.
                * For some reason it always returns 0 (not EOF)
                * the fgetc. To solve this problem, we always
                * pass it to the function pointer directly.
                */
    #ifndef WIN32

                if(current->age) {
                    if ((fstat(fileno(current->fp), &tmp_stat)) == -1) {
                        merror(FSTAT_ERROR, current->file, errno, strerror(errno));

                    } else {
                        struct timespec c_currenttime;
                        gettime(&c_currenttime);

                        /* Ignore file */
                        if((c_currenttime.tv_sec - (int)current->age) >= tmp_stat.st_mtime) {
                            mdebug1("Ignoring file '%s' due to modification time",current->file);
                            fclose(current->fp);
                            current->fp = NULL;
                            w_mutex_unlock(&current->mutex);
                            rwlock_unlock(&files_update_rwlock);
                            continue;
                        }
                    }
                }

                /* We check for the end of file. If is returns EOF,
                * we don't attempt to read it.
                * Excluding multiline_regex log format which has its own handler.
                */
               if (current->multiline == NULL) {
                   if ((r = fgetc(current->fp)) == EOF) {
                       clearerr(current->fp);
                       w_mutex_unlock(&current->mutex);
                       rwlock_unlock(&files_update_rwlock);
                       continue;
                   }

                   /* If it is not EOF, we need to return the read character */
                   ungetc(r, current->fp);
                }
    #endif

#ifdef WIN32
            if(current->age) {
                if (current->h && (GetFileInformationByHandle(current->h, &lpFileInformation) == 0)) {
                    merror("Unable to get file information by handle.");
                    w_mutex_unlock(&current->mutex);
                    rwlock_unlock(&files_update_rwlock);
                    continue;
                } else {
                    FILETIME ft_handle = lpFileInformation.ftLastWriteTime;

                    /* Current machine EPOCH time */
                    long long int c_currenttime = get_windows_time_epoch();

                    /* Current file EPOCH time */
                    long long int file_currenttime = get_windows_file_time_epoch(ft_handle);

                    /* Ignore file */
                    if((c_currenttime - current->age) >= file_currenttime) {
                        mdebug1("Ignoring file '%s' due to modification time",current->file);
                        fclose(current->fp);
                        current->fp = NULL;
                        current->h = NULL;
                        w_mutex_unlock(&current->mutex);
                        rwlock_unlock(&files_update_rwlock);
                        continue;
                    }
                }
            }

            int ucs2 = is_usc2(current->file);
            if (ucs2) {
                current->ucs2 = ucs2;
                if (current->filter_binary) {
                    /* If the file is empty, set it to UCS-2 LE */
                    if (FileSizeWin(current->file) == 0) {
                        current->ucs2 = UCS2_LE;
                        current->read = read_ucs2_le;
                        mdebug2("File '%s' is empty. Setting encoding to UCS-2 LE.",current->file);
                    } else {

                        if (current->ucs2 == UCS2_LE) {
                            mdebug1("File '%s' is UCS-2 LE",current->file);
                            current->read = read_ucs2_le;
                        }

                        if (current->ucs2 == UCS2_BE) {
                            mdebug1("File '%s' is UCS-2 BE",current->file);
                            current->read = read_ucs2_be;
                        }
                    }
                }
            }

            if (current->filter_binary) {
                /* If the file is empty, set it to UCS-2 LE */
                if (FileSizeWin(current->file) == 0) {
                    current->ucs2 = UCS2_LE;
                    current->read = read_ucs2_le;
                    mdebug2("File '%s' is empty. Setting encoding to UCS-2 LE.",current->file);
                } else {

                    if (!ucs2) {
                        if (!strcmp("syslog", current->logformat) || !strcmp("generic", current->logformat)) {
                            current->read = read_syslog;
                        } else if (strcmp("multi-line", current->logformat) == 0) {
                            current->read = read_multiline;
                        } else if (strcmp(MULTI_LINE_REGEX, current->logformat) == 0) {
                            current->read = read_multiline_regex;
                        }
                    }
                }
            }
#endif
                /* Finally, send to the function pointer to read it */
                current->read(current, &r, 0);
                /* Check for error */
                if (!ferror(current->fp)) {
                    /* Clear EOF */
                    clearerr(current->fp);

                    /* Parsing error */
                    if (r != 0) {
                        current->ign++;

                        if (open_file_attempts && j < 0) {
                            mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                        } else {
                            mdebug1(OPEN_UNABLE, current->file);
                        }

                    }
                    w_mutex_unlock(&current->mutex);
                }
                /* If ferror is set */
                else {
                    merror(FREAD_ERROR, current->file, errno, strerror(errno));
    #ifndef WIN32
                    if (fseek(current->fp, 0, SEEK_END) < 0)
    #else
                    if (1)
    #endif
                    {

    #ifndef WIN32
                        merror(FSEEK_ERROR, current->file, errno, strerror(errno));
    #endif

                        /* Close the file */
                        fclose(current->fp);
                        current->fp = NULL;

                        /* Try to open it again */
                        if (handle_file(i, j, 0, 1)) {
                            w_mutex_unlock(&current->mutex);
                            rwlock_unlock(&files_update_rwlock);
                            continue;
                        }
#ifdef WIN32
                        if (current->fp != NULL) {
                            if (current->future == 0) {
                                w_set_to_last_line_read(current);
                            } else {
                                int64_t offset = w_set_to_pos(current, 0, SEEK_END);
                                w_update_hash_node(current->file, offset);
                            }
                        }
#endif
                    }
                    /* Increase the error count  */
                    current->ign++;

                    if (open_file_attempts && j < 0) {
                        mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                    } else {
                        mdebug1(OPEN_UNABLE, current->file);
                    }

                    if (current->fp) {
                        clearerr(current->fp);
                    }

                    w_mutex_unlock(&current->mutex);
                }
            }

            rwlock_unlock(&files_update_rwlock);
        }
    }

#ifndef WIN32
    return NULL;
#endif
}

void w_create_input_threads(){

    int i;

    N_INPUT_THREADS = getDefine_Int("logcollector", "input_threads", N_MIN_INPUT_THREADS, 128);

#ifdef WIN32
    w_mutex_init(&win_el_mutex, &win_el_mutex_attr);
    w_mutexattr_destroy(&win_el_mutex_attr);
#endif

    for(i = 0; i < N_INPUT_THREADS; i++) {
#ifndef WIN32
        w_create_thread(w_input_thread,NULL);
#else
        w_create_thread(NULL,
                     0,
                     w_input_thread,
                     NULL,
                     0,
                     NULL);
#endif
    }
}

void files_lock_init()
{
    rwlock_init(&files_update_rwlock);
    rwlock_init(&can_read_rwlock);
}

static void check_text_only() {

    int i, j;

    IT_control f_control = 0;
    logreader *current;
    char file_name[PATH_MAX];

    for (i = 0, j = -1;; i++) {
        if (f_control = update_current(&current, &i, &j), f_control) {
            if (f_control == NEXT_IT) {
                continue;
            } else {
                break;
            }
        }

        /* Check for files to exclude */
        if(current->file && !current->command && current->filter_binary) {
            snprintf(file_name, PATH_MAX, "%s", current->file);

            char *file_excluded = OSHash_Get(excluded_files,file_name);

            if(is_ascii_utf8(current->file,MAX_ASCII_LINES,MAX_UTF8_CHARS)) {
                #ifdef WIN32

                    int ucs2 = is_usc2(current->file);
                    if(ucs2) {
                        current->ucs2 = ucs2;
                        continue;
                    }

                #endif
                int result = 0;
                if (j < 0) {
                    result = Remove_Localfile(&logff, i, 0, 1, NULL);
                } else {
                    result = Remove_Localfile(&(globs[j].gfiles), i, 1, 0, &globs[j]);
                }

                if (result) {
                    merror_exit(REM_ERROR, file_name);
                } else {
                    mdebug2(NON_TEXT_FILE, file_name);
                    mdebug2(CURRENT_FILES, current_files, maximum_files);

                    if(!file_excluded) {
                        OSHash_Add(excluded_files,file_name,(void *)1);
                    }

                    /* Add to binary hash table */
                    char *file_excluded_binary = OSHash_Get(excluded_binaries,file_name);

                    if (!file_excluded_binary) {
                        OSHash_Add(excluded_binaries,file_name,(void *)1);
                    }

                }
                i--;
            } else {

                if(file_excluded) {
                    OSHash_Delete(excluded_files,file_name);
                }
            }
        }
    }
}

#ifdef WIN32
static void check_pattern_expand_excluded() {

    int found;
    int j;

    if (globs) {
        for (j = 0; globs[j].gpath; j++) {

            if (!globs[j].exclude_path) {
                continue;
            }

            char *global_path = NULL;
            char *wildcard = NULL;
            os_strdup(globs[j].exclude_path,global_path);

            wildcard = strrchr(global_path,'\\');

            if (wildcard) {

                DIR *dir = NULL;
                struct dirent *dirent = NULL;

                *wildcard = '\0';
                wildcard++;

                if (dir = wopendir(global_path), !dir) {
                    merror("Couldn't open directory '%s' due to: %s", global_path, win_strerror(WSAGetLastError()));
                    os_free(global_path);
                    continue;
                }

                while (dirent = readdir(dir), dirent) {

                    // Skip "." and ".."
                    if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
                        continue;
                    }

                    char full_path[PATH_MAX] = {0};
                    snprintf(full_path,PATH_MAX,"%s\\%s",global_path,dirent->d_name);

                    /* Skip file if it is a directory */
                    DIR *is_dir = NULL;

                    if (is_dir = wopendir(full_path), is_dir) {
                        mdebug2("File %s is a directory. Skipping it.", full_path);
                        closedir(is_dir);
                        continue;
                    }

                    /* Match wildcard */
                    char *regex = NULL;
                    regex = wstr_replace(wildcard,".","\\p");
                    os_free(regex);
                    regex = wstr_replace(wildcard,"*","\\.*");

                    /* Add the starting ^ regex */
                    {
                        char p[PATH_MAX] = {0};
                        snprintf(p,PATH_MAX,"^%s",regex);
                        os_free(regex);
                        os_strdup(p,regex);
                    }

                    /* If wildcard is only ^\.* add another \.* */
                    if (strlen(regex) == 4) {
                        char *rgx = NULL;
                        rgx = wstr_replace(regex,"\\.*","\\.*\\.*");
                        os_free(regex);
                        regex = rgx;
                    }

                    /* Add $ at the end of the regex */
                    wm_strcat(&regex, "$", 0);

                    if(!OS_Regex(regex,dirent->d_name)) {
                        mdebug2("Regex %s doesn't match with file '%s'",regex,dirent->d_name);
                        os_free(regex);
                        continue;
                    }

                    os_free(regex);

                    found = 0;
                    int k;
                    for (k = 0; globs[j].gfiles[k].file; k++) {
                        if (!strcmp(globs[j].gfiles[k].file, full_path)) {
                            found = 1;
                            break;
                        }
                    }

                    /* Excluded file found, remove it completely */
                    if(found) {
                        int result;

                        if (j < 0) {
                            result = Remove_Localfile(&logff, k, 0, 1, NULL);
                        } else {
                            result = Remove_Localfile(&(globs[j].gfiles), k, 1, 0, &globs[j]);
                        }

                        if (result) {
                            merror_exit(REM_ERROR,full_path);
                        } else {

                            /* Add the excluded file to the hash table */
                            char *file = OSHash_Get(excluded_files,full_path);

                            if(!file) {
                                OSHash_Add(excluded_files,full_path,(void *)1);
                                minfo(EXCLUDE_FILE,full_path);
                            }

                            mdebug2(EXCLUDE_FILE,full_path);
                            mdebug2(CURRENT_FILES, current_files, maximum_files);
                        }
                    }
                }
                closedir(dir);
            }
            os_free(global_path);
        }
    }
}
#endif


static void set_can_read(int value){

    RWLOCK_LOCK_WRITE(&can_read_rwlock, {
        _can_read = value;
    });
}

int can_read() {

    int ret;
    RWLOCK_LOCK_READ(&can_read_rwlock, {
        ret = _can_read;
    });
    return ret;
}

int w_update_file_status(const char * path, int64_t pos, EVP_MD_CTX * context) {

    os_file_status_t * data;
    os_malloc(sizeof(os_file_status_t), data);

    data->context = context;

    os_sha1 output;
    OS_SHA1_Stream(context, output, NULL);
    memcpy(data->hash, output, sizeof(os_sha1));

    data->offset = pos;

    if (OSHash_Update_ex(files_status, path, data) != 1) {
        if (OSHash_Add_ex(files_status, path, data) != 2) {
            EVP_MD_CTX_free(context);
            os_free(data);
            return -1;
        }
    }

    return 0;
}

void free_files_status_data(os_file_status_t *data) {
    if (!data) return;
    EVP_MD_CTX_free(data->context);
    os_free(data);
}

STATIC void w_initialize_file_status() {

    /* Initialize hash table to associate paths and read position */
    if (files_status = OSHash_Create(), files_status == NULL) {
        merror_exit(HCREATE_ERROR, files_status_name);
    }

    if (OSHash_setSize(files_status, LOCALFILES_TABLE_SIZE) == 0) {
        merror_exit(HSETSIZE_ERROR, files_status_name);
    }

    OSHash_SetFreeDataPointer(files_status, (void (*)(void *))free_files_status_data);

    /* Read json file to load last read positions */
    FILE * fd = NULL;

    if (fd = wfopen(LOCALFILE_STATUS, "r"), fd != NULL) {
        char str[OS_MAXSTR] = {0};

        if (fread(str, 1, OS_MAXSTR - 1, fd) < 1) {
            merror(FREAD_ERROR, LOCALFILE_STATUS, errno, strerror(errno));
            clearerr(fd);
        } else {
            cJSON * global_json = cJSON_Parse(str);
            w_load_files_status(global_json);
            cJSON_Delete(global_json);
        }

        fclose(fd);
    } else if (errno != ENOENT) {
        merror(FOPEN_ERROR, LOCALFILE_STATUS, errno, strerror(errno));
    }
}

STATIC void w_save_file_status() {

    char * str = w_save_files_status_to_cJSON();

    if (str == NULL) {
        return;
    }

    FILE * fd = NULL;
    size_t size_str = strlen(str);

    if (fd = wfopen(LOCALFILE_STATUS, "w"), fd != NULL) {
        if (fwrite(str, 1, size_str, fd) == 0) {
            merror(FWRITE_ERROR, LOCALFILE_STATUS, errno, strerror(errno));
            clearerr(fd);
        }
        fclose(fd);
    } else {
        merror_exit(FOPEN_ERROR, LOCALFILE_STATUS, errno, strerror(errno));
    }

    os_free(str);
}

STATIC void w_load_files_status(cJSON * global_json) {

    cJSON * localfiles_array = cJSON_GetObjectItem(global_json, OS_LOGCOLLECTOR_JSON_FILES);
    int array_size = cJSON_GetArraySize(localfiles_array);

    for (int i = 0; i < array_size; i++) {
        cJSON * localfile_item = cJSON_GetArrayItem(localfiles_array, i);

        cJSON * path = cJSON_GetObjectItem(localfile_item, OS_LOGCOLLECTOR_JSON_PATH);
        if (path == NULL) {
            continue;
        }

        char * path_str = cJSON_GetStringValue(path);
        if (path_str == NULL) {
            continue;
        }

        struct stat stat_fd;

        if (w_stat(path_str, &stat_fd) == -1) {
            continue;
        }

        cJSON * hash = cJSON_GetObjectItem(localfile_item, OS_LOGCOLLECTOR_JSON_HASH);
        if (hash == NULL) {
            continue;
        }

        char * hash_str = cJSON_GetStringValue(hash);
        if (hash_str == NULL) {
            continue;
        }

        cJSON * offset = cJSON_GetObjectItem(localfile_item, OS_LOGCOLLECTOR_JSON_OFFSET);
        if (offset == NULL) {
            continue;
        }

        char * offset_str = cJSON_GetStringValue(offset);
        if (offset_str == NULL) {
            continue;
        }

        char * end;

#ifdef WIN32
        int64_t value_offset = strtoll(offset_str, &end, 10);
#else
        int64_t value_offset = strtol(offset_str, &end, 10);
#endif

        if (value_offset < 0 || *end != '\0') {
            continue;
        }

        os_file_status_t * data;

        os_malloc(sizeof(os_file_status_t), data);
        memcpy(data->hash, hash_str, sizeof(os_sha1));
        data->offset = value_offset;

        EVP_MD_CTX *context = EVP_MD_CTX_new();
        os_sha1 output;

        if (OS_SHA1_File_Nbytes(path_str, &context, output, OS_BINARY, value_offset) < 0) {
            mdebug1(LOGCOLLECTOR_FILE_NOT_EXIST, path_str);
            EVP_MD_CTX_free(context);
            os_free(data);
            return;
        }
        data->context = context;

        if (OSHash_Update_ex(files_status, path_str, data) != 1) {
            if (OSHash_Add_ex(files_status, path_str, data) != 2) {
                merror(HADD_ERROR, path_str, files_status_name);
                EVP_MD_CTX_free(context);
                os_free(data);
            }
        }
    }
#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))

   w_macos_set_status_from_JSON(global_json);

#endif

#ifdef __linux__
    w_journald_set_status_from_JSON(global_json);
#endif

}

STATIC char * w_save_files_status_to_cJSON() {

    unsigned int index = 0;
    cJSON * global_json = NULL;
    char * global_json_str = NULL;
    OSHashNode * hash_node = NULL;

    w_rwlock_rdlock(&files_status->mutex);
    if (hash_node = OSHash_Begin(files_status, &index), hash_node != NULL) {
        os_file_status_t * data = NULL;
        cJSON * array = NULL;
        cJSON * item = NULL;
        char * path = NULL;
        char offset[OFFSET_SIZE] = {0};

        global_json = cJSON_CreateObject();
        array = cJSON_AddArrayToObject(global_json, OS_LOGCOLLECTOR_JSON_FILES);

        while (hash_node != NULL) {
            data = hash_node->data;
            path = hash_node->key;
            memset(offset, 0, OFFSET_SIZE);

            snprintf(offset, OFFSET_SIZE, "%" PRIi64, data->offset);

            item = cJSON_CreateObject();

            cJSON_AddStringToObject(item, OS_LOGCOLLECTOR_JSON_PATH, path);
            cJSON_AddStringToObject(item, OS_LOGCOLLECTOR_JSON_HASH, data->hash);
            cJSON_AddStringToObject(item, OS_LOGCOLLECTOR_JSON_OFFSET, offset);
            cJSON_AddItemToArray(array, item);

            hash_node = OSHash_Next(files_status, &index, hash_node);
        }
    }
    w_rwlock_unlock(&files_status->mutex);

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))

    cJSON * macos_status = w_macos_get_status_as_JSON();
    if (macos_status != NULL && macos_processes != NULL) {
        if (global_json == NULL) {
            global_json = cJSON_CreateObject();
        }
        cJSON_AddItemToObject(global_json, OS_LOGCOLLECTOR_JSON_MACOS, macos_status);
    }

#endif

#ifdef __linux__
    cJSON * journald_status = w_journald_get_status_as_JSON();
    if (journald_status != NULL) {
        if (global_json == NULL) {
            global_json = cJSON_CreateObject();
        }
        cJSON_AddItemToObject(global_json, JOURNALD_LOG, journald_status);
    }
#endif

    if (global_json != NULL) {
        global_json_str = cJSON_PrintUnformatted(global_json);
        cJSON_Delete(global_json);
    }

    return global_json_str;
}

STATIC int w_set_to_last_line_read(logreader * lf) {

    os_file_status_t * data;

    if (lf->file == NULL) {
        return 0;
    }

    if (data = (os_file_status_t *)OSHash_Get_ex(files_status, lf->file), data == NULL) {
        w_set_to_pos(lf, 0, SEEK_END);
        if (w_update_hash_node(lf->file, w_ftell(lf->fp)) == -1) {
            merror(HUPDATE_ERROR, lf->file, files_status_name);
        }
        return 0;
    }

    struct stat stat_fd;

    if (fstat(fileno(lf->fp), &stat_fd) == -1) {
        merror(FSTAT_ERROR, lf->file, errno, strerror(errno));
        return -1;
    }

    int64_t result = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    os_sha1 output;

    if (OS_SHA1_File_Nbytes(lf->file, &context, output, OS_BINARY, data->offset) < 0) {
        merror(FAIL_SHA1_GEN, lf->file);
        EVP_MD_CTX_free(context);
        return -1;
    }

    if (strcmp(output, data->hash)) {
        result = w_set_to_pos(lf, 0, SEEK_SET);
    } else if (stat_fd.st_size - data->offset > lf->diff_max_size) {
        result = w_set_to_pos(lf, 0, SEEK_END);
    } else {
        EVP_MD_CTX_free(context);
        return w_set_to_pos(lf, data->offset, SEEK_SET);
    }

    if (result >= 0) {
        if (w_update_hash_node(lf->file, result) == -1) {
            merror(HUPDATE_ERROR, lf->file, files_status_name);
        }
    }

    EVP_MD_CTX_free(context);
    return result;
}

STATIC int w_update_hash_node(char * path, int64_t pos) {

    os_file_status_t * data;

    if (path == NULL) {
        return -1;
    }

    os_malloc(sizeof(os_file_status_t), data);

    data->offset = pos;

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    os_sha1 output;

    if (OS_SHA1_File_Nbytes(path, &context, output, OS_BINARY, pos) < 0) {
        merror(FAIL_SHA1_GEN, path);
        EVP_MD_CTX_free(context);
        os_free(data);
        return -1;
    }
    memcpy(data->hash, output, sizeof(os_sha1));
    data->context = context;

    if (OSHash_Update_ex(files_status, path, data) != 1) {
        if (OSHash_Add_ex(files_status, path, data) != 2) {
            EVP_MD_CTX_free(context);
            os_free(data);
            return -1;
        }
    }

    return 0;
}

STATIC int64_t w_set_to_pos(logreader * lf, int64_t pos, int mode) {

    if (lf == NULL || lf->file == NULL) {
        return -1;
    }

    if (w_fseek(lf->fp, pos, mode) < 0) {
        merror(FSEEK_ERROR, lf->file, errno, strerror(errno));
        fclose(lf->fp);
        lf->fp = NULL;
        return -1;
    }

    return w_ftell(lf->fp);
}

bool w_get_hash_context(logreader *lf, EVP_MD_CTX ** context, int64_t position) {

    os_file_status_t * data = (os_file_status_t *) OSHash_Get_ex(files_status, lf->file);

    if (data == NULL) {
        os_sha1 output;
        if (OS_SHA1_File_Nbytes_with_fp_check(lf->file, context, output, OS_BINARY, position, lf->fd) < 0) {
            return false;
        }
    } else {
        EVP_DigestInit(*context, EVP_sha1());
        EVP_MD_CTX_copy(*context, data->context);
    }
    return true;
}

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
void w_macos_release_log_show(void) {

    if (macos_processes != NULL && macos_processes->show.wfd != NULL) {
        mdebug1("macOS ULS: Releasing macOS `log show` resources.");
        if (macos_processes->show.wfd->pid > 0) {
            kill(macos_processes->show.wfd->pid, SIGTERM);
        }
        if (macos_processes->show.child > 0) {
            kill(macos_processes->show.child, SIGTERM);
        }
        wpclose(macos_processes->show.wfd);
        macos_processes->show.wfd = NULL;
        macos_processes->show.child = 0;
    }
}

void w_macos_release_log_stream(void) {

    if (macos_processes != NULL && macos_processes->stream.wfd != NULL) {
        mdebug1("macOS ULS: Releasing macOS `log stream` resources.");
        if (macos_processes->stream.wfd->pid > 0) {
            kill(macos_processes->stream.wfd->pid, SIGTERM);
        }
        if (macos_processes->stream.child > 0) {
            kill(macos_processes->stream.child, SIGTERM);
        }
        wpclose(macos_processes->stream.wfd);
        macos_processes->stream.wfd = NULL;
        macos_processes->stream.child = 0;
    }
}

void w_macos_release_log_execution(void) {

    w_macos_release_log_show();
    w_macos_release_log_stream();
}

#endif
