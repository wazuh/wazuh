/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"
#include <math.h>
#include <pthread.h>

/* Prototypes */
static int update_fname(int i, int j);
static int update_current(logreader **current, int *i, int *j);
static void set_read(logreader *current, int i, int j);
static IT_control remove_duplicates(logreader *current, int i, int j);
static void set_sockets();
#ifndef WIN32
static int check_pattern_expand(int do_seek);
#endif

/* Global variables */
int loop_timeout;
int logr_queue;
int open_file_attempts;
logreader *logff;
logreader_glob *globs;
logsocket *logsk;
int vcheck_files;
int maximum_lines;
int sample_log_length;
int force_reload;
int reload_interval;
int reload_delay;

static int _cday = 0;
int N_INPUT_THREADS = N_MIN_INPUT_THREADS;
int OUTPUT_QUEUE_SIZE = OUTPUT_MIN_QUEUE_SIZE;
logsocket default_agent = { .name = "agent" };

/* Output thread variables */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#ifdef WIN32
static pthread_mutex_t win_el_mutex;
static pthread_mutexattr_t win_el_mutex_attr;
#endif

/* Multiple readers / one write mutex */
static pthread_rwlock_t files_update_rwlock;

static char *rand_keepalive_str(char *dst, int size)
{
    static const char text[] = "abcdefghijklmnopqrstuvwxyz"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "0123456789"
                               "!@#$%^&*()_+-=;'[],./?";
    int i;
    int len;
    srandom_init();
    len = os_random() % (size - 10);
    len = len >= 0 ? len : -len;

    strncpy(dst, "--MARK--: ", 12);
    for ( i = 10; i < len; ++i ) {
        dst[i] = text[(unsigned int)os_random() % (sizeof text - 1)];
    }
    dst[i] = '\0';
    return dst;
}

/* Handle file management */
void LogCollectorStart()
{
    int i = 0, j = -1, tg;
    int f_check = 0;
    int f_reload = 0;
    IT_control f_control = 0;
    char keepalive[1024];
    logreader *current;

    total_files = 0;
    current_files = 0;

    set_sockets();
    w_rwlock_init(&files_update_rwlock, NULL);

#ifndef WIN32
    /* To check for inode changes */
    struct stat tmp_stat;

    check_pattern_expand(1);

    /* Set the files mutexes */
    w_set_file_mutexes();
#else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;
    int r;
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
        if (remove_duplicates(current, i, j) == NEXT_IT) {
            i--;
            continue;
        }

        if (!current->file) {
            /* Do nothing, duplicated entry */
        } else if (!strcmp(current->logformat, "eventlog")) {
#ifdef WIN32

            minfo(READING_EVTLOG, current->file);
            win_startel(current->file);

            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#endif
            current->file = NULL;
            current->command = NULL;
            current->fp = NULL;
        } else if (!strcmp(current->logformat, "eventchannel")) {
#ifdef WIN32

#ifdef EVENTCHANNEL_SUPPORT
            minfo(READING_EVTLOG, current->file);
            win_start_event_channel(current->file, current->future, current->query);
#else
            mwarn("eventchannel not available on this version of Windows");
#endif

            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#endif

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

        else if (j < 0) {
            set_read(current, i, j);
            /* More tweaks for Windows. For some reason IIS places
             * some weird characters at the end of the files and getc
             * always returns 0 (even after clearerr).
             */
#ifdef WIN32
            if (current->fp) {
                current->read(current, &r, 1);
            }

            /* Mutexes are not previously initialized under Windows*/
            w_mutex_init(&current->mutex, &win_el_mutex_attr);
#endif
        }

        if (current->alias) {
            int ii = 0;
            while (current->alias[ii] != '\0') {
                if (current->alias[ii] == ':') {
                    current->alias[ii] = '\\';
                }
                ii++;
            }
        }
    }

    /* Create the output threads */
    w_create_output_threads();

    /* Create the input threads */
    w_create_input_threads();

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());
    mdebug2(CURRENT_FILES, current_files, maximum_files);

#ifndef WIN32
    // Start com request thread
    w_create_thread(lccom_main, NULL);
#endif

    /* Daemon loop */
    while (1) {
        if (f_check >= vcheck_files) {
            w_rwlock_wrlock(&files_update_rwlock);
            int i;
            int j = -1;
            f_reload += f_check;

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

                w_rwlock_unlock(&files_update_rwlock);

                if (reload_delay) {
                    nanosleep(&delay, NULL);
                }

                w_rwlock_wrlock(&files_update_rwlock);

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
                            current->exists = 0;
                            current->ign++;

                            // Only expanded files that have been deleted will be forgotten

                            if (j >= 0) {
                                if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0)) {
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
#ifdef WIN32
                            CloseHandle(current->h);
#endif
                        }
                        current->fp = NULL;
                        current->exists = 1;

                        handle_file(i, j, 0, 1);
                        continue;
                    }

                    /* Variable file name */
                    else if (!current->fp && open_file_attempts - current->ign > 0) {
                        handle_file(i, j, 0, 1);
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
                    tf = fopen(current->file, "r");
                    if(tf == NULL) {
                        if (errno == ENOENT) {
                            if(current->exists==1){
                                minfo(FORGET_FILE, current->file);
                                current->exists = 0;
                            }
                            current->ign++;

                            // Only expanded files that have been deleted will be forgotten
                            if (j >= 0) {
                                if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0)) {
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

                    h1 = CreateFile(current->file, GENERIC_READ,
                                    FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (h1 == INVALID_HANDLE_VALUE) {
                        fclose(current->fp);
                        CloseHandle(current->h);
                        current->fp = NULL;
                        merror(FILE_ERROR, current->file);
                    } else if (GetFileInformationByHandle(h1, &lpFileInformation) == 0) {
                        fclose(current->fp);
                        CloseHandle(current->h);
                        CloseHandle(h1);
                        current->fp = NULL;
                        merror(FILE_ERROR, current->file);
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
                        SendMSG(logr_queue, msg_alert,
                                "ossec-logcollector", LOCALFILE_MQ);

                        mdebug1("File inode changed. %s",
                               current->file);

                        fclose(current->fp);

#ifdef WIN32
                        CloseHandle(current->h);
                        CloseHandle(h1);
#endif

                        current->fp = NULL;
                        handle_file(i, j, 0, 1);
                        continue;
                    }
#ifdef WIN32
                    else if (current->size > (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow))
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
                        SendMSG(logr_queue, msg_alert,
                                "ossec-logcollector", LOCALFILE_MQ);

                        mdebug1("File size reduced. %s",
                                current->file);

                        /* Get new file */
                        fclose(current->fp);

#ifdef WIN32
                        CloseHandle(current->h);
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
#ifdef WIN32
                        CloseHandle(current->h);
#endif
                    }

                    current->fp = NULL;
                    current->ign = 999;
                    continue;
                }

                /* File not open */
                if (!current->fp) {
                    if (current->ign >= 999) {
                        continue;
                    } else {
                        /* Try for a few times to open the file */
                        handle_file(i, j, 0, 1);
                        continue;
                    }
                }
            }

#ifndef WIN32
            // Check for new files to be expanded
            if (check_pattern_expand(0)) {
                /* Remove duplicate entries */
                for (i = 0, j = -1;; i++) {
                    if (f_control = update_current(&current, &i, &j), f_control) {
                        if (f_control == NEXT_IT) {
                            continue;
                        } else {
                            break;
                        }
                    }

                    if (remove_duplicates(current, i, j) == NEXT_IT) {
                        i--;
                        continue;
                    }
                }
            }
#endif
            w_rwlock_unlock(&files_update_rwlock);

            if (f_reload >= reload_interval) {
                f_reload = 0;
            }

            f_check = 0;
        }

        rand_keepalive_str(keepalive, KEEPALIVE_SIZE);
        SendMSG(logr_queue, keepalive, "ossec-keepalive", LOCALFILE_MQ);
        sleep(1);

        f_check++;
    }
}

int update_fname(int i, int j)
{
    struct tm *p;
    time_t __ctime = time(0);
    char lfile[OS_FLSIZE + 1];
    size_t ret;
    logreader *lf;

    if (j < 0) {
        lf = &logff[i];
    } else {
        lf = &globs[j].gfiles[i];
    }

    p = localtime(&__ctime);

    /* Handle file */
    if (p->tm_mday == _cday) {
        return (0);
    }

    lfile[OS_FLSIZE] = '\0';
    ret = strftime(lfile, OS_FLSIZE, lf->ffile, p);
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

    _cday = p->tm_mday;
    return (0);
}

/* Open, get the fileno, seek to the end and update mtime */
int handle_file(int i, int j, int do_fseek, int do_log)
{
    int fd;
    struct stat stat_fd = { .st_mode = 0 };
    logreader *lf;

    if (j < 0) {
        lf = &logff[i];
    } else {
        lf = &globs[j].gfiles[i];
    }

    /* We must be able to open the file, fseek and get the
     * time of change from it.
     */
#ifndef WIN32
    lf->fp = fopen(lf->file, "r");
    if (!lf->fp) {
        if (do_log == 1 && lf->exists == 1) {
            merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
            lf->exists = 0;
        }
        goto error;
    }
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

#else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;

    lf->fp = NULL;
    lf->h = CreateFile(lf->file, GENERIC_READ,
                            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (lf->h == INVALID_HANDLE_VALUE) {
        if (do_log == 1) {
            DWORD error = GetLastError();
            merror(FOPEN_ERROR, lf->file, (int)error, win_strerror(error));
        }
        goto error;
    }
    fd = _open_osfhandle((intptr_t)lf->h, 0);
    if (fd == -1) {
        merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
        CloseHandle(lf->h);
        goto error;
    }
    lf->fp = _fdopen(fd, "r");
    if (!lf->fp) {
        merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
        CloseHandle(lf->h);
        goto error;
    }


    /* On windows, we also need the real inode, which is the combination
     * of the index low + index high numbers.
     */
    if (GetFileInformationByHandle(lf->h, &lpFileInformation) == 0) {
        merror("Unable to get file information by handle.");
        fclose(lf->fp);
        CloseHandle(lf->h);
        lf->fp = NULL;
        goto error;
    }

    lf->fd = (lpFileInformation.nFileIndexLow + lpFileInformation.nFileIndexHigh);
    lf->size = (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow);

#endif

    /* Only seek the end of the file if set to */
    if (do_fseek == 1 && S_ISREG(stat_fd.st_mode)) {
        /* Windows and fseek causes some weird issues */
#ifndef WIN32
        if (fseek(lf->fp, 0, SEEK_END) < 0) {
            merror(FSEEK_ERROR, lf->file, errno, strerror(errno));
            fclose(lf->fp);
            lf->fp = NULL;
            goto error;
        }
#endif
    }

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
#ifndef WIN32
    lf->fp = fopen(lf->file, "r");

    if (!lf->fp) {
        return -1;
    }
#else
    int fd;

    lf->h = CreateFile(lf->file, GENERIC_READ,
                            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (lf->h == INVALID_HANDLE_VALUE) {
        return (-1);
    }

    fd = _open_osfhandle((intptr_t)lf->h, 0);

    if (fd == -1) {
        CloseHandle(lf->h);
        return (-1);
    }

    lf->fp = _fdopen(fd, "r");

    if (!lf->fp) {
        CloseHandle(lf->h);
        return (-1);
    }
#endif

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
    CloseHandle(lf->h);
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
    minfo(READING_FILE, current->file);
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
    } else {
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
                found = 0;
                for (i = 0; globs[j].gfiles[i].file; i++) {
                    if (!strcmp(globs[j].gfiles[i].file, g.gl_pathv[glob_offset])) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    retval = 1;
                    minfo(NEW_GLOB_FILE, globs[j].gpath, g.gl_pathv[glob_offset]);
                    os_realloc(globs[j].gfiles, (i +2)*sizeof(logreader), globs[j].gfiles);
                    if (i) {
                        memcpy(&globs[j].gfiles[i], globs[j].gfiles, sizeof(logreader));
                    }
                    os_strdup(g.gl_pathv[glob_offset], globs[j].gfiles[i].file);
                    w_mutex_init(&globs[j].gfiles[i].mutex, &attr);
                    globs[j].gfiles[i].fp = NULL;
                    globs[j].gfiles[i].exists = 1;
                    globs[j].gfiles[i + 1].file = NULL;
                    globs[j].gfiles[i + 1].target = NULL;
                    current_files++;
                    mdebug2(CURRENT_FILES, current_files, maximum_files);
                    if  (!i && !globs[j].gfiles[i].read) {
                        set_read(&globs[j].gfiles[i], i, j);
                    } else {
                        handle_file(i, j, do_seek, 1);
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
                    result = Remove_Localfile(&logff, i, 0, 1);
                } else {
                    result = Remove_Localfile(&(globs[j].gfiles), i, 1, 0);
                }
                if (result) {
                    merror_exit(REM_ERROR, current->file);
                } else {
                    mdebug2(CURRENT_FILES, current_files, maximum_files);
                }
                d_control = NEXT_IT;
                break;
            }
        }
    }

    return d_control;
}


static void set_sockets() {
    int i, j, k, t;
    logreader *current;
    char *file;

    // List readed sockets
    unsigned int sk;
    for (sk=0; logsk && logsk[sk].name; sk++) {
        mdebug1("Socket '%s' (%s) added. Location: %s", logsk[sk].name, logsk[sk].mode == UDP_PROTO ? "udp" : "tcp", logsk[sk].location);
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

    for (i = 0; targets[i].log_socket; i++)
    {
        w_mutex_lock(&mutex);

        msg = (w_msg_queue_t *)OSHash_Get(msg_queues_table, targets[i].log_socket->name);

        w_mutex_unlock(&mutex);
        w_msg_queue_push(msg, str, file, size, &targets[i], queue_mq);
    }

    return 0;
}

w_message_t * w_msg_hash_queues_pop(const char *key){
    w_msg_queue_t *msg;

    msg = OSHash_Get(msg_queues_table,key);

    if(msg)
    {
        w_message_t *message;
        message = w_msg_queue_pop(msg);

        if(message){
            return message;
        }
    }
    return NULL;
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

    w_mutex_unlock(&msg->mutex);

    if (result < 0) {
        free(message->buffer);
        free(message);
        mdebug2("Discarding log line for target '%s'", log_target->log_socket->name);

        if (!reported) {
#ifndef WIN32
            mwarn("Target '%s' message queue is full (%zu). Log lines may be lost.", log_target->log_socket->name, msg->msg_queue->size);
#else
            mwarn("Target '%s' message queue is full (%u). Log lines may be lost.", log_target->log_socket->name, msg->msg_queue->size);
#endif
            reported = 1;
        }
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

void * w_output_thread(void * args){
    char *queue_name = args;
    w_message_t *message;
    w_msg_queue_t *msg_queue;

    msg_queue = OSHash_Get(msg_queues_table,queue_name);

    while(1)
    {
        /* Pop message from the queue */
        message = w_msg_queue_pop(msg_queue);

        if (SendMSGtoSCK(logr_queue, message->buffer, message->file, message->queue_mq, message->log_target) < 0) {
            merror(QUEUE_SEND);

            if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQPATH);
            }
        }

        free(message->buffer);
        free(message);
    }

    return NULL;
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
                if (CreateThread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)w_output_thread,
                    curr_node->key,
                    0,
                    NULL) == NULL) {
                    merror(THREAD_ERROR);
                }
#endif
            }
        }
    }
}

void * w_input_thread(__attribute__((unused)) void * t_id){
    logreader *current;
    int i = 0, r = 0, j = -1;
    IT_control f_control = 0;
    time_t curr_time = 0;
#ifndef WIN32
    int int_error = 0;
    struct timeval fp_timeout;
#endif

    /* Daemon loop */
    while (1) {
#ifndef WIN32
        fp_timeout.tv_sec = loop_timeout;
        fp_timeout.tv_usec = 0;

        /* Wait for the select timeout */
        if ((r = select(0, NULL, NULL, NULL, &fp_timeout)) < 0) {
            merror(SELECT_ERROR, errno, strerror(errno));
            int_error++;

            if (int_error >= 5) {
                merror_exit(SYSTEM_ERROR);
            }
            continue;
        }
#else

        /* Windows doesn't like select that way */
        sleep(loop_timeout + 2);

        /* Check for messages in the event viewer */

        if (pthread_mutex_trylock(&win_el_mutex) == 0) {
            win_readel();
            w_mutex_unlock(&win_el_mutex);
        }
#endif

        /* Check which file is available */
        for (i = 0, j = -1;; i++) {

            w_rwlock_rdlock(&files_update_rwlock);
            if (f_control = update_current(&current, &i, &j), f_control) {
                w_rwlock_unlock(&files_update_rwlock);

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
                    w_mutex_unlock(&current->mutex);
                    w_rwlock_unlock(&files_update_rwlock);
                    continue;
                }

                /* Windows with IIS logs is very strange.
                * For some reason it always returns 0 (not EOF)
                * the fgetc. To solve this problem, we always
                * pass it to the function pointer directly.
                */
    #ifndef WIN32
                /* We check for the end of file. If is returns EOF,
                * we don't attempt to read it.
                */
                if ((r = fgetc(current->fp)) == EOF) {
                    clearerr(current->fp);
                    w_mutex_unlock(&current->mutex);
                    w_rwlock_unlock(&files_update_rwlock);
                    continue;
                }

                /* If it is not EOF, we need to return the read character */
                ungetc(r, current->fp);
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
    #ifdef WIN32
                        CloseHandle(current->h);
    #endif
                        current->fp = NULL;

                        /* Try to open it again */
                        if (handle_file(i, j, 0, 1)) {
                            w_mutex_unlock(&current->mutex);
                            w_rwlock_unlock(&files_update_rwlock);
                            continue;
                        }
    #ifdef WIN32
                        current->read(current, &r, 1);
    #endif
                    }
                    /* Increase the error count  */
                    current->ign++;

                    if (open_file_attempts && j < 0) {
                        mdebug1(OPEN_ATTEMPT, current->file, open_file_attempts - current->ign);
                    } else {
                        mdebug1(OPEN_UNABLE, current->file);
                    }

                    clearerr(current->fp);
                    w_mutex_unlock(&current->mutex);
                }
            }

            w_rwlock_unlock(&files_update_rwlock);
        }
    }

    return NULL;
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
        if (CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)w_input_thread,
                     NULL,
                     0,
                     NULL) == NULL) {
        merror(THREAD_ERROR);
    }
#endif
    }
}
