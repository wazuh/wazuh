/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

/* Prototypes */
int update_fname(int i, int j);
int update_current(logreader **current, int *i, int *j);
void set_read(logreader *current, int i, int j);

/* Global variables */
int loop_timeout;
int logr_queue;
int open_file_attempts;
logreader *logff;
logreader_glob *globs;
logsocket *logsk;
int vcheck_files;
int maximum_lines;
int maximum_files;
int current_files = 0;
static int _cday = 0;
logsocket default_agent = { .name = "agent" };


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
    int i = 0, r = 0, k = -1, j = -1, tg;
    int f_check = 0;
    IT_control f_control = 0;
    time_t curr_time = 0;
    char keepalive[1024];
    logreader *current;
    logreader *dup;

#ifndef WIN32
    int int_error = 0;
    struct timeval fp_timeout;
    /* To check for inode changes */
    struct stat tmp_stat;
#else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;

    /* Check if we are on Windows Vista */
    checkVista();

    /* Read vista descriptions */
    if (isVista) {
        win_read_vista_sec();
    }
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
        if (current->file) {
            IT_control d_control = CONTINUE_IT;
            for (r = 0;; r++) {
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
                        current_files--;
                        mdebug2(CURRENT_FILES, current_files, maximum_files);
                    }
                    d_control = NEXT_IT;
                    break;
                }
            }
            if (d_control) {
                i--;
                continue;
            }
        }
        k = -1;

        if (!current->file) {
            /* Do nothing, duplicated entry */
        } else if (!strcmp(current->logformat, "eventlog")) {
#ifdef WIN32

            minfo(READING_EVTLOG, current->file);
            win_startel(current->file);

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
            mwarn("eventchannel not available on this version of OSSEC");
#endif

#endif

            current->file = NULL;
            current->command = NULL;
            current->fp = NULL;
        }

        else if (strcmp(current->logformat, "command") == 0) {
            current->file = NULL;
            current->fp = NULL;
            current->size = 0;

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

        else {
            set_read(current, i, j);
            /* More tweaks for Windows. For some reason IIS places
             * some weird characters at the end of the files and getc
             * always returns 0 (even after clearerr).
             */
#ifdef WIN32
            if (current->fp) {
                current->read(current, &r, 1);
            }
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

    /* Update number of files */
    for (r=0; logff[r].logformat; r++) {
        if (!logff[r].file && !logff[r].ffile) {
            // It is a command
            current_files--;
        }
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());
    mdebug2(CURRENT_FILES, current_files, maximum_files);

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
        win_readel();
#endif

        f_check++;

        /* Check which file is available */
        for (i = 0, j = -1;; i++) {
            if (f_control = update_current(&current, &i, &j), f_control) {
                if (f_control == NEXT_IT) {
                    continue;
                } else {
                    break;
                }
            }

            if (!current->fp) {
                /* Run the command */
                if (current->command && (f_check % 2)) {
                    curr_time = time(0);
                    if ((curr_time - current->size) >= current->ign) {
                        current->size = curr_time;
                        current->read(current, &r, 0);
                    }
                }
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
                }
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
                    if (current->fp) {
                        fclose(current->fp);
#ifdef WIN32
                        CloseHandle(current->h);
#endif
                    }
                    current->fp = NULL;

                    /* Try to open it again */
                    if (handle_file(i, j, 1, 1)) {
                        current->ign++;
                        continue;
                    }
#ifdef WIN32
                    current->read(current, &r, 1);
#endif
                }
                /* Increase the error count  */
                current->ign++;
                clearerr(current->fp);
            }
        }

        /* Only check below if check > vcheck_files */
        if (f_check <= vcheck_files) {
            continue;
        }

        /* Send keep alive message */
        rand_keepalive_str(keepalive, KEEPALIVE_SIZE);
        SendMSG(logr_queue, keepalive, "ossec-keepalive", LOCALFILE_MQ);

        /* Zero f_check */
        f_check = 0;

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
                    if (handle_file(i, j, 0, 1)) {
                        current->ign++;
                    }
                    continue;
                }

                /* Variable file name */
                else if (!current->fp) {
                    if (handle_file(i, j, 0, 1)) {
                        current->ign++;
                    }
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
                    merror(FOPEN_ERROR, current->file, errno, strerror(errno));
                    if (errno == ENOENT) {
                        minfo(REM_FILE, current->file);
                        // Only expanded files that have been deleted will be forgotten
                        if (j >= 0) {
                            if (Remove_Localfile(&(globs[j].gfiles), i, 1, 0)) {
                                merror(REM_ERROR, current->file);
                            } else {
                                current_files--;
                                mdebug2(CURRENT_FILES, current_files, maximum_files);
                                i--;
                                continue;
                            }
                        }
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
                    if (handle_file(i, j, 0, 1) ) {
                        current->ign++;
                    }
                    continue;
                }
#ifdef WIN32
                else if (current->size > (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow))
#else
                else if (current->size > tmp_stat.st_size)
#endif
                {
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
                    if (handle_file(i, j, 1, 1) ) {
                        current->ign++;
                    }
                }
#ifdef WIN32
                else {
                    CloseHandle(h1);
                }
#endif
            }


            /* Too many errors for the file */
            if (current->ign > open_file_attempts) {
                /* 999 Maximum ignore */
                if (current->ign == 999) {
                    continue;
                }

                minfo(LOGC_FILE_ERROR, current->file);
                if (current->fp) {
                    fclose(current->fp);
#ifdef WIN32
                    CloseHandle(current->h);
#endif
                }

                current->fp = NULL;

                /* If the file has a variable date, ignore it for today only */
                if (!current->ffile) {
                    /* Variable log files should always be attempted
                     * to be open...
                     */
                    //current->file = NULL;
                }
                current->ign = 999;
                continue;
            }

            /* File not open */
            if (!current->fp) {
                if (current->ign >= 999) {
                    continue;
                } else {
                    /* Try for a few times to open the file */
                    if (handle_file(i, j, 1, 1) < 0) {
                        current->ign++;
                    }
                    continue;
                }
            }

            /* Update file size */
#ifdef WIN32
            current->size = lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow;
#else
            current->size = tmp_stat.st_size;
#endif
        }

#ifndef WIN32
        // Check for new files to be expanded
        if (globs) {
            glob_t g;
            int err;
            int glob_offset;
            int found;

            for (j=0; globs[j].gpath; j++) {
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
                        mdebug1(FILE_LIMIT);
                        break;
                    }
                    found = 0;
                    for (i=0; globs[j].gfiles[i].file; i++) {
                        if (!strcmp(globs[j].gfiles[i].file, g.gl_pathv[glob_offset])) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        minfo(NEW_GLOB_FILE, globs[j].gpath, g.gl_pathv[glob_offset]);
                        os_realloc(globs[j].gfiles, (i +2)*sizeof(logreader), globs[j].gfiles);
                        memcpy(&globs[j].gfiles[i], globs[j].gfiles, sizeof(logreader));
                        os_strdup(g.gl_pathv[glob_offset], globs[j].gfiles[i].file);
                        globs[j].gfiles[i].fp = NULL;
                        globs[j].gfiles[i + 1].file = NULL;

                        if (handle_file(i, j, 0, 0) ) {
                            current->ign++;
                        }

                        current_files++;
                        mdebug2(CURRENT_FILES, current_files, maximum_files);
                        if  (!i && !globs[j].gfiles[i].read) {
                            set_read(&globs[j].gfiles[i], i, j);
                        }
                    }

                    glob_offset++;
                }
                globfree(&g);
            }
        }
#endif
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
        if (do_log == 1) {
            merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
        }
        return (-1);
    }
    /* Get inode number for fp */
    fd = fileno(lf->fp);
    if (fstat(fd, &stat_fd) == -1) {
        merror(FSTAT_ERROR, lf->file, errno, strerror(errno));
        fclose(lf->fp);
        lf->fp = NULL;
        return (-1);
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
        return (-1);
    }
    fd = _open_osfhandle((long)lf->h, 0);
    if (fd == -1) {
        merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
        CloseHandle(lf->h);
        return (-1);
    }
    lf->fp = _fdopen(fd, "r");
    if (!lf->fp) {
        merror(FOPEN_ERROR, lf->file, errno, strerror(errno));
        CloseHandle(lf->h);
        return (-1);
    }


    /* On windows, we also need the real inode, which is the combination
     * of the index low + index high numbers.
     */
    if (GetFileInformationByHandle(lf->h, &lpFileInformation) == 0) {
        merror("Unable to get file information by handle.");
        fclose(lf->fp);
        CloseHandle(lf->h);
        lf->fp = NULL;
        return (-1);
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
            return (-1);
        }
#endif
    }

    /* Set ignore to zero */
    lf->ign = 0;
    return (0);
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

    /* Initialize the files */
    if (current->ffile) {
        /* Day must be zero for all files to be initialized */
        _cday = 0;
        if (update_fname(i, j)) {
            if (handle_file(i, j, 1, 1)) {
                current->ign++;
            }
        } else {
            merror_exit(PARSE_ERROR, current->ffile);
        }

    } else {
        if (handle_file(i, j, 1, 1)) {
            current->ign++;
        }
    }

    minfo(READING_FILE, current->file);

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
    } else if (current->logformat[0] >= '0' && current->logformat[0] <= '9') {
        current->read = read_multiline;
    } else if (strcmp("audit", current->logformat) == 0) {
        current->read = read_audit;
    } else {
        current->read = read_syslog;
    }
}
