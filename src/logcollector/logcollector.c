/* @(#) $Id: ./src/logcollector/logcollector.c, 2012/03/28 dcid Exp $
 */

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

int _cday = 0;
int update_fname(int i);


char *rand_keepalive_str(char *dst, int size)
{
    static const char text[] = "abcdefghijklmnopqrstuvwxyz"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "0123456789"
                               "!@#$%^&*()_+-=;'[],./?";
    int i, len = rand() % (size - 10);
    strncpy(dst, "--MARK--: ", 12);
    for ( i = 10; i < len; ++i )
    {
        dst[i] = text[rand() % (sizeof text - 1)];
    }
    dst[i] = '\0';
    return dst;
}

/** void LogCollectorStart() v0.4
 * Handle file management.
 */
void LogCollectorStart()
{
    int i = 0, r = 0;
    int max_file = 0;
    int f_check = 0;
    int curr_time = 0;
    char keepalive[1024];



    /* To check for inode changes */
    struct stat tmp_stat;


    #ifndef WIN32

    int int_error = 0;
    struct timeval fp_timeout;

    #else

    /* Checking if we are on vista. */
    checkVista();


    /* Reading vista descriptions. */
    if(isVista)
    {
        win_read_vista_sec();
    }

    #endif

    debug1("%s: DEBUG: Entering LogCollectorStart().", ARGV0);


    /* Initializing each file and structure */
    for(i = 0;;i++)
    {
        if(logff[i].file == NULL)
            break;


        /* Removing duplicate entries. */
        for(r = 0; r < i; r++)
        {
            if(logff[r].file && strcmp(logff[i].file, logff[r].file) == 0)
            {
                merror("%s: WARN: Duplicated log file given: '%s'.",
                       ARGV0, logff[i].file);
                logff[i].file = NULL;
                logff[i].command = NULL;
                logff[i].fp = NULL;

                break;
            }
        }

        if(logff[i].file == NULL)
        {
            /* do nothing, duplicated entry. */
        }

        else if(strcmp(logff[i].logformat,"eventlog") == 0)
        {
            #ifdef WIN32

            verbose(READING_EVTLOG, ARGV0, logff[i].file);
            win_startel(logff[i].file);

            #endif
            logff[i].file = NULL;
            logff[i].command = NULL;
            logff[i].fp = NULL;
        }
        
        else if(strcmp(logff[i].logformat, "eventchannel") == 0)
        {
			#ifdef WIN32
			
			#ifdef EVENTCHANNEL_SUPPORT
			verbose(READING_EVTLOG, ARGV0, logff[i].file);
			win_start_event_channel(logff[i].file, logff[i].future, logff[i].query);
			#else
			merror("%s: WARN: eventchannel not available on this version of OSSEC", ARGV0);
			#endif
			
			#endif
			
			logff[i].file = NULL;
			logff[i].command = NULL;
            logff[i].fp = NULL;
        }

        else if(strcmp(logff[i].logformat, "command") == 0)
        {
            logff[i].file = NULL;
            logff[i].fp = NULL;
            logff[i].size = 0;

            if(logff[i].command)
            {
                logff[i].read = (void *)read_command;

                verbose("%s: INFO: Monitoring output of command(%d): %s", ARGV0, logff[i].ign, logff[i].command);

                if(!logff[i].alias)
                {
                    os_strdup(logff[i].command, logff[i].alias);
                }
            }
            else
            {
                merror("%s: ERROR: Missing command argument. Ignoring it.",
                       ARGV0);
            }
        }
        else if(strcmp(logff[i].logformat, "full_command") == 0)
        {
            logff[i].file = NULL;
            logff[i].fp = NULL;
            logff[i].size = 0;
            if(logff[i].command)
            {
                logff[i].read = (void *)read_fullcommand;

                verbose("%s: INFO: Monitoring full output of command(%d): %s", ARGV0, logff[i].ign, logff[i].command);

                if(!logff[i].alias)
                    os_strdup(logff[i].command, logff[i].alias);
            }
            else
            {
                merror("%s: ERROR: Missing command argument. Ignoring it.",
                       ARGV0);
            }
        }

        else
        {
            logff[i].command = NULL;


            /* Initializing the files */
            if(logff[i].ffile)
            {
                /* Day must be zero for all files to be initialized */
                _cday = 0;
                if(update_fname(i))
                {
                    handle_file(i, 1, 1);
                }
                else
                {
                    ErrorExit(PARSE_ERROR, ARGV0, logff[i].ffile);
                }

            }
            else
            {
                handle_file(i, 1, 1);
            }

            verbose(READING_FILE, ARGV0, logff[i].file);

            /* Getting the log type */
            if(strcmp("snort-full", logff[i].logformat) == 0)
            {
                logff[i].read = (void *)read_snortfull;
            }
            #ifndef WIN32
            if(strcmp("ossecalert", logff[i].logformat) == 0)
            {
                logff[i].read = (void *)read_ossecalert;
            }
            #endif
            else if(strcmp("nmapg", logff[i].logformat) == 0)
            {
                logff[i].read = (void *)read_nmapg;
            }
            else if(strcmp("mysql_log", logff[i].logformat) == 0)
            {
                logff[i].read = (void *)read_mysql_log;
            }
            else if(strcmp("mssql_log", logff[i].logformat) == 0)
            {
                logff[i].read = (void *)read_mssql_log;
            }
            else if(strcmp("postgresql_log", logff[i].logformat) == 0)
            {
                logff[i].read = (void *)read_postgresql_log;
            }
            else if(strcmp("djb-multilog", logff[i].logformat) == 0)
            {
                if(!init_djbmultilog(i))
                {
                    merror(INV_MULTILOG, ARGV0, logff[i].file);
                    if(logff[i].fp)
                    {
                        fclose(logff[i].fp);
                        logff[i].fp = NULL;
                    }
                    logff[i].file = NULL;
                }
                logff[i].read = (void *)read_djbmultilog;
            }
            else if(logff[i].logformat[0] >= '0' && logff[i].logformat[0] <= '9')
            {
                logff[i].read = (void *)read_multiline;
            }
            else
            {
                logff[i].read = (void *)read_syslog;
            }

            /* More tweaks for Windows. For some reason IIS places
             * some wierd characters at the end of the files and getc
             * always returns 0 (even after clearerr).
             */
            #ifdef WIN32
            if(logff[i].fp)
            {
                logff[i].read(i, &r, 1);
            }
            #endif
        }

        if(logff[i].alias)
        {
            int ii = 0;
            while(logff[i].alias[ii] != '\0')
            {
                if(logff[i].alias[ii] == ':')
                {
                    logff[i].alias[ii] = '\\';
                }
                ii++;
            }
        }
    }


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    max_file = i -1;


    /* Cannot be zero */
    if(max_file < 0)
    {
        max_file = 0;
    }


    /* Daemon loop */
    while(1)
    {
        #ifndef WIN32
        fp_timeout.tv_sec = loop_timeout;
        fp_timeout.tv_usec = 0;

        /* Waiting for the select timeout */
        if ((r = select(0, NULL, NULL, NULL, &fp_timeout)) < 0)
        {
            merror(SELECT_ERROR, ARGV0);
            int_error++;

            if(int_error >= 5)
            {
                ErrorExit(SYSTEM_ERROR, ARGV0);
            }
            continue;
        }
        #else

        /* Windows don't like select that way */
        sleep(loop_timeout + 2);


        /* Check for messages in the event viewer */
        win_readel();
        #endif

        f_check++;


        /* Checking which file is available */
        for(i = 0; i <= max_file; i++)
        {
            if(!logff[i].fp)
            {
                /* Run the command. */
                if(logff[i].command && (f_check %2))
                {
                    curr_time = time(0);
                    if((curr_time - logff[i].size) >= logff[i].ign)
                    {
                        logff[i].size = curr_time;
                        logff[i].read(i, &r, 0);
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
            if((r = fgetc(logff[i].fp)) == EOF)
            {
                clearerr(logff[i].fp);
                continue;
            }


            /* If it is not EOF, we need to return the read character */
            ungetc(r, logff[i].fp);
            #endif


            /* Finally, send to the function pointer to read it */
            logff[i].read(i, &r, 0);


            /* Checking for error */
            if(!ferror(logff[i].fp))
            {
                /* Clearing EOF */
                clearerr(logff[i].fp);

                /* Parsing error */
                if(r != 0)
                {
                    logff[i].ign++;
                }
            }
            /* If ferror is set */
            else
            {
                merror(FREAD_ERROR, ARGV0, logff[i].file);
                #ifndef WIN32
                if(fseek(logff[i].fp, 0, SEEK_END) < 0)
                #else
                if(1)
                #endif
                {

                    #ifndef WIN32
                    merror(FSEEK_ERROR, ARGV0, logff[i].file);
                    #endif

                    /* Closing the file */
                    if(logff[i].fp)
                    {
                        fclose(logff[i].fp);
                        #ifdef WIN32
                        CloseHandle(logff[i].h);
                        #endif
                    }
                    logff[i].fp = NULL;


                    /* Trying to open it again */
                    if(handle_file(i, 1, 1) != 0)
                    {
                        logff[i].ign++;
                        continue;
                    }

                    #ifdef WIN32
                    logff[i].read(i, &r, 1);
                    #endif
                }

                /* Increase the error count  */
                logff[i].ign++;
                clearerr(logff[i].fp);
            }
        }


        /* Only check bellow if check > VCHECK_FILES */
        if(f_check <= VCHECK_FILES)
            continue;


        /* Send keep alive message */

        rand_keepalive_str(keepalive, 700);
        SendMSG(logr_queue, keepalive, "ossec-keepalive", LOCALFILE_MQ);


        /* Zeroing f_check */
        f_check = 0;


        /* Checking if any file has been renamed/removed */
        for(i = 0; i <= max_file; i++)
        {
            /* These are the windows logs or ignored files */
            if(!logff[i].file)
                continue;


            /* Files with date -- check for day change */
            if(logff[i].ffile)
            {
                if(update_fname(i))
                {
                    if(logff[i].fp)
                    {
                        fclose(logff[i].fp);
                        #ifdef WIN32
                        CloseHandle(logff[i].h);
                        #endif
                    }
                    logff[i].fp = NULL;
                    handle_file(i, 0, 1);
                    continue;
                }

                /* Variable file name */
                else if(!logff[i].fp)
                {
                    handle_file(i, 0, 0);
                    continue;
                }
            }


            /* Check for file change -- if the file is open already */
            if(logff[i].fp)
            {
                #ifndef WIN32
                if(stat(logff[i].file, &tmp_stat) == -1)
                {
                    fclose(logff[i].fp);
                    logff[i].fp = NULL;

                    merror(FILE_ERROR, ARGV0, logff[i].file);
                }

                #else
                BY_HANDLE_FILE_INFORMATION lpFileInformation;
                HANDLE h1;

                h1 = CreateFile(logff[i].file, GENERIC_READ,
                            FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if(h1 == INVALID_HANDLE_VALUE)
                {
                    fclose(logff[i].fp);
                    CloseHandle(logff[i].h);
                    logff[i].fp = NULL;
                    merror(FILE_ERROR, ARGV0, logff[i].file);
                }
                else if(GetFileInformationByHandle(h1, &lpFileInformation) == 0)
                {
                    fclose(logff[i].fp);
                    CloseHandle(logff[i].h);
                    CloseHandle(h1);
                    logff[i].fp = NULL;
                    merror(FILE_ERROR, ARGV0, logff[i].file);;
                }
                #endif


                #ifdef WIN32
                else if(logff[i].fd != (lpFileInformation.nFileIndexLow + lpFileInformation.nFileIndexHigh))
                #else
                else if(logff[i].fd != tmp_stat.st_ino)
                #endif
                {
                    char msg_alert[512 +1];

                    snprintf(msg_alert, 512, "ossec: File rotated (inode "
                                             "changed): '%s'.",
                                             logff[i].file);

                    /* Send message about log rotated  */
                    SendMSG(logr_queue, msg_alert,
                            "ossec-logcollector", LOCALFILE_MQ);

                    debug1("%s: DEBUG: File inode changed. %s",
                            ARGV0, logff[i].file);

                    fclose(logff[i].fp);

                    #ifdef WIN32
                    CloseHandle(logff[i].h);
                    CloseHandle(h1);
                    #endif

                    logff[i].fp = NULL;
                    handle_file(i, 0, 1);
                    continue;
                }
                #ifdef WIN32
                else if(logff[i].size > (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow))
                #else
                else if(logff[i].size > tmp_stat.st_size)
                #endif
                {
                    char msg_alert[512 +1];

                    snprintf(msg_alert, 512, "ossec: File size reduced "
                                             "(inode remained): '%s'.",
                                             logff[i].file);

                    /* Send message about log rotated  */
                    SendMSG(logr_queue, msg_alert,
                            "ossec-logcollector", LOCALFILE_MQ);

                    debug1("%s: DEBUG: File size reduced. %s",
                            ARGV0, logff[i].file);


                    /* Fixing size so we don't alert more than once */
                    logff[i].size = tmp_stat.st_size;


                    /* Getting new file. */
                    fclose(logff[i].fp);

                    #ifdef WIN32
                    CloseHandle(logff[i].h);
                    CloseHandle(h1);
                    #endif

                    logff[i].fp = NULL;
                    handle_file(i, 1, 1);
                }
                #ifdef WIN32
                else
                {
                    CloseHandle(h1);
                }
                #endif
            }


            /* Too many errors for the file */
            if(logff[i].ign > open_file_attempts)
            {
                /* 999 Maximum ignore */
                if(logff[i].ign == 999)
                {
                    continue;
                }

                merror(LOGC_FILE_ERROR, ARGV0, logff[i].file);
                if(logff[i].fp)
                {
                    fclose(logff[i].fp);
                    #ifdef WIN32
                    CloseHandle(logff[i].h);
                    #endif
                }

                logff[i].fp = NULL;


                /* If the file has a variable date, ignore it for
                 * today only.
                 */
                if(!logff[i].ffile)
                {
                    /* Variable log files should always be attempted
                     * to be open...
                     */
                    //logff[i].file = NULL;
                }
                logff[i].ign = 999;
                continue;
            }


            /* File not opened */
            if(!logff[i].fp)
            {
                if(logff[i].ign >= 999)
                    continue;
                else
                {
                    /* Try for a few times to open the file */
                    if(handle_file(i, 1, 1) < 0)
                    {
                        logff[i].ign++;
                    }
                    continue;
                }
            }
        }
    }
}



/**int update_fname(int i): updates file name */
int update_fname(int i)
{
    struct tm *p;
    time_t __ctime = time(0);

    char lfile[OS_FLSIZE + 1];
    size_t ret;


    p = localtime(&__ctime);


    /* Handle file */
    if(p->tm_mday == _cday)
    {
        return(0);
    }


    lfile[OS_FLSIZE] = '\0';
    ret = strftime(lfile, OS_FLSIZE, logff[i].ffile, p);
    if(ret == 0)
    {
        ErrorExit(PARSE_ERROR, ARGV0, logff[i].ffile);
    }


    /* Update the file name */
    if(strcmp(lfile, logff[i].file) != 0)
    {
        os_free(logff[i].file);

        os_strdup(lfile, logff[i].file);

        verbose(VAR_LOG_MON, ARGV0, logff[i].file);

        /* Setting cday to zero because other files may need
         * to be changed.
         */
        _cday = 0;
        return(1);
    }

    _cday = p->tm_mday;
    return(0);
}


/* handle_file: Open, get the fileno, seek to the end and update mtime */
int handle_file(int i, int do_fseek, int do_log)
{
    int fd;
    struct stat stat_fd;

    /* We must be able to open the file, fseek and get the
     * time of change from it.
     */
    #ifndef WIN32
    logff[i].fp = fopen(logff[i].file, "r");
    if(!logff[i].fp)
    {
        if(do_log == 1)
        {
            merror(FOPEN_ERROR, ARGV0, logff[i].file);
        }
        return(-1);
    }
    /* Getting inode number for fp */
    fd = fileno(logff[i].fp);
    if(fstat(fd, &stat_fd) == -1)
    {
        merror(FILE_ERROR,ARGV0,logff[i].file);
        fclose(logff[i].fp);
        logff[i].fp = NULL;
        return(-1);
    }

    logff[i].fd = stat_fd.st_ino;
    logff[i].size =  stat_fd.st_size;


    #else
    BY_HANDLE_FILE_INFORMATION lpFileInformation;

    logff[i].fp = NULL;
    logff[i].h = CreateFile(logff[i].file, GENERIC_READ,
                            FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(logff[i].h == INVALID_HANDLE_VALUE)
    {
        if(do_log == 1)
        {
            merror(FOPEN_ERROR, ARGV0, logff[i].file);
        }
        return(-1);
    }
    fd = _open_osfhandle((long)logff[i].h, 0);
    if(fd == -1)
    {
        merror(FOPEN_ERROR, ARGV0, logff[i].file);
        CloseHandle(logff[i].h);
        return(-1);
    }
    logff[i].fp = _fdopen(fd, "r");
    if(logff[i].fp == NULL)
    {
        merror(FOPEN_ERROR, ARGV0, logff[i].file);
        CloseHandle(logff[i].h);
        return(-1);
    }


    /* On windows, we also need the real inode, which is the combination
     * of the index low + index high numbers.
     */
    if(GetFileInformationByHandle(logff[i].h, &lpFileInformation) == 0)
    {
        merror("%s: Unable to get file information by handle.", ARGV0);
        fclose(logff[i].fp);
        CloseHandle(logff[i].h);
        logff[i].fp = NULL;
        return(-1);
    }

    logff[i].fd = (lpFileInformation.nFileIndexLow + lpFileInformation.nFileIndexHigh);
    logff[i].size = (lpFileInformation.nFileSizeHigh + lpFileInformation.nFileSizeLow);

    #endif


    /* Only seek the end of the file if set to. */
    if(do_fseek == 1 && S_ISREG(stat_fd.st_mode))
    {
        /* Windows and fseek causes some weird issues.. */
        #ifndef WIN32
        if(fseek(logff[i].fp, 0, SEEK_END) < 0)
        {
            merror(FSEEK_ERROR, ARGV0,logff[i].file);
            fclose(logff[i].fp);
            logff[i].fp = NULL;
            return(-1);
        }
        #endif
    }


    /* Setting ignore to zero */
    logff[i].ign = 0;
    return(0);
}


/* EOF */
