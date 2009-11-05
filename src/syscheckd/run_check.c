/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


/* SCHED_BATCH is Linux specific and is only picked up with _GNU_SOURCE */
#ifdef __linux__
	#define _GNU_SOURCE
	#include <sched.h>
#endif

#include "shared.h"
#include "syscheck.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"

#include "rootcheck/rootcheck.h"


/** Prototypes **/
int c_read_file(char *file_name, char *oldsum, char *newsum);


/* Send syscheck message.
 * Send a message related to syscheck change/addition.
 */
int send_syscheck_msg(char *msg)
{
    if(SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);

        if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        /* If we reach here, we can try to send it again */
        SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ);
    }

    return(0);
}



/* Send rootcheck message.
 * Send a message related to rootcheck change/addition.
 */
int send_rootcheck_msg(char *msg)
{
    if(SendMSG(syscheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);

        if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }

        /* If we reach here, we can try to send it again */
        SendMSG(syscheck.queue, msg, ROOTCHECK, ROOTCHECK_MQ);
    }

    return(0);
}


/* Sends syscheck db to the server.
 */
void send_sk_db()
{
    char buf[MAX_LINE +1];
    int file_count = 0;

    buf[MAX_LINE] = '\0';

    if(fseek(syscheck.fp, 0, SEEK_SET) == -1)
    {
        ErrorExit(FSEEK_ERROR, ARGV0, "syscheck_db");
    }


    /* Sending scan start message */
    if(syscheck.dir[0])
    {
        merror("%s: INFO: Starting syscheck scan (forwarding database).", ARGV0);
        send_rootcheck_msg("Starting syscheck scan.");
    }
    else
    {
        sleep(syscheck.tsleep +10);
        return;
    }
        


    while(fgets(buf,MAX_LINE, syscheck.fp) != NULL)
    {
        if((buf[0] != '#') && (buf[0] != ' ') && (buf[0] != '\n'))
        {
            char *n_buf;

            /* Removing the \n before sending to the analysis server */
            n_buf = strchr(buf,'\n');
            if(n_buf == NULL)
                continue;

            *n_buf = '\0';


            /* First 6 characters are for internal use */
            n_buf = buf;
            n_buf+=6;

            send_syscheck_msg(n_buf);


            /* A count and a sleep to avoid flooding the server.
             * Time or speed are not requirements in here
             */
            file_count++;


            /* sleep X every Y files */
            if(file_count >= syscheck.sleep_after)
            {
                sleep(syscheck.tsleep);
                file_count = 0;
            }
        }
    }


    /* Sending scan ending message */
    sleep(syscheck.tsleep +10);

    if(syscheck.dir[0])
    {
        merror("%s: INFO: Ending syscheck scan (forwarding database).", ARGV0);
        send_rootcheck_msg("Ending syscheck scan.");
    }
}
     

 
/* start_daemon
 * Run periodicaly the integrity checking 
 */
void start_daemon()
{
    int day_scanned = 0;
    int curr_day = 0;
    
    time_t curr_time = 0;
    
    time_t prev_time_rk = 0;
    time_t prev_time_sk = 0;

    char curr_hour[12];

    struct tm *p;
   

    /* To be used by select. */
    #ifdef USEINOTIFY
    struct timeval selecttime;
    fd_set rfds;
    #endif

    
    /*
     * SCHED_BATCH forces the kernel to assume this is a cpu intensive 
     * process
     * and gives it a lower priority. This keeps ossec-syscheckd 
     * from reducing
     * the interactity of an ssh session when checksumming large files.
     * This is available in kernel flavors >= 2.6.16
     */
    #ifdef SCHED_BATCH
    struct sched_param pri;
    int status;
    
    pri.sched_priority = 0;
    status = sched_setscheduler(0, SCHED_BATCH, &pri);
    
    debug1("%s: Setting SCHED_BATCH returned: %d", ARGV0, status);
    #endif
    
            
    #ifdef DEBUG
    verbose("%s: Starting daemon ..",ARGV0);
    #endif
  
  
    
    /* Some time to settle */
    memset(curr_hour, '\0', 12);
    sleep(syscheck.tsleep * 10);



    /* If the scan time/day is set, reset the 
     * syscheck.time/rootcheck.time 
     */
    if(syscheck.scan_time || syscheck.scan_day)
    {
        /* At least once a week. */
        syscheck.time = 604800;
        rootcheck.time = 604800;
    }


    /* Will create the db to store syscheck data */
    if(syscheck.scan_on_start)
    {
        create_db(1);
        fflush(syscheck.fp);

        sleep(syscheck.tsleep * 60);
        send_sk_db();
    }
    else
    {
        prev_time_rk = time(0);
    }
               

    
    /* Before entering in daemon mode itself */
    prev_time_sk = time(0);
    sleep(syscheck.tsleep * 10);
    

    /* If the scan_time or scan_day is set, we need to handle the
     * current day/time on the loop.
     */
    if(syscheck.scan_time || syscheck.scan_day)
    {
        curr_time = time(0); 
        p = localtime(&curr_time);


        /* Assign hour/min/sec values */
        snprintf(curr_hour, 9, "%02d:%02d:%02d",
                p->tm_hour,
                p->tm_min,
                p->tm_sec);


        curr_day = p->tm_mday;


        
        if(syscheck.scan_time && syscheck.scan_day)
        {
            if((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
               (OS_IsonDay(p->tm_wday, syscheck.scan_day)))
            {
                day_scanned = 1;
            }
        }

        else if(syscheck.scan_time)
        {
            if(OS_IsAfterTime(curr_hour, syscheck.scan_time))
            {
                day_scanned = 1;
            }
        }
        else if(syscheck.scan_day)
        {
            if(OS_IsonDay(p->tm_wday, syscheck.scan_day))
            {
                day_scanned = 1;
            }
        }
    }

    
    #if defined (USEINOTIFY) || defined (WIN32)
    if(syscheck.realtime && (syscheck.realtime->fd >= 0))
        verbose("%s: INFO: Starting real time file monitoring.", ARGV0);
    #endif
    

    /* Checking every SYSCHECK_WAIT */    
    while(1)
    {
        int run_now = 0;
        curr_time = time(0);
        

        /* Checking if syscheck should be restarted, */
        run_now = os_check_restart_syscheck();

        
        /* Checking if a day_time or scan_time is set. */
        if(syscheck.scan_time || syscheck.scan_day)
        {
            p = localtime(&curr_time);


            /* Day changed. */
            if(curr_day != p->tm_mday)
            {
                day_scanned = 0;
                curr_day = p->tm_mday;
            }
            
            
            /* Checking for the time of the scan. */
            if(!day_scanned && syscheck.scan_time && syscheck.scan_day)
            {
                if((OS_IsAfterTime(curr_hour, syscheck.scan_time)) &&
                   (OS_IsonDay(p->tm_wday, syscheck.scan_day)))
                {
                    day_scanned = 1;
                    run_now = 1;
                }
            }
            
            else if(!day_scanned && syscheck.scan_time)
            {
                /* Assign hour/min/sec values */
                snprintf(curr_hour, 9, "%02d:%02d:%02d", 
                                    p->tm_hour, p->tm_min, p->tm_sec);

                if(OS_IsAfterTime(curr_hour, syscheck.scan_time))
                {
                    run_now = 1;
                    day_scanned = 1;
                }
            }

            /* Checking for the day of the scan. */
            else if(!day_scanned && syscheck.scan_day)
            {
                if(OS_IsonDay(p->tm_wday, syscheck.scan_day))
                {
                    run_now = 1;
                    day_scanned = 1;
                }
            }
        }
        
        

        /* If time elapsed is higher than the rootcheck_time,
         * run it.
         */
        if(syscheck.rootcheck)
        {
            if(((curr_time - prev_time_rk) > rootcheck.time) || run_now)
            {
                run_rk_check();
                prev_time_rk = time(0);
            }
        }

        
        /* If time elapsed is higher than the syscheck time,
         * run syscheck time.
         */
        if(((curr_time - prev_time_sk) > syscheck.time) || run_now)
        {
            /* We need to create the db, if scan on start is not set. */
            if(syscheck.scan_on_start == 0)
            {
                create_db(1);
                fflush(syscheck.fp);

                sleep(syscheck.tsleep * 10);
                send_sk_db();
                sleep(syscheck.tsleep * 10);

                syscheck.scan_on_start = 1;
            }
            
            
            else
            {
                /* Sending scan start message */
                if(syscheck.dir[0])
                {
                    merror("%s: INFO: Starting syscheck scan.", ARGV0);
                    send_rootcheck_msg("Starting syscheck scan.");
                }


                #ifdef WIN32
                /* Checking for registry changes on Windows */
                os_winreg_check();
                #endif


                check_db();


                /* Set syscheck.fp to the begining of the file */
                fseek(syscheck.fp, 0, SEEK_SET);


                /* Checking for changes */
                run_check();
            }

            
            /* Sending scan ending message */
            sleep(syscheck.tsleep + 20);
            if(syscheck.dir[0])
            {
                merror("%s: INFO: Ending syscheck scan.", ARGV0);
                send_rootcheck_msg("Ending syscheck scan.");
            }
                


            /* Sending database completed message */
            send_syscheck_msg(HC_SK_DB_COMPLETED);
            debug2("%s: DEBUG: Sending database completed message.", ARGV0);

            
            prev_time_sk = time(0);
        } 


        #ifdef USEINOTIFY
        if(syscheck.realtime && (syscheck.realtime->fd >= 0))
        {
            selecttime.tv_sec = SYSCHECK_WAIT;
            selecttime.tv_usec = 0;

            /* zero-out the fd_set */
            FD_ZERO (&rfds);

            FD_SET(syscheck.realtime->fd, &rfds);

            run_now = select(syscheck.realtime->fd + 1, &rfds, 
                             NULL, NULL, &selecttime);
            if(run_now < 0)
            {
                merror("%s: ERROR: Select failed (for realtime fim).", ARGV0);
                sleep(SYSCHECK_WAIT);
            }
            else if(run_now == 0)
            {
                /* Timeout. */
            }
            else if (FD_ISSET (syscheck.realtime->fd, &rfds))
            {
                realtime_process();
            }
        }
        else
        {
            sleep(SYSCHECK_WAIT);
        }

        #elif WIN32
        if(syscheck.realtime && (syscheck.realtime->fd >= 0))
        {
            run_now = WaitForSingleObjectEx(syscheck.realtime->evt, SYSCHECK_WAIT * 1000, TRUE);
            if(run_now == WAIT_FAILED)
            {
                merror("%s: ERROR: WaitForSingleObjectEx failed (for realtime fim).", ARGV0);
                sleep(SYSCHECK_WAIT);
            }
            else
            {
                sleep(1);
            }
        }
        else
        {
            sleep(SYSCHECK_WAIT);
        }


        #else
        sleep(SYSCHECK_WAIT);
        #endif
    }
}


/* run_check: v0.1
 * Read the database and check if the binary has changed
 */
void run_check()
{
    char c_sum[256 +2];
    char alert_msg[912 +2];
    char buf[MAX_LINE +2];
    int file_count = 0;


    /* Cleaning buffer */
    memset(buf, '\0', MAX_LINE +1);
    memset(alert_msg, '\0', 912 +1);
    memset(c_sum, '\0', 256 +1);

    /* fgets garantee the null termination */
    while(fgets(buf, MAX_LINE, syscheck.fp) != NULL)
    {
        /* Buf should be in the following format:
         * header checksum file_name (checksum space filename)
         */
        char *n_file; /* file read from the db */
        char *n_sum;  /* md5sum read from the db */
        char *tmp_c;  /* tmp_char */
        
        
        /* Avoiding wrong formats in the database. Alert about them */
        if(buf[0] == '#' || buf[0] == ' ' || buf[0] == '\n')
        {
            merror("%s: Invalid entry in the integrity database: '%s'",
                                                            ARGV0, buf);
            continue;
        }
        
        /* Adding a sleep in here -- avoid floods and extreme CPU usage
         * on the client side -- speed not necessary
         */
         file_count++;
         if(file_count >= (syscheck.sleep_after))
         {
             sleep(syscheck.tsleep);
             file_count = 0;
         }
        
         
        /* Finding the file name */
        n_file = strchr(buf, ' ');
        if(n_file == NULL)
        {
            merror("%s: Invalid entry in the integrity check database.",ARGV0);
            continue;
        }

        /* Zeroing the ' ' and messing up with buf */
        *n_file = '\0';


        /* Setting n_file to the begining of the file name */
        n_file++;


        /* Removing the '\n' if present and setting it to \0 */
        tmp_c = strchr(n_file,'\n');
        if(tmp_c)
        {
            *tmp_c = '\0';
        }
        
        
        /* Setting n_sum to the begining of buf */
        n_sum = buf;


        /* Cleaning up c_sum */
        memset(c_sum, '\0', 16);        
        c_sum[255] = '\0';
        

        /* If it returns < 0, we will already have alerted. */
        if(c_read_file(n_file, n_sum, c_sum) < 0)
            continue;


        if(strcmp(c_sum, n_sum+6) != 0)
        {
            /* Sending the new checksum to the analysis server */
            alert_msg[912 +1] = '\0';
            snprintf(alert_msg, 912, "%s %s", c_sum, n_file);
            send_syscheck_msg(alert_msg);

            continue;
        }

        /* FILE OK if reached here */
    }
}


/* c_read_file
 * Read file information and return a pointer
 * to the checksum
 */
int c_read_file(char *file_name, char *oldsum, char *newsum)
{
    int size = 0, perm = 0, owner = 0, group = 0, md5sum = 0, sha1sum = 0;
    
    struct stat statbuf;

    os_md5 mf_sum;
    os_sha1 sf_sum;


    /* Cleaning sums */
    strncpy(mf_sum, "xxx", 4);
    strncpy(sf_sum, "xxx", 4);
                    
    

    /* Stating the file */
    #ifdef WIN32
    if(stat(file_name, &statbuf) < 0)
    #else
    if(lstat(file_name, &statbuf) < 0)
    #endif
    {
        char alert_msg[912 +2];

        alert_msg[912 +1] = '\0';
        snprintf(alert_msg, 912,"-1 %s", file_name);
        send_syscheck_msg(alert_msg);

        return(-1);
    }

    /* Getting the old sum values */

    /* size */
    if(oldsum[0] == '+')
        size = 1;

    /* perm */
    if(oldsum[1] == '+')
        perm = 1;

    /* owner */
    if(oldsum[2] == '+')
        owner = 1;     
    
    /* group */
    if(oldsum[3] == '+')
        group = 1;
        
    /* md5 sum */
    if(oldsum[4] == '+')
        md5sum = 1;

    /* sha1 sum */
    if(oldsum[5] == '+')
        sha1sum = 1;
    
    
    /* Generating new checksum */
    #ifdef WIN32
    if(S_ISREG(statbuf.st_mode))
    #else
    if(S_ISREG(statbuf.st_mode))
    #endif
    {
        if(sha1sum || md5sum)
        {
            /* Generating checksums of the file. */
            if(OS_MD5_SHA1_File(file_name, mf_sum, sf_sum) < 0)
            {
                strncpy(sf_sum, "xxx", 4);
                strncpy(mf_sum, "xxx", 4);
            }
        }
    }
    #ifndef WIN32
    /* If it is a link, we need to check if the actual file is valid. */
    else if(S_ISLNK(statbuf.st_mode))
    {
        struct stat statbuf_lnk;
        if(stat(file_name, &statbuf_lnk) == 0)
        {
            if(S_ISREG(statbuf_lnk.st_mode))
            {
                if(sha1sum || md5sum)
                {
                    /* Generating checksums of the file. */
                    if(OS_MD5_SHA1_File(file_name, mf_sum, sf_sum) < 0)
                    {
                        strncpy(sf_sum, "xxx", 4);
                        strncpy(mf_sum, "xxx", 4);
                    }
                }
            }
        }
    }
    #endif
    
    newsum[0] = '\0';
    newsum[255] = '\0';
    snprintf(newsum,255,"%d:%d:%d:%d:%s:%s",
            size == 0?0:(int)statbuf.st_size,
            perm == 0?0:(int)statbuf.st_mode,
            owner== 0?0:(int)statbuf.st_uid,
            group== 0?0:(int)statbuf.st_gid,
            md5sum   == 0?"xxx":mf_sum,
            sha1sum  == 0?"xxx":sf_sum);

    return(0);
}

/* EOF */
