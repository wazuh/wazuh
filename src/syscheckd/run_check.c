/* @(#) $Id$ */

/* Copyright (C) 2005-2006 Daniel B. Cid <dcid@ossec.net>
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

#include "rootcheck/rootcheck.h"


/** Prototypes **/
int c_read_file(char *file_name, char *oldsum, char *newsum);


/** Notify list values **/
char *notify_list[NOTIFY_LIST_SIZE + 3];
int notify_list_size = 0;


/* notify_agent
 * Send a message to the agent client with notification
 */
int notify_agent(char *msg, int send_now)
{
    int i = 0;
    
    
    /* msg can be null to flag send_now */
    if(msg)
    {
        /* Storing message in the notify list */
        os_strdup(msg, notify_list[notify_list_size]);
        if(notify_list_size >= NOTIFY_LIST_SIZE)
        {
            send_now = 1;
        }
        notify_list_size++;
    }


    /* Delay sending */
    if(!send_now)
        return(0);

    
    /* Sending all available messages */
    while(i < notify_list_size)
    {
        if(SendMSG(syscheck.queue, notify_list[i], SYSCHECK, SYSCHECK_MQ) < 0)
        {
            merror(QUEUE_SEND, ARGV0);

            if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }

            /* If we reach here, we can try to send it again */
            SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK_MQ);
        }

        os_free(notify_list[i]);
        notify_list[i] = NULL;
        i++;
    }

    notify_list_size = 0;
    return(0);
}
   
 
/* start_daemon
 * Run periodicaly the integrity checking 
 */
void start_daemon()
{
    time_t curr_time = 0;
    
    time_t prev_time_rk = 0;
    time_t prev_time_sk = 0;
    
    /*
     * SCHED_BATCH forces the kernel to assume this is a cpu intensive process
     * and gives it a lower priority. This keeps ossec-syscheckd from reducing
     * the interactity of an ssh session when checksumming large files.
     * This is available in kernel flavors >= 2.6.16
     */
    #ifdef SCHED_BATCH
    struct sched_param pri;
    pri.sched_priority = 0;
    
    int status = sched_setscheduler(0, SCHED_BATCH, &pri);
    
    debug1("%s: Setting SCHED_BATCH returned: %d", ARGV0, status);
    #endif
            
    #ifdef DEBUG
    verbose("%s: Starting daemon ..",ARGV0);
    #endif
  
  
    /* Zeroing memory */
    notify_list_size = NOTIFY_LIST_SIZE + 2;
    while(notify_list_size >= 0)
    {
        notify_list[notify_list_size] = NULL;
        notify_list_size--;
    }
    notify_list_size = 0;
     
    
    /* some time to settle */
    sleep(syscheck.tsleep * 10);
    
    
    /* Send the integrity database to the server */
    {
        char buf[MAX_LINE +1];
        int file_count = 0;
        
        buf[MAX_LINE] = '\0';
        
        if(fseek(syscheck.fp, 0, SEEK_SET) == -1)
        {
            ErrorExit(FSEEK_ERROR, ARGV0, "syscheck_db");
        }
    
    
        while(fgets(buf,MAX_LINE,syscheck.fp) != NULL)
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
                    
                notify_agent(n_buf, 0);


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
    }


    /* Before entering in daemon mode itself */
    prev_time_sk = time(0);
    sleep(syscheck.tsleep * 10);
    
    
    /* Check every SYSCHECK_WAIT */    
    while(1)
    {
        curr_time = time(0);


        /* If time elapsed is higher than the rootcheck_time,
         * run it.
         */
        if(syscheck.rootcheck)
        {
            if((curr_time - prev_time_rk) > rootcheck.time)
            {
                run_rk_check();
                prev_time_rk = time(0);
            }
        }

        
        /* If time elapsed is higher than the syscheck time,
         * run syscheck time.
         */
        if((curr_time - prev_time_sk) > syscheck.time)
        {
            #ifdef WIN32
            /* Checking for registry changes on Windows */
            os_winreg_check();
            #endif

            /* Looking for new files */
            check_db();

            /* Set syscheck.fp to the begining of the file */
            fseek(syscheck.fp, 0, SEEK_SET);


            /* Checking for changes */
            run_check();


            /* Sending database completed message */
            notify_agent(HC_SK_DB_COMPLETED, 1);
            debug2("%s: DEBUG: Sending database completed message.", ARGV0);

            
            prev_time_sk = time(0);
        } 

        /* Check for any message needing to be sended */
        notify_agent(NULL, 1);
        sleep(SYSCHECK_WAIT);
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
         if(file_count >= (2*syscheck.sleep_after))
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
        

        /* If it returns < 0, we will already have alerted if necessary */
        if(c_read_file(n_file, n_sum, c_sum) < 0)
            continue;


        if(strcmp(c_sum, n_sum+6) != 0)
        {
            /* Sending the new checksum to the analysis server */
            alert_msg[912 +1] = '\0';
            snprintf(alert_msg, 912, "%s %s", c_sum, n_file);
            notify_agent(alert_msg, 0);

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
        notify_agent(alert_msg, 0);

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
    if(S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
    #endif
    {
        if(sha1sum)
        {
            /* generating md5 of the file */
            if(OS_SHA1_File(file_name, sf_sum) < 0)
            {
                strncpy(sf_sum, "xxx", 4);
            }

        }

        if(md5sum)
        {
            /* generating md5 of the file */
            if(OS_MD5_File(file_name, mf_sum) < 0)
            {
                strncpy(mf_sum, "xxx", 4);
            }
        }
    }
    
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
