/*   $OSSEC, run_check.c, v0.3, 2005/10/05, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.3 (2005/10/05): Adding st_mode, owner uid and group owner.
 * v0.2 (2005/08/22): Removing st_ctime, bug 1104
 * v0.1 (2005/07/15)
  */
  
#include <stdio.h>       
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "os_crypto/md5/md5_op.h"

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/mq_op.h"

#include "syscheck.h"

#include "rootcheck/rootcheck.h"

#include "error_messages/error_messages.h"

#define MAX_LINE PATH_MAX+256

/** Prototypes **/
int c_read_file(char *file_name, char *oldsum);


/* Global variables -- currently checksum, msg to alert  */
char c_sum[256 +1];
char alert_msg[512 +1];


/* notify_agent
 * Send a message to the agent client with notification
 */
int notify_agent(char *msg)
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
   
 
/* start_daemon
 * Run periodicaly the integrity checking 
 */
void start_daemon()
{
    time_t curr_time = 0;
    time_t prev_time_rk = 0;
    time_t prev_time_sk = 0;
    
            
    #ifdef DEBUG
    verbose("%s: Starting daemon ..",ARGV0);
    #endif
  
    /* Zeroing memory */
    memset(c_sum, '\0', 256 +1);
    memset(alert_msg, '\0', 512 +1);
     
    
    /* some time to settle */
    sleep(30);

    
    /* Send the integrity database to the agent */
    if(syscheck.notify == QUEUE)
    {
        char buf[MAX_LINE];
        int file_count = 0;
        
        if(fseek(syscheck.fp,0, SEEK_SET) == -1)
        {
            ErrorExit("%s: Error setting the file pointer (fseek)",ARGV0);
        }
    
        while(fgets(buf,MAX_LINE,syscheck.fp) != NULL)
        {
            if(buf[0] != '#' && buf[0] != ' ' && buf[0] != '\n')
            {
                char *n_buf;
                
                /* Removing the \n before sending to the analysis server */
                n_buf = index(buf,'\n');
                if(n_buf == NULL)
                    continue;
                
                *n_buf = '\0';
                
                
                /* First 5 characters are for internal use */
                n_buf = buf;
                n_buf+=5;
                    
                notify_agent(n_buf);


                /* A count and a sleep to avoid flooding the server. 
                 * Time or speed are not  requirements in here
                 */
                file_count++;

                /* sleep 3 every 15 messages */
                if(file_count >= 15)
                {
                    sleep(3);
                    file_count = 0;
                }
            }
        }
    }


    /* before entering in daemon mode itself */
    sleep(30);
    
    
    /* Check every SYSCHECK_WAIT */    
    while(1)
    {
        curr_time = time(0);

        /* If time elapsed is higher than the rootcheck_time,
         * run it.
         */
        #ifdef OSSECHIDS 
        if((curr_time - prev_time_rk) > rootcheck.time)
        {
            if(syscheck.rootcheck)
                run_rk_check();
            prev_time_rk = curr_time;    
        }
        #endif
        
        
        /* If time elapsed is higher than the syscheck time,
         * run syscheck time.
         */
        if((curr_time - prev_time_sk) > syscheck.time)
        {
            /* Set syscheck.fp to the begining of the file */
            fseek(syscheck.fp,0, SEEK_SET);
            run_check();

            prev_time_sk = curr_time;
        } 

        sleep(SYSCHECK_WAIT);
    }
}


/* run_check: v0.1
 * Read the database and check if the binary has changed
 */
void run_check()
{
    char buf[MAX_LINE];
    int file_count = 0;

    /* fgets garantee the null terminator */
    while(fgets(buf,MAX_LINE,syscheck.fp) != NULL)
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
            merror("%s: Invalid entry in the integrity datase: '%s'",
                                                            ARGV0, buf);
            continue;
        }
        
        /* Adding a sleep in here -- avoid floods and extreme CPU usage
         * on the client side -- speed not necessary
         */
         file_count++;
         if(file_count >= 30)
         {
             sleep(2);
             file_count = 0;
         }
        
         
        /* Finding the file name */
        n_file = index(buf,' ');
        if(n_file == NULL)
        {
            merror("%s: Invalid entry in the integrity checking database. "
                   "Wrong format for '%s'",ARGV0, buf);

            continue;
        }

        /* Zeroing the ' ' and messing up with buf */
        *n_file ='\0';

        /* Setting n_file to the begining of the file name */
        n_file++;

        /* Removing the '\n' if present and setting it to \0 */
        tmp_c = index(n_file,'\n');
        if(tmp_c)
        {
            *tmp_c = '\0';
        }
        
        
        /* Setting n_sum to the begining of buf */
        n_sum = buf;


        /* If it returns < 0, we will already have alerted if necessary */
        if(c_read_file(n_file, n_sum) < 0)
            continue;


        if(strcmp(c_sum,n_sum+5) != 0)
        {
            /* Sending the new checksum to the analysis server */
            if(syscheck.notify == QUEUE)
            {
                snprintf(alert_msg, 512,"%s %s",c_sum,n_file);
                notify_agent(alert_msg);
            }
            else
            {
                merror("%s: Checksum differ for file %s.",ARGV0,n_file);
            }
            
            continue;
        }

        /* FILE OK if reached here */
    }
}

/* c_read_file
 * Read file information and return a pointer
 * to the checksum
 */
int c_read_file(char *file_name, char *oldsum)
{
    int size = 0, perm = 0, owner = 0, group = 0, sum = 0;
    
    struct stat statbuf;

    os_md5 f_sum;

    /* stating and generating md5 of the file */
    if((lstat(file_name, &statbuf) < 0)||
            (OS_MD5_File(file_name, f_sum) < 0))
    {
        if(syscheck.notify == QUEUE)
        {
            snprintf(alert_msg, 512,"-1 %s",file_name);
            notify_agent(alert_msg);
        }

        else
        {
            merror("%s: Error accessing '%s'",ARGV0,file_name);
        }

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
        
    /* checksum */
    if(oldsum[4] == '+')
        sum = 1;    

    
    snprintf(c_sum,255,"%d:%d:%d:%d:%s",
            size == 0?0:(int)statbuf.st_size,
            perm == 0?0:(int)statbuf.st_mode,
            owner== 0?0:(int)statbuf.st_uid,
            group== 0?0:(int)statbuf.st_gid,
            sum  == 0?"xxx":f_sum);

    return(0);
}

/* EOF */
