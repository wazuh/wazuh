/*   $OSSEC, run_check.c, v0.2, 2005/08/22, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2 (2005/08/22): Removing st_ctime, bug 1104
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

#include "os_crypto/md5/md5_op.h"

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/mq_op.h"

#include "syscheck.h"

#define MAX_LINE PATH_MAX+256

/** Prototypes **/
int c_read_file(char *file_name);


/* Global variables -- currently checksum, msg to alert  */
char c_sum[256];
char alert_msg[512];


/* notify_agent
 * Send a message to the agent client with notification
 */
int notify_agent(char *msg)
{
    if(SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK, SYSCHECK_MQ) < 0)
    {
        merror("%s: Error sending message to queue",ARGV0);

        /* Trying to send it twice */
        if(SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK, SYSCHECK_MQ) == 0)
        {
            return(0);
        }

        /* Closing before trying to open again */
        close(syscheck.queue);
        
        if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            merror("%s: Impossible to open queue",ARGV0);
            sleep(60);

            if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                ErrorExit("%s: Impossible to access queue %s",
                               ARGV0,DEFAULTQPATH); 
        }

        /* If we reach here, we can send it again */
        SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK, SYSCHECK_MQ);
        
    }

    return(0);        
}
   
 
/* start_daemon
 * Run periodicaly the integrity checking 
 */
void start_daemon()
{
        
    #ifdef DEBUG
    verbose("%s: Starting daemon ..",ARGV0);
    #endif
    
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
                    
                notify_agent(buf);

                /* A count and a sleep to avoid flooding the server. 
                 * Time or speed are not  requirements in here
                 */
                file_count++;

                /* sleep 2 on every 30 messages */
                if(file_count >= 30)
                {
                    sleep(2);
                    file_count = 0;
                }
            }
        }
    }

    sleep(60); /* before entering in daemon mode itself */
    
    /* Check every SYSCHECK_WAIT */    
    while(1)
    {
        /* Set syscheck.fp to the begining of the file */
        fseek(syscheck.fp,0, SEEK_SET);
        run_check();
                
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
         * checksum file_name (checksum space filename)
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
             sleep(1);
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
        /* Using c_sum temporaly in here */
        tmp_c = index(n_file,'\n');
        if(tmp_c)
        {
            *tmp_c = '\0';
        }
        
        /* Setting n_sum to the begining of buf */
        n_sum = buf;

        /* If it returns null, we will already have alerted if necessary */
        if(c_read_file(n_file) < 0)
            continue;

        if(strcmp(c_sum,n_sum) != 0)
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
int c_read_file(char *file_name)
{
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

    snprintf(c_sum,255,"%d%s",
                (int)statbuf.st_size,
                f_sum);

    return(0);
}

/* EOF */
