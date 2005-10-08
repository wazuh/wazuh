/*   $OSSEC, run_rk_check.c, v0.1, 2005/09/30, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
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

#include "rootcheck.h"

#define MAX_LINE PATH_MAX+256

/** Prototypes **/
int c_read_file(char *file_name);


/* Global variables -- currently checksum, msg to alert  */
char c_sum[256];
char alert_msg[512];


/* notify_agent
 * Send a message to the agent client with notification
 */
 /*
int notify_agent(char *msg)
{
    if(SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK, SYSCHECK_MQ) < 0)
    {
        merror("%s: Error sending message to queue",ARGV0);

      * Trying to send it twice *
        if(SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK, SYSCHECK_MQ) == 0)
        {
            return(0);
        }

      //  * Closing before trying to open again *
        close(syscheck.queue);
        
        if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            merror("%s: Impossible to open queue",ARGV0);
            sleep(60);

            if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                ErrorExit("%s: Impossible to access queue %s",
                               ARGV0,DEFAULTQPATH); 
        }

       // * If we reach here, we can send it again *
        SendMSG(syscheck.queue, msg, SYSCHECK, SYSCHECK, SYSCHECK_MQ);
        
    }

    return(0);        
}
*/   
 
/* start_rk_daemon
 * Run periodicaly the integrity checking 
 */
void start_rk_daemon()
{
    return;
}        
        
        /*
    #ifdef DEBUG
    verbose("%s: Starting daemon ..",ARGV0);
    #endif
    
  //  * Send the integrity database to the agent *
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
                
              //  * Removing the \n before sending to the analysis server *
                n_buf = index(buf,'\n');
                if(n_buf == NULL)
                    continue;
                
                *n_buf = '\0';
                    
                notify_agent(buf);

              //  * A count and a sleep to avoid flooding the server. 
                 * Time or speed are not  requirements in here
              //   *
                file_count++;

                * sleep 2 on every 30 messages *
                if(file_count >= 30)
                {
                    sleep(2);
                    file_count = 0;
                }
            }
        }
    }

    sleep(60);// * before entering in daemon mode itself *
    
    * Check every SYSCHECK_WAIT *    
    while(1)
    {
  //      * Set syscheck.fp to the begining of the file *
        fseek(syscheck.fp,0, SEEK_SET);
        run_rk_check();
                
        sleep(SYSCHECK_WAIT);
    }
}

*/
/* run_rk_check: v0.1
 * Execute the rootkit checks
 */
void run_rk_check()
{
    int i;

    FILE *fp;
   
    /* Hard coding basedir */ 
    char basedir[] = "/";

    /* Removing the last / from basedir */
    i = strlen(basedir);
    if(i > 0)
    {
        if(basedir[i-1] == '/')
        {
            basedir[i-1] = '\0';
        }
    }
        
        
    /***  First check, look for rootkits ***/
    /* Open rootkit_files and pass the pointer to check_rc_files */
    if(!rootcheck.rootkit_files)
    {
        merror("%s: No rootcheck_files file configured.", ARGV0);
    }

    else
    {

        fp = fopen(rootcheck.rootkit_files, "r");
        if(!fp)
        {
            merror("%s: No rootcheck_files file: '%s'",ARGV0, 
                    rootcheck.rootkit_files);
        }

        check_rc_files(basedir, fp);

        fclose(fp);
    }
  
  
    /*** Second check. look for trojan entries in common binaries ***/
    if(!rootcheck.rootkit_trojans)
    {
        merror("%s: No rootcheck_trojans file configured.", ARGV0);
    }
    
    else
    {
        fp = fopen(rootcheck.rootkit_trojans, "r");
        if(!fp)
        {
            merror("%s: No rootcheck_trojans file: '%s'",ARGV0,
                                        rootcheck.rootkit_trojans);
        }

        check_rc_trojans(basedir, fp);

        fclose(fp);
    }
   
    /*** Third check, looking for files on the /dev ***/
    check_rc_dev(basedir);
    
    /*** Fourth check,  scan the whole system looking for additional issues */
    //check_rc_sys(basedir);
    
    /*** Process checking ***/
    check_rc_pids();         

    /*** Check the open ports ***/
    check_rc_ports();    

    /*** Check interfaces ***/
    check_rc_if();    
    
    debug1("%s: DEBUG: Leaving run_rk_check",ARGV0); 
    return;
}


/* EOF */
