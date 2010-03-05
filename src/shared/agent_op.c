/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"



/** Checks if syscheck is to be executed/restarted.
 *  Returns 1 on success or 0 on failure (shouldn't be executed now).
 */
int os_check_restart_syscheck() 
{
    struct stat restart_status;

    /* If the restart is not present, return 0.
     */

    if(isChroot())
    {
        if(stat(SYSCHECK_RESTART, &restart_status) == -1)
            return(0);
        
        unlink(SYSCHECK_RESTART);    
    }
    else
    {
        if(stat(SYSCHECK_RESTART_PATH, &restart_status) == -1)
            return(0);
        
        unlink(SYSCHECK_RESTART_PATH);    
    }
    

    return(1);    
}



/** Sets syscheck to be restarted.
 *  Returns 1 on success or 0 on failure.
 */
int os_set_restart_syscheck()
{
    FILE *fp;

    fp = fopen(SYSCHECK_RESTART, "w");
    if(!fp)
    {
        merror(FOPEN_ERROR, __local_name, SYSCHECK_RESTART);
        return(0);
    }

    fprintf(fp, "%s\n", SYSCHECK_RESTART);
    fclose(fp);


    return(1);
}



/** char *os_read_agent_name()
 *  Reads the agent name for the current agent.
 *  Returns NULL on error.
 */
char* os_read_agent_name()
{
    char buf[1024 + 1];
    FILE *fp = NULL;

    if(isChroot())
        fp = fopen(AGENT_INFO_FILE, "r");
    else
        fp = fopen(AGENT_INFO_FILEP, "r");
        
    /* We give 1 second for the file to be created... */ 
    if(!fp)
    {
        sleep(1);

        if(isChroot())
            fp = fopen(AGENT_INFO_FILE, "r");
        else
            fp = fopen(AGENT_INFO_FILEP, "r");        
    }
    
    if(!fp)
    {
        debug1(FOPEN_ERROR, __local_name, AGENT_INFO_FILE);
        return(NULL);
    }

    buf[1024] = '\0';


    /* Getting name */
    if(fgets(buf, 1024, fp))
    {
        char *ret = NULL;
        os_strdup(buf, ret);
        fclose(fp);
        
        return(ret);
    }

    fclose(fp);
    return(NULL);
}



/** char *os_read_agent_ip()
 *  Reads the agent ip for the current agent.
 *  Returns NULL on error.
 */
char *os_read_agent_ip()
{
    char buf[1024 + 1];
    FILE *fp;

    fp = fopen(AGENT_INFO_FILE, "r");
    if(!fp)
    {
        merror(FOPEN_ERROR, __local_name, AGENT_INFO_FILE);
        return(NULL);
    }

    buf[1024] = '\0';


    /* Getting IP */
    if(fgets(buf, 1024, fp) && fgets(buf, 1024, fp))
    {
        char *ret = NULL;
        os_strdup(buf, ret);
        fclose(fp);

        return(ret);
    }

    fclose(fp);
    return(NULL);
}



/** char *os_read_agent_id()
 *  Reads the agent id for the current agent.
 *  Returns NULL on error.
 */
char *os_read_agent_id()
{
    char buf[1024 + 1];
    FILE *fp;

    fp = fopen(AGENT_INFO_FILE, "r");
    if(!fp)
    {
        merror(FOPEN_ERROR, __local_name, AGENT_INFO_FILE);
        return(NULL);
    }

    buf[1024] = '\0';


    /* Getting id */
    if(fgets(buf, 1024, fp) && fgets(buf, 1024, fp) && fgets(buf, 1024, fp))
    {
        char *ret = NULL;
        os_strdup(buf, ret);
        fclose(fp);

        return(ret);
    }

    fclose(fp);
    return(NULL);
}



/** int os_write_agent_info(char *agent_name, char *agent_ip, char *agent_id)
 *  Writes the agent info inside the queue, for the other processes to read.
 *  Returns 1 on success or <= 0 on failure.
 */
int os_write_agent_info(char *agent_name, char *agent_ip, char *agent_id)
{
    FILE *fp;

    fp = fopen(AGENT_INFO_FILE, "w");
    if(!fp)
    {
        merror(FOPEN_ERROR, __local_name, AGENT_INFO_FILE);
        return(0);
    }

    fprintf(fp, "%s\n-\n%s\n", agent_name, agent_id);
    fclose(fp);
    return(1);
}



int os_agent_config_changed()
{
    return(0);
}


/* EOF */
