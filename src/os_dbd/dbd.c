/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef DBD
   #define DBD
#endif

#ifndef ARGV0
   #define ARGV0 "ossec-dbd"
#endif

#include "shared.h"
#include "dbd.h"



/* OS_DBD: Monitor the alerts and insert them into the database.
 * Only return in case of error.
 */
void OS_DBD(DBConfig *db_config)
{
    unsigned int s_ip, d_ip;
    
    time_t tm;     
    struct tm *p;       

    char sql_query[OS_SIZE_2048 +1];
    file_queue *fileq;
    alert_data *al_data;


    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);	


    /* Initating file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, 0);


    memset(sql_query, '\0', OS_SIZE_2048 +1);


    /* Infinite loop reading the alerts and inserting them. */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);

        s_ip = 0;
        d_ip = 0;

        
        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 5);
        if(!al_data)
        {
            continue;
        }


        debug2("%s: DEBUG: Got data: %d, %d, %s, %s", 
                                     ARGV0,
                                     al_data->rule,
                                     al_data->level,
                                     al_data->location,
                                     al_data->group);


        /* Converting srcip to int */
        if(al_data->srcip)
        {
            struct in_addr net;

            /* Extracting ip address */
            if(inet_aton(al_data->srcip, &net))
            {
                debug2("%s: DEBUG: found ip: %u for %s", ARGV0, net.s_addr, 
                                                         al_data->srcip);
                s_ip = net.s_addr;
            }
        }
        

        /* Escaping strings */
        osdb_escapestr(al_data->user);
        osdb_escapestr(al_data->log[0]);
         

        /* We first need to insert the location */


        /* Generating SQL */
        snprintf(sql_query, OS_SIZE_2048,
                 "INSERT INTO "
                 "alert(id,signature_id,timestamp,src_ip,user,full_log) "
                 "VALUES (NULL, '%u','%u','%lu', '%s', '%s') ",
                 al_data->rule, time(0), 
                 (unsigned long)ntohl(s_ip), al_data->user, 
                 al_data->log[0]);


        /* Inserting into the db */
        if(!osdb_query_insert(db_config->conn, sql_query))
        {
            merror(DB_MAINERROR, ARGV0);
        }

        
        /* Clearing the memory */
        FreeAlertData(al_data);
    }
}

/* EOF */
