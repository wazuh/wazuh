/*
 * Wazuh Integration with Osquery
 * Copyright (C) 2018 Wazuh Inc.
 * April 5, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "wmodules.h"
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor);
void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor);
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  active   = PTHREAD_COND_INITIALIZER;
int stopped;
int unlock = 0;
char *osquery_config_temp = NULL;

const wm_context WM_OSQUERYMONITOR_CONTEXT =
{
    "osquery-monitor",
    (wm_routine)wm_osquery_monitor_main,
    (wm_routine)wm_osquery_monitor_destroy
};

int get_inode (int fd)
{
    struct stat buf;
    int ret;
    ret = fstat(fd, &buf);
    if ( ret < 0 )
    {
        perror ("fstat");
        return -1;
    }
    return buf.st_ino;
}


void *Read_Log(wm_osquery_monitor_t *osquery_monitor)
{
    int i;
    int queue_fd;
    int current_inode;
    int usec = 1000000 / wm_max_eps;
    char line[OS_MAXSTR];
    FILE *result_log = NULL;

    for (i = 0; queue_fd = StartMQ(DEFAULTQPATH, WRITE), queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++)
    {
        //Trying to connect to queue
        sleep(WM_MAX_WAIT);
    }
    if (i == WM_MAX_ATTEMPTS)
    {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }
    //Critical section
    // Lock mutex and then wait for signal to relase mutex

    pthread_mutex_lock( &mutex1 );

    while(!unlock)
    {
        pthread_cond_wait( &active, &mutex1 );
    }

    while(1)
    {
        for (i = 0; i < WM_MAX_ATTEMPTS && (result_log = fopen(osquery_monitor->log_path, "r"), !result_log); i++)
        {
            sleep(1);
        }
        if(!result_log)
        {
            mterror(WM_OSQUERYMONITOR_LOGTAG, "osQuery log has not been created or bad path");
            pthread_exit(NULL);
        }
        else
        {
            current_inode = get_inode(fileno(result_log));
            fseek(result_log, 0, SEEK_END);
            //Read the file
            while(1)
            {
                if(fgets(line, OS_MAXSTR, result_log) != NULL)
                {
                    mdebug2("Sending... '%s'", line);
                    if (wm_sendmsg(usec, queue_fd, line, "osquery-monitor", LOCALFILE_MQ) < 0)
                    {
                        mterror(WM_OSQUERYMONITOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                    }
                }
                else
                {
                    //check if result path inode has changed.
                    if(get_inode(fileno(result_log)) != current_inode)
                    {
                        for (i = 0; i < WM_MAX_ATTEMPTS && (result_log = fopen(osquery_monitor->log_path, "r"), !result_log); i++)
                        {
                            sleep(1);
                        }
                        if(!result_log)
                        {
                            mterror(WM_OSQUERYMONITOR_LOGTAG, "osQuery log has not been created");
                        }
                        else
                        {
                            current_inode = get_inode(fileno(result_log));
                        }
                    }

                    if(stopped)
                    {
                        pthread_mutex_unlock( &mutex1 );
                        pthread_exit(NULL);
                    }
                }
            }
            pthread_mutex_unlock( &mutex1 );
        }
    }
}

void *Execute_Osquery(wm_osquery_monitor_t *osquery_monitor)
{
    pthread_mutex_lock( &mutex1 );
    int down = 1;
    int daemon_pid = 0;
    int status;
    int pid;
    char *arg2 = strdup("/tmp/osquery.conf.tmp");
    char *arg1 = strdup(DEFAULTDIR);
    char *arg0 = strdup("--config_path=");
    char *arg;
    os_malloc(((strlen(arg0) + strlen(arg1) + strlen(arg2) + 2)*sizeof(char)), arg);
    snprintf(arg, strlen(arg0) + strlen(arg1) + strlen(arg2) + 2, "%s%s%s", arg0, arg1, arg2);
    //We check that the osquery demon is not down, in which case we run it again.
    while(1)
    {
        if(down)
        {
            pid = fork();
            switch(pid)
            {
            case 0: //Child
                setsid();
                daemon_pid = getpid();
                if (execl(osquery_monitor->bin_path, "osqueryd", arg, (char *) NULL))
                {
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "cannot execute osquery daemon");
                }
                break;
            case -1: //ERROR
                mterror(WM_OSQUERYMONITOR_LOGTAG, "child has not been created");
            default:
                wm_append_sid(pid);
                switch (waitpid(daemon_pid, &status, WNOHANG))
                {
                case 0:
                    //OSQUERY IS WORKING, wake up the other thread to read the log file
                    down = 0;
                    unlock = 1;
                    pthread_cond_signal( &active );
                    pthread_mutex_unlock( &mutex1 );
                    break;
                case -1:
                    if (errno == ECHILD)
                    {
                        down = 1;
                    }
                    // Finished. Bad Configuration
                    stopped = 1;
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "Bad Configuration!");
                    pthread_exit(NULL);
                    break;
                }
            }
        }
        while(down == 0)
        {
            //CHECK PERIODICALLY THE DAEMON STATUS
            int status;
            pid_t return_pid = waitpid(pid, &status, WNOHANG); /* WNOHANG def'd in wait.h */
            if (return_pid == -1)
            {
                if(errno == ECHILD)
                    down = 1;
            }
            else if (return_pid == 0)
            {
                if(errno == ECHILD)
                    down = 0;
            }
            else if (return_pid == daemon_pid)
            {
                down = 0;
            }
            sleep(1);
        }
        sleep(1);
    }
}

void wm_osquery_decorators()
{
    char *line = strdup("");
    char *select = strdup("SELECT ");
    char *as = strdup(" AS ");
    char *key = NULL;
    char *value = NULL;
    char *coma = strdup(", ");
    char *osq_conf_file = strdup("/var/ossec/tmp/osquery.conf.tmp");
    char *json_block = NULL;
    char *firstPath = strdup(DEFAULTDIR);
    char *lastpath = strdup("/etc/ossec.conf");
    char *configPath = NULL;
    cJSON *root;
    cJSON *decorators;
    cJSON *always;
    wlabel_t *labels;
    struct stat stp = { 0 };
    char *content;
    FILE *osquery_conf = NULL;
    //PATH CREATION

    osquery_config_temp = strdup("/var/ossec/tmp/osquery.conf.tmp");
    os_malloc(strlen(firstPath) + strlen(lastpath), configPath);

    strcpy(configPath, firstPath);
    strcat(configPath, lastpath);


    //CJSON OBJECTS
    int i = 0;

    os_calloc(1, sizeof(wlabel_t), labels);
    ReadConfig(CLABELS, configPath, &labels, NULL);
    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "decorators", decorators = cJSON_CreateObject());
    cJSON_AddItemToObject(decorators, "always", always = cJSON_CreateArray());

    //OPEN OSQUERY CONF
    osquery_conf = fopen(osq_conf_file, "r");
    stat(osq_conf_file, &stp);
    int filesize = stp.st_size;

    os_malloc(filesize + 1, content);

    if (fread(content, 1, filesize, osquery_conf) == 0)
    {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "error in reading");
        /**close the read file*/
        fclose(osquery_conf);
        //free input string
        free(content);
    }
    content[filesize + 1] = '\0';
    //CHECK IF CONF HAVE DECORATORS
    int decorated = 0;
    if(strstr(content, "decorators") != NULL)
        decorated = 1;
    else
        decorated = 0;

    //ADD DECORATORS FROM AGENT LABELS
    if(!decorated)
    {

        for(i = 0; labels[i].key != NULL; i++)
        {
            key = strdup(labels[i].key);
            value = strdup(labels[i].value);
            int newlen = sizeof(char) * (strlen("select") + strlen(line) + strlen(key) + strlen(as) + strlen(value) + (6 * sizeof(char)));
            line = (char *)realloc(line, newlen);
            snprintf(line, newlen, "select '%s' as '%s';", value, key);
            cJSON_AddStringToObject(always, "line", line);
        }

        json_block = cJSON_PrintUnformatted(root);
        memmove(json_block, json_block + 1, strlen(json_block));
        content[strlen(content) - 1] = ',';
        content = realloc(content, sizeof(char) * (strlen(content) + strlen(json_block)));
        strcat(content, json_block);


        fclose(osquery_conf);

        //Write content to File
        osquery_conf = fopen(osquery_config_temp, "w");
        fprintf(osquery_conf, "%s", content);
        fclose(osquery_conf);
    }

    //FREE MEMORY
    free(line);
    free(select);
    free(as);
    free(key);
    free(value);
    free(coma);
    free(firstPath);
    free(lastpath);
    free(configPath);
    free(json_block);
    cJSON_Delete(root);
}


void wm_osquery_packs()
{
    //LEER ARCHIVO AGENT.CONF
    char *agent_conf_path = NULL;
    FILE *agent_conf_file = NULL;
    FILE *osquery_config_file = NULL;
    FILE *osquery_config_temp_file = NULL;
    char *packs_line = NULL;
    char *osquery_config = NULL;
    char *content = NULL;
    char *osquery_config_temp = NULL;
    char *line = NULL;
    char *firstIndex = NULL;
    char *lastIndex = NULL;
    char *namepath = NULL;
    char *aux = NULL;
    char *auxLine = NULL;
    int line_size = OS_MAXSTR;
    int num_chars = NULL;
    struct stat stp = { 0 };
    osquery_config_temp = "/var/ossec/tmp/osquery.conf.tmp";
    os_malloc(strlen(DEFAULTDIR) + strlen("/etc/shared/default/agent.conf"), agent_conf_path);
    os_malloc(OS_MAXSTR, line);

    snprintf(agent_conf_path, strlen(DEFAULTDIR) + strlen("/etc/shared/default/agent.conf"), "%s%s", DEFAULTDIR, "/etc/shared/default/agent.conf");
    packs_line = strdup(",\"packs\": {");
    agent_conf_file = fopen("/var/ossec/etc/shared/default/agent.conf", "r");




    osquery_config = strdup("/etc/osquery/osquery.conf");
    osquery_config_file = fopen(osquery_config, "r");
    stat(osquery_config, &stp);
    int filesize = stp.st_size;

    os_malloc(filesize, content);

    if (fread(content, 1, filesize - 1, osquery_config_file) == 0)
    {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "error in reading");
        /**close the read file*/
        fclose(osquery_config_file);
        //free input string
        free(content);
    }
    int counter_packs = 0;
    while((num_chars = getline(&line, &line_size, agent_conf_file)) && num_chars != -1)
    {
        if(strstr(line, "<pack>"))
        {

            os_malloc(strlen(line), auxLine);
            firstIndex = strstr(line, ">") + 1;
            lastIndex = strstr(firstIndex, "<");

            namepath = strdup("\"Pack\": ");
            auxLine = (char *) realloc(auxLine, (strlen(firstIndex) - strlen(lastIndex)));
            memcpy(auxLine, firstIndex, strlen(firstIndex) - strlen(lastIndex));
            os_malloc(strlen(namepath) + strlen(auxLine) + strlen("\"\0"), aux);
            snprintf(aux, strlen(namepath) + strlen(auxLine) + 3, " %s\"%s", namepath, auxLine);
            int newlen = strlen(packs_line) + strlen(aux);
            packs_line = (char *)realloc(packs_line, newlen + 2);
            strcat(packs_line, aux);
            strcat(packs_line, "/*\",");
        }
    }
    strcat(packs_line, "}");

    content = (char *)realloc(content, strlen(packs_line) + strlen(content) + 2);
    char *finalAux = NULL;
    os_malloc(strlen(packs_line) + strlen(content) + 2, finalAux);
    snprintf(finalAux, strlen(packs_line) + strlen(content) + 2, "%s%s", content, packs_line);
    osquery_config_temp_file = fopen(osquery_config_temp, "w");
    fprintf(osquery_config_temp_file, "%s", finalAux);
    fclose(osquery_config_temp_file);
    
    free(agent_conf_path);
    free(packs_line);
    free(osquery_config);
    free(content);
    free(line);
    free(finalAux);
    free(namepath);
    free(aux);
}

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor)
{
    wm_osquery_packs();
    wm_osquery_decorators();
    pthread_t thread1, thread2;
    pthread_create( &thread1, NULL, (void *)&Read_Log, osquery_monitor);
    pthread_create( &thread2, NULL, (void *)&Execute_Osquery, osquery_monitor);
    pthread_join( thread2, NULL);
    pthread_join( thread1, NULL);
    return NULL;
}
void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor)
{
    if(!osquery_monitor)
    {
        free(osquery_monitor->bin_path);
        free(osquery_monitor->log_path);
        free(osquery_monitor);
    }
}


