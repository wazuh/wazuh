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
    int lenght;
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
                if(lenght = fgets(line, OS_MAXSTR, result_log), lenght)
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
    //We check that the osquery demon is not down, in which case we run it again.
    while(1)
    {
        if(down)
        {
            int pid = fork();
            switch(pid)
            {
            case 0: //Child
                
                daemon_pid = getpid();
                if (execl(osquery_monitor->bin_path, "osqueryd", (char *)NULL) < 0)
                {
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "cannot execute osquery daemon");
                }
                setsid();
                break;
            case -1: //ERROR
                mterror(WM_OSQUERYMONITOR_LOGTAG, "child has not been created");
            default:
                wm_append_sid(daemon_pid);
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
                        mterror(WM_OSQUERYMONITOR_LOGTAG,"ECHILD");
                        down = 1;
                    }
                    // Finished. Bad Configuration
                    stopped = 1;
                    //mterror(WM_OSQUERYMONITOR_LOGTAG, "Bad Configuration!");
                    pthread_exit(NULL);
                    break;
                }
            }
        }
        while(down==0)
        {
            switch (waitpid(daemon_pid, &status, WNOHANG))
            {
            case 0:
                down = 0;
                break; 
            case -1:
                if (errno == ECHILD)
                {
                    mterror(WM_OSQUERYMONITOR_LOGTAG,"ECHILD");
                }
                down = 1;
            }   
            sleep(1);
        }
        sleep(1);
    }
}

void wm_osquery_decorators(wm_osquery_monitor_t *osquery_monitor)
{
    char * LINE = strdup("");
    char * select=strdup("SELECT ");
    char * as = strdup(" AS ");
    char * key = NULL;
    char * value = NULL;
    char * coma = strdup(", ");
    
    //PATH CREATION
    char * firstPath = strdup("/var/ossec");
    char * lastpath = strdup("/etc/ossec.conf");
    char * configPath = NULL;
    configPath = malloc(strlen(firstPath)+strlen(lastpath));
    strcpy(configPath,firstPath);
    strcat(configPath,lastpath);
    mdebug2("CONFIGPATH: %s",configPath);
    char * json_block = NULL;

    //CJSON OBJECTS
    int i=0;
    cJSON *root;
    cJSON *decorators;
    cJSON *always;
    wlabel_t* labels;
    os_calloc(1, sizeof(wlabel_t), labels);
    ReadConfig(CLABELS, configPath, &labels, NULL);

    int len=0;

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root,"decorators",decorators = cJSON_CreateObject());
    cJSON_AddItemToObject(decorators,"always",always = cJSON_CreateArray());

    FILE * osquery_conf = NULL;
    osquery_conf = fopen("/etc/osquery/osquery.conf","r");
    struct stat stp = { 0 };  
    char *content;
    stat("/etc/osquery/osquery.conf", &stp);
    int filesize = stp.st_size;

    mdebug2("FILESIZE: %d", filesize);
    content = (char *) malloc(sizeof(char) * filesize);
    json_block = cJSON_PrintUnformatted(root);
        mdebug2("CONTENT : %s", json_block); 
    if (fread(content, 1, filesize - 1, osquery_conf) == -1) {
        printf("\nerror in reading\n");
        /**close the read file*/
        fclose(osquery_conf);
        //free input string
        free(content);
    }
        
    int decorated=0;
    if(strstr(content, "decorators")!=NULL)
        decorated = 1;
    else
        decorated = 0;

    if(!decorated){
        
        for(i;labels[i].key!=NULL;i++){  
            key = strdup(labels[i].key);
            value = strdup(labels[i].value); 
            LINE = strdup(select);
            int newlen = sizeof(char)*(strlen(LINE)+strlen(key)+strlen(as)+strlen(value));
            LINE = (char*)realloc(LINE, newlen);  
            strcat(LINE,key);
            strcat(LINE,as);
            strcat(LINE,value);
            mdebug2("VALUE: %s",value);
            cJSON_AddStringToObject(always,"line",LINE);
        }
        
        
        json_block = cJSON_PrintUnformatted(root);
        mdebug2("CONTENT : %s", content);
        mdebug2("CREE LAS QUERYS!: %s", json_block);
        content = realloc(content,sizeof(char)*(strlen(content)+strlen(json_block))); 
        strcat(content,json_block);
        mdebug2("FINALCONTENT : %s", content);

        //mdebug2("ARCHIVO DE CONFIG: %s",json_block);
        free(json_block);
        cJSON_Delete(root);
        fclose(osquery_conf);
        //Escribir contenido en el fichero
        osquery_conf = fopen("/etc/osquery/osquery.conf","w");
        fprintf(osquery_conf,content);
        fclose(osquery_conf);
    }
}

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor)
{
    wm_osquery_decorators(osquery_monitor);
    pthread_t thread1, thread2;
    pthread_create( &thread1, NULL, &Read_Log, osquery_monitor);
    pthread_create( &thread2, NULL, &Execute_Osquery, osquery_monitor);
    pthread_join( thread2, NULL);
    pthread_join( thread1, NULL);
}
void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor)
{
    free(osquery_monitor);
}


