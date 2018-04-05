
#include "wmodules.h"
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>

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
            current_inode = get_inode(result_log);
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
                    if(get_inode(result_log) != current_inode)
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
                            current_inode = get_inode(result_log);
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
            	setsid();
                daemon_pid = getpid();
                if (execl(osquery_monitor->bin_path, "osqueryd", "-verbose"/*(char *)NULL*/) < 0)
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
                    if (errno == ECHILD) //Not working
                    {
                        down = 1;
                    }
                    else
                    {
                        //OSQUERY IS WORKING, wake up the other thread to read the log file
                        
                        down = 0;
                        unlock = 1;
                        pthread_cond_signal( &active );
                        pthread_mutex_unlock( &mutex1 );
                    }
                    break;
                case -1:
                    // Finished. Bad Configuration
                    stopped = 1;
                    down = 1;
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "Bad Configuration!");
                    pthread_exit(NULL);
                }
            }
        }
        else	//If not down, check periodically every second the osQuery status.
        {
            while(down==0)
            {
                switch (waitpid(daemon_pid, &status, WNOHANG))
                {
                case 0:
                    if (errno == ECHILD)
                    {
                        down = 1;
                    }
                    else
                    {
                        down = 0;
                    }
                    break;
                case -1:
                    // Finished. Bad Configuration
                    down = 1;
                    mterror(WM_OSQUERYMONITOR_LOGTAG, "Bad configuration!");
                    pthread_exit(NULL);
                }
                sleep(1);
            }
        }
    }
}

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor)
{
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


