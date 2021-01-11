#include "shared.h"
#include "external/cJSON/cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netdb.h>




#define LOG_FILE "/logs/active-responses.log"
#define LOCK_PATH "/active-response/bin/fw-drop"
#define LOCK_FILE "/active-response/bin/fw-drop/pid"
#define IP4TABLES "/sbin/iptables"
#define IP6TABLES "/sbin/ip6tables"
#define ECHO "/bin/echo"
#define BUFFERSIZE 4096
#define LOGSIZE 2048
#define COMMANDSIZE 2048

static void lock (const char *filename);
static void unlock (const char *lock_path);
void write_debug_file (const char *msg);
static int get_ip_version (char * ip);
static void free_vars ();

static pid_t saved_pid = -1;
static char lock_path[PATH_MAX];
static char *srcip;
static char *action;
static char *iptables;
static char **filename;
static cJSON *input_json = NULL;

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char arg1[COMMANDSIZE];
    char arg2[COMMANDSIZE];
    char command[COMMANDSIZE];
    char log_msg[LOGSIZE];
    cJSON *origin_json = NULL;
    cJSON *version_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *srcip_json = NULL;
    const char *json_err;
    struct utsname uname_buffer;
    int res;

    input[BUFFERSIZE -1] = '\0';
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file ("Cannot read input from stdin");
        return OS_INVALID;
    }

    // Reading filename
    filename = OS_StrBreak('.', basename(argv[0]), sizeof(basename(argv[0])));
    if (filename == NULL) {
        log_msg[LOGSIZE -1] = '\0';
        snprintf(log_msg, LOGSIZE -1 , "Cannot read filename: %s (%d)", strerror(errno), errno);
        write_debug_file (log_msg);
        return OS_INVALID;
    }

    // Parsing Input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        write_debug_file ("Cannot parse input to json");
        return OS_INVALID;
    }

    // Detect version
    if (version_json = cJSON_GetObjectItem(input_json, "version"), !version_json || (version_json->type != cJSON_String)) {
        write_debug_file ("Cannot get 'version' from json");
        free_vars();
        return OS_INVALID;
    }

    // Detect origin
    if (origin_json = cJSON_GetObjectItem(input_json, "origin"), !origin_json || (origin_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'origin' from json");
        free_vars();
        return OS_INVALID;
    }

    // Detect command
    command_json = cJSON_GetObjectItem(input_json, "command");
    if (command_json && (command_json->type == cJSON_String)) {
        os_strdup(command_json->valuestring, action);
    } else {
        write_debug_file ("Invalid 'command' from json");
        free_vars();
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file ("Invalid value of 'command'");
        free_vars();
        return OS_INVALID;
    }

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input_json, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'parameters' from json");
        free_vars();
        return OS_INVALID;
    }

    // Detect Alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'alert' from parameters");
        free_vars();
        return OS_INVALID;
    }

    // Detect data
    if (data_json = cJSON_GetObjectItem(alert_json, "data"), !data_json || (data_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'data' from alert");
        free_vars();
        return OS_INVALID;
    }

    // Detect srcip
    srcip_json = cJSON_GetObjectItem(data_json, "srcip");
    if (srcip_json && (srcip_json->type == cJSON_String)) {
        os_strdup(srcip_json->valuestring, srcip);
    } else {
        write_debug_file ("Invalid 'srcip' from data");
        free_vars();
        return OS_INVALID;
    }

    int ip_version = get_ip_version(srcip);
    if (ip_version == 4) {
        os_strdup(IP4TABLES, iptables);
    } else if (ip_version == 6) {
        os_strdup(IP6TABLES, iptables);
    } else {
        log_msg[LOGSIZE -1] = '\0';
        snprintf(log_msg, LOGSIZE -1 , "Unable to run active response (invalid IP: '%s').", srcip);
        write_debug_file (log_msg);
        free_vars();
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0){
        write_debug_file ("Cannot get system name");
        free_vars();
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        arg1[COMMANDSIZE -1] = '\0';
        arg2[COMMANDSIZE -1] = '\0';
        if (!strcmp("add", action)) {
            snprintf(arg1, COMMANDSIZE -1, "-I INPUT -s %s -j DROP", srcip);
            snprintf(arg2, COMMANDSIZE -1, "-I FORWARD -s %s -j DROP", srcip);
        } else {
            snprintf(arg1, COMMANDSIZE -1, "-D INPUT -s %s -j DROP", srcip);
            snprintf(arg2, COMMANDSIZE -1, "-D FORWARD -s %s -j DROP", srcip);
        }

        // Checking if iptables is present
        if (access(iptables, F_OK) < 0) {
            char iptables_path[PATH_MAX];
            snprintf(iptables_path, PATH_MAX - 1, "/usr%s", iptables);
            if (access(iptables_path, F_OK) < 0) {
                log_msg[LOGSIZE -1] = '\0';
                snprintf(log_msg, LOGSIZE -1 , "The iptables file '%s' is not accessible: %s (%d)", iptables_path, strerror(errno), errno);
                write_debug_file (log_msg);
                free_vars();
                return OS_INVALID;
            }
            os_strdup(iptables_path, iptables);
        }

        // Executing and exiting
        int count = 0;
        lock(filename[0]);
        bool flag = true;
        while (flag) {
            snprintf(command, COMMANDSIZE - 1, "%s %s", iptables, arg1);

            res = system(command);
            if (res == 0) {
                flag = false;
            } else {
                count++;
                log_msg[LOGSIZE -1] = '\0';
                snprintf(log_msg, LOGSIZE - 1, "Unable to run (iptables returning != %d)", res);
                write_debug_file (log_msg);
                sleep(count);

                if (count > 4){
                    flag = false;
                }
            }
        }

        count = 0;
        flag = true;
        while (flag) {
            int res;
            snprintf(command, COMMANDSIZE - 1, "%s %s", iptables, arg2);

            res = system(command);

            if (res == 0) {
                flag = false;
            } else {
                count++;
                log_msg[LOGSIZE -1] = '\0';
                snprintf(log_msg, LOGSIZE - 1, "Unable to run (iptables returning != %d)", res);
                write_debug_file (log_msg);
                sleep(count);

                if (count > 4){
                    flag = false;
                }
            }
        }
        unlock(lock_path);

    } else if (!strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname) || !strcmp("NetBSD", uname_buffer.sysname)) {
        char *ipfarg = NULL;

        // Checking if ipfilter is present
        char *ipfilter_path = NULL;
        if (!strcmp("SunOS", uname_buffer.sysname)){
            os_strdup("/usr/sbin/ipf", ipfilter_path);
        } else {
            os_strdup("/sbin/ipf", ipfilter_path);
        }

        if (access(ipfilter_path, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The ipfilter file '%s' is not accessible: %s (%d)", ipfilter_path, strerror(errno), errno);
            write_debug_file (log_msg);
            return -1;
        }

        // Checking if echo is present
        if (access(ECHO, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The echo file '%s' is not accessible: %s (%d)", ECHO, strerror(errno), errno);
            write_debug_file (log_msg);
            return -1;
        }

        arg1[COMMANDSIZE -1] = '\0';
        arg2[COMMANDSIZE -1] = '\0';
        snprintf(arg1, COMMANDSIZE -1, "\"@1 block out quick from any to %s\"", srcip);
        snprintf(arg2, COMMANDSIZE -1, "\"@1 block in quick from %s to any\"", srcip);
        if (!strcmp("add", action)) {
            os_strdup("${IPFILTER} -f -", ipfarg);
        } else {
            os_strdup("${IPFILTER} -rf -", ipfarg);
        }

        // Executing it
        command[COMMANDSIZE -1] = '\0';
        snprintf(command, COMMANDSIZE - 1, "eval %s %s| %s", ECHO, arg1, ipfarg);
        res = system(command);
        command[COMMANDSIZE -1] = '\0';
        snprintf(command, COMMANDSIZE - 1, "eval %s %s| %s", ECHO, arg2, ipfarg);
        res = system(command);

    } else if (!strcmp("AIX", uname_buffer.sysname)){
        char genfilt_path[20] = "/usr/sbin/genfilt";
        char lsfilt_path[20] = "/usr/sbin/lsfilt";
        char mkfilt_path[20] = "/usr/sbin/mkfilt";
        char rmfilt_path[20] = "/usr/sbin/rmfilt";
        char grep_path[20] = "/bin/grep";

        // Checking if genfilt is present
        if (access(genfilt_path, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The genfilt file '%s' is not accessible: %s (%d)", genfilt_path, strerror(errno), errno);
            write_debug_file (log_msg);
            return OS_INVALID;
        }

        // Checking if lsfilt is present
        if (access(lsfilt_path, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The lsfilt file '%s' is not accessible: %s (%d)", lsfilt_path, strerror(errno), errno);
            write_debug_file (log_msg);
            return OS_INVALID;
        }

        // Checking if mkfilt is present
        if (access(mkfilt_path, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The mkfilt file '%s' is not accessible: %s (%d)", mkfilt_path, strerror(errno), errno);
            write_debug_file (log_msg);
            return OS_INVALID;
        }

        // Checking if rmfilt is present
        if (access(rmfilt_path, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The rmfilt file '%s' is not accessible: %s (%d)", rmfilt_path, strerror(errno), errno);
            write_debug_file (log_msg);
            return OS_INVALID;
        }

        if (!strcmp("add", action)) {
            char genfilt_arg[COMMANDSIZE];
            snprintf(genfilt_arg, COMMANDSIZE - 1, " -v 4 -a D -s %s -m 255.255.255.255 -d 0.0.0.0 -M 0.0.0.0 -w B -D \"Access Denied by OSSEC-HIDS\"", srcip);
            // Add filter to rule table
            command[COMMANDSIZE -1] = '\0';
            snprintf(command, COMMANDSIZE - 1, "eval %s %s", genfilt_path, genfilt_arg);
            res = system(command);

            // Deactivate  and activate the filter rules.
            command[COMMANDSIZE -1] = '\0';
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -d", mkfilt_path);
            res = system(command);
            command[COMMANDSIZE -1] = '\0';
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -u", mkfilt_path);
            res = system(command);
        } else {
            char output_buf[BUFFERSIZE];
            snprintf(command, 1023, "eval %s -v 4 -O  | %s %s |", lsfilt_path, grep_path, srcip);
            FILE *fp = popen(command, "r");
            if (fp) {
                while (fgets(output_buf, BUFFERSIZE, fp) != NULL) {
                    // removing a specific rule is not so easy :(
                    //eval ${LSFILT} -v 4 -O  | ${GREP} ${IP} | 
                    //while read -r LINE
                    //do
                    //    RULEID=`${ECHO} ${LINE} | cut -f 1 -d "|"`
                    //    let RULEID=${RULEID}+1
                    //    ARG1=" -v 4 -n ${RULEID}"
                    //    eval ${RMFILT} ${ARG1}
                    //done
                }

                pclose(fp);
            }

            // Deactivate  and activate the filter rules.
            command[COMMANDSIZE -1] = '\0';
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -d", mkfilt_path);
            res = system(command);
            command[COMMANDSIZE -1] = '\0';
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -u", mkfilt_path);
            res = system(command);
        }

    } else {
        write_debug_file("Invalid system");

        free_vars();
        return OS_INVALID;
    }

    free_vars();

    return 0;
}

static void free_vars (){
    cJSON_Delete(input_json);
    os_free(srcip);
    os_free(action);
    os_free(iptables);
    os_free(filename[1]);
    os_free(filename[0]);
    os_free(filename);
}

static void lock (const char *filename) {
    int i=0;
    int max_iteration = 50;
    bool flag = true;
    int read;

    // Providing a lock.
    while (flag){
        char lock_pid_path[PATH_MAX];
        FILE *pid_file;
        pid_t current_pid;
        snprintf(lock_path, PATH_MAX - 1, "%s%s", DEFAULTDIR, LOCK_PATH);
        snprintf(lock_pid_path, PATH_MAX - 1, "%s%s", DEFAULTDIR, LOCK_FILE);

        if (mkdir(lock_path, S_IRWXG) == 0) {
            // Lock acquired (setting the pid)
            pid_t pid = getpid();
            pid_file = fopen(lock_pid_path, "w");
            fprintf(pid_file, "%u", pid);
            fclose(pid_file);
            return;
        }

        // Getting currently/saved PID locking the file
        if (pid_file = fopen(lock_pid_path, "r"), !pid_file) {
            write_debug_file("Can not read pid file");
            continue;
        } else {
            read = fscanf(pid_file, "%u", &current_pid);
            fclose(pid_file);

            if (read == 1) {
                if (saved_pid == -1) {
                    saved_pid = current_pid;
                }

                if (current_pid == saved_pid) {
                    i++;
                }

            } else {
                write_debug_file("Can not read pid file");
                continue;
            }
        }

        sleep(i);

        i++;

        // So i increments 2 by 2 if the pid does not change.
        // If the pid keeps changing, we will increments one
        // by one and fail after MAX_ITERACTION
        if (i >= max_iteration) {
            bool kill = false;
            char output_buf[BUFFERSIZE];
            char command[COMMANDSIZE];
            snprintf(command, COMMANDSIZE -1, "pgrep -f %s", filename);
            FILE *fp = popen(command, "r");
            if (fp) {
                while (fgets(output_buf, BUFFERSIZE, fp) != NULL) {
                    pid_t pid = (pid_t)strtol(output_buf, NULL, 10);
                    if (pid == current_pid) {
                        memset(command, 0, COMMANDSIZE);
                        snprintf(command, COMMANDSIZE -1, "kill -9 %u", pid);
                        if (system(command) == 0) {
                            char log_msg[LOGSIZE] = "";
                            snprintf(log_msg, LOGSIZE -1, "Killed process %u holding lock.", pid);
                            write_debug_file(log_msg);
                            kill = true;
                            unlock(lock_path);
                            i = 0;
                            saved_pid = -1;
                            break;
                        }
                    }
                }

                pclose(fp);
            }

            if (!kill) {
                char log_msg[LOGSIZE] = "";
                snprintf(log_msg, LOGSIZE -1, "Unable kill process %u holding lock.", current_pid);
                write_debug_file(log_msg);

                // Unlocking and exiting
                unlock(lock_path);
                return;
            }
        }
    }

}

static void unlock (const char *lock_path) {
    char command[COMMANDSIZE];
    snprintf(command, COMMANDSIZE - 1, "rm -rf %s", lock_path);
    if (system(command) != 0){
        char log_msg[LOGSIZE] = "";
        snprintf(log_msg, LOGSIZE -1, "Unable remove file: '%s' ", lock_path);
        write_debug_file(log_msg);
    }
}

void write_debug_file (const char *msg) {
    char path[PATH_MAX];
    char *timestamp = w_get_timestamp(time(NULL));

    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOG_FILE);
    FILE *ar_log_file = fopen(path, "a");

    fprintf(ar_log_file, "%s: %s\n", timestamp, msg);
    fclose(ar_log_file);
}

static int get_ip_version (char * ip) {
    struct addrinfo hint, *res = NULL;
    int ret;

    memset (&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(ip, NULL, &hint, &res);
    if (ret) {
        return OS_INVALID;
    }
    if (res->ai_family == AF_INET) {
        freeaddrinfo(res);
        return 4;
    } else if (res->ai_family == AF_INET6) {
        freeaddrinfo(res);
        return 6;
    }

    freeaddrinfo(res);
    return OS_INVALID;

   return 4;
}
