#include "shared.h"
#include "external/cJSON/cJSON.h"
#include "../active_responses.h"

#define LOCK_PATH "/active-response/bin/fw-drop"
#define LOCK_FILE "/active-response/bin/fw-drop/pid"
#define IP4TABLES "/sbin/iptables"
#define IP6TABLES "/sbin/ip6tables"
#define ECHO "/bin/echo"


static void lock (const char *lock_path, const char *lock_pid_path, const char *log_path);
static void unlock (const char *lock_path, const char *log_path);
static int get_ip_version (char * ip);

int main (int argc, char **argv) {
    (void)argc;
    char *srcip;
    char *action;
    char iptables[COMMANDSIZE];
    char input[BUFFERSIZE];
    char arg1[COMMANDSIZE];
    char arg2[COMMANDSIZE];
    char command[COMMANDSIZE];
    char log_msg[LOGSIZE];
    cJSON *input_json = NULL;
    struct utsname uname_buffer;
    int res;

    write_debug_file (argv[0] , "Starting");

    memset(input, '\0', BUFFERSIZE);
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0], input);

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(argv[0], "Invalid input format");
        return OS_INVALID;
    }

    action = get_command(input_json);
    if (!action) {
        write_debug_file(argv[0], "Cannot read 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file(argv[0], "Invalid value of 'command'");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Get srcip
    srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    int ip_version = get_ip_version(srcip);
    memset(iptables, '\0', COMMANDSIZE);
    if (ip_version == 4) {
        strcpy(iptables, IP4TABLES);
    } else if (ip_version == 6) {
        strcpy(iptables, IP6TABLES);
    } else {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE -1 , "Unable to run active response (invalid IP: '%s').", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0){
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        char lock_path[PATH_MAX];
        char lock_pid_path[PATH_MAX];

        memset(arg1, '\0', COMMANDSIZE);
        memset(arg2, '\0', COMMANDSIZE);
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
            memset(iptables_path, '\0', PATH_MAX);
            snprintf(iptables_path, PATH_MAX - 1, "/usr%s", iptables);
            if (access(iptables_path, F_OK) < 0) {
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE -1 , "The iptables file '%s' is not accessible: %s (%d)", iptables_path, strerror(errno), errno);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                return 0;
            }
            memset(iptables, '\0', COMMANDSIZE);
            strcpy(iptables, iptables_path);
        }

        memset(lock_path, '\0', PATH_MAX);
        memset(lock_pid_path, '\0', PATH_MAX);
        snprintf(lock_path, PATH_MAX - 1, "%s%s", DEFAULTDIR, LOCK_PATH);
        snprintf(lock_pid_path, PATH_MAX - 1, "%s%s", DEFAULTDIR, LOCK_FILE);

        // Executing and exiting
        int count = 0;

        lock(lock_path, lock_pid_path, argv[0]);
        bool flag = true;
        while (flag) {
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "%s %s", iptables, arg1);
            res = system(command);
            if (res == 0) {
                flag = false;
            } else {
                count++;
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE - 1, "Unable to run (iptables returning != %d)", res);
                write_debug_file(argv[0], log_msg);
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
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "%s %s", iptables, arg2);
            res = system(command);

            if (res == 0) {
                flag = false;
            } else {
                count++;
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE - 1, "Unable to run (iptables returning != %d)", res);
                write_debug_file(argv[0], log_msg);
                sleep(count);

                if (count > 4){
                    flag = false;
                }
            }
        }
        unlock(lock_path, argv[0]);

    } else if (!strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname) || !strcmp("NetBSD", uname_buffer.sysname)) {
        char ipfarg[COMMANDSIZE];

        // Checking if ipfilter is present
        char ipfilter_path[PATH_MAX];
        memset(ipfilter_path, '\0', PATH_MAX);
        if (!strcmp("SunOS", uname_buffer.sysname)){
            strcpy(ipfilter_path, "/usr/sbin/ipf");
        } else {
            strcpy(ipfilter_path, "/sbin/ipf");
        }

        if (access(ipfilter_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The ipfilter file '%s' is not accessible: %s (%d)", ipfilter_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return 0;
        }

        // Checking if echo is present
        if (access(ECHO, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The echo file '%s' is not accessible: %s (%d)", ECHO, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return 0;
        }

        memset(arg1, '\0', COMMANDSIZE);
        memset(arg2, '\0', COMMANDSIZE);
        memset(ipfarg, '\0', COMMANDSIZE);

        snprintf(arg1, COMMANDSIZE -1, "\"@1 block out quick from any to %s\"", srcip);
        snprintf(arg2, COMMANDSIZE -1, "\"@1 block in quick from %s to any\"", srcip);
        if (!strcmp("add", action)) {
            snprintf(ipfarg, COMMANDSIZE -1,"%s -f -", ipfilter_path);
        } else {
            snprintf(ipfarg, COMMANDSIZE -1,"%s -rf -", ipfilter_path);
        }

        // Executing it
        memset(command, '\0', COMMANDSIZE);
        snprintf(command, COMMANDSIZE - 1, "eval %s %s| %s", ECHO, arg1, ipfarg);
        res = system(command);
        memset(command, '\0', COMMANDSIZE);
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
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The genfilt file '%s' is not accessible: %s (%d)", genfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return 0;
        }

        // Checking if lsfilt is present
        if (access(lsfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The lsfilt file '%s' is not accessible: %s (%d)", lsfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return 0;
        }

        // Checking if mkfilt is present
        if (access(mkfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The mkfilt file '%s' is not accessible: %s (%d)", mkfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return 0;
        }

        // Checking if rmfilt is present
        if (access(rmfilt_path, F_OK) < 0) {
            memset(log_msg, '\0', LOGSIZE);
            snprintf(log_msg, LOGSIZE - 1, "The rmfilt file '%s' is not accessible: %s (%d)", rmfilt_path, strerror(errno), errno);
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return 0;
        }

        if (!strcmp("add", action)) {
            char genfilt_arg[COMMANDSIZE];
            snprintf(genfilt_arg, COMMANDSIZE - 1, " -v 4 -a D -s %s -m 255.255.255.255 -d 0.0.0.0 -M 0.0.0.0 -w B -D \"Access Denied by WAZUH\"", srcip);
            // Add filter to rule table
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "eval %s %s", genfilt_path, genfilt_arg);
            res = system(command);

            // Deactivate  and activate the filter rules.
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -d", mkfilt_path);
            res = system(command);
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -u", mkfilt_path);
            res = system(command);
        } else {
            char output_buf[BUFFERSIZE];
            memset(output_buf, '\0', BUFFERSIZE);
            snprintf(command, 1023, "eval %s -v 4 -O  | %s %s |", lsfilt_path, grep_path, srcip);
            FILE *fp = popen(command, "r");
            if (fp) {
                while (fgets(output_buf, BUFFERSIZE, fp) != NULL) {
                    char out_buf[BUFFERSIZE];
                    memset(out_buf, '\0', BUFFERSIZE);

                    // removing a specific rule
                    memset(command, '\0', COMMANDSIZE);
                    snprintf(command, COMMANDSIZE - 1, "%s %s | cut -f 1 -d \"|\"", ECHO, output_buf);
                    FILE *fp2 = popen(command, "r");
                    if ((fgets(out_buf, BUFFERSIZE, fp2) != NULL)){
                        int rule_id = atoi(out_buf) + 1;
                        memset(arg1, '\0', COMMANDSIZE);
                        snprintf(arg1, COMMANDSIZE -1, " -v 4 -n %d", rule_id);
                        memset(command, '\0', COMMANDSIZE);
                        snprintf(command, COMMANDSIZE - 1, "eval %s %s", rmfilt_path, arg1);
                        res = system(command);
                    } else {
                        write_debug_file(argv[0], "Cannot remove rule");
                    }

                    pclose(fp2);

                }

                pclose(fp);
            }

            // Deactivate  and activate the filter rules.
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -d", mkfilt_path);
            res = system(command);
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE - 1, "eval %s -v 4 -u", mkfilt_path);
            res = system(command);
        }

    } else {
        write_debug_file(argv[0], "Invalid system");
        cJSON_Delete(input_json);

        return 0;
    }
    write_debug_file(argv[0], "Ended");
    cJSON_Delete(input_json);

    return 0;
}

static void lock (const char *lock_path, const char *lock_pid_path, const char *log_path) {
    char log_msg[LOGSIZE];
    int i=0;
    int max_iteration = 50;
    bool flag = true;
    pid_t saved_pid = -1;
    int read;

    // Providing a lock.
    while (flag){
        FILE *pid_file;
        pid_t current_pid;

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
            write_debug_file(log_path, "Can not read pid file");
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
                write_debug_file(log_path, "Can not read pid file");
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
            memset(output_buf, '\0', BUFFERSIZE);
            memset(command, '\0', COMMANDSIZE);
            snprintf(command, COMMANDSIZE -1, "pgrep -f default-firewall-drop");
            FILE *fp = popen(command, "r");
            if (fp) {
                while (fgets(output_buf, BUFFERSIZE, fp) != NULL) {
                    pid_t pid = (pid_t)strtol(output_buf, NULL, 10);
                    if (pid == current_pid) {
                        memset(command, '\0', COMMANDSIZE);
                        snprintf(command, COMMANDSIZE -1, "kill -9 %u", pid);
                        if (system(command) == 0) {
                            memset(log_msg, '\0', LOGSIZE);
                            snprintf(log_msg, LOGSIZE -1, "Killed process %u holding lock.", pid);
                            write_debug_file(log_path, log_msg);
                            kill = true;
                            unlock(lock_path, log_path);
                            i = 0;
                            saved_pid = -1;
                            break;
                        }
                    }
                }

                pclose(fp);
            }

            if (!kill) {
                memset(log_msg, '\0', LOGSIZE);
                snprintf(log_msg, LOGSIZE -1, "Unable kill process %u holding lock.", current_pid);
                write_debug_file(log_path, log_msg);

                // Unlocking and exiting
                unlock(lock_path, log_path);
                return;
            }
        }
    }

}

static void unlock (const char *lock_path, const char *log_path) {
    if (rmdir_ex(lock_path) < 0) {
        write_debug_file(log_path, "Unable to remove lock folder");
    }
}

static int get_ip_version (char * ip) {
    struct addrinfo hint, *res = NULL;
    int ret;

    memset (&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(ip, NULL, &hint, &res);
    if (ret) {
        freeaddrinfo(res);
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
}
