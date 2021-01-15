#include "shared.h"
#include "external/cJSON/cJSON.h"
#include "../active_responses.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#define LOG_FILE    "/logs/active-responses.log"
#define GREP        "/usr/bin/grep"
#define PFCTL       "/sbin/pfctl"
#define PFCTL_RULES "/etc/pf.conf"
#define PFCTL_TABLE "ossec_fwtable"
#define BUFFERSIZE  4096
#define LOGSIZE     2048
#define COMMANDSIZE 2048

int checking_if_its_configured(const char *path, const char *table);
static void free_vars();

static char *srcip;
static char *action;
static char *iptables;
static char *filename;
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

    write_debug_file ("pf" , "Starting");

    // Reading filename
    filename = basename(argv[0]);
    if (filename == NULL) {
        log_msg[LOGSIZE -1] = '\0';
        snprintf(log_msg, LOGSIZE -1 , "Cannot read filename: %s (%d)", strerror(errno), errno);
        write_debug_file("default-firewall-drop", log_msg);
        return OS_INVALID;
    }

    input[BUFFERSIZE -1] = '\0';
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file (filename, "Cannot read input from stdin");
        return OS_INVALID;
    }

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(filename, "Invalid input format");
        return OS_INVALID;
    }

    action = get_command(input_json);
    if (!action) {
        write_debug_file(filename, "Cannot read 'command' from json");
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file(filename, "Invalid value of 'command'");
        free_vars();
        return OS_INVALID;
    }

    // Get srcip
    srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(filename, "Cannot read 'srcip' from data");
        free_vars();
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0){
        write_debug_file(filename, "Cannot get system name");
        free_vars();
        return OS_INVALID;
    }

    // OpenBSD and FreeBSD pf
    if (!strcmp("OpenBSD", uname_buffer.sysname) || !strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("Darwin", uname_buffer.sysname)) {

        // Checking if pfctl is present
        if (access(PFCTL, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The pfctl file '%s' is not accessible", PFCTL);
            write_debug_file(filename, log_msg);
            return OS_SUCCESS;
        }

        arg1[COMMANDSIZE -1] = '\0';
        arg2[COMMANDSIZE -1] = '\0';

        // Checking if we have pf config file
        if(access(PFCTL_RULES, F_OK) < 0) {
            // Checking if ossec table is configured in pf.conf
            if(checking_if_its_configured(PFCTL_RULES, PFCTL_TABLE)) {
                if (!strcmp("add", action)) {
                    snprintf(arg1, COMMANDSIZE -1,"-t %s -T add %s", PFCTL_TABLE, srcip);
                    snprintf(arg2, COMMANDSIZE -1,"-k %s", srcip);
                } else {
                    snprintf(arg1, COMMANDSIZE -1,"-t %s -T delete %s", PFCTL_TABLE, srcip);
                }
            } else {
                log_msg[LOGSIZE -1] = '\0';
                snprintf(log_msg, LOGSIZE - 1, "Table %s does not exist", PFCTL_TABLE);
                write_debug_file(filename, log_msg);
                free_vars();
                return OS_INVALID;
            }

        } else {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The pf rules file %s does not exist", PFCTL_RULES);
            write_debug_file(filename, log_msg);
            free_vars();
            return OS_SUCCESS;
        }

        // Executing it
        command[COMMANDSIZE -1] = '\0';
        snprintf(command, COMMANDSIZE - 1, "%s %s > /dev/null 2>&1", PFCTL, arg1);
        command[COMMANDSIZE -1] = '\0';
        snprintf(command, COMMANDSIZE - 1, "%s %s > /dev/null 2>&1", PFCTL, arg2);

    } else {
        free_vars();
        return OS_SUCCESS;
    }

    write_debug_file(filename, "Ended");
    free_vars();

    return 0;
}

static void free_vars (){
    cJSON_Delete(input_json);
    os_free(srcip);
    os_free(action);
    os_free(iptables);
}

int checking_if_its_configured(const char *path, const char *table) {
    char command[1023];
    char output_buf[1023];

    snprintf(command, 1023, "cat %s | %s %s", path, GREP, table);
    FILE *fp = popen(command, "r");
    if (fp) {
        while (fgets(output_buf, 1023, fp) != NULL) {
            pclose(fp);
            return OS_SUCCESS;
        }
        pclose(fp);
        return OS_INVALID;
    }
    return OS_INVALID;
}

