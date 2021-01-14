#include "shared.h"
#include "external/cJSON/cJSON.h"
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
void write_debug_file (const char *msg);

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char arg1[COMMANDSIZE];
    char arg2[COMMANDSIZE];
    char command[COMMANDSIZE];
    char log_msg[LOGSIZE];
    char *srcip;
    char *action;
    cJSON *input_json = NULL;
    cJSON *origin_json = NULL;
    cJSON *version_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *srcip_json = NULL;
    const char *json_err;
    struct utsname uname_buffer;

    input[BUFFERSIZE -1] = '\0';
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file ("Cannot read input from stdin");
        return OS_INVALID;
    }

    // Parsing Input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        write_debug_file ("Cannot parse input to json");
        return OS_INVALID;
    }

    // Detect version
    if (version_json = cJSON_GetObjectItem(input_json, "version"), !version_json || (version_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'version' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Detect origin
    if (origin_json = cJSON_GetObjectItem(input_json, "origin"), !origin_json || (origin_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'origin' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Detect command
    command_json = cJSON_GetObjectItem(input_json, "command");
    write_debug_file(cJSON_PrintUnformatted(command_json));
    if (command_json && (command_json->type == cJSON_String)) {
        os_strdup(command_json->valuestring, action);
    } else {
        write_debug_file ("Invalid 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file ("Invalid value of 'command'");
        return OS_INVALID;
    }

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input_json, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'parameters' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Detect Alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'alert' from parameters");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Detect data
    if (data_json = cJSON_GetObjectItem(alert_json, "data"), !data_json || (data_json->type != cJSON_Object)) {
        write_debug_file ("Cannot get 'data' from alert");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Detect srcip
    srcip_json = cJSON_GetObjectItem(data_json, "srcip");
    if (srcip_json && (srcip_json->type == cJSON_String)) {
        os_strdup(srcip_json->valuestring, srcip);
    } else {
        write_debug_file ("Invalid 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // OpenBSD and FreeBSD pf
    if (!strcmp("OpenBSD", uname_buffer.sysname) || !strcmp("FreeBSD", uname_buffer.sysname) || !strcmp("Darwin", uname_buffer.sysname)) {

        // Checking if pfctl is present
        if (access(PFCTL, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The pfctl file '%s' is not accessible", PFCTL);
            write_debug_file (log_msg);
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
                write_debug_file (log_msg);
                return OS_INVALID;
            }

        } else {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The pf rules file %s does not exist", PFCTL_RULES);
            write_debug_file (log_msg);
            return OS_SUCCESS;
        }

        // Executing it
        command[COMMANDSIZE -1] = '\0';
        snprintf(command, COMMANDSIZE - 1, "%s %s > /dev/null 2>&1", PFCTL, arg1);
        command[COMMANDSIZE -1] = '\0';
        snprintf(command, COMMANDSIZE - 1, "%s %s > /dev/null 2>&1", PFCTL, arg2);

    } else {
        return OS_SUCCESS;
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

