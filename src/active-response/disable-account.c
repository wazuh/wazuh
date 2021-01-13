#include "shared.h"
#include "external/cJSON/cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/utsname.h>


#define LOG_FILE "/logs/active-responses.log"
#define PASSWD "/usr/bin/passwd"
#define CHUSER "/usr/bin/chuser"
#define BUFFERSIZE 4096
#define LOGSIZE 2048
#define COMMANDSIZE 2048

static char *action;
static char *user;
static char *command_ex;
static cJSON *input_json = NULL;
static char **filename;
void write_debug_file (const char *msg);
static void free_vars ();


int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char args[COMMANDSIZE];
    char command[COMMANDSIZE];
    char log_msg[LOGSIZE];
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *username_json = NULL;
    const char *json_err;
    struct utsname uname_buffer;

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

    // Detect username
    username_json = cJSON_GetObjectItem(data_json, "dstuser");
    if (username_json && (username_json->type == cJSON_String)) {
        os_strdup(username_json->valuestring, user);
    } else {
        write_debug_file ("Invalid 'dstuser' from data");
        free_vars();
        return OS_INVALID;
    }

    if (!strcmp("root", user)) {
        write_debug_file ("Invalid username");
        free_vars();
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0){
        write_debug_file ("Cannot get system name");
        free_vars();
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname)) {
        // Checking if passwd is present
        if (access(PASSWD, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The passwd file '%s' is not accessible: %s (%d)", PASSWD, strerror(errno), errno);
            write_debug_file (log_msg);
            free_vars();
            return OS_INVALID;
        }

        os_strdup(PASSWD, command_ex);
        args[COMMANDSIZE -1] = '\0';
        if (!strcmp("add", action)) {
            snprintf(args, COMMANDSIZE -1, "-l");
        } else {
            snprintf(args, COMMANDSIZE -1, "-u");
        }

    } else if (!strcmp("AIX", uname_buffer.sysname)){
        // Checking if chuser is present
        if (access(CHUSER, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The chuser file '%s' is not accessible: %s (%d)", CHUSER, strerror(errno), errno);
            write_debug_file (log_msg);
            free_vars();
            return OS_INVALID;
        }

        os_strdup(CHUSER, command_ex);
        // Disabling an account
        args[COMMANDSIZE -1] = '\0';
        if (!strcmp("add", action)) {
            snprintf(args, COMMANDSIZE -1, "account_locked=true");
        } else {
            snprintf(args, COMMANDSIZE -1, "account_locked=false");
        }

    } else {
        write_debug_file("Invalid system");
        free_vars();
        return OS_INVALID;
    }

    // Execute the command
    snprintf(command, COMMANDSIZE - 1, "%s %s %s", command_ex, args, user);
    if (system(command) != 0) {
        char log_msg[LOGSIZE] = "";
        snprintf(log_msg, LOGSIZE -1, "Unable execute the command: '%s' ", command);
        write_debug_file(log_msg);
        return OS_INVALID;
    }

    return 0;
}

static void free_vars (){
    cJSON_Delete(input_json);
    os_free(action);
    os_free(user);
    os_free(command_ex);
    os_free(filename[1]);
    os_free(filename[0]);
    os_free(filename);
}

void write_debug_file (const char *msg) {
    char path[PATH_MAX];
    char *timestamp = w_get_timestamp(time(NULL));

    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOG_FILE);
    FILE *ar_log_file = fopen(path, "a");

    fprintf(ar_log_file, "%s: %s\n", timestamp, msg);
    fclose(ar_log_file);
}
