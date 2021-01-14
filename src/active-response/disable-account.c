#include "shared.h"
#include "external/cJSON/cJSON.h"
#include "active_responses.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/utsname.h>


static char *action;
static char *user;
static char *command_ex;
static cJSON *input_json = NULL;
static char *filename;
static void free_vars ();


int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char args[COMMANDSIZE];
    char command[COMMANDSIZE];
    char log_msg[LOGSIZE];
    struct utsname uname_buffer;

    write_debug_file ("disable-account" , "Starting");

    // Reading filename
    filename = basename(argv[0]);
    if (filename == NULL) {
        log_msg[LOGSIZE -1] = '\0';
        snprintf(log_msg, LOGSIZE -1 , "Cannot read filename: %s (%d)", strerror(errno), errno);
        write_debug_file ("disable-account" ,log_msg);
        return OS_INVALID;
    }

    input[BUFFERSIZE -1] = '\0';
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file (filename, "Cannot read input from stdin");
        return OS_INVALID;
    }

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file (filename, "Invalid input format");
        return OS_INVALID;
    }

    action = get_command(input_json);
    if (!action) {
        write_debug_file (filename, "Cannot read 'command' from json");
        return OS_INVALID;
    }

    if (strcmp("add", action) && strcmp("delete", action)) {
        write_debug_file (filename, "Invalid value of 'command'");
        free_vars();
        return OS_INVALID;
    }

    // Detect username
    user = get_username_from_json(input_json);
    if (!user) {
        write_debug_file (filename, "Cannot read 'dstuser' from data");
        free_vars();
        return OS_INVALID;
    }

    if (!strcmp("root", user)) {
        write_debug_file (filename, "Invalid username");
        free_vars();
        return OS_INVALID;
    }

    log_msg[LOGSIZE -1] = '\0';
    snprintf(log_msg, LOGSIZE -1 , "Username: %s  Action: %s", user, action);
    write_debug_file ("disable-account" ,log_msg);

    if (uname(&uname_buffer) != 0){
        write_debug_file (filename, "Cannot get system name");
        free_vars();
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname) || !strcmp("SunOS", uname_buffer.sysname)) {
        // Checking if passwd is present
        if (access(PASSWD, F_OK) < 0) {
            log_msg[LOGSIZE -1] = '\0';
            snprintf(log_msg, LOGSIZE - 1, "The passwd file '%s' is not accessible: %s (%d)", PASSWD, strerror(errno), errno);
            write_debug_file (filename, log_msg);
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
            write_debug_file (filename, log_msg);
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
        write_debug_file(filename, "Invalid system");
        free_vars();
        return OS_INVALID;
    }

    // Execute the command
    snprintf(command, COMMANDSIZE - 1, "%s %s %s", command_ex, args, user);
    if (system(command) != 0) {
        char log_msg[LOGSIZE] = "";
        snprintf(log_msg, LOGSIZE -1, "Unable execute the command: '%s' ", command);
        write_debug_file(filename, log_msg);
        return OS_INVALID;
    }

    write_debug_file ("disable-account" , "Ended");
    return 0;
}

static void free_vars (){
    cJSON_Delete(input_json);
    os_free(action);
    os_free(user);
    os_free(command_ex);
    os_free(filename);
    os_free(filename);
}
