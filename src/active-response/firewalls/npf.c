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
#define NPFCTL      "/sbin/npfctl"

int main (int argc, char **argv) {
    (void)argc;
    char input[BUFFERSIZE];
    char npf_active[COMMANDSIZE];
    char npf_wazuh_ready[COMMANDSIZE];
    char arg1[COMMANDSIZE];
    char command[COMMANDSIZE];
    char log_msg[LOGSIZE];
    static char *srcip;
    static char *action;
    static char *iptables;
    static cJSON *input_json = NULL;

    write_debug_file(argv[0], "Starting");
    // Reading input
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

    cJSON_Delete(input_json);

    if (access(NPFCTL, F_OK) < 0) {
        write_debug_file(argv[0], "The NPFCTL is not accessible");
        return OS_INVALID;
    }

    memset(npf_active, '\0', COMMANDSIZE);
    snprintf(npf_active, COMMANDSIZE -1,"%s show | grep 'filtering:' | grep -c active", NPFCTL);
    if (system(npf_active) != 0) {
        char log_msg[LOGSIZE] = "";
        snprintf(log_msg, LOGSIZE -1, "Unable execute the command: '%s' ", npf_active);
        write_debug_file(argv[0], log_msg);
        return OS_INVALID;
    }

    memset(npf_wazuh_ready, '\0', COMMANDSIZE);
    snprintf(npf_wazuh_ready, COMMANDSIZE -1,"%s show | grep -c 'table <wazuh_blacklist>'", NPFCTL);
    if (system(npf_wazuh_ready) != 0) {
        char log_msg[LOGSIZE] = "";
        snprintf(log_msg, LOGSIZE -1, "Unable execute the command: '%s' ", npf_wazuh_ready);
        write_debug_file(argv[0], log_msg);
        return OS_INVALID;
    }

    memset(arg1, '\0', COMMANDSIZE);
    if (!strcmp("add", action)) {
        snprintf(arg1, COMMANDSIZE -1,"table wazuh_blacklist add %s", srcip);
    } else {
        snprintf(arg1, COMMANDSIZE -1,"table wazuh_blacklist del %s", srcip);
    }

    // Executing it
    command[COMMANDSIZE -1] = '\0';
    snprintf(command, COMMANDSIZE - 1, "%s > /dev/null 2>&1", arg1);

    char *exec_cmd[3] = {NPFCTL, command, NULL};
    wfd_t *wfd = wpopenv(*exec_cmd, exec_cmd, W_BIND_STDOUT);
    if(!wfd) {
        memset(log_msg, '\0', LOGSIZE);
        snprintf(log_msg, LOGSIZE - 1, "Error executing %s : %s", NPFCTL, strerror(errno));
        write_debug_file(argv[0], log_msg);
        return OS_INVALID;
    }
    wpclose(wfd);

    return 0;
}

