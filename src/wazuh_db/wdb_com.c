#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wdb_com.h"

typedef enum _error_codes {
    ERROR_OK = 0,
    ERROR_INVALID_INPUT,
    ERROR_EMPTY_COMMAND,
    ERROR_UNRECOGNIZED_COMMAND
} error_codes;

const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_INVALID_INPUT] = "Invalid JSON input",
    [ERROR_EMPTY_COMMAND] = "Empty command",
    [ERROR_UNRECOGNIZED_COMMAND] = "Unrecognized command"
};

STATIC char* wdbcom_output_builder(int error_code, const char* message, cJSON* data_json);

STATIC char* wdbcom_output_builder(int error_code, const char* message, cJSON* data_json) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error", error_code);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddItemToObject(root, "data", data_json ? data_json : cJSON_CreateObject());

    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return msg_string;
}

void wdbcom_dispatch(char * request, char * output) {
    cJSON *request_json = NULL;
    cJSON *command_json = NULL;
    const char *json_err;

    if (request_json = cJSON_ParseWithOpts(request, &json_err, 0), !request_json) {
        output = wdbcom_output_builder(ERROR_INVALID_INPUT, error_messages[ERROR_INVALID_INPUT], NULL);
        return strlen(output);
    }

    if (command_json = cJSON_GetObjectItem(request_json, "command"), cJSON_IsString(command_json)) {
        if (strcmp(command_json->valuestring, "getstats") == 0) {
            // output = wdbcom_output_builder(ERROR_OK, error_messages[ERROR_OK], wdb_create_state_json());
            snprintf(output, OS_MAXSTR + 1, wdbcom_output_builder(ERROR_OK, error_messages[ERROR_OK], wdb_create_state_json()));
        } else {
            output = wdbcom_output_builder(ERROR_UNRECOGNIZED_COMMAND, error_messages[ERROR_UNRECOGNIZED_COMMAND], NULL);
        }
    } else {
        output = wdbcom_output_builder(ERROR_EMPTY_COMMAND, error_messages[ERROR_EMPTY_COMMAND], NULL);
    }

    cJSON_Delete(request_json);
}