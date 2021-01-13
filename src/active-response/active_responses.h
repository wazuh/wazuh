
#include "external/cJSON/cJSON.h"

#define LOG_FILE "/logs/active-responses.log"

/**
 * Write the incomming message in active-responses log file.
 * @param ar_name Name of active response.
 * @param msg Incomming message to write.
 * */
void write_debug_file (const char *ar_name, const char *msg);

/**
 * Get the json structure from input
 * @param input Input to validate
 * @return JSON input or NULL on Invalid.
 * */
cJSON* get_json_from_input (const char *input);

/**
 * Get command from input 
 * @param input Input
 * @return char * with the command or NULL o fail
 * */
char* get_command (cJSON *input);

/**
 * Get username from input 
 * @param input Input
 * @return char * with the username or NULL o fail
 * */
char* get_username_from_json (cJSON *input);
