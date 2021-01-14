
#include "external/cJSON/cJSON.h"

#define LOG_FILE "/logs/active-responses.log"
#define LOCK_PATH "/active-response/bin/fw-drop"
#define LOCK_FILE "/active-response/bin/fw-drop/pid"
#define IP4TABLES "/sbin/iptables"
#define IP6TABLES "/sbin/ip6tables"
#define ECHO "/bin/echo"
#define PASSWD "/usr/bin/passwd"
#define CHUSER "/usr/bin/chuser"
#define BUFFERSIZE 4096
#define LOGSIZE 2048
#define COMMANDSIZE 2048

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

/**
 * Get srcip from input 
 * @param input Input
 * @return char * with the srcip or NULL o fail
 * */
char* get_srcip_from_json (cJSON *input);
