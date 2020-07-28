/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "config.h"
#include "rules.h"
#include "config.h"
#include "decoders/decoder.h"
#include "eventinfo.h"
#include "lists.h"
#include "lists_make.h"
#include "fts.h"
#include "accumulator.h"
#include "../config/logtest-config.h"
#include "../os_net/os_net.h"
#include <time.h>


/* JSON REQUEST / RESPONSE fields names */
#define W_LOGTEST_JSON_TOKEN            "token"   ///< Token field name of json input/output.
#define W_LOGTEST_JSON_EVENT            "event"   ///< Event field name of json input.
#define W_LOGTEST_JSON_LOGFORMAT   "log_format"   ///< Log format field name of json input.
#define W_LOGTEST_JSON_LOCATION      "location"   ///< Location field name of json input.
#define W_LOGTEST_JSON_ALERT            "alert"   ///< Alert field name of json output (boolean).
#define W_LOGTEST_JSON_MESSAGE        "message"   ///< Message format field name of json output.
#define W_LOGTEST_JSON_CODE           "codemsg"   ///< Code of message field name of json output (number)
#define W_LOGTEST_JSON_OUTPUT          "output"   ///< Output field name of json output.

#define W_LOGTEST_TOKEN_LENGH                 8   ///< Lenght of token
#define W_LOGTEST_ERROR_JSON_PARSE_NSTR      20   ///< Number of characters to show in parsing error

/* Return codes for responses */
#define W_LOGTEST_RCODE_ERROR_INPUT          -2   ///< Return code: Input error, malformed json, input field missing.
#define W_LOGTEST_RCODE_ERROR_PROCESS        -1   ///< Return code: Processing with error.
#define W_LOGTEST_RCODE_SUCCESS               0   ///< Return code: Successful request.
#define W_LOGTEST_RCODE_WARNING               1   ///< Return code: Successful request with warning messages.



/**
 * @brief A w_logtest_session_t instance represents a client
 */
typedef struct w_logtest_session_t {

    char *token;                            ///< Client ID
    time_t last_connection;                 ///< Timestamp of the last query
    bool expired;                           ///< Indicates that the session expired and will be deleted
    pthread_mutex_t mutex;                  ///< Prevent race condition between get a session and remove it for inactivity 

    RuleNode *rule_list;                    ///< Rule list
    OSDecoderNode *decoderlist_forpname;    ///< Decoder list to match logs which have a program name
    OSDecoderNode *decoderlist_nopname;     ///< Decoder list to match logs which haven't a program name
    ListNode *cdblistnode;                  ///< List of CDB lists
    ListRule *cdblistrule;                  ///< List to attach rules and CDB lists
    EventList *eventlist;                   ///< Previous events list
    OSHash *g_rules_hash;                   ///< Hash table of rules
    OSList *fts_list;                       ///< Save FTS previous events
    OSHash *fts_store;                      ///< Save FTS values processed
    OSHash *acm_store;                      ///< Hash to save data which have the same id
    int acm_lookups;                        ///< Counter of the number of times purged. Option accumulate
    time_t acm_purge_ts;                    ///< Counter of the time interval of last purge. Option accumulate

} w_logtest_session_t;

/**
 * @brief List of client actives
 */
OSHash *w_logtest_sessions;

/**
 * @brief An instance of w_logtest_connection allow managing the connections with the logtest socket
 */
typedef struct w_logtest_connection_t {

    pthread_mutex_t mutex;      ///< Mutex to prevent race condition in accept syscall
    int sock;                   ///< The open connection with logtest queue

} w_logtest_connection_t;

/**
 * @brief Initialize Wazuh Logtest. Initialize the listener and create threads
 * Then, call function w_logtest_main
 */
void *w_logtest_init();

/**
 * @brief Initialize logtest configuration. Then, call ReadConfig
 *
 * @return OS_SUCCESS on success, otherwise OS_INVALID
 */
int w_logtest_init_parameters();

/**
 * @brief Main function of Wazuh Logtest module
 *
 * Listen and treat connections with clients
 *
 * @param connection The listener where clients connect
 */
void *w_logtest_main(w_logtest_connection_t * connection);

/**
 * @brief Process the log within req for user represented by session
 * @param req user request
 * @param session session for user request
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages.
 * @return output response or NULL on error
 */
cJSON* w_logtest_process_log(cJSON* req, w_logtest_session_t* session, OSList* list_msg);

/**
 * @brief Create resources necessary to service client
 * @param token Token which represents the client
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @return new session or NULL on error.
 */
w_logtest_session_t *w_logtest_initialize_session(char * token, OSList * list_msg);

/**
 * @brief Free resources after client closes connection
 * @param token Token which represents the client
 */
void w_logtest_remove_session(char * token);

/**
 * @brief Check the inactive logtest sessions
 *
 * Check all the sessions. If a session has been inactive longer than session_timeout,
 * call w_logtest_remove_session to remove it.
 */
void * w_logtest_check_inactive_sessions(__attribute__((unused)) void * arg);

/**
 * @brief Initialize FTS engine for a client session
 * @param fts_list list which save fts previous events
 * @param fts_store hash table which save fts values processed previously
 * @return 1 on success, otherwise return 0
 */
int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store);

/**
 * @brief Check if input_json its valid and generate a client request.
 * @param req Client request information.
 * @param input_json Raw JSON input of requeset.
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @return OS_SUCCESS on success, otherwise OS_INVALID
 */
int w_logtest_check_input(char* input_json, cJSON** req, OSList* list_msg);

/**
 * @brief Add the messages to the json array and clear the list.
 *
 * Add the messages to the \ref W_LOGTEST_JSON_MESSAGE json array of response,
 * clear the list and set maximun error level:
 * \ref W_LOGTEST_RCODE_SUCCESS If the list is empty or there are only info messages.
 * \ref W_LOGTEST_RCODE_WARNING If there are warning messages.
 * \ref W_LOGTEST_RCODE_ERROR_PROCESS If there are error messages.
 * @param response json response for the client.
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages.
 * @param error_code Actual level error.
 */
void w_logtest_add_msg_response(cJSON* response, OSList* list_msg, int* error_code);

/**
 * @brief Generate a new hexa-token.
 * @return char* new token string.
 */
char* w_logtest_generate_token();

/**
 * @brief Get a session for a request.
 *
 * Search for an active session based on the request token. If session expires
 * or the token is invalid, returns a new session.
 * @param req request for a session.
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages.
 * @return new session or NULL on error.
 */
w_logtest_session_t* w_logtest_get_session(cJSON* req, OSList* list_msg);

/**
 * @brief Get the level of de triggered rule within json_log_processed
 * @param json_log_processed Proccessed log
 * @return level rule
 */
int w_logtest_get_rule_level(cJSON* json_log_processed);
