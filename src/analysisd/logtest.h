/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOGTEST_H
#define LOGTEST_H

#include "shared.h"
#include "config.h"
#include "rules.h"
#include "config.h"
#include "decoders/decoder.h"
#include "eventinfo.h"
#include "cleanevent.h"
#include "lists.h"
#include "lists_make.h"
#include "fts.h"
#include "accumulator.h"
#include "../config/logtest-config.h"
#include "../os_net/os_net.h"
#include "format/to_json.h"
#include <time.h>


/* JSON REQUEST / RESPONSE fields names */
#define W_LOGTEST_JSON_TOKEN                    "token"   ///< Token field name of json input/output
#define W_LOGTEST_JSON_EVENT                    "event"   ///< Event field name of json input
#define W_LOGTEST_JSON_LOGFORMAT           "log_format"   ///< Log format field name of json input
#define W_LOGTEST_JSON_LOCATION              "location"   ///< Location field name of json input
#define W_LOGTEST_JSON_REMOVE_SESSION  "remove_session"   ///< Remove session field name of json input
#define W_LOGTEST_JSON_ALERT                    "alert"   ///< Alert field name of json output (boolean)
#define W_LOGTEST_JSON_MESSAGES              "messages"   ///< Message format field name of json output
#define W_LOGTEST_JSON_CODE                   "codemsg"   ///< Code of message field name of json output (number)
#define W_LOGTEST_JSON_OUTPUT                  "output"   ///< Output field name of json output

#define W_LOGTEST_TOKEN_LENGH                 8   ///< Lenght of token
#define W_LOGTEST_ERROR_JSON_PARSE_NSTR      20   ///< Number of characters to show in parsing error

/* Return codes for responses */
#define W_LOGTEST_RCODE_ERROR_INPUT          -2   ///< Return code: Input error, malformed json, input field missing
#define W_LOGTEST_RCODE_ERROR_PROCESS        -1   ///< Return code: Processing with error
#define W_LOGTEST_RCODE_SUCCESS               0   ///< Return code: Successful request
#define W_LOGTEST_RCODE_WARNING               1   ///< Return code: Successful request with warning messages

/* Type of request */
#define W_LOGTEST_REQUEST_ERROR                  -1   ///< Request error: Missing fields or don't matches
#define W_LOGTEST_REQUEST_TYPE_REMOVE_SESSION     0   ///< Request remove session
#define W_LOGTEST_REQUEST_TYPE_LOG_PROCESSING     1   ///< Request log processing


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
    OSStore *decoder_store;                  ///< Decoder list to save internals decoders
    ListNode *cdblistnode;                  ///< List of CDB lists
    ListRule *cdblistrule;                  ///< List to attach rules and CDB lists
    EventList *eventlist;                   ///< Previous events list
    OSHash *g_rules_hash;                   ///< Hash table of rules
    OSList *fts_list;                       ///< Save FTS previous events
    OSHash *fts_store;                      ///< Save FTS values processed
    OSHash *acm_store;                      ///< Hash to save data which have the same id
    int acm_lookups;                        ///< Counter of the number of times purged. Option accumulate
    time_t acm_purge_ts;                    ///< Counter of the time interval of last purge. Option accumulate
    regex_matching decoder_match;           ///< Used for decoding phase
    regex_matching rule_match;              ///< Used for rules matching phase

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

    pthread_mutex_t mutex_hash_table;  ///< Mutex to prevent race condition in hash table and active client
    int active_client;                 ///< Number of current clients

} w_logtest_connection_t;


/**
 * @brief Initialize Wazuh Logtest. Initialize the listener and create threads
 * Then, call function w_logtest_clients_handler
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
 */
void *w_logtest_clients_handler();

/**
 * @brief Process client's request
 * @param request client input
 * @param session client session
 * @param list_msg list of error/warn/info messages
 * @return NULL on failure, otherwise the alert generated
 */
cJSON *w_logtest_process_log(cJSON * request, w_logtest_session_t * session, OSList * list_msg);

/**
 * @brief Preprocessing phase
 *
 * It's called by w_logtest_process_log
 *
 * @param lf struct to save the event processed
 * @param request client input
 * @return 0 on success, otherwise -1
 */
int w_logtest_preprocessing_phase(Eventinfo * lf, cJSON * request);

/**
 * @brief Decoding phase
 *
 * It's called by w_logtest_process_log
 *
 * @param lf struct to save the event processed
 * @param session client session
 */
void w_logtest_decoding_phase(Eventinfo * lf, w_logtest_session_t * session);

/**
 * @brief Matching rules phase
 *
 * It's called by w_logtest_process_log
 *
 * @param lf struct to save the event processed
 * @param session client session
 * @param list_msg list of error/warn/info messages
 * @return 0 on success, otherwise return -1
 */
int w_logtest_rulesmatching_phase(Eventinfo * lf, w_logtest_session_t * session, OSList * list_msg);

/**
 * @brief Create resources necessary to service client
 * @param token client identifier
 * @param msg_error contains the message to send to the client in case of invalid rules or decoder otherwise, it's null
 * @return NULL on failure, otherwise a w_logtest_session_t object which represents to the client
 */
w_logtest_session_t *w_logtest_initialize_session(char * token, OSList * list_msg);

/**
 * @brief Free resources after client closes connection
 * @param token client identifier
 */
void w_logtest_remove_session(char * token);

/**
 * @brief Check the inactive logtest sessions
 *
 * Check all the sessions. If a session has been inactive longer than session_timeout,
 * call w_logtest_remove_session to remove it
 *
 * @param connection Manager of connections
 */
void * w_logtest_check_inactive_sessions(w_logtest_connection_t * connection);

/**
 * @brief Initialize FTS engine for a client session
 * @param fts_list list which save fts previous events
 * @param fts_store hash table which save fts values processed previously
 * @return 1 on success, otherwise return 0
 */
int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store);

/**
 * @brief Check if input_json its valid and generate a client request.
 * @param req Client request information
 * @param input_json Raw JSON input of requeset
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @retval \ref W_LOGTEST_REQUEST_ERROR on invalid input
 * @retval \ref W_LOGTEST_REQUEST_TYPE_LOG_PROCESSING on valid request input
 * @retval \ref W_LOGTEST_REQUEST_TYPE_REMOVE_SESSION on valid remove session input
 */
int w_logtest_check_input(char* input_json, cJSON** req, OSList* list_msg);

/**
 * @brief Check validity of the json for a log processing request
 * @param root json to validate
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @retval \ref W_LOGTEST_REQUEST_ERROR on invalid input
 * @retval \ref W_LOGTEST_REQUEST_TYPE_LOG_PROCESSING on valid request input
 */
int w_logtest_check_input_request(cJSON * root, OSList * list_msg);

/**
 * @brief Check validity of the json for a remove session request
 * @param root json to validate
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @retval \ref W_LOGTEST_REQUEST_ERROR on invalid input
 * @retval \ref W_LOGTEST_REQUEST_TYPE_REMOVE_SESSION on valid request input
 */
int w_logtest_check_input_remove_session(cJSON * root, OSList * list_msg);

/**
 * @brief Add the messages to the json array and clear the list.
 *
 * Add the messages to the \ref W_LOGTEST_JSON_MESSAGES json array of response,
 * clear the list and set maximun error level:
 * \ref W_LOGTEST_RCODE_SUCCESS If the list is empty or there are only info messages.
 * \ref W_LOGTEST_RCODE_WARNING If there are warning messages.
 * \ref W_LOGTEST_RCODE_ERROR_PROCESS If there are error messages.
 *
 * @param response json response for the client
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @param error_code Actual level error
 */
void w_logtest_add_msg_response(cJSON* response, OSList* list_msg, int* error_code);

/**
 * @brief Generate a new hexa-token
 * @return char* new token string
 */
char* w_logtest_generate_token();

/**
 * @brief Get a session for a request
 *
 * Search for an active session based on the request token. If session expires
 * or the token is invalid, returns a new session
 *
 * @param req request for a session
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @param connection Manager of connections
 * @return new session or NULL on error
 */
w_logtest_session_t * w_logtest_get_session(cJSON * req, OSList * list_msg, w_logtest_connection_t * connection);

/**
 * @brief Register a session as active in connection
 *
 * Register a session on the hash table
 *
 * @param connection Manager of connections
 * @param session Session to register
 */
void w_logtest_register_session(w_logtest_connection_t * connection, w_logtest_session_t * session);

/**
 * @brief Remove the oldest session
 *
 * Find the session who has not made a query for the longest time and remove it
 *
 * @param connection Manager of connections
 */
void w_logtest_remove_old_session(w_logtest_connection_t * connection);

/**
 * @brief Get the level of de triggered rule within json_log_processed
 * @param json_log_processed Proccessed log
 * @return level rule
 */
int w_logtest_get_rule_level(cJSON* json_log_processed);

/**
 * @brief Processes a client input request
 * @param raw_request client request
 * @param connection Manager of connections
 * @return string (json format) with the result of the request
 */
char * w_logtest_process_request(char * raw_request, w_logtest_connection_t * connection);

/**
 * @brief Processes a client input log procecessing request
 * @param json_request Client request
 * @param json_response Client response
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @param connection Manager of connections
 * @retval \ref W_LOGTEST_RCODE_ERROR_PROCESS on failure
 * @retval \ref W_LOGTEST_RCODE_SUCCESS on success
 * @retval \ref W_LOGTEST_RCODE_WARNING on success with warnings
 */
int w_logtest_process_request_log_processing(cJSON * json_request, cJSON * json_response, OSList * list_msg,
                                             w_logtest_connection_t * connection);

/**
 * @brief Processes a client input remove request
 * @param json_request Client request
 * @param json_response Client response
 * @param list_msg list of \ref os_analysisd_log_msg_t for store messages
 * @param connection Manager of connections
 * @retval \ref W_LOGTEST_RCODE_ERROR_PROCESS on failure
 * @retval \ref W_LOGTEST_RCODE_SUCCESS on success
 * @retval \ref W_LOGTEST_RCODE_WARNING on success with warnings
 */
int w_logtest_process_request_remove_session(cJSON * json_request, cJSON * json_response, OSList * list_msg,
                                             w_logtest_connection_t * connection);
/*
 * @brief Generate failure response with \ref W_LOGTEST_JSON_CODE =  \ref W_LOGTEST_RCODE_ERROR_INPUT
 * @param msg string error description at \ref W_LOGTEST_JSON_MESSAGES field
 * @return string (json format) with the response
 */
char * w_logtest_generate_error_response(char * msg);

#endif
