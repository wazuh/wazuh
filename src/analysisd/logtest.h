/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "decoders/decoder.h"
#include "eventinfo.h"
#include "../config/logtest-config.h"
#include "../os_net/os_net.h"
#include "../os_crypto/sha256/sha256_op.h"

/* JSON REQUEST / RESPONSE fields names */
#define W_LOGTEST_JSON_TOKEN            "token"   //< Token field name of json input/output
#define W_LOGTEST_JSON_EVENT            "event"   //< Event field name of json input
#define W_LOGTEST_JSON_LOGFORMAT   "log_format"   //< Log format field name of json input
#define W_LOGTEST_JSON_LOCATION      "location"   //< Location field name of json input
#define W_LOGTEST_JSON_ALERT            "alert"   //< Alert field name of json output (true/false)
#define W_LOGTEST_JSON_MESSAGE        "message"   //< Message format field name of json output
#define W_LOGTEST_JSON_CODE           "codemsg"   //< Code of message field name of json output (int)
#define W_LOGTEST_JSON_OUTPUT          "output"   //< Output field name of json output

#define W_LOGTEST_TOKEN_LENGH                 8   //< Lenght of token 

/* Error messages */
#define LOGTEST_ERROR_JSON_PARSE              "(0000) Error parsing JSON"
#define LOGTEST_ERROR_JSON_PARSE_POS          "(0000) Error in position %i, ... %.20s ..."
#define LOGTEST_ERROR_JSON_REQUIRED_SFIELD    "(0000)\"%s\" JSON field is required and must be a string"
#define LOGTEST_ERROR_TOKEN_INVALID           "(0000) \"%s\" is not a valid token"
#define LOGTEST_ERROR_RESPONSE                "(0000) Error seding response to client %s [%i] %s."

/* Warning messages */
#define LOGTEST_WARN_TOKEN_EXPIRED            "(0000) \"%s\" token expires."

/* Info messages */
#define LOGTEST_INFO_TOKEN_NEW                "(0000) \"%s\" New token"


/**
 * @brief A w_logtest_session_t instance represents a client
 */
typedef struct w_logtest_session_t {

    char *token;                            ///< Client ID
    time_t last_connection;                 ///< Timestamp of the last query

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
 * @brief A w_logtest_request instance represents a client requeset
 */
typedef struct w_logtest_request {

    char* token;             ///< Client ID
    char* event;             ///< Log to be processed
    char* log_format;        ///< Type of log. Syslog, syscheck_event, eventchannel, eventlog, etc
    char* location;          ///< The origin of the log. User, agent, IP and file (if collected by Logcollector).

} w_logtest_request;

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
 * @brief Create resources necessary to service client
 * @param token Token which represents the client
 */
w_logtest_session_t *w_logtest_initialize_session(char *token);

/**
 * @brief Process client's request
 * 
 * @param req 
 * @param session 
 * @return cJSON* 
 */
cJSON* w_logtest_process_log(w_logtest_request* req, w_logtest_session_t* session);

/**
 * @brief Free resources after client closes connection
 * @param fd File descriptor which represents the client
 */
void w_logtest_remove_session(const char * token);

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
 * 
 * @param req Client request information.
 * @param input_json Raw JSON input of requeset.
 * @return int OS_SUCCESS on success, otherwise OS_INVALID
 * @warning  \ref w_logtest_free_request should be called before to avoid memory leaks
 */
int w_logtest_check_input(char* input_json, w_logtest_request* req);

/**
 * @brief Free internal memory of a request.
 * @param req request to free.
 */
void w_logtest_free_request(w_logtest_request* req);

/**
 * @brief Generate a new hexa-token.
 * @return char* new token string.
 */
char* w_logtest_generate_token();

/**
 * @brief Get a session for a request.
 * 
 * Search for an active session based on the request token. If session expires 
 * or the token is invalid, returns a new session and set the new token.
 * @param req request for a session.
 * @return w_logtest_session_t* 
 */
w_logtest_session_t* w_logtest_get_session(w_logtest_request* req);
