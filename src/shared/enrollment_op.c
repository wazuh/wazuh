/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_auth/check_cert.h"
#include "os_auth/auth.h"
#include "os_net/os_net.h"
#include "shared.h"
#include "headers/sec.h"
#include "os_crypto/sha1/sha1_op.h"

#ifdef WAZUH_UNIT_TESTING
    /* Remove static qualifier when unit testing */
    #define static

    // Redefine ossec_version
    #undef __ossec_version
    #define __ossec_version "v4.5.0"

    /* Replace assert with mock_assert */
    extern void mock_assert(const int result, const char* const expression,
                            const char * const file, const int line);
    #undef assert
    #define assert(expression) mock_assert((int)(expression), #expression, __FILE__, __LINE__);

    #ifndef WIN32
        #include "unit_tests/wrappers/posix/unistd_wrappers.h"
    #else
        #include "unit_tests/wrappers/windows/winsock_wrappers.h"
        #include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
    #endif
#endif

/* Main methods */
static int w_enrollment_connect(w_enrollment_ctx *cfg, const char * server_address, uint32_t network_interface);
static int w_enrollment_send_message(w_enrollment_ctx *cfg);
static int w_enrollment_process_response(SSL *ssl);
/* Auxiliary */
static int w_enrollment_verify_ca_certificate(const SSL *ssl, const char *ca_cert, const char *hostname);
static void w_enrollment_concat_agent_version (char *buff, const char *agent_version);
static void w_enrollment_concat_group(char *buff, const char* centralized_group);
static int w_enrollment_concat_src_ip(char *buff, const size_t remain_size, const char* sender_ip, const int use_src_ip);
static void w_enrollment_concat_key(char *buff, keyentry* key);
static int w_enrollment_process_agent_key(char *buffer);
static int w_enrollment_store_key_entry(const char* keys);
static char *w_enrollment_extract_agent_name(const w_enrollment_ctx *cfg);
static void w_enrollment_load_pass(w_enrollment_cert *cert_cfg);

/* Constants */
static const int ENTRY_ID = 0;
static const int ENTRY_NAME = 1;
static const int ENTRY_IP = 2;
static const int ENTRY_KEY = 3;

w_enrollment_target *w_enrollment_target_init() {
    w_enrollment_target *target_cfg;
    os_malloc(sizeof(w_enrollment_target), target_cfg);
    target_cfg->port = DEFAULT_PORT;
    target_cfg->manager_name = NULL;
    target_cfg->network_interface = 0;
    target_cfg->agent_name = NULL;
    target_cfg->centralized_group = NULL;
    target_cfg->sender_ip = NULL;
    target_cfg->use_src_ip = 0;
    return target_cfg;
}

void w_enrollment_target_destroy(w_enrollment_target *target_cfg) {
    os_free(target_cfg->manager_name);
    os_free(target_cfg->agent_name);
    os_free(target_cfg->centralized_group);
    os_free(target_cfg->sender_ip);
    os_free(target_cfg);
}

w_enrollment_cert *w_enrollment_cert_init(){
    w_enrollment_cert *cert_cfg;
    os_malloc(sizeof(w_enrollment_cert), cert_cfg);
    cert_cfg->ciphers = strdup(DEFAULT_CIPHERS);
    cert_cfg->authpass_file = strdup(AUTHD_PASS);
    cert_cfg->authpass = NULL;
    cert_cfg->agent_cert = NULL;
    cert_cfg->agent_key = NULL;
    cert_cfg->ca_cert = NULL;
    cert_cfg->auto_method = 0;
    return cert_cfg;
}

void w_enrollment_cert_destroy(w_enrollment_cert *cert_cfg) {
    os_free(cert_cfg->ciphers);
    os_free(cert_cfg->authpass_file);
    os_free(cert_cfg->authpass);
    os_free(cert_cfg->agent_cert);
    os_free(cert_cfg->agent_key);
    os_free(cert_cfg->ca_cert);
    os_free(cert_cfg);
}

w_enrollment_ctx * w_enrollment_init(w_enrollment_target *target, w_enrollment_cert *cert, keystore *keys) {
    assert(target != NULL);
    assert(cert != NULL);
    w_enrollment_ctx *cfg;
    os_malloc(sizeof(w_enrollment_ctx), cfg);
    cfg->target_cfg = target;
    cfg->cert_cfg = cert;
    cfg->enabled = true;
    cfg->ssl = NULL;
    cfg->allow_localhost = true;
    cfg->delay_after_enrollment = 20;
    cfg->keys = keys;
    os_strdup(__ossec_version, cfg->agent_version);
    return cfg;
}

void w_enrollment_destroy(w_enrollment_ctx *cfg) {
    assert(cfg != NULL);
    os_free(cfg->agent_version);
    os_free(cfg);
}

int w_enrollment_request_key(w_enrollment_ctx *cfg, const char * server_address, uint32_t network_interface) {
    assert(cfg != NULL);
    int ret = -1;
    minfo("Requesting a key from server: %s", server_address ? server_address : cfg->target_cfg->manager_name);
    int socket = w_enrollment_connect(cfg, server_address ? server_address : cfg->target_cfg->manager_name, server_address ? network_interface : cfg->target_cfg->network_interface);
    if ( socket >= 0) {
        w_enrollment_load_pass(cfg->cert_cfg);
        if (w_enrollment_send_message(cfg) == 0) {
            ret = w_enrollment_process_response(cfg->ssl);
        }
        OS_CloseSocket(socket);
    }
    if (cfg->ssl) {
        SSL_free(cfg->ssl);
        cfg->ssl = NULL;
    }
    return ret;
}

/**
 * @brief Retrieves agent name. If no agent_name has been extracted it will
 * be obtained by obtaining hostname
 *
 * @param cfg configuration structure
 * @param allow_localhost true will allow localhost as name, false will throw an merror_exit
 * @return agent_name on succes
 *         NULL on errors
 * */
static char *w_enrollment_extract_agent_name(const w_enrollment_ctx *cfg) {
    char *lhostname = NULL;
    /* agent_name extraction */
    if (cfg->target_cfg->agent_name == NULL) {
        os_malloc(513, lhostname);
        lhostname[512] = '\0';
        if (gethostname(lhostname, 512 - 1) != 0) {
            merror("Unable to extract hostname. Custom agent name not set.");
            os_free(lhostname);
            return NULL;
        }
        OS_ConvertToValidAgentName(lhostname);
    } else {
        lhostname = cfg->target_cfg->agent_name;
    }

    if(!cfg->allow_localhost && (strcmp(lhostname, "localhost") == 0)) {
        merror(AG_INV_HOST, lhostname);
        if(lhostname != cfg->target_cfg->agent_name)
            os_free(lhostname);
        return NULL;
    }

    if (!OS_IsValidName(lhostname)) {
        merror("Invalid agent name \"%s\". Please pick a valid name.", lhostname);
        if(lhostname != cfg->target_cfg->agent_name)
            os_free(lhostname);
        return NULL;
    }
    return lhostname;
}

/**
 * Starts an SSL connection with the manger instance
 * @param cfg Enrollment configuration structure
 *      @see w_enrollment_ctx for details
 * @param server_adress Address where the agent will try to connect
 * @return socket_id >= 0 if successful
 * @retval ENROLLMENT_WRONG_CONFIGURATION(-1) on invalid configuration
 * @retval ENROLLMENT_CONNECTION_FAILURE(-2) connection error
 */
static int w_enrollment_connect(w_enrollment_ctx *cfg, const char * server_address, uint32_t network_interface)
{
    assert(cfg != NULL);
    assert(server_address != NULL);

    char *ip_address = NULL;
    char *tmp_str = strchr(server_address, '/');
    if (tmp_str) {
        // server_address comes in {hostname}/{ip} format
        ip_address = strdup(++tmp_str);
    }
    if (!ip_address) {
        // server_address is either a host or a ip
        ip_address = OS_GetHost(server_address, 3);
    }

    /* Translate hostname to an ip_address */
    if (!ip_address) {
        merror("Could not resolve hostname: %s\n", server_address);
        return ENROLLMENT_WRONG_CONFIGURATION;
    }

    /* Start SSL */
    SSL_CTX *ctx = os_ssl_keys(0, NULL, cfg->cert_cfg->ciphers,
        cfg->cert_cfg->agent_cert, cfg->cert_cfg->agent_key, cfg->cert_cfg->ca_cert, cfg->cert_cfg->auto_method);
    if (!ctx) {
        merror("Could not set up SSL connection! Check certification configuration.");
        os_free(ip_address);
        return ENROLLMENT_WRONG_CONFIGURATION;
    }

    /* Connect via TCP */
    int sock = OS_ConnectTCP((u_int16_t) cfg->target_cfg->port, ip_address, strchr(ip_address, ':') != NULL ? 1 : 0, network_interface);
    if (sock < 0) {
        merror(ENROLL_CONN_ERROR, ip_address, cfg->target_cfg->port);
        os_free(ip_address);
        SSL_CTX_free(ctx);
        return ENROLLMENT_CONNECTION_FAILURE;
    }

    if (OS_SetRecvTimeout(sock, cfg->recv_timeout, 0) < 0) {
        merror(SET_TIMEO_ERR, strerror(errno), errno);
        os_free(ip_address);
        SSL_CTX_free(ctx);
        OS_CloseSocket(sock);
        return ENROLLMENT_CONNECTION_FAILURE;
    }

    /* Connect the SSL socket */
    cfg->ssl = SSL_new(ctx);
    BIO * sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(cfg->ssl, sbio, sbio);

    ERR_clear_error();
    int ret = SSL_connect(cfg->ssl);
    if (ret <= 0) {
        merror("SSL error (%d). Connection refused by the manager. Maybe the port specified is incorrect.", SSL_get_error(cfg->ssl, ret));
        ERR_print_errors_fp(stderr);  // This function empties the error queue
        os_free(ip_address);
        SSL_CTX_free(ctx);
        OS_CloseSocket(sock);
        return ENROLLMENT_CONNECTION_FAILURE;
    }

    mdebug1(ENROLL_CONNECTED, ip_address, cfg->target_cfg->port);

    if (w_enrollment_verify_ca_certificate(cfg->ssl, cfg->cert_cfg->ca_cert, server_address) == 1) {
        os_free(ip_address);
        SSL_CTX_free(ctx);
        OS_CloseSocket(sock);
        return ENROLLMENT_CONNECTION_FAILURE;
    }

    os_free(ip_address);
    SSL_CTX_free(ctx);
    return sock;
}

/**
 * Sends initial enrollment message. Must call
 *      w_enrollment_process_response to obtain response
 * @param cfg Enrollment configuration structure
 *      @see w_enrollment_ctx for details
 * @return   0 if message is sent successfully
 *          -1 if message cannot be sent
 */
static int w_enrollment_send_message(w_enrollment_ctx *cfg) {
    assert(cfg != NULL);
    char *lhostname = w_enrollment_extract_agent_name(cfg);
    if (!lhostname) {
        return -1;
    }

    minfo("Using agent name as: %s", lhostname);

    /* Message formation */
    char *buf;
    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';

    if (cfg->cert_cfg->authpass) {
        snprintf(buf, 2048, "OSSEC PASS: %s OSSEC A:'%s'", cfg->cert_cfg->authpass, lhostname);
    } else {
        snprintf(buf, 2048, "OSSEC A:'%s'", lhostname);
    }

    if (cfg->agent_version) {
        w_enrollment_concat_agent_version(buf, cfg->agent_version);
    }

    if (cfg->target_cfg->centralized_group) {
        w_enrollment_concat_group(buf, cfg->target_cfg->centralized_group);
    }

    if (w_enrollment_concat_src_ip(buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buf), cfg->target_cfg->sender_ip, cfg->target_cfg->use_src_ip)) {
        os_free(buf);
        if(lhostname != cfg->target_cfg->agent_name)
            os_free(lhostname);
        return -1;
    }

    if (cfg->keys->keysize > 0) {
        w_enrollment_concat_key(buf, cfg->keys->keyentries[0]);
    }

    /* Append new line character */
    strcat(buf,"\n");
    int ret = SSL_write(cfg->ssl, buf, strlen(buf));
    if (ret < 0) {
        merror("SSL write error (unable to send message.)");
        merror("If Agent verification is enabled, agent key and certificates are required!");
        ERR_print_errors_fp(stderr);
        os_free(buf);
        if(lhostname != cfg->target_cfg->agent_name)
            os_free(lhostname);
        return -1;
    }
    mdebug1("Request sent to manager");

    os_free(buf);
    if (lhostname != cfg->target_cfg->agent_name)
        os_free(lhostname);
    return 0;
}

/**
 * In charge of reading managers response and obtaining agent key
 *
 * @param ssl SSL connection established with manager
 * @return response code
 * @retval 0 if key is obtained and saved
 * @retval -1 if there is an error
 * */
static int w_enrollment_process_response(SSL *ssl) {
    assert(ssl != NULL);
    char *buf;
    int ret;
    int status = -1;
    int manager_error = 0; // IF manager sends error message, set this flag
    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';

    minfo("Waiting for server reply");

    while(ret = SSL_read(ssl, buf, OS_SIZE_65536 + OS_SIZE_4096), ret > 0) {
        buf[ret] = '\0';
        if (strlen(buf) > 7 && !strncmp(buf, "ERROR: ", 7)) {
            // Process error message
            char *tmpbuf;
            tmpbuf = strchr(buf, ' ');
            if (tmpbuf) {
                tmpbuf++;
                if (tmpbuf && tmpbuf[0] != '\0') {
                    merror("%s (from manager)", tmpbuf);
                    manager_error = 1;
                }
            }
        } else if (strncmp(buf, "OSSEC K:'", 9) == 0) {
            status = w_enrollment_process_agent_key(buf);
            break;
        }
    }

    int error_code = SSL_get_error(ssl, ret);
    switch (error_code)
    {
    case SSL_ERROR_NONE:
    case SSL_ERROR_ZERO_RETURN:
        mdebug1("Connection closed.");
        break;
    default:
        if(!manager_error) {
            merror("SSL read (unable to receive message)");
            merror("If Agent verification is enabled, agent key and certificates may be incorrect!");
        }
        break;
    }

    os_free(buf);
    return status;
}

/**
 * Stores entry string to the file containing the agent keys
 * @param keys string containing the following information:
 *      ENTRY_ID AGENT_NAME IP KEY
 * @return return code
 * @retval 0 if key is store successfully
 * @retval -1 if there is an error
 * */
static int w_enrollment_store_key_entry(const char* keys) {
    assert(keys != NULL);

#ifdef WIN32
    FILE *fp;
    fp = wfopen(KEYS_FILE, "w");

    if (!fp) {
        merror(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
        return -1;
    }
    fprintf(fp, "%s\n", keys);
    fclose(fp);

#else /* !WIN32 */
    File file;

    if (TempFile(&file, KEYS_FILE, 0) < 0) {
        merror(FOPEN_ERROR, KEYS_FILE, errno, strerror(errno));
        return -1;
    }

    if (chmod(file.name, 0640) == -1) {
        merror(CHMOD_ERROR, file.name, errno, strerror(errno));
        fclose(file.fp);
        unlink(file.name);
        os_free(file.name);
        return -1;
    }

    fprintf(file.fp, "%s\n", keys);
    fclose(file.fp);

    if (OS_MoveFile(file.name, KEYS_FILE) < 0) {
        os_free(file.name);
        return -1;
    }
    os_free(file.name);

#endif /* !WIN32 */

    return 0;
}

/**
 * Process string that contains agent information.
 * If the information is correct stores the key in the agent keys file
 * @param buffer format:
 * [In] OSSEC K:'ID AGENT_NAME IP KEY'\n\n
 * [Out] ID AGENT_NAME IP KEY\n
 * @return return code
 * @retval 0 on success
 * @retval -1 on failure
 *
 * */
static int w_enrollment_process_agent_key(char *buffer) {
    assert(buffer != NULL);
    assert(strlen(buffer) > 9);
    int ret = -1;
    char *keys = &buffer[9]; //Start of the information
    char *tmpstr = strchr(keys, '\'');
    if (!tmpstr) {
        // No end of string found
        merror("Invalid keys format received.");
        return ret;
    }

    *tmpstr = '\0';
    char **entrys = OS_StrBreak(' ', keys, 4);
    if (OS_IsValidID(entrys[ENTRY_ID]) && OS_IsValidName(entrys[ENTRY_NAME]) &&
            OS_IsValidIP(entrys[ENTRY_IP], NULL) && OS_IsValidName(entrys[ENTRY_KEY])) {
        if( !w_enrollment_store_key_entry(keys) ) {
            // Key was stored
            minfo("Valid key received");
            ret = 0;
        }
    } else {
        merror("One of the received key parameters does not have a valid format");
    }
    int i;
    for(i=0; i<4; i++){
        os_free(entrys[i]);
    }
    os_free(entrys);
    return ret;
}

/**
 * Verifies the manager's ca certificate. Displays a warning message if it does not match
 * @param ssl SSL connection established with the manager
 * @param ca_cert certificate to verify
 * @param hostname
 * */
static int w_enrollment_verify_ca_certificate(const SSL *ssl, const char *ca_cert, const char *hostname) {
    assert(ssl != NULL);
    if (ca_cert == NULL) {
        mdebug1("Registering agent to unverified manager");
        return 0;
    }

    minfo("Verifying manager's certificate");

    if (check_x509_cert(ssl, hostname) != VERIFY_TRUE) {
        merror("Unable to verify server certificate");
        return 1;
    }

    minfo("Manager has been verified successfully");
    return 0;
}

/**
 * @brief Concatenates the current key of the agent, if exists, as  part of the enrollment message
 *
 * @param buff buffer where the KEY section will be concatenated
 * @param key_entry The key that will be concatenated
 *
 * @pre buff must be 69633 bytes long
 */
static void w_enrollment_concat_key(char *buff, keyentry* key_entry) {
    assert(buff != NULL);
    assert(key_entry != NULL);

    os_sha1 output;
    char* opt_buf = NULL;
    os_calloc(OS_SIZE_512, sizeof(char), opt_buf);
    w_get_key_hash(key_entry, output);
    snprintf(opt_buf, OS_SIZE_512, " K:'%s'", output);
    if (strlen(buff) < (OS_SIZE_65536 + OS_SIZE_4096)) {
        strncat(buff, opt_buf, OS_SIZE_65536 + OS_SIZE_4096 - strlen(buff));
    }
    free(opt_buf);
}

/**
 * @brief Concats agent version part of the enrollment message
 *
 * @param buff buffer where the agent version section will be concatenated
 * @param agent_version version of the agent that will be added
 */
static void w_enrollment_concat_agent_version(char *buff, const char *agent_version) {
    assert(buff != NULL);
    assert(agent_version != NULL);

    char * opt_buf = NULL;
    os_calloc(OS_SIZE_32, sizeof(char), opt_buf);
    snprintf(opt_buf,OS_SIZE_32," V:'%s'",agent_version);
    strncat(buff,opt_buf,OS_SIZE_32);
    free(opt_buf);
}

/**
 * @brief Concats the group part of the enrollment message
 *
 * @param buff buffer where the IP section will be concatenated
 * @param centralized_group name of the group that will be added
 */
static void w_enrollment_concat_group(char *buff, const char* centralized_group) {
    assert(buff != NULL); // buff should not be NULL.
    assert(centralized_group != NULL);

    char * opt_buf = NULL;
    os_calloc(OS_SIZE_65536, sizeof(char), opt_buf);
    snprintf(opt_buf,OS_SIZE_65536," G:'%s'",centralized_group);
    strncat(buff,opt_buf,OS_SIZE_65536);
    free(opt_buf);
}

/**
 * @brief Concats the IP part of the enrollment message
 *
 * @param buff buffer where the IP section will be concatenated
 * @param sender_ip Sender IP, if null it will be filled with "src"
 * @param remain_size Remain size of buffer. It is buffer_size - strlen(buffer)
 * @return return code
 * @retval 0 on success
 * @retval -1 if ip is invalid
 */
static int w_enrollment_concat_src_ip(char *buff, const size_t remain_size, const char* sender_ip, const int use_src_ip) {
    assert(buff != NULL); // buff should not be NULL.

    if(sender_ip && !use_src_ip) { // Force an IP
        /* Check if this is strictly an IP address using a regex */
        if (OS_IsValidIP(sender_ip, NULL)) {
            char opt_buf[256] = {0};
            snprintf(opt_buf,254," IP:'%s'",sender_ip);
            strncat(buff,opt_buf, remain_size - 1);
        } else {
            merror("Invalid IP address provided for sender IP.");
            return -1;
        }
    } else if (!sender_ip && use_src_ip){ // Force src IP
        char opt_buf[10] = {0};
        snprintf(opt_buf,10," IP:'src'");
        strncat(buff,opt_buf,10);
    } else if (sender_ip && use_src_ip) { // Incompatible options
        merror("Incompatible sender_ip options: Forcing IP while using use_source_ip flag.");
        return -1;
    }

    return 0;
}

/**
 * Loads enrollment password
 * If no override pass is set checks in authpass_file
 * @param cert_cfg certificate configuration
 * */
static void w_enrollment_load_pass(w_enrollment_cert *cert_cfg) {
    assert(cert_cfg != NULL);
    /* Checking if there is a custom password file */
    if (cert_cfg->authpass == NULL) {
        FILE *fp;
        fp = wfopen(cert_cfg->authpass_file, "r");

        if (fp) {
            char buf[4096];
            char *ret = fgets(buf, 4095, fp);

            if (ret && strlen(buf) > 2) {
                /* Remove newline */
                if (buf[strlen(buf) - 1] == '\n')
                    buf[strlen(buf) - 1] = '\0';

                cert_cfg->authpass = strdup(buf);
            }

            fclose(fp);
            minfo("Using password specified on file: %s", cert_cfg->authpass_file);
        }

        if (!cert_cfg->authpass) {
            minfo("No authentication password provided");
        }
    }
}
