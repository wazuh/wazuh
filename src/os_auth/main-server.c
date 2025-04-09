/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#include "shared.h"
#include "auth.h"
#include <pthread.h>
#include <sys/wait.h>
#include "check_cert.h"
#include "key_request.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuhdb_op.h"
#include "os_err.h"
#include "generate_cert.h"
#include <sys/epoll.h>

/* Prototypes */
static void help_authd(char * home_path) __attribute((noreturn));

/* Thread for remote server */
static void* run_remote_server(void *arg);

/* Thread for writing keystore onto disk */
static void* run_writer(void *arg);

/* Signal handler */
static void handler(int signum);

/* Exit handler */
static void cleanup();

/* Shared variables */
static char *authpass = NULL;
static SSL_CTX *ctx;
static int remote_sock = -1;
static int g_epfd = -1;
static struct client * g_client_pool[AUTH_POOL];

volatile int write_pending = 0;
volatile int running = 1;

extern struct keynode *queue_insert;
extern struct keynode *queue_remove;
extern struct keynode * volatile *insert_tail;
extern struct keynode * volatile *remove_tail;

pthread_mutex_t mutex_keys = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;

static int g_stopFD[2] = {-1, -1};

/* Print help statement */
static void help_authd(char * home_path)
{
    print_header();
    print_out("  %s: -[Vhdtfi] [-g group] [-D dir] [-p port] [-P] [-c ciphers] [-v path [-s]] [-x path] [-k path]", ARGV0);
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");
    print_out("    -d          Debug mode. Use this parameter multiple times to increase the debug level.");
    print_out("    -t          Test configuration.");
    print_out("    -f          Run in foreground.");
    print_out("    -g <group>  Group to run as. Default: %s.", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chdir into. Default: %s.", home_path);
    print_out("    -p <port>   Manager port. Default: %d.", DEFAULT_PORT);
    print_out("    -P          Enable shared password authentication, at %s or random.", AUTHD_PASS);
    print_out("    -c          SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify clients.");
    print_out("    -s          Used with -v, enable source host verification.");
    print_out("    -x <path>   Full path to server certificate. Default: %s.", CERTFILE);
    print_out("    -k <path>   Full path to server key. Default: %s.", KEYFILE);
    print_out("    -a          Auto select SSL/TLS method. Default: TLS v1.2 only.");
    print_out("    -L          Force insertion though agent limit reached.");
    print_out("    -C          Specify the certificate validity in days.");
    print_out("    -B          Specify the certificate key size in bits.");
    print_out("    -K          Specify the path to store the certificate key.");
    print_out("    -X          Specify the path to store the certificate.");
    print_out("    -S          Specify the certificate subject.");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) flags = 0;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(int argc, char **argv)
{

    FILE *fp;
    /* Count of pids we are wait()ing on */
    int debug_level = 0;
    int test_config = 0;
    int status;
    int run_foreground = 0;
    gid_t gid;
    const char *group = GROUPGLOBAL;
    char buf[4096 + 1];

    pthread_t thread_local_server = 0;
    pthread_t thread_remote_server = 0;
    pthread_t thread_writer = 0;
    pthread_t thread_key_request = 0;

    for (int i = 0; i < AUTH_POOL; i++) {
        g_client_pool[i] = NULL;
    }

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    /* Initialize some variables */
    bio_err = 0;

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    // Get options
    {
        int c;
        int use_pass = 0;
        int auto_method = 0;
        int validate_host = 0;
        const char *ciphers = NULL;
        const char *ca_cert = NULL;
        const char *server_cert = NULL;
        const char *server_key = NULL;
        char cert_val[OS_SIZE_32 + 1] = "\0";
        char cert_key_bits[OS_SIZE_32 + 1] = "\0";
        char cert_key_path[PATH_MAX + 1] = "\0";
        char cert_path[PATH_MAX + 1] = "\0";
        char cert_subj[OS_MAXSTR + 1] = "\0";
        bool generate_certificate = false;
        unsigned short port = 0;
        unsigned long days_val = 0;
        unsigned long key_bits = 0;

        while (c = getopt(argc, argv, "Vdhtfigj:D:p:c:v:sx:k:PF:ar:L:C:B:K:X:S:"), c != -1) {
            switch (c) {
                case 'V':
                    print_version();
                    break;

                case 'h':
                    help_authd(home_path);
                    break;

                case 'd':
                    debug_level = 1;
                    nowDebug();
                    break;

                case 'i':
                    mwarn(DEPRECATED_OPTION_WARN, "-i", OSSECCONF);
                    break;

                case 'g':
                    if (!optarg) {
                        merror_exit("-g needs an argument");
                    }
                    group = optarg;
                    break;

                case 'D':
                    if (!optarg) {
                        merror_exit("-D needs an argument");
                    }
                    snprintf(home_path, PATH_MAX, "%s", optarg);
                    break;

                case 't':
                    test_config = 1;
                    break;

                case 'f':
                    run_foreground = 1;
                    break;

                case 'P':
                    use_pass = 1;
                    break;

                case 'p':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }

                    if (port = (unsigned short)atoi(optarg), port == 0) {
                        merror_exit("Invalid port: %s", optarg);
                    }
                    break;

                case 'c':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }
                    else {
                        if (w_str_is_number(optarg)) {
                            merror_exit("-%c needs a valid list of SSL ciphers", c);
                        }
                        ciphers = optarg;
                    }
                    break;

                case 'v':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }
                    ca_cert = optarg;
                    break;

                case 's':
                    validate_host = 1;
                    break;

                case 'x':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }
                    server_cert = optarg;
                    break;

                case 'k':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }
                    server_key = optarg;
                    break;

                case 'F':
                    mwarn(DEPRECATED_OPTION_WARN, "-F", OSSECCONF);
                    break;

                case 'r':
                    mwarn(DEPRECATED_OPTION_WARN, "-r", OSSECCONF);
                    break;

                case 'a':
                    auto_method = 1;
                    break;

                case 'L':
                    mwarn("This option no longer applies. The agent limit has been removed.");
                    break;

                case 'C':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }

                    if (w_str_is_number(optarg)) {
                        generate_certificate = true;
                        if (snprintf(cert_val, OS_SIZE_32 + 1, "%s", optarg) > OS_SIZE_32) {
                            mwarn("-%c argument exceeds %d bytes. Certificate validity info truncated", c, OS_SIZE_32);
                        }
                    }
                    else {
                        merror_exit("-%c needs a numeric argument", c);
                    }
                    break;

                case 'B':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }

                    if (w_str_is_number(optarg)) {
                        generate_certificate = true;
                        if (snprintf(cert_key_bits, OS_SIZE_32 + 1, "%s", optarg) > OS_SIZE_32) {
                            mwarn("-%c argument exceeds %d bytes. Certificate key size info truncated", c, OS_SIZE_32);
                        }
                    }
                    else {
                        merror_exit("-%c needs a numeric argument", c);
                    }
                    break;

                case 'K':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }

                    generate_certificate = true;
                    if (snprintf(cert_key_path, PATH_MAX + 1, "%s", optarg) > PATH_MAX) {
                        mwarn("-%c argument exceeds %d bytes. Certificate key path info truncated", c, PATH_MAX);
                    }
                    break;

                case 'X':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }

                    generate_certificate = true;
                    if (snprintf(cert_path, PATH_MAX + 1, "%s", optarg) > PATH_MAX) {
                        mwarn("-%c argument exceeds %d bytes. Certificate path info truncated", c, PATH_MAX);
                    }
                    break;

                case 'S':
                    if (!optarg) {
                        merror_exit("-%c needs an argument", c);
                    }

                    generate_certificate = true;
                    if (snprintf(cert_subj, OS_MAXSTR + 1, "%s", optarg) > OS_MAXSTR) {
                        mwarn("-%c argument exceeds %d bytes. Certificate subject info truncated", c, OS_MAXSTR);
                    }
                    break;

                default:
                    help_authd(home_path);
                    break;
            }
        }

        if (generate_certificate) {
            // Sanitize parameters
            if (strlen(cert_val) == 0) {
                merror_exit("Certificate expiration time not defined.");
            }

            if (strlen(cert_key_bits) == 0) {
                merror_exit("Certificate key size not defined.");
            }

            if (strlen(cert_key_path) == 0) {
                merror_exit("Key path not defined.");
            }

            if (strlen(cert_path) == 0) {
                merror_exit("Certificate path not defined.");
            }

            if (strlen(cert_subj) == 0) {
                merror_exit("Certificate subject not defined.");
            }

            if (days_val = strtol(cert_val, NULL, 10), days_val == 0) {
                merror_exit("Unable to set certificate validity to 0 days.");
            }

            if (key_bits = strtol(cert_key_bits, NULL, 10), key_bits == 0) {
                merror_exit("Unable to set certificate private key size to 0 bits.");
            }

            if (generate_cert(days_val, key_bits, cert_key_path, cert_path, cert_subj) == 0) {
                mdebug2("Certificates generated successfully.");
                exit(0);
            } else {
                merror_exit("Unable to generate auth certificates.");
            }
        }

        /* Set the Debug level */
        if (debug_level == 0 && test_config == 0) {
            /* Get debug level */
            debug_level = getDefine_Int("authd", "debug", 0, 2);
            while (debug_level != 0) {
                nowDebug();
                debug_level--;
            }
        }

        // Return -1 if not configured
        if (authd_read_config(OSSECCONF) < 0) {
            merror_exit(CONFIG_ERROR, OSSECCONF);
        }

        // Overwrite arguments

        if (use_pass) {
            config.flags.use_password = 1;
        }

        if (auto_method) {
            config.flags.auto_negotiate = 1;
        }

        if (validate_host) {
            config.flags.verify_host = 1;
        }

        if (run_foreground) {
            config.flags.disabled = 0;
        }

        if (ciphers) {
            os_free(config.ciphers);
            config.ciphers = strdup(ciphers);
        }

        if (ca_cert) {
            os_free(config.agent_ca);
            config.agent_ca = strdup(ca_cert);
        }

        if (server_cert) {
            os_free(config.manager_cert);
            config.manager_cert = strdup(server_cert);
        }

        if (server_key) {
            os_free(config.manager_key);
            config.manager_key = strdup(server_key);
        }

        if (port) {
            config.port = port;
        }
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Exit here if disabled */
    if (config.flags.disabled) {
        minfo("Daemon is disabled. Closing.");
        exit(0);
    }

    mdebug1(WAZUH_HOMEDIR, home_path);

    switch(w_is_worker()) {
    case -1:
        merror("Invalid option at cluster configuration");
        exit(0);
    case 1:
        config.worker_node = TRUE;
        break;
    case 0:
        config.worker_node = FALSE;
        break;
    }

    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group, strerror(errno), errno);
    }

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Signal manipulation */
    {
        struct sigaction action = { .sa_handler = handler, .sa_flags = SA_RESTART };
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);

        action.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &action, NULL);
    }

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    atexit(cleanup);

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* Checking client keys file */
    fp = wfopen(KEYS_FILE, "a");
    if (!fp) {
        merror("Unable to open %s (key file)", KEYS_FILE);
        exit(1);
    }
    fclose(fp);

    if (config.flags.remote_enrollment) {
        g_epfd = epoll_create1(0);

        if (g_epfd < 0) {
            merror("Couldn't initialize epoll");
            exit(1);
        }

        if (pipe(g_stopFD) == -1) {
            merror("Failed to create stop pipe");
            exit(1);
        }

        if (fcntl(g_stopFD[0], F_SETFL, O_NONBLOCK) == -1) {
            merror("Failed to set stop pipe to non-blocking");
            exit(1);
        }

        struct epoll_event event;
        event.events = EPOLLIN | EPOLLET;
        event.data.u32 = STOP_FD;

        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_stopFD[0], &event) < 0)
        {
            merror("Couldn't add event");
            exit(1);
        }

        /* Start SSL */
        if (ctx = os_ssl_keys(1, home_path, config.ciphers, config.manager_cert, config.manager_key, config.agent_ca, config.flags.auto_negotiate), !ctx) {
            merror("SSL error. Exiting.");
            exit(1);
        }

        /* Connect via TCP */
        if (remote_sock = OS_Bindporttcp(config.port, NULL, config.ipv6), remote_sock <= 0) {
            merror(BIND_ERROR, config.port, errno, strerror(errno));
            exit(1);
        }

        set_non_blocking(remote_sock);

        event.events = EPOLLIN;
        event.data.u32 = SERVER_INDEX;

        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, remote_sock, &event) < 0)
        {
            merror("Couldn't add event");
            exit(1);
        }

        /* Check if password is enabled */
        if (config.flags.use_password) {
            fp = wfopen(AUTHD_PASS, "r");
            buf[0] = '\0';

            /* Checking if there is a custom password file */
            if (fp) {
                fseek(fp, 0, SEEK_END);

                if (ftell(fp) <= 1) {
                    merror("Empty password provided.");
                    exit(1);
                }

                fseek(fp, 0, SEEK_SET);

                buf[4096] = '\0';
                char *ret = fgets(buf, 4095, fp);

                if (ret && strlen(buf) > 2) {
                    /* Remove newline */
                    if (buf[strlen(buf) - 1] == '\n') {
                        buf[strlen(buf) - 1] = '\0';
                    }
                    authpass = strdup(buf);
                }

                fclose(fp);
            }

            if (buf[0] != '\0') {
                minfo("Accepting connections on port %hu. Using password specified on file: %s", config.port, AUTHD_PASS);
            } else {
                /* Getting temporary pass. */
                if (authpass = w_generate_random_pass(), authpass) {
                    minfo("Accepting connections on port %hu. Random password chosen for agent authentication: %s", config.port, authpass);
                } else {
                    merror_exit("Unable to generate random password. Exiting.");
                }
            }
        } else {
            minfo("Accepting connections on port %hu. No password required.", config.port);
        }
    }

    srandom_init();
    getuname();

    if (gethostname(shost, sizeof(shost) - 1) < 0) {
        strncpy(shost, "localhost", sizeof(shost) - 1);
        shost[sizeof(shost) - 1] = '\0';
    }

    os_free(home_path);

    /* Initialize queues */
    insert_tail = &queue_insert;
    remove_tail = &queue_remove;

    /* Load client keys in master node */
    if (!config.worker_node) {
        OS_PassEmptyKeyfile();
        OS_ReadKeys(&keys, W_RAW_KEY, !config.flags.clear_removed);
        OS_ReadTimestamps(&keys);
    }

    /* Start working threads */

    if (status = pthread_create(&thread_local_server, NULL, (void *)&run_local_server, NULL), status != 0) {
        merror("Couldn't create thread: %s", strerror(status));
        return EXIT_FAILURE;
    }

    if (config.flags.remote_enrollment) {

        if (status = pthread_create(&thread_remote_server, NULL, (void *)&run_remote_server, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }
    } else {
        minfo("Port %hu was set as disabled.", config.port);
    }

    if (!config.worker_node) {
        if (status = pthread_create(&thread_writer, NULL, (void *)&run_writer, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }
    }

    if (config.key_request.enabled) {
        if (status = pthread_create(&thread_key_request, NULL, (void *)&run_key_request_main, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }
    }

    /* Join threads */
    pthread_join(thread_local_server, NULL);
    if (config.flags.remote_enrollment) {
        pthread_join(thread_remote_server, NULL);
    }
    if (!config.worker_node) {
        /* Send signal to writer thread */
        w_mutex_lock(&mutex_keys);
        w_cond_signal(&cond_pending);
        w_mutex_unlock(&mutex_keys);
        pthread_join(thread_writer, NULL);
    }
    if (config.key_request.enabled) {
        pthread_join(thread_key_request, NULL);
    }

    minfo("Exiting...");
    return (0);
}

void delete_client(uint32_t index) {
    if (g_client_pool[index]) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_client_pool[index]->socket, NULL);

        if (g_client_pool[index]->ssl) {
            SSL_shutdown(g_client_pool[index]->ssl);
            SSL_free(g_client_pool[index]->ssl);
            g_client_pool[index]->ssl = NULL;
        }

        if (g_client_pool[index]->is_ipv6) {
            os_free(g_client_pool[index]->addr6);
        } else {
            os_free(g_client_pool[index]->addr4);
        }

        close(g_client_pool[index]->socket);
        os_free(g_client_pool[index]->agentname);
        os_free(g_client_pool[index]->centralized_group);
        os_free(g_client_pool[index]->new_id);
        os_free(g_client_pool[index]);
        g_client_pool[index] = NULL;
    }
    else
    {
        merror("Client not found in pool");
    }
}
static void process_message(struct client *client) {
    char response[2048] = {0};
    bool enrollment_ok = FALSE;
    char* key_hash = NULL;
    char* new_key = NULL;

    mdebug2("Request received: <%s>", client->read_buffer);

    if (OS_SUCCESS == w_auth_parse_data(client->read_buffer, response, authpass, client->ip, &client->agentname, &client->centralized_group, &key_hash)) {
        if (config.worker_node) {
            minfo("Dispatching request to master node");
            // The force registration settings are ignored for workers. The master decides.
            if (0 == w_request_agent_add_clustered(response, client->agentname, client->ip, client->centralized_group, key_hash, &client->new_id, &new_key, NULL, NULL)) {
                enrollment_ok = TRUE;
            }
        }
        else {
            w_mutex_lock(&mutex_keys);
            if (OS_SUCCESS == w_auth_validate_data(response, client->ip, client->agentname, client->centralized_group, key_hash)) {
                if (OS_SUCCESS == w_auth_add_agent(response, client->ip, client->agentname, &client->new_id, &new_key)) {
                    enrollment_ok = TRUE;
                }
            }
            w_mutex_unlock(&mutex_keys);
        }
    }

    if (enrollment_ok)
    {
        snprintf(client->write_buffer, MAX_SSL_PACKET_SIZE, "OSSEC K:'%s %s %s %s'", client->new_id, client->agentname, client->ip, new_key);
        client->write_len = strlen(client->write_buffer);

        minfo("Agent key generated for '%s' (requested by %s)", client->agentname, client->ip);
    }
    else {
        merror("Unable to add agent %s (requested by %s) error: %s", client->agentname, client->ip, response);
        snprintf(client->write_buffer, MAX_SSL_PACKET_SIZE, "ERROR: Unable to add agent");
        client->write_offset = strlen(client->write_buffer);
    }

    os_free(key_hash);
    os_free(new_key);
}

static int handle_ssl_read(struct client *client) {
    while (true) {
        int ret = SSL_read(client->ssl,
                           client->read_buffer + client->read_offset,
                           MAX_SSL_PACKET_SIZE - client->read_offset);

        if (ret > 0) {
            client->read_offset += ret;
            char *end = memchr(client->read_buffer, '\n', client->read_offset);
            if (end) {
                *end = '\0';
                // Enable epoll for writing
                struct epoll_event event;
                event.events = EPOLLOUT;
                event.data.u32 = client->index;
                if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, client->socket, &event) < 0) {
                    merror("Couldn't modify event");
                    return -1;
                }
                process_message(client);
                break;
            }

        } else if (ret == 0) {
            // The client closed the connection
            mdebug2("Client closed connection ip: %s fd: %d", client->ip, client->socket);
            return -1;
        } else {
            int err = SSL_get_error(client->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                mdebug2("SSL read in progress for socket=%d", client->socket);
                return 0;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                return 0;
            } else {
                merror("SSL read error (%d)", err);
                return -1;
            }
        }

        if (ret < (MAX_SSL_PACKET_SIZE - client->read_offset)) {
            break;
        }
    }

    return 0;
}

static int handle_ssl_handshake(struct client *client) {
    int ret = SSL_accept(client->ssl);
    if (ret == 1) {
        client->handshake_done = true;
        mdebug1("SSL handshake completed for socket=%d", client->socket);

        /* Additional verification of the agent's certificate. */
        if (config.flags.verify_host && config.agent_ca) {
            if (check_x509_cert(client->ssl, client->ip) != VERIFY_TRUE) {
                merror("Unable to verify client certificate.");
                return -1;
            }
        }
        return 1;
    } else {
        int err = SSL_get_error(client->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            mdebug2("SSL handshake in progress for socket=%d", client->socket);
            return 0;
        } else {
            merror("SSL handshake failed for socket=%d: %s", client->socket, ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }
    }
}

static int handle_ssl_write(struct client *client) {
    while (client->write_offset < client->write_len) {
        int ret = SSL_write(client->ssl,
                            client->write_buffer + client->write_offset,
                            client->write_len - client->write_offset);

        if (ret > 0) {
            client->write_offset += ret;
        } else {
            int err = SSL_get_error(client->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    return 0;
}

void enqueue_pending_key(int ret, uint32_t index_client) {
    if (ret < 0) {
        if (config.worker_node) {
            merror("SSL write error (%d)", ret);
            ERR_print_errors_fp(stderr);
            if (0 != w_request_agent_remove_clustered(NULL, g_client_pool[index_client]->new_id, TRUE)) {
                merror("Agent key unable to be shared with %s and unable to delete from master node", g_client_pool[index_client]->agentname);
            } else {
                merror("Agent key not saved for %s", g_client_pool[index_client]->agentname);
            }
        } else {
            merror("SSL write error (%d)", ret);
            merror("Agent key not saved for %s", g_client_pool[index_client]->agentname);
            ERR_print_errors_fp(stderr);
            w_mutex_lock(&mutex_keys);
            OS_DeleteKey(&keys, keys.keyentries[keys.keysize - 1]->id, 1);
            w_mutex_unlock(&mutex_keys);
        }
        delete_client(index_client);
    } else {
        // ret == 0
        w_mutex_lock(&mutex_keys);
        add_insert(keys.keyentries[keys.keysize - 1], g_client_pool[index_client]->centralized_group);
        write_pending = 1;
        w_cond_signal(&cond_pending);
        w_mutex_unlock(&mutex_keys);
        delete_client(index_client);
    }
}

/* Thread for remote server */
void* run_remote_server(__attribute__((unused)) void *arg) {
    int client_sock = 0;
    struct sockaddr_storage _nc;
    socklen_t _ncl;

    authd_sigblock();

    if (config.timeout_sec || config.timeout_usec) {
        minfo("Setting network timeout to %.6f sec.", config.timeout_sec + config.timeout_usec / 1000000.);
    } else {
        mdebug1("Network timeout is disabled.");
    }

    mdebug1("Remote server ready.");

    while (running) {
        memset(&_nc, 0, sizeof(_nc));
        _ncl = sizeof(_nc);

        struct epoll_event events[MAX_EVENTS];
        int event_number = epoll_wait(g_epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < event_number; ++i)
        {
            uint32_t index = events[i].data.u32;
            if (index == SERVER_INDEX)
            {
                if ((client_sock = accept(remote_sock, (struct sockaddr *) &_nc, &_ncl)) > 0) {
                    struct client *new_client;
                    os_malloc(sizeof(struct client), new_client);
                    new_client->socket = client_sock;

                    memset(new_client->read_buffer, '\0', MAX_SSL_PACKET_SIZE);
                    new_client->read_offset = 0;
                    new_client->handshake_done = false;

                    memset(new_client->ip, '\0', IPSIZE + 1);

                    memset(new_client->write_buffer, '\0', MAX_SSL_PACKET_SIZE);
                    new_client->write_offset = 0;
                    new_client->write_len = 0;

                    set_non_blocking(new_client->socket);

                    int client_index = -1;
                    for (int j = 1; j < AUTH_POOL; j++) {
                        if (g_client_pool[j] == NULL) {
                            g_client_pool[j] = new_client;
                            client_index = j;
                            break;
                        }
                    }

                    if (client_index == -1) {
                        merror("Too many connections. Rejecting.");
                        os_free(new_client);
                        close(client_sock);
                        continue;
                    }

                    new_client->index = client_index;

                    switch (_nc.ss_family) {
                    case AF_INET:
                        new_client->is_ipv6 = FALSE;
                        os_calloc(1, sizeof(struct in_addr), new_client->addr4);
                        memcpy(new_client->addr4, &((struct sockaddr_in *)&_nc)->sin_addr, sizeof(struct in_addr));
                        get_ipv4_string(*new_client->addr4, new_client->ip, IPSIZE);
                        break;
                    case AF_INET6:
                        new_client->is_ipv6 = TRUE;
                        os_calloc(1, sizeof(struct in6_addr), new_client->addr6);
                        memcpy(new_client->addr6, &((struct sockaddr_in6 *)&_nc)->sin6_addr, sizeof(struct in6_addr));
                        get_ipv6_string(*new_client->addr6, new_client->ip, IPSIZE);
                        break;
                    default:
                        merror("IP address family not supported. Rejecting.");
                        g_client_pool[client_index] = NULL;
                        os_free(new_client);
                        close(client_sock);
                        continue;
                    }

                    minfo("New connection from %s", new_client->ip);

                    new_client->ssl = SSL_new(ctx);
                    if (!new_client->ssl) {
                        merror("SSL error. Exiting.");
                        delete_client(client_index);
                        continue;
                    }

                    SSL_set_fd(new_client->ssl, new_client->socket);
                    new_client->handshake_done = false;

                    struct epoll_event event = {};
                    event.events = EPOLLIN | EPOLLET;
                    event.data.u32 = client_index;

                    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, client_sock, &event) < 0)
                    {
                        merror("Couldn't add event");
                        delete_client(client_index);
                        continue;
                    }
                }
            }
            else if (index == STOP_FD) {
                mdebug1("Received stop signal");
                running = 0;
                break;
            }
            else {
                uint32_t index_client = events[i].data.u32;
                if (g_client_pool[index_client] == NULL) {
                    merror("Client not found");
                    continue;
                }

                if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                    delete_client(index_client);
                    continue;
                }

                if (!g_client_pool[index_client]->handshake_done) {
                    int ret = handle_ssl_handshake(g_client_pool[index_client]);
                    if (ret < 0) {
                        delete_client(index_client);
                        continue;
                    } else if (ret == 0) {
                        // Handshake in progress
                        continue;
                    }
                }

                if (events[i].events & EPOLLIN) {
                    int ret = handle_ssl_read(g_client_pool[index_client]);
                    if (ret < 0) {
                        delete_client(index_client);
                    }
                    continue;
                }

                if (events[i].events & EPOLLOUT) {
                    int ret = handle_ssl_write(g_client_pool[index_client]);
                    if (ret == 1) {
                        // Accepted errors SSL_ERROR_WANT_WRITE || SSL_ERROR_WANT_READ
                        continue;
                    } else {
                        enqueue_pending_key(ret, index_client);
                    }
                }
            }
        }
    }

    close(g_stopFD[0]);
    close(g_epfd);
    mdebug1("Remote server thread finished");
    close(remote_sock);
    SSL_CTX_free(ctx);
    return NULL;
}

/* Thread for writing keystore onto disk */
void* run_writer(__attribute__((unused)) void *arg) {
    keystore *copy_keys;
    struct keynode *copy_insert;
    struct keynode *copy_remove;
    struct keynode *cur;
    struct keynode *next;
    char wdbquery[OS_SIZE_128];
    char wdboutput[128];
    int wdb_sock = -1;

    authd_sigblock();

    mdebug1("Writer thread ready.");

    struct timespec global_t0, global_t1;
    struct timespec t0, t1;

    while (running) {
        int inserted_agents = 0;
        int removed_agents = 0;

        w_mutex_lock(&mutex_keys);

        while (!write_pending && running) {
            w_cond_wait(&cond_pending, &mutex_keys);
        }

        mdebug1("Dumping changes into disk.");

        gettime(&global_t0);

        copy_keys = OS_DupKeys(&keys);
        copy_insert = queue_insert;
        copy_remove = queue_remove;
        queue_insert = NULL;
        queue_remove = NULL;
        insert_tail = &queue_insert;
        remove_tail = &queue_remove;
        write_pending = 0;
        w_mutex_unlock(&mutex_keys);

        gettime(&t0);

        if (OS_WriteKeys(copy_keys) < 0) {
            merror("Couldn't write file client.keys");
            sleep(1);
        }

        gettime(&t1);
        mdebug2("[Writer] OS_WriteKeys(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

        gettime(&t0);

        if (OS_WriteTimestamps(copy_keys) < 0) {
            merror("Couldn't write file agents-timestamp.");
            sleep(1);
        }

        gettime(&t1);
        mdebug2("[Writer] OS_WriteTimestamps(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

        OS_FreeKeys(copy_keys);
        os_free(copy_keys);

        for (cur = copy_insert; cur; cur = next) {
            next = cur->next;

            mdebug1("[Writer] Performing insert([%s] %s).", cur->id, cur->name);

            gettime(&t0);
            if (wdb_insert_agent(atoi(cur->id), cur->name, NULL, cur->ip, cur->raw_key, cur->group, 1, &wdb_sock)) {
                mdebug2("The agent %s '%s' already exists in the database.", cur->id, cur->name);
            }
            gettime(&t1);
            mdebug2("[Writer] wdb_insert_agent(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            gettime(&t0);
            if (cur->group) {
                if (wdb_set_agent_groups_csv(atoi(cur->id),
                                             cur->group,
                                             WDB_GROUP_MODE_OVERRIDE,
                                             w_is_single_node(NULL) ? "synced" : "syncreq",
                                             &wdb_sock)) {
                    merror("Unable to set agent centralized group: %s (internal error)", cur->group);
                }

            }

            gettime(&t1);
            mdebug2("[Writer] wdb_set_agent_groups_csv(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            os_free(cur->id);
            os_free(cur->name);
            os_free(cur->ip);
            os_free(cur->group);
            os_free(cur->raw_key);
            os_free(cur);

            inserted_agents++;
        }

        for (cur = copy_remove; cur; cur = next) {
            next = cur->next;

            mdebug1("[Writer] Performing delete([%s] %s).", cur->id, cur->name);

            gettime(&t0);
            delete_diff(cur->name);
            gettime(&t1);
            mdebug2("[Writer] delete_diff(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            gettime(&t0);
            OS_RemoveCounter(cur->id);
            gettime(&t1);
            mdebug2("[Writer] OS_RemoveCounter(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            gettime(&t0);
            OS_RemoveAgentTimestamp(cur->id);
            gettime(&t1);
            mdebug2("[Writer] OS_RemoveAgentTimestamp(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            gettime(&t0);
            if (wdb_remove_agent(atoi(cur->id), &wdb_sock) != OS_SUCCESS) {
                mdebug1("Could not remove the information stored in Wazuh DB of the agent %s.", cur->id);
            }
            gettime(&t1);
            mdebug2("[Writer] wdb_remove_agent(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            snprintf(wdbquery, OS_SIZE_128, "wazuhdb remove %s", cur->id);
            gettime(&t0);
            wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
            gettime(&t1);
            mdebug2("[Writer] wdbc_query_ex(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));

            os_free(cur->id);
            os_free(cur->name);
            os_free(cur->ip);
            os_free(cur->group);
            os_free(cur->raw_key);
            os_free(cur);

            removed_agents++;
        }

        gettime(&global_t1);
        mdebug2("[Writer] Inserted agents: %d", inserted_agents);
        mdebug2("[Writer] Removed agents: %d", removed_agents);
        mdebug2("[Writer] Loop: %d ms.", (int)(1000. * (double)time_diff(&global_t0, &global_t1)));
    }

    return NULL;
}

/* To avoid hp-ux requirement of strsignal */
#ifdef __hpux
char* strsignal(int sig)
{
    static char str[12];
    sprintf(str, "%d", sig);
    return str;
}
#endif

/* Signal handler */
void handler(int signum) {
    char dummy = '\0';
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        dummy = 'x';
        write(g_stopFD[1], &dummy, sizeof(dummy));
        close(g_stopFD[1]);
        minfo(SIGNAL_RECV, signum, strsignal(signum));
        running = 0;
        break;
    default:
        merror("unknown signal (%d)", signum);
    }
}

/* Exit handler */
void cleanup() {
    DeletePID(ARGV0);
}

void authd_sigblock() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}
