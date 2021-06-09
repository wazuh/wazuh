/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "os_crypto/md5/md5_op.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuhdb_op.h"
#include "os_err.h"

/* Prototypes */
static void help_authd(char * home_path) __attribute((noreturn));
static int ssl_error(const SSL *ssl, int ret);

/* Thread for dispatching connection pool */
static void* run_dispatcher(void *arg);

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

/* client queue */
static w_queue_t *client_queue = NULL;

volatile int write_pending = 0;
volatile int running = 1;

extern struct keynode *queue_insert;
extern struct keynode *queue_remove;
extern struct keynode * volatile *insert_tail;
extern struct keynode * volatile *remove_tail;

pthread_mutex_t mutex_keys = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;


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
    print_out("    -D <dir>    Directory to chroot into. Default: %s.", home_path);
    print_out("    -p <port>   Manager port. Default: %d.", DEFAULT_PORT);
    print_out("    -P          Enable shared password authentication, at %s or random.", AUTHD_PASS);
    print_out("    -c          SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify clients.");
    print_out("    -s          Used with -v, enable source host verification.");
    print_out("    -x <path>   Full path to server certificate. Default: %s.", CERTFILE);
    print_out("    -k <path>   Full path to server key. Default: %s.", KEYFILE);
    print_out("    -a          Auto select SSL/TLS method. Default: TLS v1.2 only.");
    print_out("    -L          Force insertion though agent limit reached.");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

/* Generates a random and temporary shared pass to be used by the agents. */
char *__generatetmppass()
{
    int rand1;
    int rand2;
    char *rand3;
    char *rand4;
    os_md5 md1;
    os_md5 md3;
    os_md5 md4;
    char *fstring = NULL;
    char str1[STR_SIZE +1];

    rand1 = os_random();
    rand2 = os_random();

    rand3 = GetRandomNoise();
    rand4 = GetRandomNoise();

    OS_MD5_Str(rand3, -1, md3);
    OS_MD5_Str(rand4, -1, md4);

    os_snprintf(str1, STR_SIZE, "%d%d%s%d%s%s",(int)time(0), rand1, getuname(), rand2, md3, md4);
    OS_MD5_Str(str1, -1, md1);
    fstring = strdup(md1);
    free(rand3);
    free(rand4);
    return(fstring);
}

/* Function to use with SSL on non blocking socket,
 * to know if SSL operation failed for good
 */
static int ssl_error(const SSL *ssl, int ret)
{
    if (ret <= 0) {
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                usleep(100 * 1000);
                return (0);
            default:
                ERR_print_errors_fp(stderr);
                return (1);
        }
    }

    return (0);
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
    pthread_t thread_dispatcher = 0;
    pthread_t thread_remote_server = 0;
    pthread_t thread_writer = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    /* Initialize some variables */
    bio_err = 0;

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
        unsigned short port = 0;

        while (c = getopt(argc, argv, "Vdhtfig:D:p:c:v:sx:k:PF:ar:L"), c != -1) {
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
                    ciphers = optarg;
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

                default:
                    help_authd(home_path);
                    break;
            }
        }

        /* Change working directory */
        if (chdir(home_path) == -1) {
            merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
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
            free(config.ciphers);
            config.ciphers = strdup(ciphers);
        }

        if (ca_cert) {
            free(config.agent_ca);
            config.agent_ca = strdup(ca_cert);
        }

        if (server_cert) {
            free(config.manager_cert);
            config.manager_cert = strdup(server_cert);
        }

        if (server_key) {
            free(config.manager_key);
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
        minfo("Daemon is disabled. Closing.");
        exit(0);
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("authd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
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
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* Checking client keys file */
    fp = fopen(KEYS_FILE, "a");
    if (!fp) {
        merror("Unable to open %s (key file)", KEYS_FILE);
        exit(1);
    }
    fclose(fp);

    if (config.flags.remote_enrollment) {
        /* Check if password is enabled */
        if (config.flags.use_password) {
            fp = fopen(AUTHD_PASS, "r");
            buf[0] = '\0';

            /* Checking if there is a custom password file */
            if (fp) {
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
                authpass = __generatetmppass();
                minfo("Accepting connections on port %hu. Random password chosen for agent authentication: %s", config.port, authpass);
            }
        } else {
            minfo("Accepting connections on port %hu. No password required.", config.port);
        }

        /* Start SSL */
        if (ctx = os_ssl_keys(1, home_path, config.ciphers, config.manager_cert, config.manager_key, config.agent_ca, config.flags.auto_negotiate), !ctx) {
            merror("SSL error. Exiting.");
            exit(1);
        }

        /* Connect via TCP */
        if (remote_sock = OS_Bindporttcp(config.port, NULL, 0), remote_sock <= 0) {
            merror(BIND_ERROR, config.port, errno, strerror(errno));
            exit(1);
        }
    }

    /* Before chroot */
    srandom_init();
    getuname();

    if (gethostname(shost, sizeof(shost) - 1) < 0) {
        strncpy(shost, "localhost", sizeof(shost) - 1);
        shost[sizeof(shost) - 1] = '\0';
    }

    /* Chroot */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }

    nowChroot();
    os_free(home_path);

    /* Initialize queues */
    insert_tail = &queue_insert;
    remove_tail = &queue_remove;

    /* Load client keys in master node */
    if (!config.worker_node) {
        OS_PassEmptyKeyfile();
        OS_ReadKeys(&keys, 0, !config.flags.clear_removed);
    }

    /* Start working threads */

    if (status = pthread_create(&thread_local_server, NULL, (void *)&run_local_server, NULL), status != 0) {
        merror("Couldn't create thread: %s", strerror(status));
        return EXIT_FAILURE;
    }

    if (config.flags.remote_enrollment) {
        client_queue = queue_init(AUTH_POOL);

        if (status = pthread_create(&thread_dispatcher, NULL, (void *)&run_dispatcher, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }

        if (status = pthread_create(&thread_remote_server, NULL, (void *)&run_remote_server, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }
    } else {
        minfo("Port %hu was set as disabled.", config.port);
    }

    if (!config.worker_node) {
        if (status = pthread_create(&thread_writer, NULL, (void *)&run_writer, NULL), status != 0) {
            merror("Couldn't create thread: %s", strerror(status));
            return EXIT_FAILURE;
        }
    }

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    atexit(cleanup);

    /* Join threads */
    pthread_join(thread_local_server, NULL);
    if (config.flags.remote_enrollment) {
        pthread_join(thread_dispatcher, NULL);
        pthread_join(thread_remote_server, NULL);
    }
    if (!config.worker_node) {
        /* Send signal to writer thread */
        w_mutex_lock(&mutex_keys);
        w_cond_signal(&cond_pending);
        w_mutex_unlock(&mutex_keys);
        pthread_join(thread_writer, NULL);
    }

    queue_free(client_queue);
    minfo("Exiting...");
    return (0);
}

/* Thread for dispatching connection pool */
void* run_dispatcher(__attribute__((unused)) void *arg) {
    char ip[IPSIZE + 1];
    int ret;
    char* buf = NULL;
    SSL *ssl;
    char response[2048];
    response[2047] = '\0';

    authd_sigblock();

    /* Initialize some variables */
    memset(ip, '\0', IPSIZE + 1);

    mdebug1("Dispatch thread ready.");

    while (running) {
        const struct timespec timeout = { .tv_sec = time(NULL) + 1 };
        struct client *client = queue_pop_ex_timedwait(client_queue, &timeout);

        if (!client) {
            continue;
        }

        strncpy(ip, inet_ntoa(client->addr), IPSIZE - 1);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client->socket);
        ret = SSL_accept(ssl);

        if (ssl_error(ssl, ret)) {
            mdebug1("SSL Error (%d)", ret);
            SSL_free(ssl);
            close(client->socket);
            os_free(client);
            continue;
        }

        minfo("New connection from %s", ip);

        /* Additional verification of the agent's certificate. */

        if (config.flags.verify_host && config.agent_ca) {
            if (check_x509_cert(ssl, ip) != VERIFY_TRUE) {
                merror("Unable to verify client certificate.");
                SSL_free(ssl);
                close(client->socket);
                os_free(client);
                continue;
            }
        }

        os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
        buf[0] = '\0';
        ret = wrap_SSL_read(ssl, buf, OS_SIZE_65536 + OS_SIZE_4096);
        if (ret <= 0) {
            switch (ssl_error(ssl, ret)) {
            case 0:
                minfo("Client timeout from %s", ip);
                break;
            default:
                merror("SSL Error (%d)", ret);
            }
            SSL_free(ssl);
            close(client->socket);
            os_free(client);
            free(buf);
            continue;
        }
        buf[ret] = '\0';

        mdebug2("Request received: <%s>", buf);
        bool enrollment_ok = FALSE;
        char *agentname = NULL;
        char *centralized_group = NULL;
        char* new_id = NULL;
        char* new_key = NULL;
        if (OS_SUCCESS == w_auth_parse_data(buf, response, authpass, ip, &agentname, &centralized_group)) {
            if (config.worker_node) {
                minfo("Dispatching request to master node");
                if (0 == w_request_agent_add_clustered(response, agentname, ip, centralized_group, &new_id, &new_key, config.flags.force_insert?config.force_time:-1, NULL)) {
                    enrollment_ok = TRUE;
                }
            }
            else {
                w_mutex_lock(&mutex_keys);
                if (OS_SUCCESS == w_auth_validate_data(response, ip, agentname, centralized_group)) {
                    if (OS_SUCCESS == w_auth_add_agent(response, ip, agentname, centralized_group, &new_id, &new_key)) {
                        enrollment_ok = TRUE;
                    }
                }
                w_mutex_unlock(&mutex_keys);
            }
        }

        if (enrollment_ok)
        {
            snprintf(response, 2048, "OSSEC K:'%s %s %s %s'", new_id, agentname, ip, new_key);
            minfo("Agent key generated for '%s' (requested by %s)", agentname, ip);
            ret = SSL_write(ssl, response, strlen(response));

            if (config.worker_node) {
                if (ret < 0) {
                    merror("SSL write error (%d)", ret);

                    ERR_print_errors_fp(stderr);
                    if (0 != w_request_agent_remove_clustered(NULL, new_id, TRUE)) {
                        merror("Agent key unable to be shared with %s and unable to delete from master node", agentname);
                    }
                    else {
                        merror("Agent key not saved for %s", agentname);
                    }
                }
            }
            else {
                if (ret < 0) {
                    merror("SSL write error (%d)", ret);
                    merror("Agent key not saved for %s", agentname);
                    ERR_print_errors_fp(stderr);
                    w_mutex_lock(&mutex_keys);
                    OS_DeleteKey(&keys, keys.keyentries[keys.keysize - 1]->id, 1);
                    w_mutex_unlock(&mutex_keys);
                } else {
                    /* Add pending key to write */
                    w_mutex_lock(&mutex_keys);
                    add_insert(keys.keyentries[keys.keysize - 1], centralized_group);
                    write_pending = 1;
                    w_cond_signal(&cond_pending);
                    w_mutex_unlock(&mutex_keys);
                }
            }
        }
        else {
            SSL_write(ssl, response, strlen(response));
            snprintf(response, 2048, "ERROR: Unable to add agent");
            SSL_write(ssl, response, strlen(response));
        }

        SSL_free(ssl);
        close(client->socket);
        os_free(client);
        os_free(buf);
        os_free(agentname);
        os_free(centralized_group);
        os_free(new_id);
        os_free(new_key);
    }

    mdebug1("Dispatch thread finished");

    SSL_CTX_free(ctx);
    return NULL;
}

/* Thread for remote server */
void* run_remote_server(__attribute__((unused)) void *arg) {
    int client_sock = 0;
    struct sockaddr_in _nc;
    socklen_t _ncl;
    fd_set fdset;
    struct timeval timeout;

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

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(remote_sock, &fdset);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(remote_sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("at main(): select(): %s", strerror(errno));
            }
            continue;
        case 0:
            continue;
        }

        if ((client_sock = accept(remote_sock, (struct sockaddr *) &_nc, &_ncl)) > 0) {
            if (config.timeout_sec || config.timeout_usec) {
                if (OS_SetRecvTimeout(client_sock, config.timeout_sec, config.timeout_usec) < 0) {
                    static int reported = 0;

                    if (!reported) {
                        int error = errno;
                        merror("Could not set timeout to network socket: %s (%d)", strerror(error), error);
                        reported = 1;
                    }
                }
            }
            struct client *new_client;
            os_malloc(sizeof(struct client), new_client);
            new_client->socket = client_sock;
            new_client->addr = _nc.sin_addr;

            if (queue_push_ex(client_queue, new_client) == -1) {
                merror("Too many connections. Rejecting.");
                close(client_sock);
            }
        } else if ((errno == EBADF && running) || (errno != EBADF && errno != EINTR))
            merror("at main(): accept(): %s", strerror(errno));
    }

    mdebug1("Remote server thread finished");

    close(remote_sock);
    return NULL;
}

/* Thread for writing keystore onto disk */
void* run_writer(__attribute__((unused)) void *arg) {
    keystore *copy_keys;
    struct keynode *copy_insert;
    struct keynode *copy_remove;
    struct keynode *cur;
    struct keynode *next;
    time_t cur_time;
    char wdbquery[OS_SIZE_128];
    char wdboutput[128];
    int wdb_sock = -1;

    authd_sigblock();

    mdebug1("Writer thread ready.");

    while (running) {
        w_mutex_lock(&mutex_keys);

        while (!write_pending && running) {
            w_cond_wait(&cond_pending, &mutex_keys);
        }

        copy_keys = OS_DupKeys(&keys);
        copy_insert = queue_insert;
        copy_remove = queue_remove;
        queue_insert = NULL;
        queue_remove = NULL;
        insert_tail = &queue_insert;
        remove_tail = &queue_remove;
        write_pending = 0;
        w_mutex_unlock(&mutex_keys);

        if (OS_WriteKeys(copy_keys) < 0) {
            merror("Couldn't write file client.keys");
        }

        OS_FreeKeys(copy_keys);
        free(copy_keys);
        cur_time = time(0);

        for (cur = copy_insert; cur; cur = next) {
            next = cur->next;
            OS_AddAgentTimestamp(cur->id, cur->name, cur->ip, cur_time);

            if (cur->group) {
                if (set_agent_group(cur->id,cur->group) == -1) {
                    merror("Unable to set agent centralized group: %s (internal error)", cur->group);
                }

                set_agent_multigroup(cur->group);
            }

            free(cur->id);
            free(cur->name);
            free(cur->ip);
            free(cur->group);
            free(cur);
        }

        for (cur = copy_remove; cur; cur = next) {
            char full_name[FILE_SIZE + 1];
            next = cur->next;
            snprintf(full_name, sizeof(full_name), "%s-%s", cur->name, cur->ip);
            delete_agentinfo(cur->id, full_name);
            OS_RemoveCounter(cur->id);
            OS_RemoveAgentTimestamp(cur->id);
            OS_RemoveAgentGroup(cur->id);

            if (wdb_remove_agent(atoi(cur->id), &wdb_sock) != OS_SUCCESS) {
                mdebug1("Could not remove the information stored in Wazuh DB of the agent %s.", cur->id);
            }

            snprintf(wdbquery, OS_SIZE_128, "wazuhdb remove %s", cur->id);
            wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

            free(cur->id);
            free(cur->name);
            free(cur->ip);
            free(cur);
        }
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
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
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
