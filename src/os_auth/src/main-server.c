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
#include <openssl/crypto.h>
#include "mconf-config.h"
#include <pthread.h>
#include <sys/wait.h>
#include "check_cert_op.h"
#include "wazuhdb_queries_op.h"
#include "wazuhdb_op.h"
#include "os_err.h"
#include <sys/epoll.h>
#include "manager_task_op.h"
#include "enrollment_token_store.h"
#include "token_cli.h"
#include <getopt.h>

/* Prototypes */
static void help_authd(char * home_path) __attribute((noreturn));

/* Thread for remote server */
static void* run_remote_server(void *arg);

/* Thread for writing keystore onto disk */
static void* run_writer(void *arg);

/* Finish the deletions a previous run left mid-sequence, and seed the reusable-id guard. */
static void purge_startup_recover(void);

/* Thread that watches for authd.pass to appear on a worker node */
static void* run_authpass_watcher(void *arg);

/* Signal handler */
static void handler(int signum);

/* Exit handler */
static void cleanup();

/* Shared variables */
static char *authpass = NULL;
static time_t authpass_mtime = 0;  /* shared between process_message and run_authpass_watcher */
/* Log-once latch for the "password not available yet" rejection below: without it, every
 * enrollment attempt during the (expected, transient) worker sync window logs its own line.
 * Guarded by mutex_authpass like authpass/authpass_mtime; reset wherever authpass is
 * (re)loaded successfully, so a later unavailability (e.g. the file is removed) is reported again. */
static bool authpass_unavailable_reported = false;
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
pthread_mutex_t mutex_authpass = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;

static int g_stopFD[2] = {-1, -1};

/* Print help statement */
static void help_authd(char * home_path)
{
    print_header();
    print_out("  %s: -[VhdtfP] [-u user] [-g group] [-D dir] [-p port] [-c ciphersuites] [-v path [-s]] [-x path] [-k path]", ARGV0);
    print_out("  %s: --create-enrollment-token --address <host> [--port N] [--prefix P] [--ttl 30d] [--max-uses N] [--description S] [--embed-ca] [--no-credential]", ARGV0);
    print_out("  %s: --list-enrollment-tokens | --revoke-enrollment-token <id> | --purge-enrollment-tokens [--all] [--force] | --show-token[=<token>] [--token-file <path>]", ARGV0);
    print_out("    -V          Version and license message.");
    print_out("    -h          This help message.");
    print_out("    -d          Debug mode. Use this parameter multiple times to increase the debug level.");
    print_out("    -t          Test configuration.");
    print_out("    -f          Run in foreground.");
    print_out("    -u <user>   User to run as. Default: %s.", USER);
    print_out("    -g <group>  Group to run as. Default: %s.", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chdir into. Default: %s.", home_path);
    print_out("    -p <port>   Manager port. Default: %d.", DEFAULT_PORT);
    print_out("    -P          Force shared-password enrollment on (enabled by default in the installer-shipped config, but off by default in the daemon itself); password read from %s or generated.", AUTHD_PASS);
    print_out("    -c          TLS 1.3 cipher suite list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify clients.");
    print_out("    -s          Used with -v, enable source host verification.");
    print_out("    -x <path>   Full path to server certificate. Default: %s.", CERTFILE);
    print_out("    -k <path>   Full path to server key. Default: %s.", KEYFILE);
    print_out(" ");
    print_out("  Enrollment tokens (the daemon must be running; mint and revoke only on the master node):");
    print_out("    --create-enrollment-token   Mint a token for --address <host>; prints the token on stdout.");
    print_out("      --address <host>          Name (or IP) the agents connect to; must be in the listener certificate's SAN.");
    print_out("      --port <N>                Listener port to write into the token when it differs from the configured one.");
    print_out("      --prefix <P>              URL prefix to write into the token when it differs from the configured one.");
    print_out("      --ttl <30d|12h|45m|90s>   Lifetime. Default: 30 days.");
    print_out("      --max-uses <N>            Enrollments the token allows. Default: unlimited.");
    print_out("      --description <text>      Free text shown by --list-enrollment-tokens.");
    print_out("      --embed-ca                Carry the CA certificate instead of its pin (no /cacerts fetch).");
    print_out("      --no-credential           Token without credential (public: address and pin only).");
    print_out("    --list-enrollment-tokens    List the tokens (never their credential).");
    print_out("    --revoke-enrollment-token <id>");
    print_out("    --purge-enrollment-tokens   Remove the tokens that can no longer authorise an enrollment (revoked, expired or out of uses).");
    print_out("      --all                     Remove every token instead, the ones still in use included.");
    print_out("      --force                   Do not ask for confirmation (needed for --all without a terminal).");
    print_out("    --show-token[=<token>]      Decode a token (from the argument, --token-file <path> or stdin) without its credential.");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) flags = 0;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        merror("Failed to set socket to non-blocking mode: %s", strerror(errno));
    }
}

static void* run_authpass_watcher(void *arg) {
    (void)arg;
    while (running) {
        /* Interruptible wait: poll the shutdown flag every second instead of sleeping a
         * full interval, so the thread exits promptly and can be joined at shutdown. */
        for (int i = 0; i < 5 && running; i++) {
            sleep(1);
        }
        if (!running) {
            break;
        }

        time_t mtime = File_DateofChange(AUTHD_PASS);
        if (mtime < 0) {
            continue;  /* file not there yet */
        }

        w_mutex_lock(&mutex_authpass);

        if (mtime == authpass_mtime) {
            /* File unchanged since last check. */
            w_mutex_unlock(&mutex_authpass);
            continue;
        }

        char *pass = w_authd_read_password(AUTHD_PASS);
        authpass_mtime = mtime;

        if (pass) {
            int first_load = (authpass == NULL);
            os_free(authpass);
            authpass = pass;
            authpass_unavailable_reported = false;
            if (first_load) {
                minfo("Enrollment password synchronized from the master node and now available at '%s'.", AUTHD_PASS);
            } else {
                minfo("Enrollment password reloaded from '%s'.", AUTHD_PASS);
            }
        }

        w_mutex_unlock(&mutex_authpass);
    }
    return NULL;
}

int main(int argc, char **argv)
{

    FILE *fp;
    /* Count of pids we are wait()ing on */
    int debug_level = 0;
    int test_config = 0;
    int status;
    int run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *user = USER;
    const char *group = GROUPGLOBAL;

    pthread_t thread_local_server = 0;
    pthread_t thread_remote_server = 0;
    pthread_t thread_writer = 0;
    pthread_t thread_authpass_watcher = 0;
    bool authpass_watcher_started = false;

    for (int i = 0; i < AUTH_POOL; i++) {
        g_client_pool[i] = NULL;
    }

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    // Get options
    {
        int c;
        int use_pass = 0;
        int validate_host = 0;
        const char *ciphers = NULL;
        const char *ca_cert = NULL;
        const char *server_cert = NULL;
        const char *server_key = NULL;
        unsigned short port = 0;
        /* Enrollment token utility mode (#38993): parsed here, run right after the loop. */
        token_cli_opts_t token_opts = {0};

        while (c = getopt_long(argc, argv, "Vdhtfu:g:D:p:c:v:sx:k:P", token_cli_long_opts, NULL), c != -1) {
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

                case 'u':
                    if (!optarg) {
                        merror_exit("-u needs an argument");
                    }
                    user = optarg;
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
                        if (w_authd_validate_ciphers(optarg) == OS_INVALID) {
                            merror_exit("-%c needs a valid list of TLS 1.3 cipher suites", c);
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

                default: {
                    /* The long options belong to the token CLI; anything else is unknown. */
                    int consumed = w_token_cli_parse_opt(&token_opts, c, optarg, stderr);

                    if (consumed < 0) {
                        exit(1);
                    }

                    if (consumed == 0) {
                        help_authd(home_path);
                    }
                    break;
                }
            }
        }

        /* Enrollment token utility mode: a client of the running daemon over auth.sock (or, for
         * --show-token, a local decode) that exits before the daemon reads its configuration or
         * drops privileges. Access to the socket is what authorises the caller, and the cwd is
         * already the manager home (chdir above), so the relative socket path resolves. */
        if (token_opts.requested) {
            exit(w_token_cli_run(&token_opts, stdin, stdout, stderr));
        }

        /* Set the Debug level */
        if (debug_level == 0 && test_config == 0) {
            /* Get debug level */
            debug_level = getDefine_Int_default("authd", "debug", 0, 2, 0);
            while (debug_level != 0) {
                nowDebug();
                debug_level--;
            }
        }

        // Return -1 if not configured
        if (authd_read_config(WAZUHCONF) < 0) {
            merror_exit(CONFIG_ERROR, WAZUHCONF);
        }

        // Overwrite arguments

        if (use_pass) {
            config.flags.use_password = 1;
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
        /* Start-up does not require the certificate files to exist; the test run does. */
        if (w_mconf_validate(WAZUHCONF) < 0) {
            merror_exit(CONFIG_ERROR, WAZUHCONF);
        }
        exit(0);
    }

    /* Exit here if disabled */
    if (config.flags.disabled) {
        mdebug1("Daemon is disabled. Closing.");
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

    /* Enrollment tokens (#38993): the master mints them over auth.sock and the workers hold the copy
     * the cluster synchronises next to authd.pass. Loaded once here; every token verb and every
     * enrollment that presents a token re-checks the file's mtime (etoken_store_reload_if_changed),
     * so a freshly synchronised copy is seen at once and no extra thread is needed. An absent file
     * just means "no tokens"; a malformed one is reported and leaves token enrollments rejected. */
    etoken_store_init(ENROLLMENT_TOKENS_FILE);
    if (etoken_store_load() == 0) {
        if (etoken_store_count() > 0) {
            minfo("%d enrollment token(s) loaded from '%s'.", etoken_store_count(), ENROLLMENT_TOKENS_FILE);
        }
    } else {
        mwarn("Could not load the enrollment tokens from '%s'; enrollments presenting a token will be rejected until the file is fixed.", ENROLLMENT_TOKENS_FILE);
    }

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
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

    /* Enrollment password: loaded here -- and, on a master, GENERATED here if absent -- whenever
     * shared-password enrollment is enabled, deliberately OUTSIDE the <legacy_enrollment> gate
     * below. etc/authd.pass is a manager-wide enrollment credential, not a property of the legacy
     * port-1515 listener: remoted's POST /enroll bridge reads the file directly (see
     * PasswordKeySource in remoted_module). w_authd_load_password() is the only thing anywhere in
     * the product that creates it -- no installer, package or framework step writes it -- so
     * gating this on legacy_enrollment would leave an HTTPS-only manager (<legacy_enrollment>no,
     * the very configuration that flag exists to enable) with a password file nothing ever
     * creates, and every Password-mode /enroll request failing 401 permanently, cluster-wide.
     * Gated on remote_enrollment alone: with that off, both enrollment paths are closed and no
     * password is needed by either. */
    if (config.flags.remote_enrollment && config.flags.use_password) {
        if (config.worker_node) {
            /* Owned by the master and synced to workers; never generated here.
             * If not synced yet, picked up later in process_message. */
            authpass = w_authd_read_password(AUTHD_PASS);

            if (authpass) {
                authpass_mtime = File_DateofChange(AUTHD_PASS);
                minfo("Using the enrollment password synchronized from the master node.");
            } else {
                minfo("Shared-password enrollment is enabled but '%s' has not been synchronized from the master node yet. Enrollment requests will be rejected until it is available.", AUTHD_PASS);
            }
        } else {
            bool pass_generated = false;

            authpass = w_authd_load_password(AUTHD_PASS, &pass_generated);

            if (pass_generated) {
                minfo("A new enrollment password was generated and written to '%s'", AUTHD_PASS);
            } else {
                minfo("Using the existing enrollment password from '%s'. To rotate the password, delete the file and restart.", AUTHD_PASS);
            }
        }
    }

    if (config.flags.remote_enrollment && config.flags.legacy_enrollment) {
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
        if (ctx = os_ssl_keys(1, home_path, config.ciphers, config.manager_cert, config.manager_key, config.agent_ca), !ctx) {
            merror("SSL context setup failed (certificate '%s', key '%s'). wazuh-manager does not generate TLS "
                   "certificates: provision them with wazuh-certs-tool (Wazuh installation assistant); see 'Deploy "
                   "certificates' in the installation guide. Exiting.", config.manager_cert, config.manager_key);
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

        /* The password itself was already loaded/generated above, before this block: it serves
         * POST /enroll too, so it must not depend on this listener existing. Only the
         * listener-specific announcement belongs here. */
        if (config.flags.use_password) {
            minfo("Accepting connections on port %hu. Shared-password enrollment is required.", config.port);
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

    /* BEFORE the listeners, not just before the writer. Read what the previous run left, decide
     * what each surviving line means against the client.keys just loaded, and record the deletions
     * that were interrupted before their task row existed.
     *
     * The ordering is the point. Every request that can reassign an agent id consults
     * purge_is_pending(), which answers from the journal held in memory -- so a request served
     * while the journal is still unread is answered against an empty one. The id of an agent
     * deleted before the last crash would be judged free, handed to a new agent, and then
     * reconciliation would find that id present in client.keys and drop the line as "never
     * deleted": the original agent's documents are never purged, which is the exact window this
     * design exists to close, reopened at startup.
     *
     * Nothing contends for the journal here, which is also what lets these two run without the
     * mutex doing any real work. */
    if (!config.worker_node) {
        purge_file_load();
        purge_startup_recover();

        /* The other journal, and for the same reason it runs here (issue #39078, H03): what it
         * decides is read against the client.keys just loaded, and it must be decided before any
         * request can rotate an agent it still owes. wazuh-db is deliberately not consulted --
         * its socket does not exist yet, as purge_startup_recover() explains -- so this only
         * discards what is no longer owed; the writer applies the rest on its own clock. */
        identity_journal_load();
        identity_journal_reconcile();
    }

    /* Start working threads */

    if (status = pthread_create(&thread_local_server, NULL, (void *)&run_local_server, NULL), status != 0) {
        merror("Couldn't create thread: %s", strerror(status));
        return EXIT_FAILURE;
    }

    if (config.flags.remote_enrollment && config.flags.legacy_enrollment) {

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

    if (config.worker_node && config.flags.use_password) {
        if (status = pthread_create(&thread_authpass_watcher, NULL, run_authpass_watcher, NULL), status != 0) {
            merror("Couldn't create authpass watcher thread: %s", strerror(status));
        } else {
            authpass_watcher_started = true;
        }
    }

    /* Join threads */
    pthread_join(thread_local_server, NULL);
    if (config.flags.remote_enrollment && config.flags.legacy_enrollment) {
        pthread_join(thread_remote_server, NULL);
    }
    if (!config.worker_node) {
        /* Send signal to writer thread */
        w_mutex_lock(&mutex_keys);
        w_cond_signal(&cond_pending);
        w_mutex_unlock(&mutex_keys);
        pthread_join(thread_writer, NULL);

        /* After the writer, its only producer, so a line it journaled on its way out is counted. */
        purge_journal_discard();
    }

    /* Join the watcher so it cannot touch authpass/mutex_authpass during shutdown. */
    if (authpass_watcher_started) {
        pthread_join(thread_authpass_watcher, NULL);
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
        os_free(g_client_pool[index]->read_buffer);
        os_free(g_client_pool[index]->write_buffer);
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
    client->enrollment_ok = FALSE;
    char* key_hash = NULL;
    char* new_key = NULL;

    mdebug2("Request received: <%s>", client->read_buffer);

    /* authpass is only mutable on the worker: the watcher thread reloads it and so does the
     * block below. The master sets it once at startup, so it needs no serialisation there and
     * enrollment parsing stays concurrent. Only enter the critical section on the worker. */
    const bool serialize_authpass = config.flags.use_password && config.worker_node;

    if (serialize_authpass) {
        w_mutex_lock(&mutex_authpass);
    }

    /* Worker: re-read on mtime change so a synced/rotated password is picked up without
     * restart. A failed read keeps the current password. */
    if (config.flags.use_password && config.worker_node) {
        time_t mtime = File_DateofChange(AUTHD_PASS);

        if (mtime >= 0 && (authpass == NULL || mtime != authpass_mtime)) {
            char *fresh = w_authd_read_password(AUTHD_PASS);

            if (fresh) {
                os_free(authpass);
                authpass = fresh;
                authpass_unavailable_reported = false;
                minfo("Enrollment password reloaded from '%s'.", AUTHD_PASS);
            }
            /* Record the mtime regardless of success: avoids re-logging a corrupt file
             * on every request until the file is replaced with a valid one. */
            authpass_mtime = mtime;
        }
    }

    /* Fail closed: required password missing (worker not synced yet) -> reject, never
     * validate against NULL (which skips the check). */
    if (config.flags.use_password && authpass == NULL) {
        const bool should_log = !authpass_unavailable_reported;
        authpass_unavailable_reported = true;

        if (serialize_authpass) {
            w_mutex_unlock(&mutex_authpass);
        }
        if (should_log) {
            mwarn("Enrollment password required but not available yet. Rejecting request from %s. "
                  "This is expected while a worker is syncing the password from the master; this "
                  "warning will not repeat until the password becomes available.",
                  client->ip);
        }
        snprintf(client->write_buffer, MAX_SSL_MSG_SIZE, "ERROR: Enrollment password not available. Unable to add agent");
        client->write_len = strlen(client->write_buffer);
        return;
    }

    int auth_parse_result = w_auth_parse_data(client->read_buffer, response, authpass, client->ip, &client->agentname, &client->centralized_group, &key_hash);
    if (serialize_authpass) {
        w_mutex_unlock(&mutex_authpass);
    }

    if (OS_SUCCESS == auth_parse_result) {
        if (config.worker_node) {
            minfo("Dispatching request to master node");
            // The force registration settings are ignored for workers. The master decides.
            if (0 == w_request_agent_add_clustered(response, client->agentname, client->ip, client->centralized_group, key_hash, &client->new_id, &new_key, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                client->enrollment_ok = TRUE;
            }
        }
        else {
            w_mutex_lock(&mutex_keys);
            if (OS_SUCCESS == w_auth_validate_data(response, client->ip, client->agentname, client->centralized_group, key_hash)) {
                if (OS_SUCCESS == w_auth_add_agent(response, client->ip, client->agentname, &client->new_id, &new_key)) {
                    client->enrollment_ok = TRUE;
                }
            }
            w_mutex_unlock(&mutex_keys);
        }
    }

    if (client->enrollment_ok)
    {
        snprintf(client->write_buffer, MAX_SSL_MSG_SIZE, "OSSEC K:'%s %s %s %s'", client->new_id, client->agentname, client->ip, new_key);
        client->write_len = strlen(client->write_buffer);

        mdebug1("Agent key generated for '%s' (requested by %s)", client->agentname, client->ip);
    } else {
        snprintf(client->write_buffer, MAX_SSL_MSG_SIZE, "%s. %s", response, "Unable to add agent");
        client->write_len = strlen(client->write_buffer);
    }

    os_free(key_hash);
    os_free(new_key);
}

static int handle_ssl_read(struct client *client) {
    while (true) {
        int ret = SSL_read(client->ssl,
                           client->read_buffer + client->read_offset,
                           MAX_SSL_MSG_SIZE - client->read_offset);

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

        if (ret < (MAX_SSL_MSG_SIZE - client->read_offset) && ret < MAX_SSL_PACKET_SIZE) {
            merror("Newline terminator not found in message request for %s", client->ip);
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
            mdebug2("SSL handshake failed for socket=%d: %s", client->socket, ERR_error_string(ERR_get_error(), NULL));
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
    if (g_client_pool[index_client]->enrollment_ok)
    {
        if (config.worker_node) {
            if (ret < 0) {
                merror("SSL write error (%d)", ret);
                ERR_print_errors_fp(stderr);
                if (0 != w_request_agent_remove_clustered(NULL, g_client_pool[index_client]->new_id, TRUE)) {
                    merror("Agent key unable to be shared with %s and unable to delete from master node", g_client_pool[index_client]->agentname);
                } else {
                    merror("Agent key not saved for %s", g_client_pool[index_client]->agentname);
                }
            }
        } else {
            if (ret < 0) {
                merror("SSL write error (%d)", ret);
                merror("Agent key not saved for %s", g_client_pool[index_client]->agentname);
                ERR_print_errors_fp(stderr);
                w_mutex_lock(&mutex_keys);
                if (g_client_pool[index_client]->new_id) {
                    OS_DeleteKey(&keys, g_client_pool[index_client]->new_id, 1);
                }
                w_mutex_unlock(&mutex_keys);
            } else {
                /* Add pending key to write */
                w_mutex_lock(&mutex_keys);
                int key_index = OS_IsAllowedID(&keys, g_client_pool[index_client]->new_id);
                if (key_index >= 0) {
                    /* No re-enrollment secret on 1515 (#38993): its OSSEC K: line has no field for it and
                     * a 4.x agent never re-enrolls over HTTPS, so none is generated or stored. */
                    add_insert(keys.keyentries[key_index], g_client_pool[index_client]->centralized_group, NULL, 0);
                    write_pending = 1;
                    w_cond_signal(&cond_pending);
                }
                w_mutex_unlock(&mutex_keys);
            }
        }
    }

    delete_client(index_client);
}

/* Thread for remote server */
void* run_remote_server(__attribute__((unused)) void *arg) {
    int client_sock = 0;
    struct sockaddr_storage _nc;
    socklen_t _ncl;

    authd_sigblock();

    if (config.timeout_sec || config.timeout_usec) {
        mdebug1("Setting network timeout to %.6f sec.", config.timeout_sec + config.timeout_usec / 1000000.);
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
                if ((client_sock = accept(remote_sock, (struct sockaddr *) &_nc, &_ncl)) >= 0) {
                    struct client *new_client;
                    os_malloc(sizeof(struct client), new_client);
                    new_client->socket = client_sock;

                    os_calloc(MAX_SSL_MSG_SIZE + 1, sizeof(char), new_client->read_buffer);
                    new_client->read_offset = 0;
                    new_client->handshake_done = false;

                    memset(new_client->ip, '\0', IPSIZE + 1);

                    os_calloc(MAX_SSL_MSG_SIZE + 1, sizeof(char), new_client->write_buffer);
                    new_client->write_offset = 0;
                    new_client->write_len = 0;

                    new_client->centralized_group = NULL;
                    new_client->agentname = NULL;
                    new_client->new_id = NULL;
                    new_client->enrollment_ok = FALSE;

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
                        os_free(new_client->write_buffer);
                        os_free(new_client->read_buffer);
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
                        os_free(new_client->write_buffer);
                        os_free(new_client->read_buffer);
                        os_free(new_client);
                        close(client_sock);
                        continue;
                    }

                    mdebug2("New connection from %s", new_client->ip);

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

/**
 * @brief Phases 3 and 4: record each journaled deletion as a manager task, then forget it.
 *
 * One row per id, over a socket the caller already holds, and the create commits inside its own
 * wazuh-db command -- so its `ok` is the durability acknowledgement, not a buffered write. That is
 * precisely what lets phase 4 drop the journal line: dropping it on a merely-buffered ok would
 * leave a window in which wazuh-db's death loses the row AND the record that it was owed.
 *
 * `collided` is SUCCESS here. A deletion has two legitimate creators -- this function on the
 * writer's cycle, and the same function during startup recovery -- and the task id is derived from
 * the agent and its journal sequence precisely so the second one is a no-op rather than a duplicate.
 *
 * `queue_full` is NOT success and does not drop the line: the row was not created, so the deletion
 * is still owed. The next writer cycle retries it, and the backlog it is waiting on is the same one
 * phase 0 refuses new deletions against. The rest of the batch is abandoned for this pass, because
 * a full queue does not empty between two rows.
 *
 * Both non-success cases leave their line in place and abandon the rest of the pass, which is only
 * safe because the callers hand over EVERY outstanding line rather than one cycle's additions:
 * purge_journal_snapshot() on the writer, purge_journal_reconcile() at startup. Called with just
 * the ids a single cycle journaled, an untouched line would wait for the next process start while
 * its agent was already gone from client.keys.
 *
 * @param entries Every deletion still owed, oldest first.
 * @param count How many.
 * @param wdb_sock Reusable wazuh-db socket.
 * @return How many rows are now recorded.
 */
static size_t purge_create_rows(const purge_journal_entry_t *entries, size_t count, int *wdb_sock) {
    purge_journal_entry_t *durable = NULL;
    size_t recorded = 0;
    size_t i;

    if (!entries || count == 0) {
        return 0;
    }

    /* The entries whose rows are durable, collected rather than dropped one by one: every drop
     * rewrites the whole journal file, so a per-entry drop makes a bulk deletion quadratic in file
     * writes -- 20 000 rewrites of a 20 000-line file. */
    os_calloc(count, sizeof(purge_journal_entry_t), durable);

    for (i = 0; i < count; i++) {
        manager_task_request_t request = {0};
        char payload[OS_SIZE_128];
        char *task_id = NULL;
        int result;

        if (task_id = manager_task_id_agent_delete(entries[i].id, entries[i].journal_seq), !task_id) {
            merror("Could not derive the deletion task id of agent '%s'.", entries[i].id);
            continue;
        }

        /* The consumer's request body, verbatim: POST /_internal/agents/delete reads the agent id
         * from here because the dispatcher forwards a row's payload and adds no headers. */
        snprintf(payload, sizeof(payload), "{\"agent_id\":\"%s\"}", entries[i].id);

        request.task_id = task_id;
        request.task_type = MANAGER_TASK_TYPE_AGENT_DELETE;
        request.agent_id = entries[i].id;
        request.payload = payload;
        request.create_time = (long long)entries[i].requested_at;
        /* authd.purge_delay, expressed where it now belongs. Part of what it buys is the indexer
         * having refreshed and the cluster workers having reloaded client.keys, neither of which
         * this daemon can observe -- so it stays a delay rather than becoming a condition. */
        request.next_attempt_at = (long long)entries[i].requested_at + config.purge_delay;
        /* Never coalesced: two deletions of one agent are two obligations. */
        request.coalesce = false;
        request.max_pending = config.max_pending_deletes;

        result = manager_task_create(&request, config.wdb_timeout, NULL);

        os_free(task_id);

        switch (result) {
        case MANAGER_TASK_CREATED:
            durable[recorded++] = entries[i];
            break;

        case MANAGER_TASK_COLLIDED:
            mdebug1("The deletion of agent '%s' was already recorded.", entries[i].id);
            durable[recorded++] = entries[i];
            break;

        case MANAGER_TASK_QUEUE_FULL:
            mwarn("The deletion of agent '%s' could not be recorded: %d deletions are already "
                  "waiting to be applied to the indexer. It stays journaled and will be retried.",
                  entries[i].id, config.max_pending_deletes);
            goto finish;

        default:
            mwarn("The deletion of agent '%s' could not be recorded; it stays journaled and will be "
                  "retried.", entries[i].id);
            goto finish;
        }
    }

finish:
    /* PHASE 4, once per pass. Only the entries above are dropped, so one that failed cannot take a
     * durable one down with it -- which is the property the per-entry drop was there for.
     *
     * Batching the PERSIST costs nothing in correctness: a crash between a row becoming durable and
     * this write leaves the line journaled, and reconciliation then derives the same task id and
     * collides, which this function already treats as recorded. */
    purge_journal_drop(durable, recorded);
    os_free(durable);

    return recorded;
}

/**
 * @brief Startup recovery: finish the deletions a previous run left mid-sequence.
 *
 * Called from main() after OS_ReadKeys() and purge_file_load(), before any thread starts.
 *
 * Nothing here is fatal, and nothing here is required for correctness: an owed row that is not
 * created now is created by the writer's next cycle, and phase 0's row bound simply keeps the value
 * it had until the writer measures it.
 */
static void purge_startup_recover(void) {
    purge_journal_entry_t *owed = NULL;
    size_t count = 0;
    int wdb_sock = -1;

    /* wazuh-db is started AFTER this daemon (wazuh-server.sh starts the reversed daemon list, and
     * authd comes before wazuh-manager-db in it), so on a normal start its socket does not exist
     * yet and neither call below can succeed. Both are self-healing -- owed rows are retried by the
     * writer's next cycle, and the row count is re-measured on every one of them -- so attempting
     * them here would buy nothing and cost a failed connect plus an ERROR line from the wazuh-db
     * client on every single manager start.
     *
     * Existence only, and access() rather than w_is_file(): the latter opens the path, which fails
     * on a socket whether or not anything is listening. A socket that exists but has no listener
     * yet still fails below, and is handled the same way. */
    const bool wdb_listening = access(WDB_LOCAL_SOCK, F_OK) == 0;

    // Local work regardless: this reads the journal against client.keys. Only the row creation and
    // the count below need the database.
    owed = purge_journal_reconcile(&count);

    if (owed) {
        size_t recorded = wdb_listening ? purge_create_rows(owed, count, &wdb_sock) : 0;

        if (recorded < count) {
            mwarn("%zu recovered agent deletion(s) could not be recorded yet; they stay journaled "
                  "and are retried on the next write cycle.", count - recorded);
        }

        os_free(owed);
    }

    /* Prime phase 0's row bound, which is otherwise zero until the writer's first cycle -- and the
     * writer waits on cond_pending, so on an idle manager that cycle can be a long way off. This is
     * the restart-with-a-deep-backlog case: authd alone restarting while wazuh-db is up and holding
     * thousands of pending deletions, where a bound reading zero would admit deletions the queue has
     * no room for. A failure is passed through as -1, which keeps the previous value rather than
     * reporting an outage as an empty queue. */
    if (wdb_listening) {
        purge_pending_rows_update(
            manager_task_count(MANAGER_TASK_TYPE_AGENT_DELETE, MANAGER_TASK_STATUS_PENDING, config.wdb_timeout));
    }

    wdbc_close(&wdb_sock);
}

/* --- Applying what the identity journal still owes ---------------------------------------------
 *
 * The journal (issue #39078, H03) holds every credential this manager handed out and the database
 * has not stored yet. Three things happen here and nowhere else: the leftovers of earlier cycles
 * are retried, ONE `global commit` per cycle turns wazuh-db's `ok` into durability, and only then
 * are the entries forgotten -- and a rotation's reservation released.
 */

/// How many owed transitions one cycle retries. A bound, not a budget: the rest wait for the next
/// wake-up, which is at most IDENTITY_RETRY_MAX_SECONDS away.
#define IDENTITY_RETRY_BATCH 256
#define IDENTITY_RETRY_MIN_SECONDS 1
#define IDENTITY_RETRY_MAX_SECONDS 60

/// Seconds until the writer wakes itself while anything is owed. Doubles while the database stays
/// out of reach, and drops back to the minimum on the first commit. Writer thread only.
static unsigned int identity_retry_delay = IDENTITY_RETRY_MIN_SECONDS;

/// A transition whose database write went through and is waiting for the commit that makes it real.
typedef struct identity_applied_t {
    long long seq;
    char *id;
    bool rotate;
} identity_applied_t;

static void identity_applied_add(identity_applied_t **applied, size_t *count, long long seq, const char *id, bool rotate) {
    if (seq <= 0) {
        return; // not journaled: the legacy 1515 path, which hands out no secret
    }

    os_realloc(*applied, (*count + 1) * sizeof(identity_applied_t), *applied);
    (*applied)[*count].seq = seq;
    (*applied)[*count].rotate = rotate;
    os_strdup(id, (*applied)[*count].id);
    (*count)++;
}

static void identity_applied_free(identity_applied_t *applied, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        os_free(applied[i].id);
    }

    os_free(applied);
}

/**
 * @brief Put one owed transition in the database.
 *
 * The row is read first, and that read is the whole reason this is not simply an insert:
 *
 *   - it may already carry this very credential (this cycle applied it, or a previous run did
 *     before it could drop the entry) -- nothing to write, and the entry may go;
 *   - it may exist with another one, including the NULL secret sync_keys_with_wdb() writes when it
 *     mirrors client.keys into a database that lost the row -- an UPDATE, not an insert;
 *   - it may not exist at all -- an insert.
 *
 * @return true when the database now holds this credential (write done, or already there).
 */
static bool identity_apply(const identity_journal_entry_t *entry, int *wdb_sock) {
    cJSON *info = wdb_get_agent_info(atoi(entry->id), wdb_sock);
    cJSON *j_secret = info ? cJSON_GetObjectItem(info->child, "reenroll_secret") : NULL;
    bool present = info != NULL && info->child != NULL;
    bool applied;

    if (present && cJSON_IsString(j_secret) && !strcmp(j_secret->valuestring, entry->secret)) {
        OPENSSL_cleanse(j_secret->valuestring, strlen(j_secret->valuestring));
        cJSON_Delete(info);
        return true;
    }

    if (j_secret && cJSON_IsString(j_secret)) {
        OPENSSL_cleanse(j_secret->valuestring, strlen(j_secret->valuestring));
    }
    cJSON_Delete(info);

    if (present) {
        applied = wdb_set_agent_credentials(atoi(entry->id), entry->name, entry->ip, entry->key,
                                            entry->secret, wdb_sock) == OS_SUCCESS;
    } else {
        applied = wdb_insert_agent(atoi(entry->id), entry->name, NULL, entry->ip, entry->key,
                                   entry->secret, NULL, 1, wdb_sock) == OS_SUCCESS;
    }

    if (applied) {
        minfo("Recorded credentials of agent '%s' written to the database%s.", entry->id,
              entry->rotate ? " (rotation recovered)" : " (enrollment recovered)");
    }

    return applied;
}

static bool identity_applied_has(const identity_applied_t *applied, size_t count, long long seq) {
    size_t i;

    for (i = 0; i < count; i++) {
        if (applied[i].seq == seq) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Whether the keystore still says this transition is the live one.
 *
 * The same rule identity_journal_reconcile() applies at start-up, applied here because the world
 * moves while a transition is owed: an agent enrolled during a wazuh-db outage can be DELETED
 * before the database comes back, and writing its row then would resurrect an agent the operator
 * removed. The key in client.keys is the generation marker; the id alone says nothing, since both
 * generations of a rotation share it.
 */
static bool identity_still_owed(const identity_journal_entry_t *entry) {
    bool owed;
    int index;

    w_mutex_lock(&mutex_keys);
    index = OS_IsAllowedID(&keys, entry->id);
    owed = index >= 0 && keys.keyentries[index]->raw_key != NULL &&
           strcmp(keys.keyentries[index]->raw_key, entry->key) == 0;
    w_mutex_unlock(&mutex_keys);

    return owed;
}

/// Retry what earlier cycles could not write, adding whatever went through to @p applied.
static void identity_apply_pending(identity_applied_t **applied, size_t *count, int *wdb_sock) {
    size_t pending = 0;
    size_t i;
    identity_journal_entry_t *entries = identity_journal_snapshot(IDENTITY_RETRY_BATCH, &pending);

    for (i = 0; i < pending; i++) {
        // Written by this cycle's own loop above: it is in the journal until the commit, but it
        // does not need a second round trip to find out the database already has it.
        if (identity_applied_has(*applied, *count, entries[i].seq)) {
            continue;
        }

        if (!identity_still_owed(&entries[i])) {
            mdebug1("Dropping the recorded transition of agent '%s': client.keys no longer names "
                    "that credential.", entries[i].id);
            identity_journal_drop(&entries[i].seq, 1);

            if (entries[i].rotate) {
                // Nothing is owed, so nothing is holding the agent back either.
                w_reenroll_abandon(entries[i].id);
            }
            continue;
        }

        if (identity_apply(&entries[i], wdb_sock)) {
            identity_applied_add(applied, count, entries[i].seq, entries[i].id, entries[i].rotate);
        }
    }

    identity_journal_free(entries, pending);
}

/**
 * @brief Commit, then forget: the only place an entry leaves the journal.
 *
 * wazuh-db answers `ok` from inside a deferred transaction it commits on its own clock
 * (wdb_commit_old()), so dropping an entry on that `ok` would lose exactly the crash this journal
 * exists for. A failed commit keeps everything -- entries, and the reservations of the rotations
 * among them -- and lengthens the wait before the next attempt.
 */
static void identity_commit_and_forget(identity_applied_t *applied, size_t count, int *wdb_sock) {
    long long *seqs = NULL;
    size_t i;

    if (count > 0) {
        if (wdb_commit_global(wdb_sock) != OS_SUCCESS) {
            merror("Could not commit the credentials of %zu agent(s) to the database. They stay "
                   "recorded and are retried; the agents keep the credentials they were given.", count);
        } else {
            os_calloc(count, sizeof(long long), seqs);

            for (i = 0; i < count; i++) {
                seqs[i] = applied[i].seq;
            }

            identity_journal_drop(seqs, count);
            os_free(seqs);

            /* Here, and only here (issue #39078, H02 + H03): while the transition was owed the row
             * still named the previous secret, so releasing the reservation earlier would let that
             * secret authorise another rotation. */
            for (i = 0; i < count; i++) {
                if (applied[i].rotate) {
                    w_reenroll_complete(applied[i].id);
                }
            }

            identity_retry_delay = IDENTITY_RETRY_MIN_SECONDS;
        }
    }

    if (identity_journal_pending() > 0) {
        identity_retry_delay = identity_retry_delay >= IDENTITY_RETRY_MAX_SECONDS
                                   ? IDENTITY_RETRY_MAX_SECONDS
                                   : identity_retry_delay * 2;
    } else {
        identity_retry_delay = IDENTITY_RETRY_MIN_SECONDS;
    }
}

/* Thread for writing keystore onto disk */
void* run_writer(__attribute__((unused)) void *arg) {
    keystore *copy_keys;
    struct keynode *copy_insert;
    struct keynode *copy_remove;
    struct keynode *cur;
    struct keynode *next;
    int wdb_sock = -1;

    authd_sigblock();

    mdebug1("Writer thread ready.");

    struct timespec global_t0, global_t1;
    struct timespec t0, t1;

    while (running) {
        int inserted_agents = 0;
        int removed_agents = 0;
        char **removed_ids = NULL;
        size_t removed_count = 0;
        purge_journal_entry_t *journaled = NULL;
        identity_applied_t *applied = NULL;
        size_t applied_count = 0;
        bool keys_written = false;
        bool retry_only = false;

        w_mutex_lock(&mutex_keys);

        while (!write_pending && running) {
            /* An owed identity transition cannot wait for the next enrollment to come along
             * (issue #39078, H03): this thread sleeps until something signals it, so on an idle
             * manager a credential the database never got would stay owed until the next agent
             * enrolled -- or forever. While anything is owed the wait has a deadline, doubling up
             * to a minute for as long as the database stays out of reach. */
            if (identity_journal_pending() > 0) {
                struct timeval now;
                struct timespec deadline;

                gettimeofday(&now, NULL);
                deadline.tv_sec = now.tv_sec + identity_retry_delay;
                deadline.tv_nsec = now.tv_usec * 1000;

                if (pthread_cond_timedwait(&cond_pending, &mutex_keys, &deadline) == ETIMEDOUT && !write_pending) {
                    retry_only = true;
                    break;
                }
            } else {
                w_cond_wait(&cond_pending, &mutex_keys);
            }
        }

        /* Woken by the clock and not by a change: there is nothing to dump. client.keys is NOT
         * rewritten on these cycles -- retrying a database write must not cost a full keystore
         * rewrite every minute. */
        if (retry_only) {
            w_mutex_unlock(&mutex_keys);

            identity_apply_pending(&applied, &applied_count, &wdb_sock);
            identity_commit_and_forget(applied, applied_count, &wdb_sock);
            identity_applied_free(applied, applied_count);
            continue;
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

        /* PHASE 1: the intent, before client.keys is rewritten.
         *
         * Local only -- a temp file and a rename. Creating the task rows here instead would put a
         * wazuh-db round trip in front of every client.keys write, so a database outage would block
         * enrollment: the wedge this whole design exists to remove. The rows come later, in phase 3,
         * where a failure costs a retry rather than an outage. */
        for (cur = copy_remove; cur; cur = cur->next) {
            os_realloc(removed_ids, (removed_count + 1) * sizeof(char *), removed_ids);
            removed_ids[removed_count++] = cur->id;
        }

        journaled = purge_journal_append(removed_ids, removed_count);
        os_free(removed_ids);

        gettime(&t0);

        /* PHASE 2: the point of no return, and its RESULT IS CAPTURED.
         *
         * A failure here is logged and falls through to the removal loop below -- it always has --
         * so without an explicit gate phase 3 would create purge rows for agents that are still on
         * disk. The in-memory keystore cannot serve as that gate: OS_DeleteKey() already ran, so it
         * says "deleted" while the file still says "alive". */
        keys_written = (OS_WriteKeys(copy_keys) >= 0);

        if (!keys_written) {
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

        /* Persist the high-water mark of handed-out ids from the same snapshot that was just
         * written, so the file can never claim an id client.keys does not account for. */
        purge_last_id_update(copy_keys->id_counter);

        OS_FreeKeys(copy_keys);
        os_free(copy_keys);

        for (cur = copy_insert; cur; cur = next) {
            next = cur->next;

            if (cur->rotate) {
                /* A re-enrollment (#38993): the agent already has its row, so its credentials are replaced on
                 * it -- id, date_add and the rest untouched -- rather than inserted (which the duplicate id
                 * would refuse). Its groups are only overridden when the request named some (below). */
                mdebug1("[Writer] Performing credential rotation([%s] %s).", cur->id, cur->name);

                gettime(&t0);
                if (wdb_set_agent_credentials(atoi(cur->id), cur->name, cur->ip, cur->raw_key, cur->reenroll_secret, &wdb_sock)) {
                    /* The reservation taken when the rotation was accepted STAYS: the row still holds the
                     * previous secret, so releasing here would let that secret authorise another rotation
                     * (issue #39078, H02). The agent cannot rotate again on this manager until the
                     * transition is resolved -- and it will be: the entry is still journaled, and this
                     * thread retries it on its own clock (H03). */
                    merror("Unable to store the rotated credentials of agent %s '%s' in the database. The agent "
                           "keeps the credentials it was given; the change stays recorded and is retried.",
                           cur->id, cur->name);
                } else {
                    /* Not w_reenroll_complete() yet: the write is not durable until the commit below. */
                    identity_applied_add(&applied, &applied_count, cur->journal_seq, cur->id, true);
                }
                gettime(&t1);
                mdebug2("[Writer] wdb_set_agent_credentials(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));
            } else {
                mdebug1("[Writer] Performing insert([%s] %s).", cur->id, cur->name);

                gettime(&t0);
                if (wdb_insert_agent(atoi(cur->id), cur->name, NULL, cur->ip, cur->raw_key, cur->reenroll_secret, cur->group, 1, &wdb_sock)) {
                    /* Either the row is already there or the database is unreachable, and the answer
                     * does not say which. The entry stays journaled and the retry below reads the row
                     * to tell the two apart (issue #39078, H03). */
                    mdebug2("The agent %s '%s' was not inserted; its credentials stay recorded.", cur->id, cur->name);
                } else {
                    identity_applied_add(&applied, &applied_count, cur->journal_seq, cur->id, false);
                }
                gettime(&t1);
                mdebug2("[Writer] wdb_insert_agent(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));
            }

            if (!cur->rotate || cur->group) {
                gettime(&t0);
                char *groups_to_set = cur->group ? cur->group : "default";
                if (wdb_set_agent_groups_csv(atoi(cur->id),
                                             groups_to_set,
                                             WDB_GROUP_MODE_OVERRIDE,
                                             w_is_single_node(NULL) ? "synced" : "syncreq",
                                             &wdb_sock)) {
                    merror("Unable to set agent centralized group: %s (internal error)", groups_to_set);
                }

                gettime(&t1);
                mdebug2("[Writer] wdb_set_agent_groups_csv(): %d µs.", (int)(1000000. * (double)time_diff(&t0, &t1)));
            }

            os_free(cur->id);
            os_free(cur->name);
            os_free(cur->ip);
            os_free(cur->group);
            os_free(cur->raw_key);
            if (cur->reenroll_secret) {
                OPENSSL_cleanse(cur->reenroll_secret, strlen(cur->reenroll_secret));
            }
            os_free(cur->reenroll_secret);
            os_free(cur);

            inserted_agents++;
        }

        for (cur = copy_remove; cur; cur = next) {
            next = cur->next;

            mdebug1("[Writer] Performing delete([%s] %s).", cur->id, cur->name);

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

            os_free(cur->id);
            os_free(cur->name);
            os_free(cur->ip);
            os_free(cur->group);
            os_free(cur->raw_key);
            os_free(cur->reenroll_secret); // always NULL for removals (add_remove() sets none)
            os_free(cur);

            removed_agents++;
        }

        /* Whatever earlier cycles could not write, and then the one commit that makes everything
         * above durable -- this cycle's credentials included. Only after it are the entries
         * forgotten and the rotations' reservations released (issue #39078, H03). */
        identity_apply_pending(&applied, &applied_count, &wdb_sock);
        identity_commit_and_forget(applied, applied_count, &wdb_sock);
        identity_applied_free(applied, applied_count);

        /* PHASES 3 and 4, gated on phase 2. Skipping them costs nothing: the journal lines stay and
         * the next cycle retries them, because phase 3 below works from the whole outstanding set
         * rather than from this cycle's ids. */
        if (journaled) {
            os_free(journaled);

            if (!keys_written) {
                mwarn("client.keys could not be written, so %zu deletion(s) were not recorded; they "
                      "stay journaled until a write succeeds.", removed_count);
            }
        }

        /* Everything the journal still owes, not just what this cycle added. A create that failed
         * -- wazuh-db restarting, a socket timeout, a full admission bound -- left its line in
         * place, and this is what picks it up on the next cycle. Working from `journaled` instead
         * stranded those ids until the process restarted, with their agents already gone from
         * client.keys and their documents orphaned in the meantime.
         *
         * Gated on keys_written, which is the whole safety argument: the write is attempted on
         * every cycle, so a successful one means the keys ON DISK already reflect every deletion
         * applied to the in-memory keystore -- this cycle's and every earlier one's -- and any line
         * still journaled therefore belongs to an agent that is really gone. A failed write means
         * the opposite for at least some of them, so nothing is recorded until one succeeds. */
        if (keys_written) {
            size_t owed_count = 0;
            purge_journal_entry_t *owed = purge_journal_snapshot(&owed_count);

            if (owed) {
                purge_create_rows(owed, owed_count, &wdb_sock);
                os_free(owed);
            }
        }

        /* Phase 0's second term, refreshed once per cycle rather than once per agent. A failed
         * measurement is passed through as -1 and keeps the previous value: reporting it as zero
         * would lift the bound for exactly as long as wazuh-db is unreachable.
         *
         * It goes stale on an idle manager, which is harmless in both directions -- stale-high
         * over-refuses, stale-low lets wazuh-db refuse at creation instead, which re-queues -- and
         * the count only matters while deletions are flowing, which is when this thread cycles. */
        // Not on the way out. It feeds phase 0, which refuses new deletions, and no deletion will
        // be admitted after this point -- while wazuh-db is being stopped alongside this daemon, so
        // the query would usually just fail and put an ERROR from the wazuh-db client in the log of
        // every clean stop.
        if (running) {
            purge_pending_rows_update(
                manager_task_count(MANAGER_TASK_TYPE_AGENT_DELETE, MANAGER_TASK_STATUS_PENDING, config.wdb_timeout));
        }

        gettime(&global_t1);
        mdebug2("[Writer] Inserted agents: %d", inserted_agents);
        mdebug2("[Writer] Removed agents: %d", removed_agents);
        mdebug2("[Writer] Loop: %d ms.", (int)(1000. * (double)time_diff(&global_t0, &global_t1)));
    }

    wdbc_close(&wdb_sock);

    return NULL;
}

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
    etoken_store_free();
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
