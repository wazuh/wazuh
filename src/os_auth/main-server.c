/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
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

#ifndef LIBOPENSSL_ENABLED

#include <stdlib.h>
#include <stdio.h>
int main()
{
    printf("ERROR: Not compiled. Missing OpenSSL support.\n");
    exit(0);
}

#else

#include <pthread.h>
#include <sys/wait.h>
#include "auth.h"
#include "check_cert.h"
#include "os_crypto/md5/md5_op.h"

/* Prototypes */
static void help_authd(void) __attribute((noreturn));
static int ssl_error(const SSL *ssl, int ret);

/* Thread for dispatching connection pool */
static void* run_dispatcher(void *arg);

/* Thread for writing keystore onto disk */
static void* run_writer(void *arg);

/* Append key to insertion queue */
static void add_insert(const keyentry *entry);

/* Append key to deletion queue */
static void add_backup(const keyentry *entry);

/* Signal handler */
static void handler(int signum);

/* Exit handler */
static void cleanup();

/* Shared variables */
char *authpass = NULL;
const char *ca_cert = NULL;
int validate_host = 0;
int use_ip_address = 0;
SSL_CTX *ctx;
int force_antiquity = -1;
int m_queue = 0;
int sock = 0;
int save_removed = 1;

keystore keys;
struct client pool[AUTH_POOL];
volatile int pool_i = 0;
volatile int pool_j = 0;
volatile int write_pending = 0;
volatile int running = 1;
struct keynode *queue_insert = NULL;
struct keynode *queue_backup = NULL;
struct keynode * volatile *insert_tail;
struct keynode * volatile *backup_tail;

pthread_mutex_t mutex_pool = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_keys = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_new_client = PTHREAD_COND_INITIALIZER;
pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;

/* Print help statement */
static void help_authd()
{
    print_header();
    print_out("  %s: -[Vhdti] [-f sec] [-g group] [-D dir] [-p port] [-P] [-v path [-s]] [-x path] [-k path]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -i          Use client's source IP address");
    print_out("    -f <sec>    Remove old agents with same IP if disconnected since <sec> seconds");
    print_out("    -r          Do not keep removed agents (delete).");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -p <port>   Manager port (default: %d)", DEFAULT_PORT);
    print_out("    -P          Enable shared password authentication (at %s or random).", AUTHDPASS_PATH);
    print_out("    -v <path>   Full path to CA certificate used to verify clients");
    print_out("    -s          Used with -v, enable source host verification");
    print_out("    -x <path>   Full path to server certificate (default: %s%s)", DEFAULTDIR, CERTFILE);
    print_out("    -k <path>   Full path to server key (default: %s%s)", DEFAULTDIR, KEYFILE);
    print_out("    -a          Auto select SSL/TLS method. Default: TLS v1.2 only.");
    print_out(" ");
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
    char *muname = NULL;

    #ifndef WIN32
        #ifdef __OpenBSD__
        srandomdev();
        #else
        srandom(time(0) + getpid() + getppid());
        #endif
    #else
        srandom(time(0) + getpid());
    #endif

    rand1 = os_random();
    rand2 = os_random();

    rand3 = GetRandomNoise();
    rand4 = GetRandomNoise();

    OS_MD5_Str(rand3, md3);
    OS_MD5_Str(rand4, md4);

    muname = getuname();

    snprintf(str1, STR_SIZE, "%d%d%s%d%s%s",(int)time(0), rand1, muname, rand2, md3, md4);
    OS_MD5_Str(str1, md1);
    fstring = strdup(md1);
    free(rand3);
    free(rand4);
    free(muname);
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
                merror("%s: ERROR: SSL Error (%d)", ARGV0, ret);
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
    int c = 0, test_config = 0, status;
    int use_pass = 0;
    int auto_method = 0;
    gid_t gid;
    int client_sock = 0, port = DEFAULT_PORT;
    const char *dir  = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *server_cert = NULL;
    const char *server_key = NULL;
    char buf[4096 + 1];
    struct sockaddr_in _nc;
    socklen_t _ncl;
    pthread_t thread_dispatcher;
    pthread_t thread_writer;

    /* Initialize some variables */
    bio_err = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtig:D:p:v:sx:k:Pf:ar")) != -1) {
        char *end;

        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_authd();
                break;
            case 'd':
                nowDebug();
                break;
            case 'i':
                use_ip_address = 1;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'P':
                use_pass = 1;
                break;
            case 'p':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                port = atoi(optarg);
                if (port <= 0 || port >= 65536) {
                    ErrorExit("%s: Invalid port: %s", ARGV0, optarg);
                }
                break;
            case 'v':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                ca_cert = optarg;
                break;
            case 's':
                validate_host = 1;
                break;
            case 'x':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                server_cert = optarg;
                break;
            case 'k':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                server_key = optarg;
                break;
            case 'f':
                if (!optarg)
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);

                force_antiquity = strtol(optarg, &end, 10);

                if (optarg == end || force_antiquity < 0)
                    ErrorExit("%s: Invalid number for -f", ARGV0);

                break;
            case 'r':
                save_removed = 0;
                break;
            case 'a':
                auto_method = 1;
                break;
            default:
                help_authd();
                break;
        }
    }

    /* Start daemon -- NB: need to double fork and setsid */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, "", group);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot -- TODO: this isn't a chroot. Should also close
     * unneeded open file descriptors (like stdin/stdout)
     */
    if (chdir(dir) == -1) {
        ErrorExit(CHDIR_ERROR, ARGV0, dir, errno, strerror(errno));
    }

    /* Signal manipulation */

    {
        struct sigaction action = { .sa_handler = handler };
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

#ifdef LEGACY_SSL
    auto_method = 1;
    merror("WARN: TLS v1.2 method-forcing disabled. This program was compiled to use SSL/TLS auto-negotiation.");
#endif

    if (use_pass) {

        /* Checking if there is a custom password file */
        fp = fopen(AUTHDPASS_PATH, "r");
        buf[0] = '\0';
        if (fp) {
            buf[4096] = '\0';
            char *ret = fgets(buf, 4095, fp);

            if (ret && strlen(buf) > 2) {
                /* Remove newline */
                if (buf[strlen(buf) - 1] == '\n')
                    buf[strlen(buf) - 1] = '\0';

                authpass = strdup(buf);
            }

            fclose(fp);
        }

        if (buf[0] != '\0')
            verbose("Accepting connections. Using password specified on file: %s", AUTHDPASS_PATH);
        else {
            /* Getting temporary pass. */
            authpass = __generatetmppass();
            verbose("Accepting connections. Random password chosen for agent authentication: %s", authpass);
        }
    } else
        verbose("Accepting connections. No password required.");

    /* Getting SSL cert. */

    fp = fopen(KEYSFILE_PATH, "a");
    if (!fp) {
        merror("%s: ERROR: Unable to open %s (key file)", ARGV0, KEYSFILE_PATH);
        exit(1);
    }
    fclose(fp);

    /* Start SSL */
    ctx = os_ssl_keys(1, dir, server_cert, server_key, ca_cert, auto_method);
    if (!ctx) {
        merror("%s: ERROR: SSL error. Exiting.", ARGV0);
        exit(1);
    }

    /* Connect via TCP */
    sock = OS_Bindporttcp(port, NULL, 0);
    if (sock <= 0) {
        merror("%s: Unable to bind to port %d", ARGV0, port);
        exit(1);
    }

    /* Setup random */
    srandom_init();

    /* Load ossec uid and gid for creating backups */
    if (OS_LoadUid() < 0) {
        ErrorExit("%s: ERROR: Couldn't get user and group id.", ARGV0);
    }

    /* Chroot */
    if (Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));

    nowChroot();

    /* Queue for sending alerts */
    if ((m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        merror("%s: WARN: Can't connect to queue.", ARGV0);
    }

    /* Initialize queues */

    insert_tail = &queue_insert;
    backup_tail = &queue_backup;

    /* Start working threads */

    status = pthread_create(&thread_dispatcher, NULL, run_dispatcher, NULL);

    if (status != 0) {
        merror("%s: ERROR: Couldn't create thread: %s", ARGV0, strerror(status));
        return EXIT_FAILURE;
    }

    status = pthread_create(&thread_writer, NULL, run_writer, NULL);

    if (status != 0) {
        merror("%s: ERROR: Couldn't create thread: %s", ARGV0, strerror(status));
        return EXIT_FAILURE;
    }

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    atexit(cleanup);

    /* Main loop */

    while (running) {
        memset(&_nc, 0, sizeof(_nc));
        _ncl = sizeof(_nc);

        if ((client_sock = accept(sock, (struct sockaddr *) &_nc, &_ncl)) > 0) {
            pthread_mutex_lock(&mutex_pool);

            if (full(pool_i, pool_j)) {
                merror("%s: ERROR: Too many connections. Rejecting.", ARGV0);
                close(client_sock);
            } else {
                pool[pool_i].socket = client_sock;
                pool[pool_i].addr = _nc.sin_addr;
                forward(pool_i);
                pthread_cond_signal(&cond_new_client);
            }

            pthread_mutex_unlock(&mutex_pool);
        } else if ((errno == EBADF && running) || (errno != EBADF && errno != EINTR))
            merror("%s: ERROR: accept(): %s", ARGV0, strerror(errno));
    }

    /* Join threads */

    pthread_mutex_lock(&mutex_pool);
    pthread_cond_signal(&cond_new_client);
    pthread_mutex_unlock(&mutex_pool);
    pthread_mutex_lock(&mutex_keys);
    pthread_cond_signal(&cond_pending);
    pthread_mutex_unlock(&mutex_keys);

    pthread_join(thread_dispatcher, NULL);
    pthread_join(thread_writer, NULL);

    verbose("%s: Exiting...", ARGV0);
    return (0);
}

/* Thread for dispatching connection pool */
void* run_dispatcher(__attribute__((unused)) void *arg) {
    struct client client;
    char srcip[IPSIZE + 1];
    char *agentname;
    int ret;
    int parseok;
    char *tmpstr;
    double antiquity;
    int acount;
    char fname[2048 + 1];
    char response[2048 + 1];
    char *finalkey;
    SSL *ssl;
    char *id_exist = NULL;
    char buf[4096 + 1];
    int index;

    /* Initialize some variables */
    memset(srcip, '\0', IPSIZE + 1);

    OS_PassEmptyKeyfile();
    OS_ReadKeys(&keys, 0, save_removed);
    debug1("%s: DEBUG: Dispatch thread ready", ARGV0);

    while (running) {
        pthread_mutex_lock(&mutex_pool);

        while (empty(pool_i, pool_j) && running)
            pthread_cond_wait(&cond_new_client, &mutex_pool);

        client = pool[pool_j];
        forward(pool_j);
        pthread_mutex_unlock(&mutex_pool);

        if (!running)
            break;

        strncpy(srcip, inet_ntoa(client.addr), IPSIZE - 1);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client.socket);
        ret = SSL_accept(ssl);

        if (ssl_error(ssl, ret)) {
            SSL_free(ssl);
            close(client.socket);
            continue;
        }

        verbose("%s: INFO: New connection from %s", ARGV0, srcip);

        /* Additional verification of the agent's certificate. */

        if (validate_host && ca_cert) {
            if (check_x509_cert(ssl, srcip) != VERIFY_TRUE) {
                merror("%s: DEBUG: Unable to verify server certificate.", ARGV0);
                SSL_free(ssl);
                close(client.socket);
                continue;
            }
        }

        buf[0] = '\0';
        ret = SSL_read(ssl, buf, sizeof(buf));

        if (ssl_error(ssl, ret)) {
            SSL_free(ssl);
            close(client.socket);
            continue;
        }

        parseok = 0;
        tmpstr = buf;

        /* Checking for shared password authentication. */
        if(authpass) {
            /* Format is pretty simple: OSSEC PASS: PASS WHATEVERACTION */
            if (strncmp(tmpstr, "OSSEC PASS: ", 12) == 0) {
                tmpstr = tmpstr + 12;

                if (strlen(tmpstr) > strlen(authpass) && strncmp(tmpstr, authpass, strlen(authpass)) == 0) {
                    tmpstr += strlen(authpass);

                    if (*tmpstr == ' ') {
                        tmpstr++;
                        parseok = 1;
                    }
                }
            }

            if (parseok == 0) {
                merror("%s: ERROR: Invalid password provided by %s. Closing connection.", ARGV0, srcip);
                SSL_free(ssl);
                close(client.socket);
                continue;
            }
        }

        /* Checking for action A (add agent) */
        parseok = 0;
        if (strncmp(tmpstr, "OSSEC A:'", 9) == 0) {
            agentname = tmpstr + 9;
            tmpstr += 9;
            while (*tmpstr != '\0') {
                if (*tmpstr == '\'') {
                    *tmpstr = '\0';
                    verbose("%s: INFO: Received request for a new agent (%s) from: %s", ARGV0, agentname, srcip);
                    parseok = 1;
                    break;
                }
                tmpstr++;
            }
        }

        if (parseok == 0) {
            merror("%s: ERROR: Invalid request for new agent from: %s", ARGV0, srcip);
        } else {
            acount = 2;
            finalkey = NULL;
            response[2048] = '\0';
            fname[2048] = '\0';

            if (!OS_IsValidName(agentname)) {
                merror("%s: ERROR: Invalid agent name: %s from %s", ARGV0, agentname, srcip);
                snprintf(response, 2048, "ERROR: Invalid agent name: %s\n\n", agentname);
                SSL_write(ssl, response, strlen(response));
                snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                SSL_write(ssl, response, strlen(response));
                SSL_free(ssl);
                close(client.socket);
                continue;
            }

            pthread_mutex_lock(&mutex_keys);

            /* Check for duplicated IP */

            if (use_ip_address) {
                index = OS_IsAllowedIP(&keys, srcip);

                if (index >= 0) {
                    id_exist = keys.keyentries[index]->id;
                    antiquity = OS_AgentAntiquity(keys.keyentries[index]->name, keys.keyentries[index]->ip->ip);

                    if (force_antiquity >= 0 && (antiquity >= force_antiquity || antiquity < 0)) {
                        verbose("INFO: Duplicated IP '%s' (%s). Saving backup.", srcip, id_exist);
                        add_backup(keys.keyentries[index]);
                        OS_DeleteKey(&keys, id_exist);
                    } else {
                        pthread_mutex_unlock(&mutex_keys);
                        merror("%s: ERROR: Duplicated IP %s", ARGV0, srcip);
                        snprintf(response, 2048, "ERROR: Duplicated IP: %s\n\n", srcip);

                        if (m_queue >= 0) {
                            char buffer[64];
                            snprintf(buffer, 64, "ossec: Duplicated IP %s", srcip);

                            if (SendMSG(m_queue, buffer, "ossec-authd", AUTH_MQ) < 0) {
                                merror("%s: ERROR: Can't send event across socket.", ARGV0);
                            }
                        }

                        SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        SSL_write(ssl, response, strlen(response));
                        SSL_free(ssl);
                        close(client.socket);
                        continue;
                    }
                }
            }

            /* Check for duplicated names */
            strncpy(fname, agentname, 2048);

            while (OS_IsAllowedName(&keys, fname) >= 0) {
                snprintf(fname, 2048, "%s%d", agentname, acount);

                if (++acount > MAX_TAG_COUNTER)
                    break;
            }

            if (acount > MAX_TAG_COUNTER) {
                pthread_mutex_unlock(&mutex_keys);
                merror("%s: ERROR: Invalid agent name %s (duplicated)", ARGV0, agentname);
                snprintf(response, 2048, "ERROR: Invalid agent name: %s\n\n", agentname);
                SSL_write(ssl, response, strlen(response));
                snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                SSL_write(ssl, response, strlen(response));
                SSL_free(ssl);
                close(client.socket);
                continue;
            }

            agentname = fname;

            /* Add the new agent */

            finalkey = OS_AddNewAgent(&keys, agentname, use_ip_address ? srcip : NULL);

            if (!finalkey) {
                pthread_mutex_unlock(&mutex_keys);
                merror("%s: ERROR: Unable to add agent: %s (internal error)", ARGV0, agentname);
                snprintf(response, 2048, "ERROR: Internal manager error adding agent: %s\n\n", agentname);
                SSL_write(ssl, response, strlen(response));
                snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                SSL_write(ssl, response, strlen(response));
                SSL_free(ssl);
                close(client.socket);
                continue;
            }

            snprintf(response, 2048, "OSSEC K:'%s'\n\n", finalkey);
            verbose("%s: INFO: Agent key generated for %s (requested by %s)", ARGV0, agentname, srcip);
            ret = SSL_write(ssl, response, strlen(response));

            if (ret < 0) {
                merror("%s: ERROR: SSL write error (%d)", ARGV0, ret);
                merror("%s: ERROR: Agent key not saved for %s", ARGV0, agentname);
                ERR_print_errors_fp(stderr);
                OS_DeleteKey(&keys, keys.keyentries[keys.keysize - 1]->id);
            } else {
                verbose("%s: INFO: Agent key created for %s (requested by %s)", ARGV0, agentname, srcip);

                /* Add pending key to write */
                add_insert(keys.keyentries[keys.keysize - 1]);
                write_pending = 1;
                pthread_cond_signal(&cond_pending);
            }

            pthread_mutex_unlock(&mutex_keys);
            free(finalkey);
        }

        SSL_free(ssl);
        close(client.socket);
    }

    SSL_CTX_free(ctx);
    return NULL;
}

/* Thread for writing keystore onto disk */
void* run_writer(__attribute__((unused)) void *arg) {
    keystore *copy_keys;
    struct keynode *copy_insert;
    struct keynode *copy_backup;
    struct keynode *cur;
    struct keynode *next;
    time_t cur_time;

    while (running) {
        pthread_mutex_lock(&mutex_keys);

        while (!write_pending && running)
            pthread_cond_wait(&cond_pending, &mutex_keys);

        copy_keys = OS_DupKeys(&keys);
        copy_insert = queue_insert;
        copy_backup = queue_backup;
        queue_insert = NULL;
        queue_backup = NULL;
        insert_tail = &queue_insert;
        backup_tail = &queue_backup;
        write_pending = 0;
        pthread_mutex_unlock(&mutex_keys);

        if (OS_WriteKeys(copy_keys) < 0)
            merror("%s: ERROR: Could't write file client.keys", ARGV0);

        OS_FreeKeys(copy_keys);
        free(copy_keys);
        cur_time = time(0);

        for (cur = copy_insert; cur; cur = next) {
            next = cur->next;
            OS_AddAgentTimestamp(cur->id, cur->name, cur->ip, cur_time);
            free(cur->id);
            free(cur->name);
            free(cur->ip);
            free(cur);
        }

        for (cur = copy_backup; cur; cur = next) {
            next = cur->next;
            OS_BackupAgentInfo(cur->id, cur->name, cur->ip);
            free(cur->id);
            free(cur->name);
            free(cur->ip);
            free(cur);
        }
    }

    return NULL;
}

/* Append key to insertion queue */
void add_insert(const keyentry *entry) {
    struct keynode *node;

    os_calloc(1, sizeof(struct keynode), node);
    node->id = strdup(entry->id);
    node->name = strdup(entry->name);
    node->ip = strdup(entry->ip->ip);

    (*insert_tail) = node;
    insert_tail = &node->next;
}

/* Append key to deletion queue */
void add_backup(const keyentry *entry) {
    struct keynode *node;

    os_calloc(1, sizeof(struct keynode), node);
    node->id = strdup(entry->id);
    node->name = strdup(entry->name);
    node->ip = strdup(entry->ip->ip);

    (*backup_tail) = node;
    backup_tail = &node->next;
}

/* Signal handler */
static void handler(int signum) {
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        merror(SIGNAL_RECV, ARGV0, signum, strsignal(signum));
        running = 0;
        close(sock);
        sock = -1;
        break;
    default:
        merror("%s: ERROR: unknown signal (%d)", ARGV0, signum);
    }
}

/* Exit handler */
static void cleanup() {
    DeletePID(ARGV0);
}

#endif /* LIBOPENSSL_ENABLED */
