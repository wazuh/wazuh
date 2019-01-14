/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
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

#include "shared.h"
#include "check_cert.h"
#include <openssl/ssl.h>
#include "auth.h"

#undef ARGV0
#define ARGV0 "agent-auth"

static void help_agent_auth(void) __attribute__((noreturn));

/* Print help statement */
static void help_agent_auth()
{
    print_header();
    print_out("  %s: -[Vhdti] [-g group] [-D dir] [-m IP address] [-p port] [-A name] [-c ciphers] [-v path] [-x path] [-k path] [-P pass] [-G group] [-I IP address]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
#ifndef WIN32
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
#endif
    print_out("    -m <addr>   Manager IP address");
    print_out("    -p <port>   Manager port (default: %d)", DEFAULT_PORT);
    print_out("    -A <name>   Agent name (default: hostname)");
    print_out("    -c          SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify the server");
    print_out("    -x <path>   Full path to agent certificate");
    print_out("    -k <path>   Full path to agent key");
    print_out("    -P <pass>   Authorization password");
    print_out("    -a          Auto select SSL/TLS method. Default: TLS v1.2 only.");
    print_out("    -G <group>  Set the group for centralized configuration");
    print_out("    -I <IP>     Set the agent IP address");
    print_out("    -i          Let the agent IP address be set by the manager connection");
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int key_added = 0;
    int c;
    int test_config = 0;
    int auto_method = 0;
#ifndef WIN32
    gid_t gid = 0;
    const char *group = GROUPGLOBAL;
#endif

    int sock = 0, port = DEFAULT_PORT, ret = 0;
    char *ciphers = DEFAULT_CIPHERS;
    const char *dir = DEFAULTDIR;
    char *authpass = NULL;
    const char *manager = NULL;
    const char *ipaddress = NULL;
    const char *agentname = NULL;
    const char *agent_cert = NULL;
    const char *agent_key = NULL;
    const char *ca_cert = NULL;
    const char *centralized_group = NULL;
    const char *sender_ip = NULL;
    int use_src_ip = 0;
    char lhostname[512 + 1];
    char * buf;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    bio_err = 0;
    int debug_level = 0;

#ifdef WIN32
    WSADATA wsaData;

    // Move to the directory where this executable lives in
    w_ch_exec_dir();
#endif

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "VdhtG:m:p:A:c:v:x:k:D:P:a:I:i"
#ifndef WIN32
    "g:D:"
#endif
    )) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agent_auth();
                break;
            case 'd':
                debug_level = 1;
                nowDebug();
                break;
#ifndef WIN32
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                dir = optarg;
                break;
#endif
            case 't':
                test_config = 1;
                break;
            case 'm':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                manager = optarg;
                break;
            case 'A':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                agentname = optarg;
                break;
            case 'p':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                port = atoi(optarg);
                if (port <= 0 || port >= 65536) {
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
            case 'x':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                agent_cert = optarg;
                break;
            case 'k':
                if (!optarg) {
                    merror_exit("-%c needs an argument", c);
                }
                agent_key = optarg;
                break;
            case 'P':
                if (!optarg)
                    merror_exit("-%c needs an argument", c);

                authpass = optarg;
                break;
            case 'a':
                auto_method = 1;
                break;
            case 'G':
                if(!optarg){
                    merror_exit("-%c needs an argument",c);
                }
                centralized_group = optarg;
                break;
            case 'I':
                if(!optarg){
                    merror_exit("-%c needs an argument",c);
                }
                sender_ip = optarg;
                break;
            case 'i':
                use_src_ip = 1;
                break;
            default:
                help_agent_auth();
                break;
        }
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("authd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (sender_ip && use_src_ip) {
        merror("Options '-I' and '-i' are uncompatible.");
        exit(1);
    }

    /* Start daemon */
    mdebug1(STARTED_MSG);

#ifndef WIN32
    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }
#else
    /* Initialize Windows socket stuff */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        merror_exit("WSAStartup() failed");
    }

#endif /* WIN32 */

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    if (agentname == NULL) {
        lhostname[512] = '\0';
        if (gethostname(lhostname, 512 - 1) != 0) {
            merror("Unable to extract hostname. Custom agent name not set.");
            exit(1);
        }
        agentname = lhostname;
    }


    /* Start SSL */
    ctx = os_ssl_keys(0, dir, ciphers, agent_cert, agent_key, ca_cert, auto_method);
    if (!ctx) {
        merror("SSL error. Exiting.");
        exit(1);
    }

    if (!manager) {
        merror("Manager IP not set.");
        exit(1);
    }

    /* Check to see if the manager to connect to was specified as an IP address
     * or hostname on the command line. If it was given as a hostname then ensure
     * the hostname is preserved so that certificate verification can be done.
     */
    if (!(ipaddress = OS_GetHost(manager, 3))) {
        merror("Could not resolve hostname: %s\n", manager);
        exit(1);
    }

    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';

    /* Checking if there is a custom password file */
    if (authpass == NULL) {
        FILE *fp;
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
            printf("INFO: Using password specified on file: %s\n", AUTHDPASS_PATH);
        }
    }
    if (!authpass) {
        printf("INFO: No authentication password provided.\n");
    }

    /* Connect via TCP */
    sock = OS_ConnectTCP(port, ipaddress, 0);
    if (sock <= 0) {
        merror("Unable to connect to %s:%d", ipaddress, port);
        free(buf);
        exit(1);
    }

    /* Connect the SSL socket */
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    ret = SSL_connect(ssl);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
        merror("SSL error (%d). Exiting.", ret);
        free(buf);
        exit(1);
    }

    printf("INFO: Connected to %s:%d\n", ipaddress, port);

    /* Additional verification of the manager's certificate if a hostname
     * rather than an IP address is given on the command line. Could change
     * this to do the additional validation on IP addresses as well if needed.
     */
    if (ca_cert) {
        printf("INFO: Verifying manager's certificate\n");
        if (check_x509_cert(ssl, manager) != VERIFY_TRUE) {
            merror("Unable to verify server certificate.");
            free(buf);
            exit(1);
        }
    }

    printf("INFO: Using agent name as: %s\n", agentname);

    if (authpass) {
        snprintf(buf, 2048, "OSSEC PASS: %s OSSEC A:'%s'", authpass, agentname);
    }
    else {
        snprintf(buf, 2048, "OSSEC A:'%s'", agentname);
    }

    if(centralized_group){
        char * opt_buf = NULL;
        os_calloc(OS_SIZE_65536, sizeof(char), opt_buf);
        snprintf(opt_buf,OS_SIZE_65536," G:'%s'",centralized_group);
        strncat(buf,opt_buf,OS_SIZE_65536);
        free(opt_buf);
    }

    if(sender_ip){
		/* Check if this is strictly an IP address using a regex */
		if (OS_IsValidIP(sender_ip, NULL))
		{
			char opt_buf[256] = {0};
			snprintf(opt_buf,254," IP:'%s'",sender_ip);
			strncat(buf,opt_buf,254);
		} else {
			merror("Invalid IP address provided with '-I' option.");
			free(buf);
			exit(1);
		}
    }

    if(use_src_ip)
    {
        char opt_buf[10] = {0};
        snprintf(opt_buf,10," IP:'src'");
        strncat(buf,opt_buf,10);
    }

    /* Append new line character */
    strncat(buf,"\n",1);
    ret = SSL_write(ssl, buf, strlen(buf));
    if (ret < 0) {
        printf("SSL write error (unable to send message.)\n");
        ERR_print_errors_fp(stderr);
        free(buf);
        exit(1);
    }

    printf("INFO: Send request to manager. Waiting for reply.\n");

    while (1) {
        ret = SSL_read(ssl, buf, OS_SIZE_65536 + OS_SIZE_4096);
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_NONE:
                buf[ret] = '\0';
                if (strncmp(buf, "ERROR", 5) == 0) {
                    char *tmpstr;
                    tmpstr = strchr(buf, '\n');
                    if (tmpstr) {
                        *tmpstr = '\0';
                    }
                    printf("%s (from manager)\n", buf);
                } else if (strncmp(buf, "OSSEC K:'", 9) == 0) {
                    char *key;
                    char *tmpstr;
                    char **entry;
                    printf("INFO: Received response with agent key\n");

                    key = buf;
                    key += 9;
                    tmpstr = strchr(key, '\'');
                    if (!tmpstr) {
                        printf("ERROR: Invalid key received. Closing connection.\n");
                        free(buf);
                        exit(1);
                    }
                    *tmpstr = '\0';
                    entry = OS_StrBreak(' ', key, 4);
                    if (!OS_IsValidID(entry[0]) || !OS_IsValidName(entry[1]) ||
                            !OS_IsValidIP(entry[2], NULL) || !OS_IsValidName(entry[3])) {
                        printf("ERROR: Invalid key received (2). Closing connection.\n");
                        free(buf);
                        exit(1);
                    }

                    {
                        FILE *fp;

                        umask(0026);
                        fp = fopen(KEYSFILE_PATH, "w");

                        if (!fp) {
                            printf("ERROR: Unable to open key file: %s", KEYSFILE_PATH);
                            free(buf);
                            exit(1);
                        }
                        fprintf(fp, "%s\n", key);
                        fclose(fp);
                    }
                    key_added = 1;
                    printf("INFO: Valid key created. Finished.\n");
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
                if (key_added == 0) {
                    printf("ERROR: Unable to create key. Either wrong password or connection not accepted by the manager.\n");
                }
                printf("INFO: Connection closed.\n");
                free(buf);
                exit(!key_added);
                break;
            default:
                printf("ERROR: SSL read (unable to receive message)\n");
                free(buf);
                exit(1);
                break;
        }

    }

    /* Shut down the socket */
    if (key_added == 0) {
        printf("ERROR: Unable to create key. Either wrong password or connection not accepted by the manager.\n");
    }
    SSL_CTX_free(ctx);
    close(sock);
    free(buf);

    exit(0);
}
