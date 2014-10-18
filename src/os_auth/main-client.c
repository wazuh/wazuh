/* @(#) $Id: ./src/os_auth/main-client.c, 2012/02/07 dcid Exp $
 */

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

#include "shared.h"
#include "check_cert.h"

#ifndef USE_OPENSSL

int main()
{
    printf("ERROR: Not compiled. Missing OpenSSL support.\n");
    exit(0);
}


#else

#include <openssl/ssl.h>
#include "auth.h"

static void help_agent_auth(void) __attribute__((noreturn));

/* print help statement */
static void help_agent_auth()
{
    print_header();
    print_out("  %s: -[Vhdt] [-g group] [-D dir] [-m IP address] [-p port] [-A name] [-v path] [-x path] [-k path]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -m <addr>   Manager IP address");
    print_out("    -p <port>   Manager port (default: %d)", DEFAULT_PORT);
    print_out("    -A <name>   Agent name (default: hostname)");
    print_out("    -v <path>   Full path to CA certificate used to verify the server");
    print_out("    -x <path>   Full path to agent certificate");
    print_out("    -k <path>   Full path to agent key");
    print_out(" ");
    exit(1);
}



int main(int argc, char **argv)
{
    int c;
    int test_config = 0;
#ifndef WIN32
    int gid = 0;
#endif

    int sock = 0, port = DEFAULT_PORT, ret = 0;
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *manager = NULL;
    const char *ipaddress = NULL;
    const char *agentname = NULL;
    const char *agent_cert = NULL;
    const char *agent_key = NULL;
    const char *ca_cert = NULL;
    char lhostname[512 + 1];
    char buf[2048 +1];
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    bio_err = 0;
    buf[2048] = '\0';

#ifdef WIN32
    WSADATA wsaData;
#endif


    /* Setting the name */
    OS_SetName(ARGV0);

    while((c = getopt(argc, argv, "Vdhtg:m:p:A:v:x:k:")) != -1)
    {
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help_agent_auth();
                break;
            case 'd':
                nowDebug();
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'm':
               if(!optarg)
                    ErrorExit("%s: -%c needs an argument",ARGV0, c);
                manager = optarg;
                break;
            case 'A':
               if(!optarg)
                    ErrorExit("%s: -%c needs an argument",ARGV0, c);
                agentname = optarg;
                break;
            case 'p':
               if(!optarg)
                    ErrorExit("%s: -%c needs an argument",ARGV0, c);
                port = atoi(optarg);
                if(port <= 0 || port >= 65536)
                {
                    ErrorExit("%s: Invalid port: %s", ARGV0, optarg);
                }
                break;
            case 'v':
                if (!optarg)
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                ca_cert = optarg;
                break;
            case 'x':
                if (!optarg)
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                agent_cert = optarg;
                break;
            case 'k':
                if (!optarg)
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                agent_key = optarg;
                break;
            default:
                help_agent_auth();
                break;
        }
    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);


#ifndef WIN32
    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
        ErrorExit(USER_ERROR,ARGV0,"",group);

    /* Exit here if test config is set */
    if(test_config)
        exit(0);

    /* Privilege separation */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);



    /* Signal manipulation */
    StartSIG(ARGV0);



    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);
#else
    /* Initialize Windows socket stuff.
     */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
    {
        ErrorExit("%s: WSAStartup() failed", ARGV0);
    }
#endif /* WIN32 */

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    if(agentname == NULL)
    {
        lhostname[512] = '\0';
        if(gethostname(lhostname, 512 -1) != 0)
        {
            merror("%s: ERROR: Unable to extract hostname. Custom agent name not set.", ARGV0);
            exit(1);
        }
        agentname = lhostname;
    }



    /* Starting SSL */
    ctx = os_ssl_keys(0, dir, agent_cert, agent_key, ca_cert);
    if(!ctx)
    {
        merror("%s: ERROR: SSL error. Exiting.", ARGV0);
        exit(1);
    }

    if(!manager)
    {
        merror("%s: ERROR: Manager IP not set.", ARGV0);
        exit(1);
    }


    /* Check to see if the manager to connect to was specified as an IP address
     * or hostname on the command line. If it was given as a hostname then ensure
     * the hostname is preserved so that certificate verification can be done.
     */
    if(!(ipaddress = OS_GetHost(manager, 3)))
    {
        merror("%s: Could not resolve hostname: %s\n", ARGV0, manager);
        exit(1);
    }

    /* Connecting via TCP */
    sock = OS_ConnectTCP(port, ipaddress, 0);
    if(sock <= 0)
    {
        merror("%s: Unable to connect to %s:%d", ARGV0, ipaddress, port);
        exit(1);
    }


    /* Connecting the SSL socket */
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);


    ret = SSL_connect(ssl);
    if(ret <= 0)
    {
        ERR_print_errors_fp(stderr);
        merror("%s: ERROR: SSL error (%d). Exiting.", ARGV0, ret);
        exit(1);
    }


    printf("INFO: Connected to %s:%d\n", ipaddress, port);

    /* Additional verification of the manager's certificate if a hostname
     * rather than an IP address is given on the command line. Could change
     * this to do the additional validation on IP addresses as well if needed.
     */
    if(ca_cert)
    {
        printf("INFO: Verifing manager's certificate\n");
        if(check_x509_cert(ssl, manager) != VERIFY_TRUE) {
            debug1("%s: DEBUG: Unable to verify server certificate.", ARGV0);
            exit(1);
        }
    }

    printf("INFO: Using agent name as: %s\n", agentname);


    snprintf(buf, 2048, "OSSEC A:'%s'\n", agentname);
    ret = SSL_write(ssl, buf, strlen(buf));
    if(ret < 0)
    {
        printf("SSL write error (unable to send message.)\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("INFO: Send request to manager. Waiting for reply.\n");

    while(1)
    {
        ret = SSL_read(ssl,buf,sizeof(buf) -1);
        switch(SSL_get_error(ssl,ret))
        {
            case SSL_ERROR_NONE:
                buf[ret] = '\0';
                if(strncmp(buf, "ERROR", 5) == 0)
                {
                    char *tmpstr;
                    tmpstr = strchr(buf, '\n');
                    if(tmpstr) *tmpstr = '\0';
                    printf("%s (from manager)\n", buf);
                }
                else if(strncmp(buf, "OSSEC K:'",9) == 0)
                {
                    char *key;
                    char *tmpstr;
                    char **entry;
                    printf("INFO: Received response with agent key\n");

                    key = buf;
                    key += 9;
                    tmpstr = strchr(key, '\'');
                    if(!tmpstr)
                    {
                        printf("ERROR: Invalid key received. Closing connection.\n");
                        exit(1);
                    }
                    *tmpstr = '\0';
                    entry = OS_StrBreak(' ', key, 4);
                    if(!OS_IsValidID(entry[0]) || !OS_IsValidName(entry[1]) ||
                       !OS_IsValidName(entry[2]) || !OS_IsValidName(entry[3]))
                    {
                        printf("ERROR: Invalid key received (2). Closing connection.\n");
                        exit(1);
                    }

                    {
                        FILE *fp;
                        fp = fopen(KEYSFILE_PATH,"w");
                        if(!fp)
                        {
                            printf("ERROR: Unable to open key file: %s", KEYSFILE_PATH);
                            exit(1);
                        }
                        fprintf(fp, "%s\n", key);
                        fclose(fp);
                    }
                    printf("INFO: Valid key created. Finished.\n");
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
                printf("INFO: Connection closed.\n");
                exit(0);
                break;
            default:
                printf("ERROR: SSL read (unable to receive message)\n");
                exit(1);
                break;
        }

    }



    /* Shutdown the socket */
    SSL_CTX_free(ctx);
    close(sock);

    exit(0);
}

#endif /* USE_OPENSSL */

