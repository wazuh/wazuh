/* @(#) $Id$ */

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

#ifndef USE_OPENSSL
int main()
{
    printf("ERROR: Not compiled. Missing OpenSSL support.\n");
    exit(0);
}
#else

#include <sys/wait.h>

#include "shared.h"
#include "auth.h"

/* TODO: Pulled this value out of the sky, may or may not be sane */
#define POOL_SIZE 512

static void help_authd(void) __attribute((noreturn));
static int ssl_error(const SSL* ssl, int ret);
static void clean_exit(SSL_CTX* ctx, int sock) __attribute__((noreturn));

/* print help statement */
static void help_authd()
{
    print_header();
    print_out("  %s: -[Vhdti] [-g group] [-D dir] [-p port] [-v path] [-x path] [-k path]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -i          Use client's source IP address");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -p <port>   Manager port (default: %d)", DEFAULT_PORT);
    print_out("    -v <path>   Full path to CA certificate used to verify clients");
    print_out("    -x <path>   Full path to server certificate");
    print_out("    -k <path>   Full path to server key");
    print_out(" ");
    exit(1);
}



/* Function to use with SSL on non blocking socket,
   to know if SSL operation failed for good */
static int ssl_error(const SSL* ssl, int ret)
{
    if (ret <= 0)
    {
        switch (SSL_get_error(ssl, ret))
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                usleep(100*1000);
                return (0);
            default:
                merror("%s: ERROR: SSL Error (%d)", ARGV0, ret);
                ERR_print_errors_fp(stderr);
                return (1);
        }
    }

    return (0);
}

static void clean_exit(SSL_CTX* ctx, int sock)
{
    SSL_CTX_free(ctx);
    close(sock);
    exit(0);
}

int main(int argc, char **argv)
{
    FILE *fp;
    // Bucket to keep pids in.
    int process_pool[POOL_SIZE];
    // Count of pids we are wait()ing on.
    int c = 0, test_config = 0, use_ip_address = 0, pid = 0, status, i = 0, active_processes = 0;
    int gid = 0, client_sock = 0, sock = 0, port = DEFAULT_PORT, ret = 0;
    const char *dir  = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *server_cert = NULL;
    const char *server_key = NULL;
    const char *ca_cert = NULL;
    char buf[4096 +1];
    SSL_CTX *ctx;
    SSL *ssl;
    char srcip[IPSIZE +1];
    struct sockaddr_in _nc;
    socklen_t _ncl;


    /* Initializing some variables */
    memset(srcip, '\0', IPSIZE + 1);
    memset(process_pool, 0x0, POOL_SIZE * sizeof(*process_pool));

    bio_err = 0;


    /* Setting the name */
    OS_SetName(ARGV0);
    /* add an option to use the ip on the socket to tie the name to a
       specific address */
    while((c = getopt(argc, argv, "Vdhtig:D:m:p:v:x:k:")) != -1)
    {
        switch(c){
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
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group = optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
                break;
            case 't':
                test_config = 1;
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
                server_cert = optarg;
                break;
            case 'k':
                if (!optarg)
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                server_key = optarg;
                break;
            default:
                help_authd();
                break;
        }

    }

    /* Starting daemon -- NB: need to double fork and setsid */
    debug1(STARTED_MSG,ARGV0);

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


    /* chrooting -- TODO: this isn't a chroot. Should also close
       unneeded open file descriptors (like stdin/stdout)*/
    if(chdir(dir) == -1)
    {
        ErrorExit(CHDIR_ERROR, ARGV0, dir);
    }



    /* Signal manipulation */
    StartSIG(ARGV0);


    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    fp = fopen(KEYSFILE_PATH,"a");
    if(!fp)
    {
        merror("%s: ERROR: Unable to open %s (key file)", ARGV0, KEYSFILE_PATH);
        exit(1);
    }
    fclose(fp);


    /* Starting SSL */
    ctx = os_ssl_keys(1, dir, server_cert, server_key, ca_cert);
    if(!ctx)
    {
        merror("%s: ERROR: SSL error. Exiting.", ARGV0);
        exit(1);
    }


    /* Connecting via TCP */
    sock = OS_Bindporttcp(port, NULL, 0);
    if(sock <= 0)
    {
        merror("%s: Unable to bind to port %d", ARGV0, port);
        exit(1);
    }
    fcntl(sock, F_SETFL, O_NONBLOCK);

    debug1("%s: DEBUG: Going into listening mode.", ARGV0);
    while(1)
    {

        // no need to completely pin the cpu, 100ms should be fast enough
        usleep(100*1000);

        // Only check process-pool if we have active processes
        if(active_processes > 0){
            for (i = 0; i < POOL_SIZE; i++)
            {
                int rv = 0;
                status = 0;
                if (process_pool[i])
                {
                    rv = waitpid(process_pool[i], &status, WNOHANG);
                    if (rv != 0){
                        debug1("%s: DEBUG: Process %d exited", ARGV0, process_pool[i]);
                        process_pool[i] = 0;
                        active_processes = active_processes - 1;
                    }
                }
            }
        }
        memset(&_nc, 0, sizeof(_nc));
        _ncl = sizeof(_nc);

        if((client_sock = accept(sock, (struct sockaddr *) &_nc, &_ncl)) > 0){
            if (active_processes >= POOL_SIZE)
            {
                merror("%s: Error: Max concurrency reached. Unable to fork", ARGV0);
                break;
            }
            pid = fork();
            if(pid)
            {
                active_processes = active_processes + 1;
                close(client_sock);
                for (i = 0; i < POOL_SIZE; i++)
                {
                    if (! process_pool[i])
                    {
                        process_pool[i] = pid;
                        break;
                    }
                }
            }
            else
            {
                strncpy(srcip, inet_ntoa(_nc.sin_addr),IPSIZE -1);
                char *agentname = NULL;
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_sock);

                do
                {
                    ret = SSL_accept(ssl);

                    if (ssl_error(ssl, ret))
                        clean_exit(ctx, client_sock);

                } while (ret <= 0);

                verbose("%s: INFO: New connection from %s", ARGV0, srcip);

                do
                {
                    ret = SSL_read(ssl, buf, sizeof(buf));

                    if (ssl_error(ssl, ret))
                        clean_exit(ctx, client_sock);

                } while (ret <= 0);

                int parseok = 0;
                if(strncmp(buf, "OSSEC A:'", 9) == 0)
                {
                    char *tmpstr = buf;
                    agentname = tmpstr + 9;
                    tmpstr += 9;
                    while(*tmpstr != '\0')
                    {
                        if(*tmpstr == '\'')
                        {
                            *tmpstr = '\0';
                            verbose("%s: INFO: Received request for a new agent (%s) from: %s", ARGV0, agentname, srcip);
                            parseok = 1;
                            break;
                        }
                        tmpstr++;
                    }
                }
                if(parseok == 0)
                {
                    merror("%s: ERROR: Invalid request for new agent from: %s", ARGV0, srcip);
                }
                else
                {
                    int acount = 2;
                    char fname[2048 +1];
                    char response[2048 +1];
                    char *finalkey = NULL;
                    response[2048] = '\0';
                    fname[2048] = '\0';
                    if(!OS_IsValidName(agentname))
                    {
                        merror("%s: ERROR: Invalid agent name: %s from %s", ARGV0, agentname, srcip);
                        snprintf(response, 2048, "ERROR: Invalid agent name: %s\n\n", agentname);
                        SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        SSL_write(ssl, response, strlen(response));
                        sleep(1);
                        exit(0);
                    }


                    /* Checking for a duplicated names. */
                    strncpy(fname, agentname, 2048);
                    while(NameExist(fname))
                    {
                        snprintf(fname, 2048, "%s%d", agentname, acount);
                        acount++;
                        if(acount > 256)
                        {
                            merror("%s: ERROR: Invalid agent name %s (duplicated)", ARGV0, agentname);
                            snprintf(response, 2048, "ERROR: Invalid agent name: %s\n\n", agentname);
                            SSL_write(ssl, response, strlen(response));
                            snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                            SSL_write(ssl, response, strlen(response));
                            sleep(1);
                            exit(0);
                        }
                    }
                    agentname = fname;


                    /* Adding the new agent. */
                    if (use_ip_address)
                    {
                        finalkey = OS_AddNewAgent(agentname, srcip, NULL);
                    }
                    else
                    {
                        finalkey = OS_AddNewAgent(agentname, NULL, NULL);
                    }
                    if(!finalkey)
                    {
                        merror("%s: ERROR: Unable to add agent: %s (internal error)", ARGV0, agentname);
                        snprintf(response, 2048, "ERROR: Internal manager error adding agent: %s\n\n", agentname);
                        SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        SSL_write(ssl, response, strlen(response));
                        sleep(1);
                        exit(0);
                    }


                    snprintf(response, 2048,"OSSEC K:'%s'\n\n", finalkey);
                    verbose("%s: INFO: Agent key generated for %s (requested by %s)", ARGV0, agentname, srcip);
                    ret = SSL_write(ssl, response, strlen(response));
                    if(ret < 0)
                    {
                        merror("%s: ERROR: SSL write error (%d)", ARGV0, ret);
                        merror("%s: ERROR: Agen key not saved for %s", ARGV0, agentname);
                        ERR_print_errors_fp(stderr);
                    }
                    else
                    {
                        verbose("%s: INFO: Agent key created for %s (requested by %s)", ARGV0, agentname, srcip);
                    }
                }

                clean_exit(ctx, client_sock);
            }
        }
    }


    /* Shutdown the socket */
    clean_exit(ctx, sock);

    return (0);
}


#endif /* USE_OPENSSL */

