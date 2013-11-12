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

#ifndef USE_OPENSSL

int main()
{
    printf("ERROR: Not compiled. Missing OpenSSL support.\n");
    exit(0);
}


#else

#include <openssl/ssl.h>
#include "auth.h"



void report_help()
{
    printf("\nOSSEC HIDS %s: Connects to the manager to extract the agent key.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h                  This help message.\n");
    printf("\t-m <manager ip>     Manager IP Address.\n");
    printf("\t-p <port>           Manager port (default 1515).\n");
    printf("\t-A <agent name>     Agent name (default is the hostname).\n");
    printf("\t-D <OSSEC Dir>      Location where OSSEC is installed.\n");
    exit(1);
}



int main(int argc, char **argv)
{
    int c, test_config = 0, s;
    #ifndef WIN32
    int gid = 0;
    #endif

    int sock = 0, portnum, ret = 0;
    char *port = "1515";
    char *dir  = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;
    char *manager = NULL;
    char *agentname = NULL;
    char lhostname[512 + 1];
    char buf[2048 +1];
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    struct sockaddr_storage addr;
    struct addrinfo hints;
    struct addrinfo *result, *rp;


    bio_err = 0;
    buf[2048] = '\0';


    /* Setting the name */
    OS_SetName(ARGV0);

    while((c = getopt(argc, argv, "Vdhu:g:D:c:m:p:A:")) != -1)
    {
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                report_help();
                break;
            case 'd':
                nowDebug();
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
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
                portnum = atoi(optarg);
                if(portnum <= 0 || portnum >= 65536)
                {
                    ErrorExit("%s: Invalid port: %s", ARGV0, optarg);
                }
                port = optarg;
                break;
            default:
                report_help();
                break;
        }
    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);


    #ifndef WIN32
    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
        ErrorExit(USER_ERROR,ARGV0,user,group);



    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);



    /* Signal manipulation */
    StartSIG(ARGV0);



    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);
    #endif


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
    ctx = os_ssl_keys(1, NULL);
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


    /* Connecting via TCP */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    s = getaddrinfo(manager, port, &hints, &result);
    if (s != 0)
    {
        printf("Could not resolve hostname: %s\n", manager);
        return(1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
        {
            continue;
        }
  
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
        {
            break;                  /* Success */
        } 
        close(sock);
    }
    if (rp == NULL)
    {               /* No address succeeded */
        merror("%s: Unable to connect to %s:%s", ARGV0, manager, port);
        exit(1);
    }

    freeaddrinfo(result);           /* No longer needed */


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


    printf("INFO: Connected to %s:%s\n", manager, port);
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

#endif
/* EOF */
