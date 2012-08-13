/* @(#) $Id: ./src/os_auth/main-server.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "auth.h"


/* ossec-reportd - Runs manual reports. */
void report_help()
{
}

#ifndef USE_OPENSSL
int main()
{
    printf("ERROR: Not compiled. Missing OpenSSL support.\n");
    exit(0);
}
#else


int main(int argc, char **argv)
{
    FILE *fp;
    int c, test_config = 0;
    int gid = 0, client_sock = 0, sock = 0, port = 1515, ret = 0;
    char *dir  = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;
    char buf[4096 +1];
    SSL_CTX *ctx;
    SSL *ssl;
    char srcip[IPSIZE +1];


    /* Initializing some variables */
    memset(srcip, '\0', IPSIZE + 1);

    bio_err = 0;


    /* Setting the name */
    OS_SetName(ARGV0);
        
    while((c = getopt(argc, argv, "Vdhu:g:D:c:m:p:")) != -1)
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
                user = optarg;
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
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
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
            default:
                report_help();
                break;
        }

    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
        ErrorExit(USER_ERROR,ARGV0,user,group);

    

    /* Exit here if test config is set */
    if(test_config)
        exit(0);

        
    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    
    /* chrooting */
    chdir(dir);



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
    

    /* Starting SSL */	
    ctx = os_ssl_keys(0, dir);
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

    debug1("%s: DEBUG: Going into listening mode.", ARGV0);

    while(1)
    {
        client_sock = OS_AcceptTCP(sock, srcip, IPSIZE);

        if(fork())
        {
            close(client_sock);
        }
        else
        {
            char *agentname = NULL;
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_sock);

            ret = SSL_accept(ssl);
            if(ret <= 0)
            {
                merror("%s: ERROR: SSL Accept error (%d)", ARGV0, ret);
                ERR_print_errors_fp(stderr);
            }

            verbose("%s: INFO: New connection from %s", ARGV0, srcip);

            ret = SSL_read(ssl, buf, sizeof(buf));
            sleep(1);
            if(ret > 0)
            {
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
                        ret = SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        ret = SSL_write(ssl, response, strlen(response));
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
                            ret = SSL_write(ssl, response, strlen(response));
                            snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                            ret = SSL_write(ssl, response, strlen(response));
                            sleep(1);
                            exit(0);
                        }
                    }
                    agentname = fname;


                    /* Adding the new agent. */
                    finalkey = OS_AddNewAgent(agentname, NULL, NULL, NULL);
                    if(!finalkey)
                    {
                        merror("%s: ERROR: Unable to add agent: %s (internal error)", ARGV0, agentname);
                        snprintf(response, 2048, "ERROR: Internal manager error adding agent: %s\n\n", agentname);
                        ret = SSL_write(ssl, response, strlen(response));
                        snprintf(response, 2048, "ERROR: Unable to add agent.\n\n");
                        ret = SSL_write(ssl, response, strlen(response));
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
            }
            else
            {
                merror("%s: ERROR: SSL read error (%d)", ARGV0, ret);
                ERR_print_errors_fp(stderr);
            }
            SSL_CTX_free(ctx);
            close(client_sock);
            exit(0);
        }
    }
    

    /* Shutdown the socket */
    SSL_CTX_free(ctx);
    close(sock);

    exit(0);
}


#endif
/* EOF */
