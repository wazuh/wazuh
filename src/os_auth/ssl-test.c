/*
 *
 * Copyright (C) 2011 Trend Micro Inc. All rights reserved.
 *
 * OSSEC HIDS is a free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (version 2) as
 * published by the FSF - Free Software Foundation.
 *
 * Note that this license applies to the source code, as well as
 * decoders, rules and any other data file included with OSSEC (unless
 * otherwise specified).
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/param.h>


#include <sys/wait.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>


#define TEST "GET / HTTP/1.0\r\n\r\n\r\n"

int main(int argc, char **argv)
{
    int c;
    int sock = 0, portnum, ret = 0;
    char *host = NULL, *port = "443";
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_METHOD *sslmeth;
    BIO *sbio;
    BIO *bio_err = 0;


    while((c = getopt(argc, argv, "h:p:")) != -1)
    {
        switch(c){
            case 'h':
                host = optarg;
                break;
            case 'p':
                portnum = atoi(optarg);
                if(portnum <= 0 || portnum >= 65536)
                {
                    exit(1);
                }
                port = optarg;
                break;
            default:
                exit(1);
                break;
        }
    }

    if(!bio_err)
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    sslmeth = SSLv23_method();
    ctx = SSL_CTX_new(sslmeth);
    if(!ctx)
    {
        printf("CTX ERROR\n");
        exit(1);
    }

    if(!host)
    {
        printf("ERROR - host not set.\n");
        exit(1);
    }

    /* Connecting via TCP */
    sock = OS_ConnectTCP(port, host);
    if (sock <= 0)
    {
        printf("connect error\n");
        exit(1);
    }


    /* Connecting the SSL socket */
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    ret = SSL_connect(ssl);
    if(ret <= 0)
    {
        printf("SSL connect error\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("Connected!\n");


    ret=SSL_write(ssl,TEST, sizeof(TEST));
    if(ret < 0)
    {
        printf("SSL write error\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    while(1)
    {
        char buf[2048];
        ret = SSL_read(ssl,buf,sizeof(buf) -1);
        printf("ret: %d\n", ret);
        switch(SSL_get_error(ssl,ret))
        {
        case SSL_ERROR_NONE:
          buf[ret] = '\0';
          printf("no error: %s\n", buf);
          break;
        case SSL_ERROR_ZERO_RETURN:
          printf("no returen\n");
           exit(1);
          break;
        case SSL_ERROR_SYSCALL:
          fprintf(stderr,
            "SSL Error: Premature close\n");
           exit(1);
           break;
        default:
          printf("default error\n");
           exit(1);
          break;
      }

    }

    exit(0);
}
