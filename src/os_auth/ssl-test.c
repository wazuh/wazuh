
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
    int sock = 0, port = 443, ret = 0;
    char *host = NULL;
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_METHOD *sslmeth;
    BIO *sbio;
    BIO *bio_err = 0;
    struct sockaddr_in addr;


    while((c = getopt(argc, argv, "h:p:")) != -1)
    {
        switch(c){
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                if(port <= 0 || port >= 65536)
                {
                    exit(1);
                }
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
    sock = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0)
    {
        printf("sock error\n");
        exit(1);
    }

    memset(&addr,0,sizeof(addr));
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    if(connect(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0)
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
