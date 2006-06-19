#include "shared.h"
#include "os_zlib.h"

#ifndef ARGV0
  #define ARGV0   "zlib-test"
#endif

/* Zlib test */
int main(int argc, char **argv)
{
    int ret, srcsize, dstsize = 2010; 
    char dst[2048];
    char dst2[2048];

    memset(dst, 0, 2048);
    memset(dst2, 0, 2048);

    if(argc < 2)
    {
        printf("%s: string\n", argv[0]);
        exit(1);
    }
    
    srcsize = strlen(argv[1]);
    if(srcsize > 2000)
    {
        printf("%s: string too large\n", argv[0]);
        exit(1);

    }
    
    if((ret = os_compress(argv[1], dst, srcsize, dstsize)))
    {
        printf("Compressed, from %d->%d\n",srcsize, ret);
    }
    else
    {
        printf("FAILED compressing.\n");
        exit(1);
    }

    /* Setting new srcsize for decompression */
    srcsize = ret;
    
    if((ret = os_uncompress(dst, dst2, srcsize, dstsize)))
    {
        printf("Uncompressed ok. String: '%s', size %d->%d\n", 
                                        dst2, srcsize, ret); 
    }
    else
    {
        printf("FAILED uncompressing.\n");
        exit(1);
    }

    return(0);
}
