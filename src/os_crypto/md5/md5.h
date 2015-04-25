/* This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ifndef MD5_H
#define MD5_H

#include <sys/types.h>
#if defined SOLARIS
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
#endif

#if defined HPUX
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
#endif

#ifdef WIN32
typedef unsigned int u_int32_t;
#endif

typedef u_int32_t uint32;

struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    union {
        unsigned char in[64];
        uint32 in32[16];
    };
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
               unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32 buf[4], uint32 const in[16]);

/* This is needed to make RSAREF happy on some MS-DOS compilers */
typedef struct MD5Context MD5_CTX;

#endif /* MD5_H */

