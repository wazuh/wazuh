#ifndef UINT32_H
#define UINT32_H

/* adopted from libowfat 0.9 (GPL) */

typedef unsigned int uint32;

extern void uint32_pack(char *out,uint32 in);
extern void uint32_unpack(const char *in,uint32 *out);

#endif
