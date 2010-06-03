#define NO_UINT32_MACROS
#include "uint32.h"

/* adopted from libowfat 0.9 (GPL) */

void uint32_pack(char *out,uint32 in) {
  *out=in&0xff; in>>=8;
  *++out=in&0xff; in>>=8;
  *++out=in&0xff; in>>=8;
  *++out=in&0xff;
}
