/* adopted from libowfat 0.9 (GPL) */
/* Copyright (C) 2015-2019, Wazuh Inc. */

#define NO_UINT32_MACROS
#include "uint32.h"


void uint32_unpack(const char *in, uint32 *out)
{
    *out = (((uint32)(unsigned char)in[3]) << 24) |
           (((uint32)(unsigned char)in[2]) << 16) |
           (((uint32)(unsigned char)in[1]) << 8) |
           (uint32)(unsigned char)in[0];
}
