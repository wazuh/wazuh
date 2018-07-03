#ifndef __SHA256_OP_H
#define __SHA256_OP_H

#include <sys/types.h>

typedef char os_sha256[65];

int OS_SHA256_File(const char *fname, os_sha256 output, int mode) __attribute((nonnull));

#endif
