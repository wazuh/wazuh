#ifndef PROCPS_PROC_WCHAN_H
#define PROCPS_PROC_WCHAN_H

#include "procps.h"

EXTERN_C_BEGIN

typedef void (*message_fn)(const char *restrict, ...) __attribute__((format(printf,1,2)));

extern const char * lookup_wchan(unsigned KLONG address, unsigned pid);
extern int   open_psdb(const char *restrict override);
extern int   open_psdb_message(const char *restrict override, message_fn message);

EXTERN_C_END

#endif
