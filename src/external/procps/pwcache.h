#ifndef PROCPS_PROC_PWCACHE_H
#define PROCPS_PROC_PWCACHE_H

#include <sys/types.h>
#include "procps.h"

EXTERN_C_BEGIN

// used in pwcache and in readproc to set size of username or groupname
#define P_G_SZ 20

extern char *user_from_uid(uid_t uid);
extern char *group_from_gid(gid_t gid);

EXTERN_C_END

#endif
