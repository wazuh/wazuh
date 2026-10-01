#ifndef RPMLOCK_H
#define RPMLOCK_H 

#include <rpm/rpmutil.h>

typedef struct rpmlock_s * rpmlock;

enum {
    RPMLOCK_READ   = 1 << 0,
    RPMLOCK_WRITE  = 1 << 1,
    RPMLOCK_WAIT   = 1 << 2,
};

RPM_GNUC_INTERNAL
rpmlock rpmlockNew(const char *lock_path, const char *descr);

RPM_GNUC_INTERNAL
rpmlock rpmlockNewAcquire(const char *lock_path, const char *descr);

RPM_GNUC_INTERNAL
int rpmlockAcquire(rpmlock lock, int lockmode);

RPM_GNUC_INTERNAL
void rpmlockRelease(rpmlock lock);

RPM_GNUC_INTERNAL
rpmlock rpmlockFree(rpmlock lock);

#endif
