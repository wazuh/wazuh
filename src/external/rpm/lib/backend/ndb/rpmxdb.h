#include "rpmpkg.h"

struct rpmxdb_s;
typedef struct rpmxdb_s *rpmxdb;

#ifdef __cplusplus
extern "C" {
#endif

int rpmxdbOpen(rpmxdb *xdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode);
void rpmxdbClose(rpmxdb xdb);
void rpmxdbSetFsync(rpmxdb xdb, int dofsync);
int rpmxdbIsRdonly(rpmxdb xdb);
unsigned int rpmxdbPagesize(rpmxdb xdb);

int rpmxdbLock(rpmxdb xdb, int excl);
int rpmxdbUnlock(rpmxdb xdb, int excl);

int rpmxdbLookupBlob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag, int flags);
int rpmxdbDelBlob(rpmxdb xdb, unsigned int id) ;
int rpmxdbDelAllBlobs(rpmxdb xdb);

int rpmxdbMapBlob(rpmxdb xdb, unsigned int id, int flags, void (*mapcallback)(rpmxdb xdb, void *data, void *newaddr, size_t newsize), void *mapcallbackdata);
int rpmxdbUnmapBlob(rpmxdb xdb, unsigned int id);

int rpmxdbResizeBlob(rpmxdb xdb, unsigned int id, size_t newsize);
int rpmxdbRenameBlob(rpmxdb xdb, unsigned int *idp, unsigned int blobtag, unsigned int subtag);

int rpmxdbSetUserGeneration(rpmxdb xdb, unsigned int usergeneration);
int rpmxdbGetUserGeneration(rpmxdb xdb, unsigned int *usergenerationp);

int rpmxdbStats(rpmxdb xdb);

#ifdef __cplusplus
}
#endif
