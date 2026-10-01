#include <rpm/rpmtypes.h>

struct rpmpkgdb_s;
typedef struct rpmpkgdb_s *rpmpkgdb;

#ifdef __cplusplus
extern "C" {
#endif

int rpmpkgOpen(rpmpkgdb *pkgdbp, const char *filename, int flags, int mode);
int rpmpkgSalvage(rpmpkgdb *pkgdbp, const char *filename);
void rpmpkgClose(rpmpkgdb pkgdbp);
void rpmpkgSetFsync(rpmpkgdb pkgdbp, int dofsync);

int rpmpkgLock(rpmpkgdb pkgdb, int excl);
int rpmpkgUnlock(rpmpkgdb pkgdb, int excl);

rpmRC rpmpkgGet(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char **blobp, unsigned int *bloblp);
rpmRC rpmpkgPut(rpmpkgdb pkgdb, unsigned int pkgidx, unsigned char *blob, unsigned int blobl);
rpmRC rpmpkgDel(rpmpkgdb pkgdb, unsigned int pkgidx);
rpmRC rpmpkgList(rpmpkgdb pkgdb, unsigned int **pkgidxlistp, unsigned int *npkgidxlistp);
rpmRC rpmpkgVerify(rpmpkgdb pkgdb);

rpmRC rpmpkgNextPkgIdx(rpmpkgdb pkgdb, unsigned int *pkgidxp);
int rpmpkgGeneration(rpmpkgdb pkgdb, unsigned int *generationp);

int rpmpkgStats(rpmpkgdb pkgdb);

#ifdef __cplusplus
}
#endif
