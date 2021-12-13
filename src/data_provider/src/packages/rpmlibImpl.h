#include "rpmlibWrapper.h"

class RpmLibWrapperImpl final {
public:
    int rpmReadConfigFiles(const char * file, const char * target)
    {
        return rpmReadConfigFiles(file, target);
    }
    void rpmFreeRpmrc()
    {
        rpmFreeRpmrc();
    }
    rpmtd rpmtdNew()
    {
        return rpmtdNew();
    }
    rpmts rpmtsCreate()
    {
        return rpmtsCreate();
    }
    int rpmtsOpenDB(rpmts ts, int dbmode)
    {
        return rpmtsOpenDB(ts, dbmode);
    }
    rpmts rpmtsFree(rpmts ts)
    {
        return rpmtsFree(ts);
    }
    int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags)
    {
        return headerGet(h, tag, td, flags);
    }
    const char *rpmtdGetString(rpmtd td)
    {
        return rpmtdGetString(td);
    }
    uint64_t rpmtdGetNumber(rpmtd td)
    {
        return rpmtdGetNumber(td);
    }
    rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi)
    {
        return rpmdbFreeIterator(mi);
    }
};