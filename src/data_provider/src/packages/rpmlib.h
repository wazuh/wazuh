#include "rpmlibWrapper.h"

class RpmLib : public IRpmLibWrapper {
public:
    int rpmReadConfigFiles(const char * file, const char * target) override
    {
        return rpmReadConfigFiles(file, target);
    }
    void rpmFreeRpmrc() override
    {
        rpmFreeRpmrc();
    }
    rpmtd rpmtdNew() override
    {
        return rpmtdNew();
    }
    rpmts rpmtsCreate() override
    {
        return rpmtsCreate();
    }
    int rpmtsOpenDB(rpmts ts, int dbmode) override
    {
        return rpmtsOpenDB(ts, dbmode);
    }
    rpmts rpmtsFree(rpmts ts) override
    {
        return rpmtsFree(ts);
    }
    int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags) override
    {
        return headerGet(h, tag, td, flags);
    }
    const char *rpmtdGetString(rpmtd td) override
    {
        return rpmtdGetString(td);
    }
    uint64_t rpmtdGetNumber(rpmtd td) override
    {
        return rpmtdGetNumber(td);
    }
    rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi) override
    {
        return rpmdbFreeIterator(mi);
    }
};