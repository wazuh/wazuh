#ifndef RPMLIB_WRAPPER_H
#define RPMLIB_WRAPPER_H

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>

class IRpmLibWrapper {
public:
    virtual ~IRpmLibWrapper() = default;
    virtual int rpmReadConfigFiles(const char * file, const char * target) = 0;
    virtual void rpmFreeRpmrc() = 0;
    virtual rpmtd rpmtdNew(void) = 0;
    virtual rpmts rpmtsCreate(void) = 0;
    virtual int rpmtsOpenDB(rpmts ts, int dbmode) = 0;
    virtual rpmts rpmtsFree(rpmts ts) = 0;
    virtual int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags) = 0;
    virtual const char *rpmtdGetString(rpmtd td) = 0;
    virtual uint64_t rpmtdGetNumber(rpmtd td) = 0;
    virtual rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi) = 0;
};

#endif // RPMLIB_WRAPPER_H