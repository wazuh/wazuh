/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _RPMLIB_WRAPPER_H
#define _RPMLIB_WRAPPER_H

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>

class IRpmLibWrapper
{
    public:
        // LCOV_EXCL_START
        virtual ~IRpmLibWrapper() = default;
        // LCOV_EXCL_STOP
        virtual int rpmReadConfigFiles(const char* file, const char* target) = 0;
        virtual void rpmFreeRpmrc() = 0;
        virtual rpmtd rpmtdNew() = 0;
        virtual void rpmtdFree(rpmtd td) = 0;
        virtual rpmts rpmtsCreate() = 0;
        virtual int rpmtsOpenDB(rpmts ts, int dbmode) = 0;
        virtual int rpmtsCloseDB(rpmts ts) = 0;
        virtual rpmts rpmtsFree(rpmts ts) = 0;
        virtual int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags) = 0;
        virtual const char* rpmtdGetString(rpmtd td) = 0;
        virtual uint64_t rpmtdGetNumber(rpmtd td) = 0;
        virtual int rpmtsRun(rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet) = 0;
        virtual rpmdbMatchIterator rpmtsInitIterator(const rpmts ts, rpmDbiTagVal rpmtag, const void* keypointer, size_t keylen) = 0;
        virtual Header rpmdbNextIterator(rpmdbMatchIterator mi) = 0;
        virtual rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi) = 0;
};

#endif // _RPMLIB_WRAPPER_H
