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

#include "rpmlibWrapper.h"

#ifndef _RPMLIB_H
#define _RPMLIB_H

class RpmLib final : public IRpmLibWrapper
{
    public:
        int rpmReadConfigFiles(const char* file, const char* target) override
        {
            return ::rpmReadConfigFiles(file, target);
        }

        void rpmFreeRpmrc() override
        {
            ::rpmFreeRpmrc();
        }

        void rpmFreeMacros() override
        {
            // rpmReadConfigFiles() (called from RpmPackageManager's constructor,
            // once per scanPackages() cycle) calls rpmInitMacros() internally, which PUSHES
            // built-in + config-file macros onto rpm's process-global macro context every time,
            // without clearing it first (confirmed in rpm/rpmio/macro.c). rpmFreeRpmrc() alone
            // does not undo this — it's a different subsystem (platform/arch tables). Only
            // rpmFreeMacros() empties the macro table; rpm's own reference CLI (poptALL.c) calls
            // both together on exit. Without this, every scan cycle permanently grows rpm's
            // global macro table — a genuine accumulating leak in third-party library state.
            ::rpmFreeMacros(nullptr);
        }

        rpmtd rpmtdNew() override
        {
            return ::rpmtdNew();
        }

        void rpmtdFree(rpmtd td) override
        {
            ::rpmtdFree(td);
        }

        rpmts rpmtsCreate() override
        {
            return ::rpmtsCreate();
        }

        int rpmtsOpenDB(rpmts ts, int dbmode) override
        {
            return ::rpmtsOpenDB(ts, dbmode);
        }

        int rpmtsCloseDB(rpmts ts) override
        {
            return ::rpmtsCloseDB(ts);
        }

        rpmts rpmtsFree(rpmts ts) override
        {
            return ::rpmtsFree(ts);
        }

        int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags) override
        {
            return ::headerGet(h, tag, td, flags);
        }

        const char* rpmtdGetString(rpmtd td) override
        {
            return ::rpmtdGetString(td);
        }

        uint64_t rpmtdGetNumber(rpmtd td) override
        {
            return ::rpmtdGetNumber(td);
        }

        int rpmtsRun(rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet) override
        {
            return ::rpmtsRun(ts, okProbs, ignoreSet);
        }

        rpmdbMatchIterator rpmtsInitIterator(const rpmts ts, rpmDbiTagVal rpmtag, const void* keypointer, size_t keylen) override
        {
            return ::rpmtsInitIterator(ts, rpmtag, keypointer, keylen);
        }

        rpmVSFlags rpmtsSetVSFlags(rpmts ts, rpmVSFlags vsflags) override
        {
            return ::rpmtsSetVSFlags(ts, vsflags);
        }

        Header rpmdbNextIterator(rpmdbMatchIterator mi) override
        {
            return ::rpmdbNextIterator(mi);
        }

        rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi) override
        {
            return ::rpmdbFreeIterator(mi);
        }

        rpmfi rpmfiNew(rpmts ts, Header h, rpmTagVal tag, rpmfiFlags flags) override
        {
            return ::rpmfiNew(ts, h, tag, flags);
        }

        rpm_count_t rpmfiFC(rpmfi fi) override
        {
            return ::rpmfiFC(fi);
        }

        int rpmfiNext(rpmfi fi) override
        {
            return ::rpmfiNext(fi);
        }

        const char* rpmfiFN(rpmfi fi) override
        {
            return ::rpmfiFN(fi);
        }

        rpmfi rpmfiFree(rpmfi fi) override
        {
            return ::rpmfiFree(fi);
        }
};
#endif //_RPMLIB_H
