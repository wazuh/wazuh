/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STUB_IMAGE_READER_HPP
#define _STUB_IMAGE_READER_HPP

#include "iimage_reader.hpp"

namespace containerimages
{
    /// @brief In-memory test double used to exercise the persistence path.
    ///
    /// It lives in the test tree on purpose: the shipped library must never produce
    /// synthetic inventory. Tests reach it through the reader factory the orchestrator
    /// takes as a constructor argument.
    ///
    /// Package extraction from image layers is not implemented yet, so this reader returns
    /// a small fixed inventory instead. The fixture mutates across successive scans (a
    /// package is added, one is changed, one is removed) so that create / modify / delete
    /// deltas are produced and can be observed.
    class StubImageReader final : public IImageReader
    {
        public:
            std::vector<ImageReferenceRecord> discover() override;
            std::string sourceType() const override;

        private:
            /// @brief Scan counter, used to vary the fixture between successive scans.
            static int s_scanCount;
    };
} // namespace containerimages

#endif // _STUB_IMAGE_READER_HPP
