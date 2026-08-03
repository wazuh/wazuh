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
    /// @brief Temporary in-memory reader used to exercise the persistence and sync path.
    ///
    /// Real package extraction (OCI/local image reading) is deferred to a later stage.
    /// Until then this reader returns a small fixed inventory so the DBSync storage and
    /// the agent sync protocol can be validated end to end. The fixture mutates across
    /// successive scans (a package is added, one is changed, one is removed) so that
    /// create / modify / delete deltas are produced and can be observed.
    ///
    /// This class is the seam that the real readers will replace; nothing downstream
    /// depends on it.
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
