/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _LOCAL_IMAGE_READER_HPP
#define _LOCAL_IMAGE_READER_HPP

#include "iimage_reader.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief Reads image references from a local OCI image layout on disk.
    ///
    /// Walks an `oci-layout` directory: the top-level `index.json` lists the image
    /// manifests; each manifest points to a configuration blob that carries the
    /// platform metadata. No daemon connection and no external dependencies are used.
    class LocalImageReader final : public IImageReader
    {
        public:
            explicit LocalImageReader(std::string layoutPath);

            std::vector<ImageReferenceRecord> discover() override;
            std::string sourceType() const override;

        private:
            std::vector<ImageReferenceRecord> readOciLayout(const std::filesystem::path& layoutPath);

            std::string m_layoutPath;
    };
} // namespace containerimages

#endif // _LOCAL_IMAGE_READER_HPP
