/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "metadata_provider.h"

#include <cstring>
#include <mutex>

namespace
{

    /**
     * @brief Thread-safe singleton metadata provider implementation
     */
    class MetadataProviderImpl
    {
        public:
            static MetadataProviderImpl& instance()
            {
                static MetadataProviderImpl instance;
                return instance;
            }

            // Delete copy/move constructors
            MetadataProviderImpl(const MetadataProviderImpl&) = delete;
            MetadataProviderImpl& operator=(const MetadataProviderImpl&) = delete;

            int update(const agent_metadata_t* metadata)
            {
                if (!metadata)
                {
                    return -1;
                }

                std::lock_guard<std::mutex> lock(m_mutex);

                // Copy scalar fields
                std::strncpy(m_metadata.agent_id, metadata->agent_id, sizeof(m_metadata.agent_id) - 1);
                std::strncpy(m_metadata.agent_name, metadata->agent_name, sizeof(m_metadata.agent_name) - 1);
                std::strncpy(m_metadata.agent_version, metadata->agent_version, sizeof(m_metadata.agent_version) - 1);
                std::strncpy(m_metadata.architecture, metadata->architecture, sizeof(m_metadata.architecture) - 1);
                std::strncpy(m_metadata.hostname, metadata->hostname, sizeof(m_metadata.hostname) - 1);
                std::strncpy(m_metadata.os_name, metadata->os_name, sizeof(m_metadata.os_name) - 1);
                std::strncpy(m_metadata.os_type, metadata->os_type, sizeof(m_metadata.os_type) - 1);
                std::strncpy(m_metadata.os_platform, metadata->os_platform, sizeof(m_metadata.os_platform) - 1);
                std::strncpy(m_metadata.os_version, metadata->os_version, sizeof(m_metadata.os_version) - 1);
                std::strncpy(m_metadata.checksum_metadata, metadata->checksum_metadata, sizeof(m_metadata.checksum_metadata) - 1);

                // Free old groups
                freeGroups();

                // Copy groups
                if (metadata->groups_count > 0 && metadata->groups)
                {
                    m_metadata.groups = new char* [metadata->groups_count];
                    m_metadata.groups_count = metadata->groups_count;

                    for (size_t i = 0; i < metadata->groups_count; ++i)
                    {
                        const size_t len = std::strlen(metadata->groups[i]);
                        m_metadata.groups[i] = new char[len + 1];
                        std::strcpy(m_metadata.groups[i], metadata->groups[i]);
                    }
                }
                else
                {
                    m_metadata.groups = nullptr;
                    m_metadata.groups_count = 0;
                }

                m_has_metadata = true;

                return 0;
            }

            int get(agent_metadata_t* out_metadata) const
            {
                if (!out_metadata)
                {
                    return -1;
                }

                std::lock_guard<std::mutex> lock(m_mutex);

                if (!m_has_metadata)
                {
                    return -1;
                }

                // Copy scalar fields
                std::strncpy(out_metadata->agent_id, m_metadata.agent_id, sizeof(out_metadata->agent_id) - 1);
                std::strncpy(out_metadata->agent_name, m_metadata.agent_name, sizeof(out_metadata->agent_name) - 1);
                std::strncpy(out_metadata->agent_version, m_metadata.agent_version, sizeof(out_metadata->agent_version) - 1);
                std::strncpy(out_metadata->architecture, m_metadata.architecture, sizeof(out_metadata->architecture) - 1);
                std::strncpy(out_metadata->hostname, m_metadata.hostname, sizeof(out_metadata->hostname) - 1);
                std::strncpy(out_metadata->os_name, m_metadata.os_name, sizeof(out_metadata->os_name) - 1);
                std::strncpy(out_metadata->os_type, m_metadata.os_type, sizeof(out_metadata->os_type) - 1);
                std::strncpy(out_metadata->os_platform, m_metadata.os_platform, sizeof(out_metadata->os_platform) - 1);
                std::strncpy(out_metadata->os_version, m_metadata.os_version, sizeof(out_metadata->os_version) - 1);
                std::strncpy(out_metadata->checksum_metadata, m_metadata.checksum_metadata, sizeof(out_metadata->checksum_metadata) - 1);

                // Copy groups
                if (m_metadata.groups_count > 0 && m_metadata.groups)
                {
                    out_metadata->groups = new char* [m_metadata.groups_count];
                    out_metadata->groups_count = m_metadata.groups_count;

                    for (size_t i = 0; i < m_metadata.groups_count; ++i)
                    {
                        const size_t len = std::strlen(m_metadata.groups[i]);
                        out_metadata->groups[i] = new char[len + 1];
                        std::strcpy(out_metadata->groups[i], m_metadata.groups[i]);
                    }
                }
                else
                {
                    out_metadata->groups = nullptr;
                    out_metadata->groups_count = 0;
                }

                return 0;
            }

            void reset()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                freeGroups();
                m_has_metadata = false;
            }

        private:
            MetadataProviderImpl() = default;
            ~MetadataProviderImpl()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                freeGroups();
            }

            void freeGroups()
            {
                if (m_metadata.groups)
                {
                    for (size_t i = 0; i < m_metadata.groups_count; ++i)
                    {
                        delete[] m_metadata.groups[i];
                    }

                    delete[] m_metadata.groups;
                    m_metadata.groups = nullptr;
                }

                m_metadata.groups_count = 0;
            }

            mutable std::mutex m_mutex;
            bool m_has_metadata{false};
            agent_metadata_t m_metadata{};
    };
}

// C API implementation

int metadata_provider_update(const agent_metadata_t* metadata)
{
    return MetadataProviderImpl::instance().update(metadata);
}

int metadata_provider_get(agent_metadata_t* out_metadata)
{
    return MetadataProviderImpl::instance().get(out_metadata);
}

void metadata_provider_free_metadata(agent_metadata_t* metadata)
{
    if (!metadata)
    {
        return;
    }

    if (metadata->groups)
    {
        for (size_t i = 0; i < metadata->groups_count; ++i)
        {
            delete[] metadata->groups[i];
        }

        delete[] metadata->groups;
        metadata->groups = nullptr;
    }

    metadata->groups_count = 0;
}

void metadata_provider_reset(void)
{
    MetadataProviderImpl::instance().reset();
}
