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

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#endif

#define MAX_GROUPS_PER_MULTIGROUP 128
#define MAX_GROUP_NAME_LEN 256  // 255 + 1 for null terminator

#ifdef _WIN32
#define SHM_PATH "Global\\WazuhAgentMetadata"
#else
#define SHM_PATH "var/run/.wazuh_agent_metadata"
#endif

namespace
{
    /**
     * @brief Shared memory structure for agent metadata
     *
     * This structure is mapped to shared memory and accessible across processes.
     * Groups are stored inline to avoid pointer issues across process boundaries.
     */
    struct SharedMetadata
    {
#ifdef _WIN32
        LONG lock;  // Simple spinlock for Windows
#else
        pthread_mutex_t mutex;
#endif
        bool has_metadata;
        agent_metadata_t base_metadata;
        size_t groups_count;
        char groups[MAX_GROUPS_PER_MULTIGROUP][MAX_GROUP_NAME_LEN];
    };

    /**
     * @brief Cross-platform lock/unlock helpers
     */
    class ShmLock
    {
        public:
            explicit ShmLock(SharedMetadata* shm) : m_shm(shm)
            {
#ifdef _WIN32

                while (InterlockedCompareExchange(&m_shm->lock, 1, 0) != 0)
                {
                    SwitchToThread();
                }

#else
                pthread_mutex_lock(&m_shm->mutex);
#endif
            }

            ~ShmLock()
            {
#ifdef _WIN32
                InterlockedExchange(&m_shm->lock, 0);
#else
                pthread_mutex_unlock(&m_shm->mutex);
#endif
            }

        private:
            SharedMetadata* m_shm;
    };

    /**
     * @brief RAII wrapper for shared memory
     */
    class SharedMemoryProvider
    {
        public:
            static SharedMemoryProvider& instance()
            {
                static SharedMemoryProvider instance;
                return instance;
            }

            SharedMemoryProvider(const SharedMemoryProvider&) = delete;
            SharedMemoryProvider& operator=(const SharedMemoryProvider&) = delete;

            int update(const agent_metadata_t* metadata)
            {
                if (!metadata || !m_shm)
                {
                    return -1;
                }

                ShmLock lock(m_shm);

                // Copy scalar fields
                std::strncpy(m_shm->base_metadata.agent_id, metadata->agent_id, sizeof(m_shm->base_metadata.agent_id) - 1);
                m_shm->base_metadata.agent_id[sizeof(m_shm->base_metadata.agent_id) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.agent_name, metadata->agent_name, sizeof(m_shm->base_metadata.agent_name) - 1);
                m_shm->base_metadata.agent_name[sizeof(m_shm->base_metadata.agent_name) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.agent_version, metadata->agent_version, sizeof(m_shm->base_metadata.agent_version) - 1);
                m_shm->base_metadata.agent_version[sizeof(m_shm->base_metadata.agent_version) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.architecture, metadata->architecture, sizeof(m_shm->base_metadata.architecture) - 1);
                m_shm->base_metadata.architecture[sizeof(m_shm->base_metadata.architecture) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.hostname, metadata->hostname, sizeof(m_shm->base_metadata.hostname) - 1);
                m_shm->base_metadata.hostname[sizeof(m_shm->base_metadata.hostname) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.os_name, metadata->os_name, sizeof(m_shm->base_metadata.os_name) - 1);
                m_shm->base_metadata.os_name[sizeof(m_shm->base_metadata.os_name) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.os_type, metadata->os_type, sizeof(m_shm->base_metadata.os_type) - 1);
                m_shm->base_metadata.os_type[sizeof(m_shm->base_metadata.os_type) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.os_platform, metadata->os_platform, sizeof(m_shm->base_metadata.os_platform) - 1);
                m_shm->base_metadata.os_platform[sizeof(m_shm->base_metadata.os_platform) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.os_version, metadata->os_version, sizeof(m_shm->base_metadata.os_version) - 1);
                m_shm->base_metadata.os_version[sizeof(m_shm->base_metadata.os_version) - 1] = '\0';

                std::strncpy(m_shm->base_metadata.checksum_metadata, metadata->checksum_metadata, sizeof(m_shm->base_metadata.checksum_metadata) - 1);
                m_shm->base_metadata.checksum_metadata[sizeof(m_shm->base_metadata.checksum_metadata) - 1] = '\0';

                // Copy groups
                m_shm->groups_count = (metadata->groups_count > MAX_GROUPS_PER_MULTIGROUP) ? MAX_GROUPS_PER_MULTIGROUP : metadata->groups_count;

                for (size_t i = 0; i < m_shm->groups_count; ++i)
                {
                    if (metadata->groups && metadata->groups[i])
                    {
                        std::strncpy(m_shm->groups[i], metadata->groups[i], MAX_GROUP_NAME_LEN - 1);
                        m_shm->groups[i][MAX_GROUP_NAME_LEN - 1] = '\0';
                    }
                    else
                    {
                        m_shm->groups[i][0] = '\0';
                    }
                }

                m_shm->has_metadata = true;

                return 0;
            }

            int get(agent_metadata_t* out_metadata) const
            {
                if (!out_metadata || !m_shm)
                {
                    return -1;
                }

                ShmLock lock(m_shm);

                if (!m_shm->has_metadata)
                {
                    return -1;
                }

                // Copy scalar fields
                std::strncpy(out_metadata->agent_id, m_shm->base_metadata.agent_id, sizeof(out_metadata->agent_id) - 1);
                out_metadata->agent_id[sizeof(out_metadata->agent_id) - 1] = '\0';

                std::strncpy(out_metadata->agent_name, m_shm->base_metadata.agent_name, sizeof(out_metadata->agent_name) - 1);
                out_metadata->agent_name[sizeof(out_metadata->agent_name) - 1] = '\0';

                std::strncpy(out_metadata->agent_version, m_shm->base_metadata.agent_version, sizeof(out_metadata->agent_version) - 1);
                out_metadata->agent_version[sizeof(out_metadata->agent_version) - 1] = '\0';

                std::strncpy(out_metadata->architecture, m_shm->base_metadata.architecture, sizeof(out_metadata->architecture) - 1);
                out_metadata->architecture[sizeof(out_metadata->architecture) - 1] = '\0';

                std::strncpy(out_metadata->hostname, m_shm->base_metadata.hostname, sizeof(out_metadata->hostname) - 1);
                out_metadata->hostname[sizeof(out_metadata->hostname) - 1] = '\0';

                std::strncpy(out_metadata->os_name, m_shm->base_metadata.os_name, sizeof(out_metadata->os_name) - 1);
                out_metadata->os_name[sizeof(out_metadata->os_name) - 1] = '\0';

                std::strncpy(out_metadata->os_type, m_shm->base_metadata.os_type, sizeof(out_metadata->os_type) - 1);
                out_metadata->os_type[sizeof(out_metadata->os_type) - 1] = '\0';

                std::strncpy(out_metadata->os_platform, m_shm->base_metadata.os_platform, sizeof(out_metadata->os_platform) - 1);
                out_metadata->os_platform[sizeof(out_metadata->os_platform) - 1] = '\0';

                std::strncpy(out_metadata->os_version, m_shm->base_metadata.os_version, sizeof(out_metadata->os_version) - 1);
                out_metadata->os_version[sizeof(out_metadata->os_version) - 1] = '\0';

                std::strncpy(out_metadata->checksum_metadata, m_shm->base_metadata.checksum_metadata, sizeof(out_metadata->checksum_metadata) - 1);
                out_metadata->checksum_metadata[sizeof(out_metadata->checksum_metadata) - 1] = '\0';

                // Copy groups
                if (m_shm->groups_count > 0)
                {
                    out_metadata->groups = new char* [m_shm->groups_count];
                    out_metadata->groups_count = m_shm->groups_count;

                    for (size_t i = 0; i < m_shm->groups_count; ++i)
                    {
                        const size_t len = std::strlen(m_shm->groups[i]);
                        out_metadata->groups[i] = new char[len + 1];
                        std::strcpy(out_metadata->groups[i], m_shm->groups[i]);
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
                if (m_shm)
                {
                    ShmLock lock(m_shm);
                    m_shm->has_metadata = false;
                    m_shm->groups_count = 0;
                }
            }

        private:
            SharedMemoryProvider()
                : m_shm(nullptr)
#ifdef _WIN32
                , m_hMapFile(NULL)
#else
                , m_shm_fd(-1)
#endif
            {
#ifdef _WIN32
                // Windows: Use CreateFileMapping
                m_hMapFile = CreateFileMappingA(
                                 INVALID_HANDLE_VALUE,
                                 NULL,
                                 PAGE_READWRITE,
                                 0,
                                 sizeof(SharedMetadata),
                                 SHM_PATH);

                if (!m_hMapFile)
                {
                    return;
                }

                bool created = (GetLastError() != ERROR_ALREADY_EXISTS);

                m_shm = static_cast<SharedMetadata*>(MapViewOfFile(
                                                         m_hMapFile,
                                                         FILE_MAP_ALL_ACCESS,
                                                         0,
                                                         0,
                                                         sizeof(SharedMetadata)));

                if (!m_shm)
                {
                    CloseHandle(m_hMapFile);
                    m_hMapFile = NULL;
                    return;
                }

                if (created)
                {
                    m_shm->lock = 0;
                    m_shm->has_metadata = false;
                    m_shm->groups_count = 0;
                }

#else
                // Unix/Linux: Use mmap on a file
                m_shm_fd = open(SHM_PATH, O_RDWR | O_CREAT, 0600);

                if (m_shm_fd == -1)
                {
                    return;
                }

                struct stat st;

                bool created = (fstat(m_shm_fd, &st) == 0 && st.st_size < static_cast<off_t>(sizeof(SharedMetadata)));

                // Always set correct size
                if (ftruncate(m_shm_fd, sizeof(SharedMetadata)) == -1)
                {
                    close(m_shm_fd);
                    m_shm_fd = -1;
                    return;
                }

                m_shm = static_cast<SharedMetadata*>(mmap(
                                                         nullptr,
                                                         sizeof(SharedMetadata),
                                                         PROT_READ | PROT_WRITE,
                                                         MAP_SHARED,
                                                         m_shm_fd,
                                                         0));

                if (m_shm == MAP_FAILED)
                {
                    close(m_shm_fd);
                    m_shm_fd = -1;
                    m_shm = nullptr;
                    return;
                }

                if (created)
                {
                    pthread_mutexattr_t attr;
                    pthread_mutexattr_init(&attr);
                    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
                    pthread_mutex_init(&m_shm->mutex, &attr);
                    pthread_mutexattr_destroy(&attr);

                    m_shm->has_metadata = false;
                    m_shm->groups_count = 0;
                }

#endif
            }

            ~SharedMemoryProvider()
            {
#ifdef _WIN32

                if (m_shm)
                {
                    UnmapViewOfFile(m_shm);
                }

                if (m_hMapFile)
                {
                    CloseHandle(m_hMapFile);
                }

#else

                if (m_shm && m_shm != MAP_FAILED)
                {
                    munmap(m_shm, sizeof(SharedMetadata));
                }

                if (m_shm_fd != -1)
                {
                    close(m_shm_fd);
                }

#endif
            }

            SharedMetadata* m_shm;
#ifdef _WIN32
            HANDLE m_hMapFile;
#else
            int m_shm_fd;
#endif
    };
}

// C API implementation

int metadata_provider_update(const agent_metadata_t* metadata)
{
    return SharedMemoryProvider::instance().update(metadata);
}

int metadata_provider_get(agent_metadata_t* out_metadata)
{
    return SharedMemoryProvider::instance().get(out_metadata);
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
    SharedMemoryProvider::instance().reset();
}
