#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <shared_mutex>
#include <stdexcept>

#include <base/logging.hpp>

#include <cmstore/cmstore.hpp>

#include "fileutils.hpp"
#include "storens.hpp"

namespace cm::store
{

const std::vector<NamespaceId> FORBIDDEN_NAMESPACES = {
    NamespaceId("output"),
    NamespaceId("system"),
    NamespaceId("default")
};

CMStore::~CMStore() = default;

CMStore::CMStore(std::string_view path, std::string_view outputsPath)
    : m_baseStoragePath(path)
    , m_defaultOutputsPath(outputsPath)
    , m_namespaces()
    , m_mutex()
{
    // Validate the base path
    if (!m_baseStoragePath.is_absolute() || m_baseStoragePath.empty())
    {
        throw std::runtime_error("Base path must be an absolute path");
    }
    if (!std::filesystem::exists(m_baseStoragePath) || !std::filesystem::is_directory(m_baseStoragePath))
    {
        throw std::runtime_error("Base path must exist and be a directory: " + m_baseStoragePath.string());
    }

    // Check if default outputs path exists, if path exist and is a directory
    if (!m_defaultOutputsPath.is_absolute() || m_defaultOutputsPath.empty())
    {
        throw std::runtime_error("Default outputs path does not exist: " + m_defaultOutputsPath.string());
    }
    if (!std::filesystem::exists(m_defaultOutputsPath) || !std::filesystem::is_directory(m_defaultOutputsPath))
    {
        throw std::runtime_error("Default outputs path is not a directory: " + m_defaultOutputsPath.string());
    }

    // Check if the base path is writable, avoiding check mode_t
    {
        // File test
        auto testPath = m_baseStoragePath / ".wazuh_test_write_permission";
        std::ofstream testFile(testPath);
        if (!testFile)
        {
            throw std::runtime_error("Cannot write to base path: " + m_baseStoragePath.string() + ": "
                                     + std::strerror(errno));
        }
        testFile.close();
        std::filesystem::remove(testPath);

        // Dir test
        auto testDirPath = m_baseStoragePath / ".wazuh_test_dir_permission";
        std::error_code ec;
        std::filesystem::create_directory(testDirPath, ec);
        if (ec)
        {
            throw std::runtime_error("Cannot create directory in base path: " + m_baseStoragePath.string() + ": "
                                     + ec.message());
        }
        std::filesystem::remove(testDirPath, ec);
    }

    // Load existing namespaces from disk
    loadAllNamespacesFromDisk();
}

void CMStore::loadAllNamespacesFromDisk()
{
    std::unique_lock lock(m_mutex);

    m_namespaces.clear();

    for (const auto& dirEntry : std::filesystem::directory_iterator(m_baseStoragePath))
    {
        if (!dirEntry.is_directory())
        {
            continue;
        }

        // Ignore forbidden namespaces
        NamespaceId nsIdCandidate(dirEntry.path().filename().string());
        if (std::find(FORBIDDEN_NAMESPACES.begin(), FORBIDDEN_NAMESPACES.end(), nsIdCandidate)
            != FORBIDDEN_NAMESPACES.end())
        {
            continue;
        }

        // Get namespace ID from directory name
        NamespaceId nsId(dirEntry.path().filename().string());

        // Load namespace
        auto nsInstance = std::make_shared<CMStoreNS>(nsId, dirEntry.path(), m_defaultOutputsPath);
        m_namespaces[nsId] = nsInstance;
    }
}

std::shared_ptr<ICMstoreNS> CMStore::createNamespace(const NamespaceId& nsId)
{
    std::unique_lock lock(m_mutex);

    // Check if namespace already exists
    if (m_namespaces.find(nsId) != m_namespaces.end())
    {
        throw std::runtime_error("Namespace already exists: " + nsId.toStr());
    }

    // Check if namespace is forbidden
    if (std::find(FORBIDDEN_NAMESPACES.begin(), FORBIDDEN_NAMESPACES.end(), nsId) != FORBIDDEN_NAMESPACES.end())
    {
        throw std::runtime_error("Namespace name is forbidden: " + nsId.toStr());
    }

    // Create namespace directory
    auto nsPath = m_baseStoragePath / nsId.toStr();
    if (std::filesystem::exists(nsPath))
    {
        throw std::runtime_error("Namespace directory already exists on disk: " + nsPath.string());
    }

    std::error_code ec;
    std::filesystem::create_directory(nsPath, ec);
    if (ec)
    {
        throw std::runtime_error("Failed to create namespace directory: " + nsPath.string() + ": " + ec.message());
    }

    // Set directory permissions to 0750
    auto dirPermErr = fileutils::setDirectoryPermissions(nsPath);
    if (dirPermErr)
    {
        throw std::runtime_error("Failed to set permissions on namespace directory: " + nsPath.string() + ": "
                                 + dirPermErr.value());
    }

    // Create empty cache file
    auto cacheFilePath = nsPath / pathns::CACHE_NS_FILE;
    auto cacheFileErr = fileutils::upsertFile(cacheFilePath, "[]");
    if (cacheFileErr.has_value())
    {
        throw std::runtime_error("Failed to create cache file for namespace: " + cacheFilePath.string() + ": "
                                 + cacheFileErr.value());
    }
    auto nsInstance = std::make_shared<CMStoreNS>(nsId, nsPath, m_defaultOutputsPath);
    m_namespaces[nsId] = nsInstance;

    return nsInstance;
}

void CMStore::deleteNamespace(const NamespaceId& nsId)
{
    std::unique_lock lock(m_mutex);

    // Check if namespace exists
    auto it = m_namespaces.find(nsId);
    if (it == m_namespaces.end())
    {
        throw std::runtime_error("Namespace does not exist: " + nsId.toStr());
    }

    // Check if read-only namespace (forbidden)
    if (std::find(FORBIDDEN_NAMESPACES.begin(), FORBIDDEN_NAMESPACES.end(), nsId) != FORBIDDEN_NAMESPACES.end())
    {
        throw std::runtime_error("Cannot delete read-only namespace: " + nsId.toStr());
    }

    // Abort if there are live shared_ptr CMStoreNS
    if (it->second.use_count() > 1)
    {
        throw std::runtime_error(fmt::format("Cannot delete namespace '{}': active references detected (use_count={})",
                                             nsId.toStr(),
                                             it->second.use_count()));
    }

    // Remove namespace directory from disk
    auto nsPath = m_baseStoragePath / nsId.toStr();
    std::error_code ec;
    std::filesystem::remove_all(nsPath, ec);
    if (ec)
    {
        throw std::runtime_error("Failed to delete namespace directory: " + nsPath.string() + ": " + ec.message());
    }

    // Remove from in-memory map
    m_namespaces.erase(it);
}

void CMStore::renameNamespace(const NamespaceId& from, const NamespaceId& to)
{
    std::unique_lock lock(m_mutex);

    auto itFrom = m_namespaces.find(from);
    if (itFrom == m_namespaces.end())
    {
        throw std::runtime_error("Namespace does not exist: " + from.toStr());
    }

    if (m_namespaces.find(to) != m_namespaces.end())
    {
        throw std::runtime_error("Namespace already exists: " + to.toStr());
    }

    if (std::find(FORBIDDEN_NAMESPACES.begin(), FORBIDDEN_NAMESPACES.end(), from) != FORBIDDEN_NAMESPACES.end())
    {
        throw std::runtime_error("Cannot rename read-only namespace: " + from.toStr());
    }
    if (std::find(FORBIDDEN_NAMESPACES.begin(), FORBIDDEN_NAMESPACES.end(), to) != FORBIDDEN_NAMESPACES.end())
    {
        throw std::runtime_error("Namespace name is forbidden: " + to.toStr());
    }

    const auto srcPath = m_baseStoragePath / from.toStr();
    const auto dstPath = m_baseStoragePath / to.toStr();

    if (!std::filesystem::exists(srcPath))
    {
        throw std::runtime_error("Namespace directory does not exist on disk: " + srcPath.string());
    }
    if (std::filesystem::exists(dstPath))
    {
        throw std::runtime_error("Namespace directory already exists on disk: " + dstPath.string());
    }

    // Abort if there are live shared_ptr outside the store (same policy as deleteNamespace).
    // Map holds exactly 1 reference; anything >1 means active readers/writers exist.
    const auto activeRefs = itFrom->second.use_count();
    if (activeRefs > 1)
    {
        throw std::runtime_error(
            fmt::format("Cannot rename namespace '{}' -> '{}': active references detected (use_count={})",
                        from.toStr(),
                        to.toStr(),
                        activeRefs));
    }

    // Keep the instance only to rollback the map if filesystem rename fails.
    auto oldPtr = std::move(itFrom->second);
    m_namespaces.erase(itFrom);

    std::error_code ec;
    std::filesystem::rename(srcPath, dstPath, ec);
    if (ec)
    {
        m_namespaces.emplace(from, std::move(oldPtr));
        throw std::runtime_error(fmt::format(
            "Failed to rename namespace directory: {} -> {}: {}", srcPath.string(), dstPath.string(), ec.message()));
    }

    auto newNsInstance = std::make_shared<CMStoreNS>(to, dstPath, m_defaultOutputsPath);
    m_namespaces.emplace(to, std::move(newNsInstance));
}

std::vector<NamespaceId> CMStore::getNamespaces() const
{
    std::shared_lock lock(m_mutex);

    std::vector<NamespaceId> nsIds;
    for (const auto& [nsId, nsPtr] : m_namespaces)
    {
        nsIds.push_back(nsId);
    }
    return nsIds;
}

bool CMStore::existsNamespace(const NamespaceId& nsId) const
{
    std::shared_lock lock(m_mutex);

    return m_namespaces.find(nsId) != m_namespaces.end();
}

std::shared_ptr<ICMstoreNS> CMStore::getNS(const NamespaceId& nsId)
{
    std::shared_lock lock(m_mutex);

    auto it = m_namespaces.find(nsId);
    if (it == m_namespaces.end())
    {
        throw std::runtime_error("Namespace does not exist: " + nsId.toStr());
    }
    return it->second;
}

std::shared_ptr<ICMStoreNSReader> CMStore::getNSReader(const NamespaceId& nsId) const
{
    std::shared_lock lock(m_mutex);

    auto it = m_namespaces.find(nsId);
    if (it == m_namespaces.end())
    {
        throw std::runtime_error("Namespace does not exist: " + nsId.toStr());
    }
    return it->second;
}

} // namespace cm::store
