#include <stdexcept>

#include <fmt/format.h>

#include <kvdbioc/dbHandle.hpp>
#include <kvdbioc/dbInstance.hpp>

namespace kvdb
{

json::Json DbHandle::get(std::string_view key) const
{
    auto inst = load();
    if (!inst)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': no instance published", m_name));
    }
    return inst->get(key);
}

bool DbHandle::hasBuild() const
{
    std::lock_guard<std::mutex> lk(m_buildMutex);
    return m_buildState.has_value();
}

BuildState& DbHandle::getBuild()
{
    std::lock_guard<std::mutex> lk(m_buildMutex);
    if (!m_buildState.has_value())
    {
        throw std::runtime_error("No build in progress");
    }
    return m_buildState.value();
}

void DbHandle::startBuild(BuildState state)
{
    std::lock_guard<std::mutex> lk(m_buildMutex);
    if (m_buildState.has_value())
    {
        throw std::runtime_error("Build already in progress");
    }
    m_buildState = std::move(state);
}

BuildState DbHandle::extractBuild()
{
    std::lock_guard<std::mutex> lk(m_buildMutex);
    if (!m_buildState.has_value())
    {
        throw std::runtime_error("No build to extract");
    }
    auto state = std::move(m_buildState.value());
    m_buildState.reset();
    return state;
}

void DbHandle::putValue(std::string_view key, std::string_view value)
{
    std::lock_guard<std::mutex> lk(m_buildMutex);
    if (!m_buildState.has_value())
    {
        throw std::runtime_error("No build in progress");
    }
    auto status = m_buildState->db->Put(
        rocksdb::WriteOptions {}, rocksdb::Slice(key.data(), key.size()), rocksdb::Slice(value.data(), value.size()));
    if (!status.ok())
    {
        throw std::runtime_error(std::string("Put failed: ") + status.ToString());
    }
}

} // namespace kvdb
