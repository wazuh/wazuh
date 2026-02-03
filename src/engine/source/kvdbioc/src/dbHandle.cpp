#include <stdexcept>

#include <fmt/format.h>

#include <kvdbioc/dbHandle.hpp>
#include <kvdbioc/dbInstance.hpp>

namespace kvdbioc
{

std::optional<json::Json> DbHandle::get(std::string_view key) const
{
    // Load published instance (lock-free atomic load)
    auto inst = load();

    if (!inst)
    {
        auto currentState = state();
        if (currentState == DbState::DELETING)
        {
            throw std::runtime_error(fmt::format("KVDB '{}': database is being deleted", m_name));
        }
        throw std::runtime_error(fmt::format("KVDB '{}': no instance available", m_name));
    }

    // Read from instance (DB is open in r/w mode, reads are safe)
    return inst->get(key);
}

std::vector<std::optional<json::Json>> DbHandle::multiGet(const std::vector<std::string_view>& keys) const
{
    // Load published instance (lock-free atomic load)
    auto inst = load();

    if (!inst)
    {
        auto currentState = state();
        if (currentState == DbState::DELETING)
        {
            throw std::runtime_error(fmt::format("KVDB '{}': database is being deleted", m_name));
        }
        throw std::runtime_error(fmt::format("KVDB '{}': no instance available", m_name));
    }

    // Read all keys from same instance (consistency!)
    return inst->multiGet(keys);
}

void DbHandle::putValue(std::string_view key, std::string_view value)
{
    // Load current instance
    auto inst = load();
    if (!inst)
    {
        throw std::runtime_error(fmt::format("KVDB '{}': no instance available", m_name));
    }

    // Write directly to the DB (open in r/w mode)
    inst->put(key, value);
}

} // namespace kvdbioc
