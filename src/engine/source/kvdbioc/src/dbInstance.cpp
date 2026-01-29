#include <kvdbioc/dbInstance.hpp>

#include <stdexcept>

#include <rocksdb/db.h>

#include <base/json.hpp>
#include <fmt/format.h>

namespace kvdb
{

json::Json DbInstance::get(std::string_view key) const
{
    std::string value;
    auto status = m_db->Get(rocksdb::ReadOptions {}, rocksdb::Slice(key.data(), key.size()), &value);

    if (status.IsNotFound())
    {
        throw std::runtime_error(fmt::format("Key '{}' not found", key));
    }

    if (!status.ok())
    {
        throw std::runtime_error(fmt::format("RocksDB error: {}", status.ToString()));
    }

    // Parse JSON from stored string
    try
    {
        return json::Json(value.c_str());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("JSON parse error for key '{}': {}", key, e.what()));
    }
}

} // namespace kvdb
