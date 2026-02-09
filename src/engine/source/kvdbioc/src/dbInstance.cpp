#include <kvdbioc/dbInstance.hpp>

#include <stdexcept>

#include <rocksdb/db.h>

#include <base/json.hpp>
#include <fmt/format.h>

namespace kvdbioc
{

std::optional<json::Json> DbInstance::get(std::string_view key) const
{
    std::string value;
    auto status = m_db->Get(rocksdb::ReadOptions {}, rocksdb::Slice(key.data(), key.size()), &value);
    if (status.IsNotFound())
        return std::nullopt;
    if (!status.ok())
        throw std::runtime_error(fmt::format("RocksDB error: {}", status.ToString()));
    try
    {
        return json::Json(value.c_str());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("JSON parse error for key '{}': {}", key, e.what()));
    }
}

std::vector<std::optional<json::Json>> DbInstance::multiGet(const std::vector<std::string_view>& keys) const
{
    std::vector<std::optional<json::Json>> result;
    result.reserve(keys.size());
    std::vector<rocksdb::Slice> slices;
    slices.reserve(keys.size());
    for (const auto& key : keys) slices.emplace_back(key.data(), key.size());
    std::vector<std::string> values(keys.size());
    auto statuses = m_db->MultiGet(rocksdb::ReadOptions {}, slices, &values);
    for (size_t i = 0; i < keys.size(); ++i)
    {
        if (statuses[i].IsNotFound())
        {
            result.emplace_back(std::nullopt);
        }
        else if (!statuses[i].ok())
        {
            throw std::runtime_error(fmt::format("RocksDB error for key '{}': {}", keys[i], statuses[i].ToString()));
        }
        else
        {
            try
            {
                result.emplace_back(json::Json(values[i].c_str()));
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("JSON parse error for key '{}': {}", keys[i], e.what()));
            }
        }
    }
    return result;
}

void DbInstance::put(std::string_view key, std::string_view value)
{
    auto status = m_db->Put(
        rocksdb::WriteOptions {}, rocksdb::Slice(key.data(), key.size()), rocksdb::Slice(value.data(), value.size()));
    if (!status.ok())
    {
        throw std::runtime_error(fmt::format("RocksDB Put error: {}", status.ToString()));
    }
}

} // namespace kvdbioc
