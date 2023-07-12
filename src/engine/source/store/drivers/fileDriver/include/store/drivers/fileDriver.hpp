#ifndef _FILE_DRIVER_H
#define _FILE_DRIVER_H

#include "name.hpp"
#include "store/istore.hpp"

#include <filesystem>
#include <fstream>

#include <json/json.hpp>

/**
 * @brief File driver for the store.
 *
 */
namespace store
{

/**
 * @brief File driver.
 *
 * This driver stores the jsons in the filesystem. Starting from the base path,
 * it organizes the jsons based on the store::base::Name, creating a directory hierarchy
 * following basePath/base::Name::m_type/base::Name::m_name/base::Name::m_version.json
 *
 */
class FileDriver : public IStore
{
private:
    std::filesystem::path m_path;

    std::filesystem::path nameToPath(const base::Name& name) const;

public:
    /**
     * @brief Construct a new File Driver object.
     *
     * @param path Base path for the driver.
     * @param create If true, the base path will be created if it doesn't exist.
     */
    FileDriver(const std::filesystem::path& path, bool create = false);
    ~FileDriver() = default;

    FileDriver(const FileDriver&) = delete;
    FileDriver& operator=(const FileDriver&) = delete;

    std::optional<base::Error> del(const base::Name& name) override;
    std::optional<base::Error> add(const base::Name& name, const json::Json& content) override;
    std::variant<json::Json, base::Error> get(const base::Name& name) const override;
    std::optional<base::Error> update(const base::Name& name, const json::Json& content) override;
    std::optional<base::Error> addUpdate(const base::Name& name, const json::Json& content) override;
};
} // namespace store

#endif // _FILE_DRIVER_H
