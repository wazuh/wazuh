#ifndef _FILE_DRIVER_H
#define _FILE_DRIVER_H

#include "store/shared.hpp"
#include "store/store.hpp"

#include <filesystem>
#include <fstream>

#include <json/json.hpp>

/**
 * @brief File driver for the store.
 *
 */
namespace store::fileDriver
{

/**
 * @brief File driver.
 *
 * This driver stores the jsons in the filesystem. Starting from the base path,
 * it organizes the jsons based on the store::Name, creating a directory hierarchy following
 * basePath/Name::m_type/Name::m_name/Name::m_version.json
 *
 */
class FileDriver : public IStore
{
private:
    std::filesystem::path m_path;

    std::filesystem::path nameToPath(const Name& name) const;

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

    std::optional<Error> del(const Name& name) override;
    std::optional<Error> add(const Name& name, const json::Json& content) override;
    std::variant<json::Json, Error> get(const Name& name) const override;
};
} // namespace store::fileDriver

#endif // _FILE_DRIVER_H
