#ifndef _FILE_DRIVER_H
#define _FILE_DRIVER_H

#include <store/idriver.hpp>

#include <filesystem>
#include <fstream>

/**
 * @brief File driver for the store.
 *
 */
namespace store::drivers
{

/**
 * @brief File driver.
 *
 * This driver stores the jsons in the filesystem. Starting from the base path,
 * it organizes the jsons based on the store::base::Name, creating a directory hierarchy
 * following basePath/base::Name::m_type/base::Name::m_name/base::Name::m_version.json
 *
 */
class FileDriver : public IDriver
{
private:
    std::filesystem::path m_path;

    std::filesystem::path nameToPath(const base::Name& name) const;

    base::OptError removeEmptyParentDirs(const std::filesystem::path& path, const base::Name& name);

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

    /**
     * @copydoc IDriver::createDoc
     */
    base::OptError createDoc(const base::Name& name, const json::Json& content) override;

    /**
     * @copydoc IDriver::readDoc
     */
    base::RespOrError<Doc> readDoc(const base::Name& name) const override;

    /**
     * @copydoc IDriver::updateDoc
     */
    base::OptError updateDoc(const base::Name& name, const json::Json& content) override;

    /**
     * @copydoc IDriver::upsertDoc
     */
    base::OptError upsertDoc(const base::Name& name, const json::Json& content) override;

    /**
     * @copydoc IDriver::deleteDoc
     */
    base::OptError deleteDoc(const base::Name& name) override;

    /**
     * @copydoc IDriver::readCol
     */
    base::RespOrError<Col> readCol(const base::Name& name) const override;

    /**
     * @copydoc IDriver::readCol
     */
    base::RespOrError<Col> readRoot() const override;

    /**
     * @copydoc IDriver::deleteCol
     */
    base::OptError deleteCol(const base::Name& name) override;

    /**
     * @copydoc IDriver::exists
     */
    bool exists(const base::Name& name) const override;

    /**
     * @copydoc IDriver::existsDoc
     */
    bool existsDoc(const base::Name& name) const override;

    /**
     * @copydoc IDriver::existsCol
     */
    bool existsCol(const base::Name& name) const override;
};
} // namespace store::drivers

#endif // _FILE_DRIVER_H
