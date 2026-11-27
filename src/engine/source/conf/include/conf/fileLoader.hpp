// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CONF_FILELOADER_HPP
#define _CONF_FILELOADER_HPP

#include <filesystem>
#include <optional>

#include <sys/types.h>

namespace conf
{

using OptionMap = std::unordered_map<std::string, std::string>; // (full_key, value)

struct IFileLoader
{
protected:
    /**
     * @brief Load the configuration from the API.
     *
     * @throw std::runtime_error If cannot retrieve the configuration from the framework API.
     * @return ConfigMap
     */
    virtual OptionMap load() const = 0;

public:
    virtual ~IFileLoader() = default;

    /**
     * @brief Load the configuration from the API.
     *
     * @throw std::runtime_error If cannot retrieve the configuration from the framework API.
     * @return ConfigMap
     */
    OptionMap operator()() const { return load(); }
};

class FileLoader : public IFileLoader
{
private:
    std::filesystem::path m_path;
    std::optional<uid_t> m_euid;

public:
    /**
     * @param path Configuration file.
     * @param euid User the file may also be owned by besides root; the process's effective user when empty. Tests
     * set it to stand for another user; production callers leave it empty.
     */
    FileLoader(std::filesystem::path path, std::optional<uid_t> euid = std::nullopt)
        : m_path(std::move(path))
        , m_euid(euid)
    {
    }
    /**
     * @brief Load the configuration from the file.
     *
     * @throw std::runtime_error If cannot read the configuration file.
     * @return OptionMap
     */
    OptionMap load() const override;
};

} // namespace conf

#endif // _CONF_FILELOADER_HPP
