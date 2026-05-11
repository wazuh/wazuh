#ifndef _CONF_FILELOADER_HPP
#define _CONF_FILELOADER_HPP

#include <filesystem>

namespace conf
{

using OptionMap = std::unordered_map<std::string, std::string>; // (full_key, value)
constexpr auto WAZUH_LDEFINES = "/var/wazuh-manager/etc/wazuh-manager-internal-options.conf";

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

public:
    FileLoader(std::filesystem::path path = WAZUH_LDEFINES)
        : m_path(std::move(path))
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
