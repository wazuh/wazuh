#ifndef _CONF_FILELOADER_HPP
#define _CONF_FILELOADER_HPP

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
public:
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
