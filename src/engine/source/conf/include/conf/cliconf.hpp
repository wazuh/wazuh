#ifndef _CLI_CONF_HPP
#define _CLI_CONF_HPP

#include <algorithm>
#include <filesystem>
#include <fstream>

#include <CLI/CLI.hpp>

#include <utils/stringUtils.hpp>

namespace conf
{
class CliConf
{
private:
    CLI::App_p m_app;

    const CLI::Option* getOption(const std::string& key) const
    {
        // Modules are nested by dots
        // Find the module holding the option
        const CLI::App* module = m_app.get();

        auto splitted = utils::string::split(key, '.');
        for (auto i = 0; i < splitted.size() - 1; ++i)
        {
            module = module->get_subcommand(splitted[i]);
        }

        std::string cliKey = "--";
        cliKey += splitted.back();

        return module->get_option(cliKey);
    }

    CLI::Option* getOption(const std::string& key)
    {
        return const_cast<CLI::Option*>(
            static_cast<const CliConf*>(this)->getOption(key));
    }

public:
    explicit CliConf(CLI::App_p app)
        : m_app {app}
    {
    }

    template<typename T>
    T get(const std::string& key) const
    {
        return getOption(key)->as<T>();
    }

    void saveConfiguration(const std::string& path = "") const
    {
        std::string pathStr = path.empty() ? get<std::string>("config") : path;

        auto savePath = std::filesystem::path(pathStr);

        std::ofstream ofs;
        ofs.open(savePath, std::ios::out | std::ios::trunc);
        ofs << getConfiguration() << std::endl;
        ofs.close();
    }

    std::string getConfiguration() const
    {
        auto fmtr = m_app->get_subcommand("server")->get_config_formatter();
        return fmtr->to_config(m_app->get_subcommand("server"), true, true, "server.");
    }

    void put(const std::string& key, const std::string& value)
    {
        auto opt = getOption(key);
        auto prev = opt->as<std::string>();
        // Config option does not behave like the rest
        // Only options with capture variable return the callback
        if (opt->get_name() == "--config")
        {
            throw std::runtime_error(
                "Cannot modify config file path, restart the application specifying a "
                "new path with --config 'path'");
        }

        auto callback = opt->get_callback();
        std::vector<std::string> args {value};
        if (callback(args))
        {
            try
            {
                opt->clear();
                opt->add_result(value)->as<std::string>();
            }
            catch (...)
            {
                opt->clear();
                opt->add_result(prev);
                throw;
            }
        }
        else
        {
            throw std::runtime_error("Invalid value '" + value + "'for option '" + key
                                     + "'");
        }
    }
};
} // namespace conf

#endif // _CLI_CONF_HPP
