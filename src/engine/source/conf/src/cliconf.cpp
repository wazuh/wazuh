#include <conf/cliconf.hpp>

#include <fmt/format.h>

namespace conf
{

const CLI::Option* CliConf::getOption(const std::string& key) const
{
    // Modules are nested by dots
    // Find the module holding the option
    const CLI::App* module = m_app.get();

    auto splitted = base::utils::string::split(key, '.');
    for (auto i = 0; i < splitted.size() - 1; ++i)
    {
        module = module->get_subcommand(splitted[i]);
    }

    std::string cliKey = "--";
    cliKey += splitted.back();

    return module->get_option(cliKey);
}

CLI::Option* CliConf::getOption(const std::string& key)
{
    return const_cast<CLI::Option*>(static_cast<const CliConf*>(this)->getOption(key));
}

CliConf::CliConf(CLI::App_p app)
    : m_app {app}
{
}

void CliConf::saveConfiguration(const std::string& path) const
{
    std::string pathStr = path.empty() ? get<std::string>("config") : path;

    auto savePath = std::filesystem::path(pathStr);

    // Create the directory if it does not exist
    if (!std::filesystem::exists(savePath.parent_path()))
    {
        std::error_code ec;
        if (!std::filesystem::create_directories(savePath.parent_path(), ec))
        {
            throw std::runtime_error(
                fmt::format("Cannot create directory tree '{}': {}", savePath.parent_path().string(), ec.message()));
        }
    }

    std::ofstream ofs;
    ofs.open(savePath, std::ios::out | std::ios::trunc);
    if (!ofs.is_open())
    {
        throw std::runtime_error(fmt::format("Cannot open file '{}': {}", savePath.string(), strerror(errno)));
    }
    ofs << getConfiguration() << std::endl;
    ofs.close();
}

std::string CliConf::getConfiguration() const
{
    auto fmtr = m_app->get_subcommand("server")->get_config_formatter();
    return fmtr->to_config(m_app->get_subcommand("server"), true, true, "server.");
}

void CliConf::put(const std::string& key, const std::string& value)
{
    auto opt = getOption(key);
    auto prev = opt->as<std::string>();
    // Config option does not behave like the rest
    // Only options with capture variable return the callback
    if ("--config" == opt->get_name())
    {
        throw std::runtime_error("Cannot modify config file path, restart the application specifying a "
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
        throw std::runtime_error("Invalid value '" + value + "' for option '" + key + "'");
    }
}

} // namespace conf
