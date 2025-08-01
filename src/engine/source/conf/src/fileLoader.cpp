#include <filesystem>
#include <fstream>

#include <base/logging.hpp>
#include <conf/fileLoader.hpp>

namespace conf
{
constexpr auto OSSEC_DEFINES  = "etc/internal_options.conf";
constexpr auto OSSEC_LDEFINES = "etc/local_internal_options.conf";

static std::string makeKey(const std::string& high, const std::string& low)
{
    return high + "." + low;
}

static OptionMap parseFile(const std::filesystem::path& path)
{
    OptionMap result;
    std::ifstream file(path);

    if (!file.is_open())
    {
        throw std::runtime_error("Cannot open configuration file: " + path.string());
    }

    std::string line;
    while (std::getline(file, line))
    {
        // Trim start and end
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // Ignore empty lines or comments
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        auto pos_dot = line.find('.');
        auto pos_eq  = line.find('=');

        if (pos_dot == std::string::npos || pos_eq == std::string::npos || pos_dot > pos_eq)
        {
            LOG_WARNING("Invalid configuration line ignored: '{}'", line);
            continue;
        }

        std::string high = line.substr(0, pos_dot);
        std::string low  = line.substr(pos_dot + 1, pos_eq - pos_dot - 1);
        std::string value = line.substr(pos_eq + 1);

        // Trim
        high.erase(0, high.find_first_not_of(" \t"));
        high.erase(high.find_last_not_of(" \t") + 1);
        low.erase(0, low.find_first_not_of(" \t"));
        low.erase(low.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);

        // Only engine configuration
        if (high != "engine")
        {
            continue;
        }

        result[makeKey(high, low)] = value;
    }

    return result;
}

OptionMap FileLoader::load() const
{
    OptionMap config;

    // First load internal options
    try
    {
        auto base = parseFile(OSSEC_DEFINES);
        config.insert(base.begin(), base.end());
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to load internal options configuration: {}", e.what());
    }

    // Then overwrite with local internal options
    try
    {
        auto local = parseFile(OSSEC_LDEFINES);
        config.insert(local.begin(), local.end()); // does not overwrite if it already exists
        for (const auto& [k, v] : local)
        {
            config[k] = v; // this does overwrite
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to load local internal options configuration: {}", e.what());
    }

    return config;
}

} // namespace conf
