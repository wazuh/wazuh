#include <filesystem>
#include <fstream>

#include <base/logging.hpp>
#include <base/utils/stringUtils.hpp>

#include <conf/fileLoader.hpp>

namespace conf
{

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
        line = base::utils::string::trim(line, " \t\r\n");

        // Ignore empty lines or comments
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        auto pos_dot = line.find('.');
        auto pos_eq = line.find('=');

        if (pos_dot == std::string::npos || pos_eq == std::string::npos || pos_dot > pos_eq)
        {
            LOG_WARNING("Invalid configuration line ignored: '{}'", line);
            continue;
        }

        std::string high = base::utils::string::trim(line.substr(0, pos_dot), " \t");
        std::string low = base::utils::string::trim(line.substr(pos_dot + 1, pos_eq - pos_dot - 1), " \t");
        std::string value = base::utils::string::trim(line.substr(pos_eq + 1), " \t\r\n");

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
    OptionMap config {};

    // First load internal options
    try
    {
        auto base = parseFile(m_internal);
        config.insert(base.begin(), base.end());
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to load internal options configuration: {}", e.what());
    }

    // Then overwrite with local internal options
    try
    {
        auto local = parseFile(m_local);
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
