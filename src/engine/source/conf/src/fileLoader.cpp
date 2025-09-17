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

static std::string strip_outer_quotes(std::string s)
{
    // Remove surrounding quotes if they are the same type (single or double) and balanced
    if (s.size() >= 2)
    {
        char a = s.front();
        char b = s.back();
        if ((a == '"' && b == '"') || (a == '\'' && b == '\''))
        {
            s.erase(s.begin()); // remove first char
            s.pop_back();       // remove last char
        }
    }
    return s;
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
        // Trim the line and skip empty lines or full-line comments
        line = base::utils::string::trim(line, " \t\r\n");
        if (line.empty() || line[0] == '#')
            continue;

        // Find positions of '.' and '=' to split into high.key=value
        auto pos_eq = line.find('=');
        auto pos_dot = line.find('.');
        if (pos_eq == std::string::npos || pos_dot == std::string::npos || pos_dot > pos_eq)
        {
            LOG_WARNING("Invalid configuration line ignored: '{}'", line);
            continue;
        }

        std::string high = base::utils::string::trim(line.substr(0, pos_dot), " \t");
        std::string low = base::utils::string::trim(line.substr(pos_dot + 1, pos_eq - pos_dot - 1), " \t");

        // Only parse keys under "analysisd"
        if (high != "analysisd")
            continue;

        // Extract the right-hand side (RHS) after '='
        std::string rhs = line.substr(pos_eq + 1);

        // Split on unescaped '#' (inline comments)
        auto parts = base::utils::string::splitEscaped(rhs, '#', '\\');
        std::string value = parts.empty() ? std::string {} : parts.front();

        // Trim whitespace from the value
        value = base::utils::string::trim(value, " \t\r\n");

        // Unescape sequences like \#, \\, \", \'
        value = base::utils::string::unescapeString(value, '\\', "#\\\"'", /*strictMode=*/false);

        // Remove surrounding quotes if present
        value = strip_outer_quotes(value);

        // Store in the result map
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
