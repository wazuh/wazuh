// SPDX-License-Identifier: AGPL-3.0-or-later
#include <base/managerConfig.hpp>

#include <base/json.hpp>

#include <memory>
#include <stdexcept>
#include <variant>

#include <manager_config/manager_config.hpp>

namespace
{
std::unique_ptr<manager_config::Document> g_document;

manager_config::LoadOptions loadOptions(const std::filesystem::path& home, bool checkFiles)
{
    manager_config::LoadOptions options;
    options.checkFiles = checkFiles;
    options.home = home;
    return options;
}

std::string stringMember(const json::Document& object, const char* key)
{
    const auto it = object.FindMember(key);
    if (it == object.MemberEnd() || !it->value.IsString())
    {
        return {};
    }
    return std::string(it->value.GetString(), it->value.GetStringLength());
}
} // namespace

namespace base::managerConfig
{

std::filesystem::path filePath()
{
    return std::filesystem::path(std::string(MANAGER_CONF_DIR)) / std::string(FILE_NAME);
}

void load(const std::filesystem::path& home, const std::filesystem::path& file)
{
    auto result = manager_config::Document::load(file, loadOptions(home, false));
    if (const auto* error = std::get_if<manager_config::Error>(&result))
    {
        throw std::runtime_error(error->what());
    }

    g_document = std::make_unique<manager_config::Document>(std::move(std::get<manager_config::Document>(result)));
}

std::optional<std::string> validate(const std::filesystem::path& home, const std::filesystem::path& file)
{
    if (const auto error = manager_config::validateFile(file, loadOptions(home, true)))
    {
        return error->what();
    }
    return std::nullopt;
}

bool isLoaded()
{
    return g_document != nullptr;
}

std::string sectionJson(std::string_view section)
{
    if (!g_document)
    {
        return {};
    }
    return g_document->sectionJson(section);
}

std::pair<std::string, std::string> clusterNames()
{
    const auto text = sectionJson("cluster");
    if (text.empty())
    {
        return {};
    }

    json::Document cluster;
    if (cluster.Parse(text.c_str()).HasParseError() || !cluster.IsObject())
    {
        return {};
    }

    return {stringMember(cluster, "name"), stringMember(cluster, "node_name")};
}

LogFormat logFormat()
{
    constexpr LogFormat DEFAULT_FORMAT {true, false};

    const auto text = sectionJson("logging");
    if (text.empty())
    {
        return DEFAULT_FORMAT;
    }

    json::Document section;
    if (section.Parse(text.c_str()).HasParseError() || !section.IsObject())
    {
        return DEFAULT_FORMAT;
    }

    const auto it = section.FindMember("log_format");
    if (it == section.MemberEnd() || !it->value.IsArray())
    {
        return DEFAULT_FORMAT;
    }

    LogFormat format {false, false};
    for (const auto& value : it->value.GetArray())
    {
        if (!value.IsString())
        {
            continue;
        }
        const std::string_view name(value.GetString(), value.GetStringLength());
        if (name == "plain")
        {
            format.plain = true;
        }
        else if (name == "json")
        {
            format.json = true;
        }
    }

    return (format.plain || format.json) ? format : DEFAULT_FORMAT;
}

void reset()
{
    g_document.reset();
}

} // namespace base::managerConfig
