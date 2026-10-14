#include <base/managerConfig.hpp>

#include <memory>
#include <stdexcept>
#include <variant>

#include <manager_config/manager_config.hpp>
#include <rapidjson/document.h>

#include <base/libwazuhshared.hpp>

namespace
{
std::unique_ptr<manager_config::Document> g_document;

/// cJSON_Parse of libwazuhext.so (dependency of libwazuhshared.so), resolved by registerSharedHook().
using ParseFn = void* (*)(const char*);
ParseFn g_parseFn = nullptr;

manager_config::LoadOptions loadOptions(const std::filesystem::path& home, bool checkFiles)
{
    manager_config::LoadOptions options;
    options.checkFiles = checkFiles;
    options.home = home;
    return options;
}

std::string stringMember(const rapidjson::Document& object, const char* key)
{
    const auto it = object.FindMember(key);
    if (it == object.MemberEnd() || !it->value.IsString())
    {
        return {};
    }
    return std::string(it->value.GetString(), it->value.GetStringLength());
}

// Section provider handed to libwazuhshared.so: the cJSON it returns is allocated by the shared
// library's own cJSON (libwazuhext.so), which is what its callers release with cJSON_Delete().
void* sectionProvider(const char* section)
{
    if (g_parseFn == nullptr || section == nullptr)
    {
        return nullptr;
    }

    const auto json = base::managerConfig::sectionJson(section);
    return json.empty() ? nullptr : g_parseFn(json.c_str());
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
    const auto json = sectionJson("cluster");
    if (json.empty())
    {
        return {};
    }

    rapidjson::Document cluster;
    if (cluster.Parse(json.c_str()).HasParseError() || !cluster.IsObject())
    {
        return {};
    }

    return {stringMember(cluster, "name"), stringMember(cluster, "node_name")};
}

void registerSharedHook()
{
    using HookSetFn = void (*)(void* (*)(const char*));
    const auto hookSet = base::libwazuhshared::getFunction<HookSetFn>("w_mconf_hook_set");
    g_parseFn = base::libwazuhshared::getFunction<ParseFn>("cJSON_Parse");
    hookSet(&sectionProvider);
}

void reset()
{
    g_document.reset();
}

} // namespace base::managerConfig
