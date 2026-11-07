// SPDX-License-Identifier: AGPL-3.0-or-later
#include <wiconnector/engineConfigSource.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <set>
#include <utility>

#include <keyStore.hpp>

namespace wiconnector
{

namespace
{

constexpr std::string_view ENGINE_KEY_PREFIX {"analysisd."};
constexpr std::string_view ENVIRONMENT_PREFIX {"WAZUH_"};

/// A v1 key (seconds) that feeds its v2 equivalent (milliseconds) when the v2 key is not set (I192).
struct LegacyMapping
{
    std::string_view v2Key;
    std::string_view v1Key;
};

constexpr LegacyMapping LEGACY_MAPPINGS[] {
    {"analysisd.indexer_client_request_timeout_ms", "analysisd.indexer_request_timeout"},
    {"analysisd.indexer_client_probe_interval_ms", "analysisd.indexer_monitoring_interval"},
};

const LegacyMapping* mappingForV2(std::string_view key)
{
    for (const auto& mapping : LEGACY_MAPPINGS)
    {
        if (mapping.v2Key == key)
        {
            return &mapping;
        }
    }
    return nullptr;
}

/// An unsigned decimal integer with no sign, blank or suffix; nullopt otherwise or on overflow.
std::optional<std::uint64_t> parseUnsigned(std::string_view text)
{
    if (text.empty())
    {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const char c : text)
    {
        if (c < '0' || c > '9')
        {
            return std::nullopt;
        }
        const auto digit = static_cast<std::uint64_t>(c - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
        {
            return std::nullopt;
        }
        value = value * 10 + digit;
    }
    return value;
}

/// The v1 value in milliseconds, or why it cannot be used.
struct LegacyValue
{
    std::optional<std::uint64_t> milliseconds; ///< nullopt for 0 ("no limit") or an unusable value.
    std::optional<std::string> problem;
};

LegacyValue convertLegacy(std::string_view v1Key, const std::string& text)
{
    const auto seconds = parseUnsigned(text);
    if (!seconds)
    {
        return {std::nullopt, std::string {v1Key} + ": '" + text + "' is not an unsigned decimal number of seconds"};
    }
    if (*seconds > std::numeric_limits<std::uint64_t>::max() / 1000)
    {
        return {std::nullopt, std::string {v1Key} + ": '" + text + "' seconds is not representable in milliseconds"};
    }
    if (*seconds == 0)
    {
        return {std::nullopt, std::nullopt};
    }
    return {*seconds * 1000, std::nullopt};
}

} // namespace

EngineConfigSource::EngineConfigSource(std::string indexerSectionJson,
                                       std::map<std::string, std::string> fileOptions,
                                       CredentialsProvider credentials,
                                       std::function<std::optional<std::string>(const std::string&)> environment,
                                       std::function<std::vector<std::string>()> environmentNames)
    : m_indexerSectionJson(std::move(indexerSectionJson))
    , m_fileOptions(std::move(fileOptions))
    , m_credentials(std::move(credentials))
    , m_environment(std::move(environment))
    , m_environmentNames(std::move(environmentNames))
{
}

std::string EngineConfigSource::environmentName(std::string_view key)
{
    if (key.substr(0, ENGINE_KEY_PREFIX.size()) == ENGINE_KEY_PREFIX)
    {
        key.remove_prefix(ENGINE_KEY_PREFIX.size());
    }
    std::string name {ENVIRONMENT_PREFIX};
    name.reserve(name.size() + key.size());
    for (const char c : key)
    {
        name += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return name;
}

namespace
{

/// The key an environment variable name stands for (`WAZUH_X_Y` → `analysisd.x_y`), or nullopt.
std::optional<std::string> keyForEnvironmentName(std::string_view name)
{
    if (name.size() <= ENVIRONMENT_PREFIX.size() || name.substr(0, ENVIRONMENT_PREFIX.size()) != ENVIRONMENT_PREFIX)
    {
        return std::nullopt;
    }
    name.remove_prefix(ENVIRONMENT_PREFIX.size());
    std::string key {ENGINE_KEY_PREFIX};
    key.reserve(key.size() + name.size());
    for (const char c : name)
    {
        key += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return key;
}

/// Environment first, then the internal options file (empty in standalone mode), else unset (I26, I191).
std::optional<std::string> lookupIn(const std::function<std::optional<std::string>(const std::string&)>& environment,
                                    const std::map<std::string, std::string>& fileOptions,
                                    std::string_view key)
{
    if (environment)
    {
        if (auto value = environment(EngineConfigSource::environmentName(key)))
        {
            return value;
        }
    }
    const auto it = fileOptions.find(std::string {key});
    if (it != fileOptions.end())
    {
        return it->second;
    }
    return std::nullopt;
}

} // namespace

std::optional<std::string> EngineConfigSource::raw(std::string_view key) const
{
    const auto lookup = [this](std::string_view k)
    {
        return lookupIn(m_environment, m_fileOptions, k);
    };
    if (auto value = lookup(key))
    {
        return value;
    }
    if (const auto* mapping = mappingForV2(key))
    {
        if (const auto legacy = lookup(mapping->v1Key))
        {
            const auto converted = convertLegacy(mapping->v1Key, *legacy);
            if (converted.milliseconds)
            {
                return std::to_string(*converted.milliseconds);
            }
        }
    }
    return std::nullopt;
}

std::vector<std::string> EngineConfigSource::keysWithPrefix(std::string_view prefix) const
{
    const auto lookup = [this](std::string_view k)
    {
        return lookupIn(m_environment, m_fileOptions, k);
    };
    std::set<std::string> keys;
    const auto underPrefix = [prefix](std::string_view key)
    {
        return key.substr(0, prefix.size()) == prefix;
    };

    for (const auto& [key, value] : m_fileOptions)
    {
        if (underPrefix(key))
        {
            keys.insert(key);
        }
    }
    if (m_environmentNames)
    {
        for (const auto& name : m_environmentNames())
        {
            if (auto key = keyForEnvironmentName(name); key && underPrefix(*key))
            {
                keys.insert(std::move(*key));
            }
        }
    }
    // A v2 key fed by its v1 key is present too, so problem() is asked about an unusable v1 value.
    for (const auto& mapping : LEGACY_MAPPINGS)
    {
        if (underPrefix(mapping.v2Key) && lookup(mapping.v1Key))
        {
            keys.emplace(mapping.v2Key);
        }
    }
    return {keys.begin(), keys.end()};
}

std::optional<std::string> EngineConfigSource::problem(std::string_view key) const
{
    const auto lookup = [this](std::string_view k)
    {
        return lookupIn(m_environment, m_fileOptions, k);
    };
    const auto value = lookup(key);
    if (value && value->empty())
    {
        return std::string {key} + ": empty value";
    }

    const auto* mapping = mappingForV2(key);
    if (mapping == nullptr)
    {
        return std::nullopt;
    }
    const auto legacy = lookup(mapping->v1Key);
    if (!legacy)
    {
        return std::nullopt;
    }
    const auto converted = convertLegacy(mapping->v1Key, *legacy);
    if (converted.problem)
    {
        return converted.problem;
    }
    const auto explicitMs = value ? parseUnsigned(*value) : std::nullopt;
    if (explicitMs && converted.milliseconds && *explicitMs != *converted.milliseconds)
    {
        return std::string {key} + " (" + *value + " ms) and " + std::string {mapping->v1Key} + " (" + *legacy
               + " s) are both set and differ; set only one of them";
    }
    return std::nullopt;
}

std::string EngineConfigSource::indexerSectionJson() const
{
    return m_indexerSectionJson;
}

indexer_client::Credentials EngineConfigSource::credentials() const
{
    if (!m_credentials)
    {
        return {};
    }
    return m_credentials();
}

std::vector<std::string> EngineConfigSource::warnings() const
{
    const auto lookup = [this](std::string_view k)
    {
        return lookupIn(m_environment, m_fileOptions, k);
    };
    std::vector<std::string> notes;
    for (const auto& mapping : LEGACY_MAPPINGS)
    {
        const auto legacy = lookup(mapping.v1Key);
        if (!legacy)
        {
            continue;
        }
        const auto converted = convertLegacy(mapping.v1Key, *legacy);
        if (converted.problem)
        {
            continue; // Reported by problem(): the start fails.
        }
        if (!converted.milliseconds)
        {
            notes.push_back(std::string {mapping.v1Key} + "=0 (no limit) has no equivalent in the indexer client; "
                            + std::string {mapping.v2Key} + " keeps "
                            + (lookup(mapping.v2Key) ? std::string {"its own value"} : std::string {"its default"}));
        }
        else if (!lookup(mapping.v2Key))
        {
            notes.push_back(std::string {mapping.v1Key} + " also sets " + std::string {mapping.v2Key} + "="
                            + std::to_string(*converted.milliseconds));
        }
    }
    return notes;
}

CredentialsProvider keystoreCredentials()
{
    return []()
    {
        indexer_client::Credentials credentials;
        credentials.user = Keystore::get("indexer", "username");
        credentials.password = Keystore::get("indexer", "password");
        return credentials;
    };
}

} // namespace wiconnector
