// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef WI_ENGINE_CONFIG_SOURCE_HPP
#define WI_ENGINE_CONFIG_SOURCE_HPP

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <indexer_client/iConfigSource.hpp>
#include <indexer_client/types.hpp>

namespace wiconnector
{

/// Reads the indexer user and password (production: the keystore's `indexer` column).
using CredentialsProvider = std::function<indexer_client::Credentials()>;

/**
 * @brief The engine's configuration source for its indexer_client runtime.
 *
 * Keys are the full names under `analysisd.indexer_client_` (the prefix the library expects for the engine, in
 * standalone too). Each key resolves from the environment first — `WAZUH_<key without "analysisd.", upper case>`,
 * the convention of the engine's `conf` — then, in manager mode only, from the internal options file; otherwise it is
 * unset and the library's default applies. In standalone mode the file is never read.
 *
 * Two v1 keys feed their v2 equivalent when that one is not set: `analysisd.indexer_request_timeout`
 * (seconds) → `indexer_client_request_timeout_ms` and `analysisd.indexer_monitoring_interval` (seconds) →
 * `indexer_client_probe_interval_ms`. "Set" means an environment variable or a file entry, never a `conf` default.
 * Both set and different (in ms) is reported by problem() on the v2 key; a v1 value of 0 ("no limit") leaves the v2
 * key unset (its default) and is reported once through warnings().
 */
class EngineConfigSource final : public indexer_client::IConfigSource
{
public:
    /**
     * @param indexerSectionJson The `<indexer>` section as canonical JSON (`hosts` and optional `ssl` only).
     * @param fileOptions The internal options file as key → value (empty in standalone mode).
     * @param credentials Reads the indexer user and password.
     * @param environment Reads one environment variable (tests inject it; production: std::getenv).
     * @param environmentNames Every environment variable name (production: from `environ`), for keysWithPrefix().
     */
    EngineConfigSource(std::string indexerSectionJson,
                       std::map<std::string, std::string> fileOptions,
                       CredentialsProvider credentials,
                       std::function<std::optional<std::string>(const std::string&)> environment,
                       std::function<std::vector<std::string>()> environmentNames);

    std::optional<std::string> raw(std::string_view key) const override;
    std::vector<std::string> keysWithPrefix(std::string_view prefix) const override;
    std::optional<std::string> problem(std::string_view key) const override;
    std::string indexerSectionJson() const override;
    indexer_client::Credentials credentials() const override;

    /// Non-fatal notes for the operator (a v1 key ignored or mapped), each to be logged once as a WARN.
    std::vector<std::string> warnings() const;

    /// `WAZUH_<key without "analysisd.", upper case>`, the engine's environment naming convention.
    static std::string environmentName(std::string_view key);

private:
    std::string m_indexerSectionJson;
    std::map<std::string, std::string> m_fileOptions;
    CredentialsProvider m_credentials;
    std::function<std::optional<std::string>(const std::string&)> m_environment;
    std::function<std::vector<std::string>()> m_environmentNames;
};

/// The production credentials provider: `Keystore::get("indexer", "username"|"password")`.
CredentialsProvider keystoreCredentials();

} // namespace wiconnector

#endif // WI_ENGINE_CONFIG_SOURCE_HPP
