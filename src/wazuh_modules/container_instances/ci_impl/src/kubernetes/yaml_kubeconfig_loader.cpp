#include "yaml_kubeconfig_loader.hpp"

#include "yaml_to_json.hpp"

#include <openssl/evp.h>

#include <optional>
#include <utility>
#include <vector>

namespace wazuh::container_instances
{

    namespace
    {

        /// Strict base64 -> bytes. @throws KubeconfigError on invalid input.
        std::string base64Decode(const std::string& encoded)
        {
            std::string compact;
            compact.reserve(encoded.size());
            for (const char c : encoded)
            {
                if (c != '\n' && c != '\r')
                {
                    compact.push_back(c);
                }
            }
            if (compact.empty() || compact.size() % 4 != 0)
            {
                throw KubeconfigError("invalid base64 field in kubeconfig");
            }

            std::vector<unsigned char> decoded(compact.size() / 4 * 3);
            const int written = EVP_DecodeBlock(decoded.data(),
                                                reinterpret_cast<const unsigned char*>(compact.data()),
                                                static_cast<int>(compact.size()));
            if (written < 0)
            {
                throw KubeconfigError("invalid base64 field in kubeconfig");
            }

            std::size_t padding = 0;
            for (auto it = compact.rbegin(); it != compact.rend() && *it == '='; ++it)
            {
                ++padding;
            }
            return {reinterpret_cast<const char*>(decoded.data()), static_cast<std::size_t>(written) - padding};
        }

        /// Finds the named entry in a kubeconfig list ({name, cluster|user|context}).
        std::optional<nlohmann::json>
        findNamed(const nlohmann::json& list, const std::string& name, const char* innerKey)
        {
            if (!list.is_array())
            {
                return std::nullopt;
            }
            for (const auto& item : list)
            {
                if (item.value("name", "") == name && item.contains(innerKey))
                {
                    return item[innerKey];
                }
            }
            return std::nullopt;
        }

        /// Reads a field that comes either inline base64 ("<field>-data") or as a file
        /// reference ("<field>"). Returns the raw PEM content.
        std::optional<std::string>
        resolveBlob(const nlohmann::json& object, const std::string& field, const IFileIOUtils& fileIO)
        {
            const auto dataKey = field + "-data";
            if (object.contains(dataKey) && object[dataKey].is_string())
            {
                return base64Decode(object[dataKey].get<std::string>());
            }
            if (object.contains(field) && object[field].is_string())
            {
                try
                {
                    return fileIO.getFileContent(object[field].get<std::string>());
                }
                catch (const std::exception& error)
                {
                    throw KubeconfigError("cannot read " + field + " file: " + error.what());
                }
            }
            return std::nullopt;
        }

    } // namespace

    YamlKubeconfigLoader::YamlKubeconfigLoader(const IFileIOUtils& fileIO, Logger logger)
        : m_fileIO(fileIO)
        , m_logger(std::move(logger))
    {
    }

    KubeCredentials YamlKubeconfigLoader::load(const std::string& path) const
    {
        std::string content;
        try
        {
            content = m_fileIO.getFileContent(path);
        }
        catch (const std::exception& error)
        {
            throw KubeconfigError("cannot read kubeconfig at " + path + ": " + error.what());
        }
        if (content.empty())
        {
            throw KubeconfigError("kubeconfig at " + path + " is empty or unreadable");
        }

        nlohmann::json config;
        try
        {
            config = yamlToJson(content);
        }
        catch (const YamlParseError& error)
        {
            throw KubeconfigError("kubeconfig at " + path + " is not valid YAML: " + error.what());
        }

        const auto currentContext = config.value("current-context", "");
        if (currentContext.empty())
        {
            throw KubeconfigError("kubeconfig has no current-context");
        }

        const auto context = findNamed(config.value("contexts", nlohmann::json::array()), currentContext, "context");
        if (!context)
        {
            throw KubeconfigError("kubeconfig context '" + currentContext + "' not found");
        }

        const auto clusterName = context->value("cluster", "");
        const auto userName = context->value("user", "");
        const auto cluster = findNamed(config.value("clusters", nlohmann::json::array()), clusterName, "cluster");
        if (!cluster)
        {
            throw KubeconfigError("kubeconfig cluster '" + clusterName + "' not found");
        }
        const auto user = findNamed(config.value("users", nlohmann::json::array()), userName, "user");
        if (!user)
        {
            throw KubeconfigError("kubeconfig user '" + userName + "' not found");
        }

        if (user->contains("exec"))
        {
            throw KubeconfigError("kubeconfig user '" + userName +
                                  "' uses an exec credential plugin, which is not supported; "
                                  "provide a token, token file or client certificate instead");
        }
        if (user->contains("auth-provider"))
        {
            throw KubeconfigError("kubeconfig user '" + userName + "' uses an auth-provider, which is not supported");
        }

        KubeCredentials credentials;
        credentials.serverUrl = cluster->value("server", "");
        if (credentials.serverUrl.empty())
        {
            throw KubeconfigError("kubeconfig cluster '" + clusterName + "' has no server URL");
        }

        credentials.skipVerify = cluster->value("insecure-skip-tls-verify", false);
        credentials.caBlob = resolveBlob(*cluster, "certificate-authority", m_fileIO);

        const auto clientCert = resolveBlob(*user, "client-certificate", m_fileIO);
        const auto clientKey = resolveBlob(*user, "client-key", m_fileIO);
        if (clientCert.has_value() != clientKey.has_value())
        {
            throw KubeconfigError("kubeconfig user '" + userName +
                                  "' has a client certificate without a key (or vice versa)");
        }
        if (clientCert)
        {
            ClientCertPair pair;
            pair.certBlob = *clientCert;
            pair.keyBlob = *clientKey;
            credentials.clientCert = std::move(pair);
        }

        if (user->contains("tokenFile") && (*user)["tokenFile"].is_string())
        {
            TokenFile tokenFile;
            tokenFile.path = (*user)["tokenFile"].get<std::string>();
            credentials.token = tokenFile;
        }
        else if (user->contains("token") && (*user)["token"].is_string())
        {
            StaticToken token;
            token.token = (*user)["token"].get<std::string>();
            credentials.token = token;
        }
        else if (!credentials.clientCert)
        {
            throw KubeconfigError("kubeconfig user '" + userName + "' has no usable credentials");
        }

        return credentials;
    }

} // namespace wazuh::container_instances
