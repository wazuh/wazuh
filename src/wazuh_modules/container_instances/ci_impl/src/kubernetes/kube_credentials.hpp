#pragma once

#include <optional>
#include <string>
#include <variant>

namespace wazuh::container_instances
{

    struct ClientCertPair
    {
        std::string certBlob; ///< PEM.
        std::string keyBlob;  ///< PEM.
    };

    struct StaticToken
    {
        std::string token;
    };

    struct TokenFile
    {
        std::string path;
    };

    /// monostate = no bearer token (client-certificate auth only). `exec`
    /// credential plugins are deliberately unrepresentable: the loader rejects
    /// such kubeconfigs at validation time (documented v1 limitation).
    using TokenSource = std::variant<std::monostate, StaticToken, TokenFile>;

    struct KubeCredentials
    {
        std::string serverUrl;
        std::optional<std::string> caBlob; ///< PEM; absent = system trust store.
        std::optional<ClientCertPair> clientCert;
        bool skipVerify {false};
        TokenSource token;
    };

} // namespace wazuh::container_instances
