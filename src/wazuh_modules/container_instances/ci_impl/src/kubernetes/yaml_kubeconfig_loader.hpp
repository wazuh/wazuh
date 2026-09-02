#pragma once

#include "../core/logger.hpp"
#include "i_kubeconfig_loader.hpp"
#include "ifile_io_utils.hpp"

namespace wazuh::container_instances
{

    /// kubeconfig -> KubeCredentials: resolves current-context, inlines
    /// certificate-authority / client-certificate material (file references and
    /// base64 *-data variants both end up as in-memory PEM blobs), and rejects
    /// what the module cannot honor (`exec` plugins, `auth-provider`).
    class YamlKubeconfigLoader final : public IKubeconfigLoader
    {
    public:
        YamlKubeconfigLoader(const IFileIOUtils& fileIO, Logger logger);

        [[nodiscard]] KubeCredentials load(const std::string& path) const override;

    private:
        const IFileIOUtils& m_fileIO;
        Logger m_logger;
    };

} // namespace wazuh::container_instances
