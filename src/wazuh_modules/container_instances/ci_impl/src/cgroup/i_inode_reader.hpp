#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace wazuh::container_instances
{

    /// Minimal stat()->st_ino seam. file_helper's IFileSystemWrapper has no inode
    /// accessor; this fills the gap module-locally (candidate for upstreaming).
    class IInodeReader
    {
    public:
        virtual ~IInodeReader() = default;

        [[nodiscard]] virtual std::optional<std::uint64_t> inodeOf(const std::string& path) const = 0;
    };

} // namespace wazuh::container_instances
