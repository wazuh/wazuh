#pragma once

#include "i_inode_reader.hpp"

#include <sys/stat.h>

namespace wazuh::container_instances
{

    class InodeReader final : public IInodeReader
    {
    public:
        [[nodiscard]] std::optional<std::uint64_t> inodeOf(const std::string& path) const override
        {
            struct stat info = {};
            if (::stat(path.c_str(), &info) != 0)
            {
                return std::nullopt;
            }
            return static_cast<std::uint64_t>(info.st_ino);
        }
    };

} // namespace wazuh::container_instances
