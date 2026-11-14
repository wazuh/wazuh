#pragma once

#include <ifilesystem_utils.hpp>
#include <ifilesystem_wrapper.hpp>

#include <memory>

namespace file_system
{
    /// @brief A wrapper class for file system operations, implementing the IFileSystemUtils interface.
    ///
    /// This class provides a method for expanding paths that contain wildcards. It is designed
    /// to be used as a concrete implementation of the IFileSystemUtils interface.
    class FileSystemUtils : public IFileSystemUtils
    {
    public:
        /// @brief Constructor for the FileSystemUtils class.
        FileSystemUtils(std::shared_ptr<IFileSystemWrapper> fsWrapper = nullptr);

        /// @copydoc IFileSystemUtils::expand_absolute_path
        void expand_absolute_path(const std::string& path, std::deque<std::string>& output) const override;

    private:
        std::shared_ptr<IFileSystemWrapper> m_fsWrapper;
    };
} // namespace file_system
