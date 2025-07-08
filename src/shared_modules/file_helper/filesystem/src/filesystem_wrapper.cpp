#include <filesystem_wrapper.hpp>

namespace file_system
{
    bool FileSystemWrapper::exists(const std::filesystem::path& path) const
    {
        return std::filesystem::exists(path);
    }

    bool FileSystemWrapper::is_directory(const std::filesystem::path& path) const
    {
        return std::filesystem::is_directory(path);
    }

    bool FileSystemWrapper::is_regular_file(const std::filesystem::path& path) const
    {
        return std::filesystem::is_regular_file(path);
    }

    bool FileSystemWrapper::is_socket(const std::filesystem::path& path) const
    {
        return std::filesystem::is_socket(path);
    }

    bool FileSystemWrapper::is_symlink(const std::filesystem::path& path) const
    {
        return std::filesystem::is_symlink(path);
    }

    std::filesystem::path FileSystemWrapper::canonical(const std::filesystem::path& path) const
    {
        return std::filesystem::canonical(path);
    }

    std::uintmax_t FileSystemWrapper::remove_all(const std::filesystem::path& path) const
    {
        return std::filesystem::remove_all(path);
    }

    std::filesystem::path FileSystemWrapper::temp_directory_path() const
    {
        return std::filesystem::temp_directory_path();
    }

    bool FileSystemWrapper::create_directories(const std::filesystem::path& path) const
    {
        return std::filesystem::create_directories(path);
    }

    std::vector<std::filesystem::path> FileSystemWrapper::list_directory(const std::filesystem::path& path) const
    {
        std::vector<std::filesystem::path> result;
        for (const auto& entry : std::filesystem::directory_iterator(path))
        {
            result.push_back(entry.path());
        }
        return result;
    }

    void FileSystemWrapper::rename(const std::filesystem::path& from, const std::filesystem::path& to) const
    {
        std::filesystem::rename(from, to);
    }

    bool FileSystemWrapper::remove(const std::filesystem::path& path) const
    {
        return std::filesystem::remove(path);
    }
} // namespace file_system
