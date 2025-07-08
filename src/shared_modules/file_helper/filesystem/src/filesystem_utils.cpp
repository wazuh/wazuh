#include <filesystem>
#include <filesystem_utils.hpp>
#include <filesystem_wrapper.hpp>

#include <globHelper.hpp>

#include <array>

namespace file_system
{
    FileSystemUtils::FileSystemUtils(std::shared_ptr<IFileSystemWrapper> fsWrapper)
        : m_fsWrapper(fsWrapper ? fsWrapper : std::make_shared<FileSystemWrapper>())
    {
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    void FileSystemUtils::expand_absolute_path(const std::string& path, std::deque<std::string>& output) const
    {
        // Find the first * or ? from path.
        const std::array<char, 2> wildcards {'*', '?'};
        size_t wildcardPos = std::string::npos;

        for (const auto& wildcard : wildcards)
        {
            // Find the first wildcard.
            const auto pos = path.find_first_of(wildcard);

            // If the wildcard is found and it is before the current wildcard, then update the wildcard position.
            if (pos != std::string::npos && (wildcardPos == std::string::npos || pos < wildcardPos))
            {
                wildcardPos = pos;
            }
        }

        if (wildcardPos != std::string::npos)
        {
            const auto parentDirectoryPos {path.find_last_of(std::filesystem::path::preferred_separator, wildcardPos)};

            // The parent directory is the part of the path before the first wildcard.
            // If the wildcard is the first character, then the parent directory is the root directory.
            const auto nextDirectoryPos {
                wildcardPos == 0 ? 0 : path.find_first_of(std::filesystem::path::preferred_separator, wildcardPos)};

            if (parentDirectoryPos == std::string::npos)
            {
                throw std::runtime_error {"Invalid path: " + path};
            }

            // The base directory is the part of the path before the first wildcard.
            // If there is no wildcard, then the base directory is the whole path.
            // If the wildcard is the first character, then the base directory is the root directory.
            std::string baseDir;

            if (wildcardPos == 0)
            {
                baseDir = "";
            }
            else
            {
                baseDir = path.substr(0, parentDirectoryPos);
            }

            // The pattern is the part of the path after the first wildcard.
            // If the wildcard is the last character, then the pattern is the rest of the string.
            // If the wildcard is the first character, then the pattern is the rest of the string, minus the next '\'.
            // If there is no next '\', then the pattern is the rest of the string.
            const auto pattern {
                path.substr(parentDirectoryPos == 0 ? 0 : parentDirectoryPos + 1,
                            nextDirectoryPos == std::string::npos
                                ? std::string::npos
                                : nextDirectoryPos - (parentDirectoryPos == 0 ? 0 : parentDirectoryPos + 1))};

            if (m_fsWrapper->exists(baseDir))
            {
                if (m_fsWrapper->is_directory(baseDir))
                {
                    for (const auto& entry : m_fsWrapper->list_directory(baseDir))
                    {
                        const auto entryName {entry.filename().string()};

                        if (Utils::patternMatch(entryName, pattern))
                        {
                            std::string nextPath {baseDir};
                            nextPath += std::filesystem::path::preferred_separator;
                            nextPath += entryName;
                            nextPath += nextDirectoryPos == std::string::npos ? "" : path.substr(nextDirectoryPos);

                            expand_absolute_path(nextPath, output);
                        }
                    }
                }
                else if (Utils::patternMatch(baseDir, pattern))
                {
                    output.push_back(baseDir);
                }
            }
        }
        else
        {
            output.push_back(path);
        }
    }
} // namespace file_system
