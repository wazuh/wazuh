#include <filesystem>
#include <filesystem_utils.hpp>
#include <filesystem_wrapper.hpp>

#include <globHelper.h>

#include <stdexcept>

namespace file_system
{
    FileSystemUtils::FileSystemUtils(std::shared_ptr<IFileSystemWrapper> fsWrapper)
        : m_fsWrapper(fsWrapper ? std::move(fsWrapper) : std::make_shared<FileSystemWrapper>())
    {
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    void FileSystemUtils::expand_absolute_path(const std::string& path, std::deque<std::string>& output) const
    {
        constexpr auto SEPARATOR {std::filesystem::path::preferred_separator};

        // Find the first * or ? from path.
        const auto wildcardPos {path.find_first_of("*?")};

        // A path without wildcards is a literal: it is a result only if it exists, like every path the
        // expansion below produces.
        if (wildcardPos == std::string::npos)
        {
            if (m_fsWrapper->exists(path))
            {
                output.push_back(path);
            }

            return;
        }

        // The pattern must be absolute: a separator has to come before the first wildcard, so a path
        // that starts with a wildcard (or has no separator before it) is refused.
        const auto parentDirectoryPos {path.find_last_of(SEPARATOR, wildcardPos)};

        if (parentDirectoryPos == std::string::npos)
        {
            throw std::runtime_error {"Invalid path: " + path};
        }

        // The base directory is the part of the path before the component holding the first wildcard.
        // When that component sits right under the root ("/x*" or "C:\x*"), the base directory keeps its
        // separator: an empty string is not a directory, and "C:" names the drive's current directory.
        std::string baseDir {path.substr(0, parentDirectoryPos)};

        if (baseDir.empty() || baseDir.back() == ':')
        {
            baseDir += SEPARATOR;
        }

        // The pattern is the component holding the first wildcard; the rest of the path (from its next
        // separator on, if any) is appended to every match and expanded in turn.
        const auto nextDirectoryPos {path.find_first_of(SEPARATOR, wildcardPos)};
        const auto patternPos {parentDirectoryPos + 1};
        const auto pattern {path.substr(patternPos,
                                        nextDirectoryPos == std::string::npos ? std::string::npos
                                        : nextDirectoryPos - patternPos)};

        // Only a directory has entries to match; a file or a missing path in its place matches nothing.
        if (!m_fsWrapper->exists(baseDir) || !m_fsWrapper->is_directory(baseDir))
        {
            return;
        }

        for (const auto& entry : m_fsWrapper->list_directory(baseDir))
        {
            const auto entryName {entry.filename().string()};

            if (Utils::patternMatch(entryName, pattern))
            {
                std::string nextPath {baseDir};

                if (nextPath.back() != SEPARATOR)
                {
                    nextPath += SEPARATOR;
                }

                nextPath += entryName;
                nextPath += nextDirectoryPos == std::string::npos ? "" : path.substr(nextDirectoryPos);

                expand_absolute_path(nextPath, output);
            }
        }
    }
} // namespace file_system
