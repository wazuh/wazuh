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

        // Every result must exist, so a literal is checked too.
        if (wildcardPos == std::string::npos)
        {
            if (m_fsWrapper->exists(path))
            {
                output.push_back(path);
            }

            return;
        }

        // A separator must precede the first wildcard.
        const auto parentDirectoryPos {path.find_last_of(SEPARATOR, wildcardPos)};

        if (parentDirectoryPos == std::string::npos)
        {
            throw std::runtime_error {"Invalid path: " + path};
        }

        // "/x*" and "C:\x*" sit under the root: keep the separator, since "" is not a directory and "C:" means
        // the drive's current directory.
        std::string baseDir {path.substr(0, parentDirectoryPos)};

        if (baseDir.empty() || baseDir.back() == ':')
        {
            baseDir += SEPARATOR;
        }

        const auto nextDirectoryPos {path.find_first_of(SEPARATOR, wildcardPos)};
        const auto patternPos {parentDirectoryPos + 1};
        const auto pattern {path.substr(patternPos,
                                        nextDirectoryPos == std::string::npos ? std::string::npos
                                        : nextDirectoryPos - patternPos)};
        const auto suffix {nextDirectoryPos == std::string::npos ? std::string {} : path.substr(nextDirectoryPos)};

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
                nextPath += suffix;

                expand_absolute_path(nextPath, output);
            }
        }
    }
} // namespace file_system
