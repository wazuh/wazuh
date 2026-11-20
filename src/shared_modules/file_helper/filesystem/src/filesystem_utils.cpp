#include <filesystem>
#include <filesystem_utils.hpp>
#include <filesystem_wrapper.hpp>

#include <globHelper.h>

#include <deque>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    constexpr auto SEPARATOR
    {
        std::filesystem::path::preferred_separator
    };

    // Runs a wrapper query; a filesystem error (e.g. EACCES) makes the entry unusable instead of failing the expansion.
    template<typename Query, typename Fallback>
    auto queryOrSkip(Query&& query, Fallback&& fallback)
    {
        try
        {
            return query();
        }
        catch (const std::filesystem::filesystem_error&)
        {
            return fallback;
        }
    }

    // Expands the first wildcard of 'remaining' under 'resolved' and recurses on what follows it. 'resolved' is a
    // path already expanded, so a name in it holding '*' or '?' is never read as a pattern.
    // NOLINTNEXTLINE(misc-no-recursion)
    void expand(const IFileSystemWrapper& fsWrapper,
                const std::string& resolved,
                const std::string& remaining,
                std::deque<std::string>& output)
    {
        const auto wildcardPos {remaining.find_first_of("*?")};

        // Every result must exist, so a literal is checked too.
        if (wildcardPos == std::string::npos)
        {
            const auto path {resolved + remaining};

            if (queryOrSkip([&] { return fsWrapper.exists(path); }, false))
            {
                output.push_back(path);
            }

            return;
        }

        // A separator must precede the first wildcard.
        const auto parentDirectoryPos {remaining.find_last_of(SEPARATOR, wildcardPos)};

        if (parentDirectoryPos == std::string::npos)
        {
            throw std::runtime_error {"Invalid path: " + resolved + remaining};
        }

        // "/x*" and "C:\x*" sit under the root: keep the separator, since "" is not a directory and "C:" means
        // the drive's current directory.
        std::string baseDir {resolved + remaining.substr(0, parentDirectoryPos)};

        if (baseDir.empty() || baseDir.back() == ':')
        {
            baseDir += SEPARATOR;
        }

        const auto nextDirectoryPos {remaining.find_first_of(SEPARATOR, wildcardPos)};
        const auto patternPos {parentDirectoryPos + 1};
        const auto pattern {remaining.substr(patternPos,
                                             nextDirectoryPos == std::string::npos ? std::string::npos
                                             : nextDirectoryPos - patternPos)};
        const auto suffix {nextDirectoryPos == std::string::npos ? std::string {} : remaining.substr(nextDirectoryPos)};

        const auto entries {queryOrSkip(
                                [&]
        {
            return fsWrapper.exists(baseDir) && fsWrapper.is_directory(baseDir) ? fsWrapper.list_directory(baseDir)
            : std::vector<std::filesystem::path> {};
        },
        std::vector<std::filesystem::path> {})};

        for (const auto& entry : entries)
        {
            const auto entryName {entry.filename().string()};

            if (Utils::patternMatch(entryName, pattern))
            {
                std::string nextResolved {baseDir};

                if (nextResolved.back() != SEPARATOR)
                {
                    nextResolved += SEPARATOR;
                }

                nextResolved += entryName;

                expand(fsWrapper, nextResolved, suffix, output);
            }
        }
    }
} // namespace

namespace file_system
{
    FileSystemUtils::FileSystemUtils(std::shared_ptr<IFileSystemWrapper> fsWrapper)
        : m_fsWrapper(fsWrapper ? std::move(fsWrapper) : std::make_shared<FileSystemWrapper>())
    {
    }

    void FileSystemUtils::expand_absolute_path(const std::string& path, std::deque<std::string>& output) const
    {
        expand(*m_fsWrapper, {}, path, output);
    }
} // namespace file_system
