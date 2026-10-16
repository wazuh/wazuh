#include <file_io_utils.hpp>
#include <file_io_wrapper.hpp>

#include <fstream>
#include <sstream>

#ifdef _WIN32
// GetFileInformationByHandleEx needs Windows Vista
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// CentOS 5 (legacy rpm packages) predates O_CLOEXEC; fall back to 0 as defs.h does for the C sources.
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#endif

namespace
{
    constexpr std::size_t READ_CHUNK_SIZE {64 * 1024};

#ifdef _WIN32
    // A reparse point that keeps the name (deduplication, compression, cloud files) redirects nothing;
    // symbolic links, junctions and any third-party tag do.
    bool isPlainReparseTag(DWORD tag)
    {
        constexpr DWORD MICROSOFT_TAG_BIT {0x80000000};
        constexpr DWORD NAME_SURROGATE_BIT {0x20000000};
        return (tag & MICROSOFT_TAG_BIT) != 0 && (tag & NAME_SURROGATE_BIT) == 0;
    }

    bool isSameFile(const BY_HANDLE_FILE_INFORMATION& lhs, const BY_HANDLE_FILE_INFORMATION& rhs)
    {
        return lhs.dwVolumeSerialNumber == rhs.dwVolumeSerialNumber && lhs.nFileIndexHigh == rhs.nFileIndexHigh &&
               lhs.nFileIndexLow == rhs.nFileIndexLow;
    }

    HANDLE openForRead(const std::string& path, bool openReparsePoint)
    {
        // Backup semantics lets a directory be opened, so it is reported as not regular instead of as an open failure
        const DWORD flags {FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS |
                           (openReparsePoint ? static_cast<DWORD>(FILE_FLAG_OPEN_REPARSE_POINT) : 0)};
        return CreateFileA(path.c_str(),
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr,
                           OPEN_EXISTING,
                           flags,
                           nullptr);
    }

    // Opens the file and checks its type on the handle. Returns INVALID_HANDLE_VALUE with the status set on failure.
    HANDLE openRegularFile(const std::string& path, bool followSymlinks, RegularFileStatus& status)
    {
        // Without following, the handle refers to a symbolic link or junction itself and never to its target
        HANDLE handle {openForRead(path, !followSymlinks)};

        if (handle == INVALID_HANDLE_VALUE)
        {
            status = RegularFileStatus::OpenFailed;
            return INVALID_HANDLE_VALUE;
        }

        BY_HANDLE_FILE_INFORMATION info {};

        if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            CloseHandle(handle);
            status = RegularFileStatus::NotRegular;
            return INVALID_HANDLE_VALUE;
        }

        if (followSymlinks || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
        {
            return handle;
        }

        FILE_ATTRIBUTE_TAG_INFO tagInfo {};

        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tagInfo, sizeof(tagInfo)) ||
                !isPlainReparseTag(tagInfo.ReparseTag))
        {
            CloseHandle(handle);
            status = RegularFileStatus::NotRegular;
            return INVALID_HANDLE_VALUE;
        }

        // The content of a deduplicated or compressed file is only served through its filter, so it is opened
        // again normally. The first handle stays open and both must be the same file, or the path was replaced.
        HANDLE contentHandle {openForRead(path, false)};
        BY_HANDLE_FILE_INFORMATION contentInfo {};

        if (contentHandle == INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
            status = RegularFileStatus::OpenFailed;
            return INVALID_HANDLE_VALUE;
        }

        const BOOL gotInfo {GetFileInformationByHandle(contentHandle, &contentInfo)};
        CloseHandle(handle);

        if (!gotInfo || !isSameFile(info, contentInfo))
        {
            CloseHandle(contentHandle);
            status = RegularFileStatus::NotRegular;
            return INVALID_HANDLE_VALUE;
        }

        return contentHandle;
    }
#endif
} // namespace

namespace file_io
{
    FileIOUtils::FileIOUtils(std::shared_ptr<IFileIOWrapper> fileIOWrapper)
        : m_fileIOWrapper(fileIOWrapper ? std::move(fileIOWrapper) : std::make_shared<FileIOWrapper>())
    {
    }

    void FileIOUtils::readLineByLine(const std::filesystem::path& filePath,
                                     const std::function<bool(const std::string&)>& callback) const
    {
        auto file = m_fileIOWrapper->create_ifstream(filePath.string());

        if (file == nullptr || !m_fileIOWrapper->is_open(*file))
        {
            throw std::runtime_error("Could not open file");
        }

        std::string line;

        while (m_fileIOWrapper->get_line(*file, line))
        {
            if (!callback(line))
            {
                break;
            }
        }
    }

    std::string FileIOUtils::getFileContent(const std::string& filePath) const
    {
        std::stringstream content;
        const auto file = m_fileIOWrapper->create_ifstream(filePath);

        if (file != nullptr && m_fileIOWrapper->is_open(*file))
        {
            content << m_fileIOWrapper->get_rdbuf(*file);
        }

        return content.str();
    }

    std::vector<char> FileIOUtils::getBinaryContent(const std::string& filePath) const
    {
        std::streamoff size {0};
        std::unique_ptr<char[]> spBuffer;
        auto file = m_fileIOWrapper->create_ifstream(filePath);

        if (file != nullptr && m_fileIOWrapper->is_open(*file))
        {
            // Get pointer to associated buffer object
            auto* buffer = m_fileIOWrapper->get_rdbuf(*file);

            if (nullptr != buffer)
            {
                // Get file size using buffer's members
                size = buffer->pubseekoff(0, file->end, file->in);

                if (size < 0)
                {
                    return std::vector<char> {};
                }

                buffer->pubseekpos(0, file->in);
                // Allocate memory to contain file data
                auto size_t_size = static_cast<std::size_t>(size);
                spBuffer = std::make_unique<char[]>(size_t_size);
                // Get file data
                buffer->sgetn(spBuffer.get(), static_cast<std::streamsize>(size_t_size));
            }
        }

        if (!spBuffer)
        {
            return std::vector<char> {};
        }

        return std::vector<char> {spBuffer.get(), spBuffer.get() + static_cast<std::size_t>(size)};
    }

    RegularFileStatus FileIOUtils::getRegularFileContent(const std::filesystem::path& filePath,
                                                         bool followSymlinks,
                                                         std::string& content) const
    {
        content.clear();
        std::string chunk(READ_CHUNK_SIZE, '\0');
#ifdef _WIN32
        auto status {RegularFileStatus::OpenFailed};
        const HANDLE handle {openRegularFile(filePath.string(), followSymlinks, status)};

        if (handle == INVALID_HANDLE_VALUE)
        {
            return status;
        }

        // Text mode, as std::ifstream reads it, so CRLF line endings are converted
        const int fd {_open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_RDONLY | _O_TEXT)};

        if (fd < 0)
        {
            CloseHandle(handle);
            return RegularFileStatus::OpenFailed;
        }

        int bytes {0};

        while ((bytes = _read(fd, chunk.data(), static_cast<unsigned int>(chunk.size()))) > 0)
        {
            content.append(chunk.data(), static_cast<std::size_t>(bytes));
        }

        // Closes the handle as well
        _close(fd);
#else
        // O_NONBLOCK makes opening a named pipe return at once instead of waiting for a writer
        const int flags {O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | (followSymlinks ? 0 : O_NOFOLLOW)};
        const int fd {::open(filePath.c_str(), flags)};

        if (fd < 0)
        {
            // ELOOP: the last component is a symbolic link and O_NOFOLLOW was given. ENXIO: a socket.
            if ((!followSymlinks && errno == ELOOP) || errno == ENXIO)
            {
                return RegularFileStatus::NotRegular;
            }

            return RegularFileStatus::OpenFailed;
        }

        struct stat fileStat {};

        if (::fstat(fd, &fileStat) != 0)
        {
            ::close(fd);
            return RegularFileStatus::OpenFailed;
        }

        if (!S_ISREG(fileStat.st_mode))
        {
            ::close(fd);
            return RegularFileStatus::NotRegular;
        }

        // Back to blocking reads, which some network and FUSE file systems need on regular files
        const int fdFlags {::fcntl(fd, F_GETFL)};

        if (fdFlags < 0 || ::fcntl(fd, F_SETFL, fdFlags & ~O_NONBLOCK) < 0)
        {
            ::close(fd);
            return RegularFileStatus::OpenFailed;
        }

        ssize_t bytes {0};

        while ((bytes = ::read(fd, chunk.data(), chunk.size())) != 0)
        {
            if (bytes > 0)
            {
                content.append(chunk.data(), static_cast<std::size_t>(bytes));
            }
            else if (errno != EINTR)
            {
                break;
            }
        }

        ::close(fd);
#endif

        if (bytes < 0)
        {
            content.clear();
            return RegularFileStatus::OpenFailed;
        }

        return RegularFileStatus::Read;
    }
}; // namespace file_io
