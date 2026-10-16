#include <file_io_utils.hpp>
#include <file_io_wrapper.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>

#ifdef _WIN32
// FILE_ID_INFO is declared from Windows 8 on. On older systems the call that uses it fails at run time and
// the 64-bit file index is used instead, so only the declarations depend on this.
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0602
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <windows.h>
#include <cstring>
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
    constexpr int INVALID_FD {-1};

    /// @brief Closes a descriptor when it goes out of scope, so an exception thrown while reading cannot leak it.
    template<typename T, T Invalid, int (*Close)(T)>
    class UniqueDescriptor final
    {
        public:
            explicit UniqueDescriptor(T value)
                : m_value(value)
            {
            }

            ~UniqueDescriptor()
            {
                if (m_value != Invalid)
                {
                    Close(m_value);
                }
            }

            UniqueDescriptor(UniqueDescriptor&& other) noexcept
                : m_value(other.release())
            {
            }

            UniqueDescriptor(const UniqueDescriptor&) = delete;
            UniqueDescriptor& operator=(const UniqueDescriptor&) = delete;
            UniqueDescriptor& operator=(UniqueDescriptor&&) = delete;

            T get() const
            {
                return m_value;
            }

            T release()
            {
                const auto value {m_value};
                m_value = Invalid;
                return value;
            }

            explicit operator bool() const
            {
                return m_value != Invalid;
            }

        private:
            T m_value;
    };

#ifdef _WIN32
    int closeHandle(HANDLE handle)
    {
        return CloseHandle(handle) ? 0 : -1;
    }

    // INVALID_HANDLE_VALUE is not a constant expression, so the invalid value is checked through nullptr and
    // every handle is stored only after it has been checked against INVALID_HANDLE_VALUE
    using UniqueHandle = UniqueDescriptor<HANDLE, nullptr, closeHandle>;
    using UniqueCrtFd = UniqueDescriptor<int, INVALID_FD, _close>;

    constexpr DWORD MICROSOFT_TAG_BIT {0x80000000};
    constexpr DWORD NAME_SURROGATE_BIT {0x20000000};

    // Symbolic links, junctions and the like name another file
    bool isNameSurrogateReparseTag(DWORD tag)
    {
        return (tag & NAME_SURROGATE_BIT) != 0;
    }

    // A reparse point that keeps the name (deduplication, compression, cloud files) redirects nothing.
    // A third-party tag may do anything, so it is not treated as plain.
    bool isPlainReparseTag(DWORD tag)
    {
        return (tag & MICROSOFT_TAG_BIT) != 0 && !isNameSurrogateReparseTag(tag);
    }

    bool isSameFile(HANDLE first, HANDLE second)
    {
        FILE_ID_INFO firstId {};
        FILE_ID_INFO secondId {};

        if (GetFileInformationByHandleEx(first, FileIdInfo, &firstId, sizeof(firstId)) &&
                GetFileInformationByHandleEx(second, FileIdInfo, &secondId, sizeof(secondId)))
        {
            return firstId.VolumeSerialNumber == secondId.VolumeSerialNumber &&
                   std::memcmp(&firstId.FileId, &secondId.FileId, sizeof(firstId.FileId)) == 0;
        }

        // Before Windows 8 only the 64-bit index exists. It is not unique on ReFS, which reports all ones when it
        // cannot give a unique one, so that value (and zero) never counts as the same file.
        BY_HANDLE_FILE_INFORMATION firstInfo {};
        BY_HANDLE_FILE_INFORMATION secondInfo {};

        if (!GetFileInformationByHandle(first, &firstInfo) || !GetFileInformationByHandle(second, &secondInfo))
        {
            return false;
        }

        const auto index = [](const BY_HANDLE_FILE_INFORMATION & info)
        {
            return (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
        };
        const auto firstIndex {index(firstInfo)};

        return firstIndex != 0 && firstIndex != UINT64_MAX && firstIndex == index(secondInfo) &&
               firstInfo.dwVolumeSerialNumber == secondInfo.dwVolumeSerialNumber;
    }

    UniqueHandle openForRead(const std::string& path, bool openReparsePoint)
    {
        // Backup semantics lets a directory be opened, so it is reported as not regular instead of as an open failure
        const DWORD flags {FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS |
                           (openReparsePoint ? static_cast<DWORD>(FILE_FLAG_OPEN_REPARSE_POINT) : 0)};
        const HANDLE handle {CreateFileA(path.c_str(),
                                         GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr,
                                         OPEN_EXISTING,
                                         flags,
                                         nullptr)};
        return UniqueHandle {handle == INVALID_HANDLE_VALUE ? nullptr : handle};
    }

    // Opens the file and checks its type on the handle. Returns an empty handle with the status set on failure.
    UniqueHandle openRegularFile(const std::string& path, bool followSymlinks, RegularFileStatus& status)
    {
        // Without following, the handle refers to a symbolic link or junction itself and never to its target
        auto handle {openForRead(path, !followSymlinks)};

        if (!handle)
        {
            status = RegularFileStatus::OpenFailed;
            return UniqueHandle {nullptr};
        }

        BY_HANDLE_FILE_INFORMATION info {};

        if (GetFileType(handle.get()) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle.get(), &info))
        {
            status = RegularFileStatus::NotRegular;
            return UniqueHandle {nullptr};
        }

        const bool isReparsePoint = !followSymlinks && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        FILE_ATTRIBUTE_TAG_INFO tagInfo {};

        if (isReparsePoint &&
                !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &tagInfo, sizeof(tagInfo)))
        {
            status = RegularFileStatus::OpenFailed;
            return UniqueHandle {nullptr};
        }

        // Checked before the directory attribute, so a junction is reported as a link like on other systems
        if (isReparsePoint && isNameSurrogateReparseTag(tagInfo.ReparseTag))
        {
            status = RegularFileStatus::SymbolicLink;
            return UniqueHandle {nullptr};
        }

        if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                (isReparsePoint && !isPlainReparseTag(tagInfo.ReparseTag)))
        {
            status = RegularFileStatus::NotRegular;
            return UniqueHandle {nullptr};
        }

        if (!isReparsePoint)
        {
            return handle;
        }

        // The content of a deduplicated or compressed file is only served through its filter, so it is opened
        // again normally. The first handle stays open and both must be the same file, or the path was replaced.
        auto contentHandle {openForRead(path, false)};

        if (!contentHandle)
        {
            status = RegularFileStatus::OpenFailed;
            return UniqueHandle {nullptr};
        }

        if (!isSameFile(handle.get(), contentHandle.get()))
        {
            status = RegularFileStatus::NotRegular;
            return UniqueHandle {nullptr};
        }

        return contentHandle;
    }
#else
    using UniqueFd = UniqueDescriptor<int, INVALID_FD, ::close>;
#endif

    /// @brief Opens a regular file once, checks its type on the open file and passes its content in chunks.
    /// @param onChunk Receives each chunk; returning false stops reading. An exception it throws closes the file.
    /// @return Read when the whole file was passed or onChunk stopped it, otherwise why it was not read.
    RegularFileStatus readRegularFile(const std::filesystem::path& filePath,
                                      bool followSymlinks,
                                      const std::function<bool(const char*, std::size_t)>& onChunk)
    {
#ifdef _WIN32
        auto status {RegularFileStatus::OpenFailed};
        auto handle {openRegularFile(filePath.string(), followSymlinks, status)};

        if (!handle)
        {
            return status;
        }

        // Text mode, as std::ifstream reads it, so CRLF line endings are converted
        const int fd {_open_osfhandle(reinterpret_cast<intptr_t>(handle.get()), _O_RDONLY | _O_TEXT)};

        if (fd < 0)
        {
            return RegularFileStatus::OpenFailed;
        }

        // The descriptor owns the handle from here on
        handle.release();
        const UniqueCrtFd file {fd};
        std::string chunk(READ_CHUNK_SIZE, '\0');

        while (true)
        {
            const int bytes {_read(file.get(), chunk.data(), static_cast<unsigned int>(chunk.size()))};

            if (bytes == 0)
            {
                return RegularFileStatus::Read;
            }

            if (bytes < 0)
            {
                return RegularFileStatus::OpenFailed;
            }

            if (!onChunk(chunk.data(), static_cast<std::size_t>(bytes)))
            {
                return RegularFileStatus::Read;
            }
        }

#else
        // O_NONBLOCK makes opening a named pipe return at once instead of waiting for a writer
        const int flags {O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | (followSymlinks ? 0 : O_NOFOLLOW)};
        const UniqueFd file {::open(filePath.c_str(), flags)};

        if (!file)
        {
            // ELOOP: the last component is a symbolic link and O_NOFOLLOW was given
            if (!followSymlinks && errno == ELOOP)
            {
                return RegularFileStatus::SymbolicLink;
            }

            // ENXIO: a socket
            if (errno == ENXIO)
            {
                return RegularFileStatus::NotRegular;
            }

            return RegularFileStatus::OpenFailed;
        }

        struct stat fileStat {};

        if (::fstat(file.get(), &fileStat) != 0)
        {
            return RegularFileStatus::OpenFailed;
        }

        if (!S_ISREG(fileStat.st_mode))
        {
            return RegularFileStatus::NotRegular;
        }

        // Back to blocking reads, which some network and FUSE file systems need on regular files
        const int fdFlags {::fcntl(file.get(), F_GETFL)};

        if (fdFlags < 0 || ::fcntl(file.get(), F_SETFL, fdFlags & ~O_NONBLOCK) < 0)
        {
            return RegularFileStatus::OpenFailed;
        }

        std::string chunk(READ_CHUNK_SIZE, '\0');

        while (true)
        {
            const ssize_t bytes {::read(file.get(), chunk.data(), chunk.size())};

            if (bytes == 0)
            {
                return RegularFileStatus::Read;
            }

            if (bytes < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }

                return RegularFileStatus::OpenFailed;
            }

            if (!onChunk(chunk.data(), static_cast<std::size_t>(bytes)))
            {
                return RegularFileStatus::Read;
            }
        }

#endif
    }
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
        const auto status {readRegularFile(filePath,
                                           followSymlinks,
                                           [&content](const char* data, std::size_t size)
        {
            content.append(data, size);
            return true;
        })};

        if (status != RegularFileStatus::Read)
        {
            content.clear();
        }

        return status;
    }

    RegularFileStatus FileIOUtils::readRegularFileLineByLine(const std::filesystem::path& filePath,
                                                             bool followSymlinks,
                                                             const std::function<bool(const std::string&)>& callback) const
    {
        // Lines are split as std::getline does: a last line without a newline still counts, an empty file has none
        std::string line;
        bool keepReading {true};
        const auto status {readRegularFile(filePath,
                                           followSymlinks,
                                           [&](const char* data, std::size_t size)
        {
            const char* const end {data + size};

            while (keepReading)
            {
                const char* const newline {std::find(data, end, '\n')};
                line.append(data, newline);

                if (newline == end)
                {
                    break;
                }

                keepReading = callback(line);
                line.clear();
                data = newline + 1;
            }

            return keepReading;
        })};

        if (status == RegularFileStatus::Read && keepReading && !line.empty())
        {
            callback(line);
        }

        return status;
    }
}; // namespace file_io
