#include "store/drivers/fileDriver.hpp"

#include <base/logging.hpp>
#include <fmt/format.h>

namespace store::drivers
{
FileDriver::FileDriver(const std::filesystem::path& path, bool create)
{
    LOG_DEBUG("Engine file driver init with path '{}' and create '{}'.", path.string(), create);

    // Check path validity
    if (!std::filesystem::exists(path))
    {
        if (create)
        {
            if (!std::filesystem::create_directories(path))
            {
                throw std::runtime_error(fmt::format("Path '{}' cannot be created", path.string()));
            }
        }
        else
        {
            throw std::runtime_error(fmt::format("Path '{}' does not exist", path.string()));
        }
    }
    if (!std::filesystem::is_directory(path))
    {
        throw std::runtime_error(fmt::format("Path '{}' is not a directory", path.string()));
    }

    m_path = path;
}

std::filesystem::path FileDriver::nameToPath(const base::Name& name) const
{
    std::filesystem::path path {m_path};
    for (const auto& part : name.parts())
    {
        path /= part;
    }

    return path;
}

base::OptError FileDriver::createDoc(const base::Name& name, const Doc& content)
{
    auto error = base::noError();
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver createDoc name: '{}'.", name.fullName());
    LOG_TRACE("FileDriver createDoc content: '{}'.", content.prettyStr());

    auto duplicateError = content.checkDuplicateKeys();
    if (duplicateError)
    {
        error = base::Error {
            fmt::format("Content '{}' has duplicate keys: {}", name.fullName(), duplicateError.value().message)};
    }
    else if (std::filesystem::exists(path))
    {
        error = base::Error {fmt::format("File '{}' already exists", path.string())};
    }
    else
    {
        std::error_code ec;
        if (!std::filesystem::create_directories(path.parent_path(), ec) && ec.value() != 0)
        {
            error = base::Error {fmt::format(
                "Directory '{}' could not be created: ({}) {}", path.parent_path().string(), ec.value(), ec.message())};
        }
        else
        {
            std::ofstream file(path);
            if (!file.is_open())
            {
                error = base::Error {fmt::format("File '{}' could not be opened on writing mode", path.string())};
            }
            else
            {
                file << content.str();
            }
        }
    }
    return error;
}

base::RespOrError<Doc> FileDriver::readDoc(const base::Name& name) const
{
    base::RespOrError<Doc> result;
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver readDoc name: '{}'.", name.fullName());

    if (std::filesystem::exists(path))
    {
        if (std::filesystem::is_directory(path))
        {
            return base::Error {fmt::format("File '{}' is a directory", path.string())};
        }

        std::ifstream file(path);
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content {buffer.str()};
        file.close();
        try
        {
            result = Doc {content.c_str()};
        }
        catch (const std::exception& e)
        {
            result = base::Error {fmt::format("File '{}' could not be parsed: {}", path.string(), e.what())};
        }
    }
    else
    {
        result = base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    return result;
}

base::OptError FileDriver::updateDoc(const base::Name& name, const Doc& content)
{
    base::OptError error = base::noError();
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver updateDoc name: '{}'.", name.fullName());
    LOG_TRACE("FileDriver updateDoc content: '{}'.", content.prettyStr());

    auto duplicateError = content.checkDuplicateKeys();
    if (duplicateError)
    {
        error = base::Error {
            fmt::format("Content '{}' has duplicate keys: {}", name.fullName(), duplicateError.value().message)};
    }
    else if (!std::filesystem::exists(path))
    {
        error = base::Error {fmt::format("File '{}' does not exist", path.string())};
    }
    else if (std::filesystem::is_directory(path))
    {
        error = base::Error {fmt::format("File '{}' is a directory", path.string())};
    }
    else
    {
        std::ofstream file(path);
        if (!file.is_open())
        {
            error = base::Error {fmt::format("File '{}' could not be opened on writing mode", path.string())};
        }
        else
        {
            file << content.str();
        }
    }

    return error;
}

base::OptError FileDriver::upsertDoc(const base::Name& name, const Doc& content)
{
    LOG_DEBUG("FileDriver upsertDoc name: '{}'.", name.fullName());

    if (existsDoc(name))
    {
        return updateDoc(name, content);
    }
    else
    {
        return createDoc(name, content);
    }
}

base::OptError FileDriver::removeEmptyParentDirs(const std::filesystem::path& path, const base::Name& name)
{
    base::OptError error = base::noError();
    std::error_code ec;
    bool next = true;
    auto current = path;
    for (current = current.parent_path(); next && current != m_path && std::filesystem::is_empty(current);
         current = current.parent_path())
    {
        if (!std::filesystem::remove(current, ec))
        {
            error = base::Error {fmt::format(
                "File '{}' was successfully removed but its parent directory '{}' could not be removed: ({}) {}",
                name.fullName(),
                path.string(),
                ec.value(),
                ec.message())};
            next = false;
        }
    }

    return error;
}

base::OptError FileDriver::deleteDoc(const base::Name& name)
{
    base::OptError error = base::noError();
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver deleteDoc name: '{}'.", name.fullName());

    if (!existsDoc(name))
    {
        error = base::Error {fmt::format("File '{}' does not exist", path.string())};
    }
    else
    {
        std::error_code ec;
        if (!std::filesystem::remove_all(path, ec))
        {
            error = base::Error {
                fmt::format("File '{}' could not be removed: ({}) {}", path.string(), ec.value(), ec.message())};
        }

        // Remove empty parent directories
        error = removeEmptyParentDirs(path, name);
    }
    return error;
}

base::RespOrError<Col> FileDriver::readCol(const base::Name& name) const
{
    base::RespOrError<Col> result;
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver readCol name: '{}'.", name.fullName());

    if (std::filesystem::exists(path))
    {
        if (!std::filesystem::is_directory(path))
        {
            result = base::Error {fmt::format("File '{}' is not a directory", path.string())};
        }
        else
        {

            std::vector<base::Name> names;

            for (const auto& entry : std::filesystem::directory_iterator(path))
            {
                names.emplace_back(base::Name(name) + entry.path().filename().string());
            }

            result = std::move(names);
        }
    }
    else
    {
        result = base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    return result;
}

base::RespOrError<Col> FileDriver::readRoot() const
{
    base::RespOrError<Col> result;
    const auto& path = m_path;

    LOG_DEBUG("FileDriver readRoot.");

    if (std::filesystem::exists(path))
    {
        if (!std::filesystem::is_directory(path))
        {
            result = base::Error {fmt::format("File '{}' is not a directory", path.string())};
        }
        else
        {

            std::vector<base::Name> names;

            for (const auto& entry : std::filesystem::directory_iterator(path))
            {
                names.emplace_back(entry.path().filename().string());
            }

            result = std::move(names);
        }
    }
    else
    {
        result = base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    return result;
}

base::OptError FileDriver::deleteCol(const base::Name& name)
{
    base::OptError error = base::noError();
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver deleteCol name: '{}'.", name.fullName());

    if (!std::filesystem::exists(path))
    {
        error = base::Error {fmt::format("File '{}' does not exist", path.string())};
    }
    else if (!std::filesystem::is_directory(path))
    {
        error = base::Error {fmt::format("File '{}' is not a directory", path.string())};
    }
    else
    {
        std::error_code ec;
        if (!std::filesystem::remove_all(path, ec))
        {
            error = base::Error {
                fmt::format("File '{}' could not be removed: ({}) {}", path.string(), ec.value(), ec.message())};
        }

        // Remove empty parent directories
        error = removeEmptyParentDirs(path, name);
    }

    return error;
}

bool FileDriver::exists(const base::Name& name) const
{
    auto path = nameToPath(name);

    return std::filesystem::exists(path);
}

bool FileDriver::existsDoc(const base::Name& name) const
{
    auto path = nameToPath(name);

    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

bool FileDriver::existsCol(const base::Name& name) const
{
    auto path = nameToPath(name);

    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

} // namespace store::drivers
