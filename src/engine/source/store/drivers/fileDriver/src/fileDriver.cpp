#include "store/drivers/fileDriver.hpp"

#include <base/logging.hpp>
#include <fmt/format.h>

#include <cctype>
#include <set>

namespace store::drivers
{
namespace
{
constexpr auto JSON_EXTENSION = ".json";
constexpr char HEX_DIGITS[] = "0123456789ABCDEF";

std::string encodeName(const base::Name& name)
{
    const auto& fullName = name.fullName();
    std::string encoded;
    encoded.reserve(fullName.size() * 3);

    for (unsigned char ch : fullName)
    {
        if (ch == '%' || ch == base::Name::SEPARATOR_C)
        {
            encoded += '%';
            encoded += HEX_DIGITS[ch >> 4];
            encoded += HEX_DIGITS[ch & 0x0F];
        }
        else
        {
            encoded += ch;
        }
    }
    return encoded;
}

bool decodeName(const std::string& encoded, std::string& decoded)
{
    decoded.clear();
    decoded.reserve(encoded.size());

    for (std::size_t i = 0; i < encoded.size(); ++i)
    {
        if (encoded[i] != '%')
        {
            decoded += encoded[i];
            continue;
        }

        if (i + 2 >= encoded.size())
        {
            return false;
        }

        auto hi = std::find(HEX_DIGITS, HEX_DIGITS + 16, std::toupper(encoded[i + 1]));
        auto lo = std::find(HEX_DIGITS, HEX_DIGITS + 16, std::toupper(encoded[i + 2]));

        if (hi == HEX_DIGITS + 16 || lo == HEX_DIGITS + 16)
        {
            return false;
        }

        decoded += static_cast<char>((hi - HEX_DIGITS) << 4 | (lo - HEX_DIGITS));
        i += 2;
    }
    return true;
}

bool startsWith(const std::string& value, const std::string& prefix)
{
    return value.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

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
    return m_path / (encodeName(name) + JSON_EXTENSION);
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
        std::ofstream file(path);
        if (!file.is_open())
        {
            error = base::Error {fmt::format("File '{}' could not be opened on writing mode", path.string())};
        }
        else
        {
            file << content.prettyStr();
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
            file << content.prettyStr();
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


base::OptError FileDriver::deleteDoc(const base::Name& name)
{
    base::OptError error = base::noError();
    auto path = nameToPath(name);

    LOG_DEBUG("FileDriver deleteDoc name: '{}'.", name.fullName());

    if (!std::filesystem::exists(path))
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
    }
    return error;
}

base::RespOrError<Col> FileDriver::readCol(const base::Name& name) const
{
    base::RespOrError<Col> result;
    const auto prefix = name.fullName();
    const auto prefixWithSep = prefix + base::Name::SEPARATOR_S;

    LOG_DEBUG("FileDriver readCol name: '{}'.", name.fullName());

    if (std::filesystem::exists(m_path))
    {
        if (!std::filesystem::is_directory(m_path))
        {
            result = base::Error {fmt::format("File '{}' is not a directory", m_path.string())};
        }
        else
        {
            std::set<base::Name> names;
            bool hasExact = false;
            std::string decoded;

            for (const auto& entry : std::filesystem::directory_iterator(m_path))
            {
                if (!entry.is_regular_file() || entry.path().extension() != JSON_EXTENSION)
                {
                    continue;
                }

                const auto filename = entry.path().filename().string();
                const auto encoded = filename.substr(0, filename.size() - std::string(JSON_EXTENSION).size());
                if (!decodeName(encoded, decoded))
                {
                    continue;
                }

                if (decoded == prefix)
                {
                    hasExact = true;
                    continue;
                }

                if (!startsWith(decoded, prefixWithSep))
                {
                    continue;
                }

                const auto remainder = decoded.substr(prefixWithSep.size());
                const auto nextSep = remainder.find(base::Name::SEPARATOR_C);
                const auto child = remainder.substr(0, nextSep);
                if (child.empty())
                {
                    continue;
                }

                names.emplace(base::Name(prefixWithSep + child));
            }

            if (names.empty())
            {
                if (hasExact)
                {
                    result = base::Error {fmt::format("File '{}' is not a directory", prefix)};
                }
                else
                {
                    result = base::Error {fmt::format("Collection '{}' does not exist", prefix)};
                }
            }
            else
            {
                result = Col(names.begin(), names.end());
            }
        }
    }
    else
    {
        result = base::Error {fmt::format("File '{}' does not exist", m_path.string())};
    }

    return result;
}

bool FileDriver::existsDoc(const base::Name& name) const
{
    auto path = nameToPath(name);

    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

} // namespace store::drivers
