#include <dnm/docStorage/fileDriver.hpp>

namespace dnm::drivers
{

FileDocStorage::FileDocStorage(const std::filesystem::path& path, bool create)
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
        // Check path validity
        if (!std::filesystem::exists(path))
        {
            throw std::runtime_error(fmt::format("Path '{}' does not exist", path.string()));
        }
        if (!std::filesystem::is_directory(path))
        {
            throw std::runtime_error(fmt::format("Path '{}' is not a directory", path.string()));
        }
    }

    m_path = path;
}

std::filesystem::path FileDocStorage::nameToPath(const base::Name& name) const
{
    std::filesystem::path path {m_path};
    for (const auto& part : name.parts())
    {
        path /= part;
    }

    return path;
}

std::variant<json::Json, base::Error> FileDocStorage::read(const base::Name& key) const
{
    const auto path = nameToPath(key);

    LOG_DEBUG("Reading file '{}'", path.string()); // TODO Change to trace

    if (!std::filesystem::exists(path))
    {
        return base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    if (!std::filesystem::is_regular_file(path))
    {
        return base::Error {fmt::format("File '{}' is not a regular file", path.string())};
    }

    std::ifstream file {path};
    if (!file.is_open())
    {
        return base::Error {fmt::format("File '{}' cannot be opened", path.string())};
    }

    // File to std::string
    std::string str;
    file.seekg(0, std::ios::end);
    str.reserve(file.tellg());
    file.seekg(0, std::ios::beg);
    str.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    file.close();

    try
    {
        return json::Json(str.data());
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("File '{}' cannot be parsed as json: {}", path.string(), e.what())};
    }
}

std::optional<base::Error> FileDocStorage::write(const base::Name& key, const json::Json& json)
{
    const auto path = nameToPath(key);

    LOG_DEBUG("Writing file '{}'", path.string()); // TODO Change to trace

    if (std::filesystem::exists(path))
    {
        return base::Error {fmt::format("File '{}' already exists", path.string())};
    }

    // Create the directory if it does not exist
    if (!std::filesystem::exists(path.parent_path()))
    {
        if (!std::filesystem::create_directories(path.parent_path()))
        {
            return base::Error {fmt::format("Directory '{}' cannot be created", path.parent_path().string())};
        }
    }

    // Create the file
    std::ofstream file {path};
    if (!file.is_open())
    {
        return base::Error {fmt::format("File '{}' cannot be opened", path.string())};
    }

    file << json.str();

    file.close();

    return {};
}

std::optional<base::Error> FileDocStorage::update(const base::Name& key, const json::Json& json)
{

    const auto path = nameToPath(key);

    LOG_DEBUG("Updating file '{}'", path.string()); // TODO Change to trace

    if (!std::filesystem::exists(path))
    {
        return base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    if (!std::filesystem::is_regular_file(path))
    {
        return base::Error {fmt::format("File '{}' is not a regular file", path.string())};
    }

    std::ofstream file {path};
    if (!file.is_open())
    {
        return base::Error {fmt::format("File '{}' cannot be opened", path.string())};
    }

    file << json.str();

    file.close();

    return {};
}

std::optional<base::Error> FileDocStorage::remove(const base::Name& key)
{
    const auto path = nameToPath(key);

    LOG_DEBUG("Removing file '{}'", path.string()); // TODO Change to trace

    if (!std::filesystem::exists(path))
    {
        return base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    if (!std::filesystem::is_regular_file(path))
    {
        return base::Error {fmt::format("File '{}' is not a regular file", path.string())};
    }

    if (!std::filesystem::remove(path))
    {
        return base::Error {fmt::format("File '{}' cannot be removed", path.string())};
    }

    return {};
}
std::optional<base::Error> FileDocStorage::upsert(const base::Name& key, const json::Json& json)
{
    const auto path = nameToPath(key);

    LOG_DEBUG("Upserting file '{}'", path.string()); // TODO Change to trace

    if (std::filesystem::exists(path))
    {
        return update(key, json);
    }

    return write(key, json);
}
std::variant<std::list<std::pair<base::Name, KeyType>>, base::Error> FileDocStorage::list(const base::Name& key) const
{
    std::list<std::pair<base::Name, KeyType>> res;

    const auto path = nameToPath(key);

    LOG_DEBUG("Listing files '{}'", path.string()); // TODO Change to trace

    if (!std::filesystem::exists(path))
    {
        return base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    if (std::filesystem::is_regular_file(path))
    {
        res.emplace_back(key, KeyType::DOCUMENT);
        return res;
    }

    if (!std::filesystem::is_directory(path))
    {
        return base::Error {fmt::format("File '{}' is not a directory or file", path.string())};
    }

    for (const auto& entry : std::filesystem::directory_iterator(path))
    {
        const auto& entryPath = entry.path();
        base::Name entryName = key + entryPath.filename().string();

        if (std::filesystem::is_regular_file(entryPath))
        {
            // remove the path prefix
            res.emplace_back(entryName, KeyType::DOCUMENT);
        }
        else if (std::filesystem::is_directory(entryPath))
        {
            res.emplace_back(entryName, KeyType::COLLECTION);
        }
        else
        {
            LOG_DEBUG("File '{}' is not a regular file or directory", entryPath.string());
        }
    }

    return res;
}


std::variant<KeyType, base::Error> FileDocStorage::getType(const base::Name& key) const
{
    const auto path = nameToPath(key);

    LOG_DEBUG("Getting type of file '{}'", path.string()); // TODO Change to trace

    if (!std::filesystem::exists(path))
    {
        return base::Error {fmt::format("File '{}' does not exist", path.string())};
    }

    if (std::filesystem::is_regular_file(path))
    {
        return KeyType::DOCUMENT;
    }

    if (!std::filesystem::is_directory(path))
    {
        return base::Error {fmt::format("File '{}' is not a directory or file", path.string())};
    }

    return KeyType::COLLECTION;
}

} // namespace dnm::drivers
