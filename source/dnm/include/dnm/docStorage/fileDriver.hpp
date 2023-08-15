#ifndef DNM_DOC_STORAGE_FILE_DRIVER_HPP
#define DNM_DOC_STORAGE_FILE_DRIVER_HPP

#include <dnm/IDocStorage.hpp>

#include <filesystem>
#include <fstream>

namespace dnm::drivers
{

class FileDocStorage : public IDocumentStorage
{
private:
    std::filesystem::path m_path;
    std::filesystem::path nameToPath(const base::Name& name) const;

public:
    FileDocStorage(const std::filesystem::path& path, bool create = false);

    std::variant<json::Json, base::Error> read(const base::Name& key) const override;

    std::optional<base::Error> write(const base::Name& key, const json::Json& json) override;

    std::optional<base::Error> update(const base::Name& key, const json::Json& json) override;

    std::optional<base::Error> remove(const base::Name& key) override;

    std::optional<base::Error> upsert(const base::Name& key, const json::Json& json) override;

    std::variant<std::list<std::pair<base::Name, KeyType>>, base::Error> list(const base::Name& key) const override;

    std::variant<KeyType, base::Error> getType(const base::Name& key) const override;
};

} // namespace dnm::drivers

#endif // DNM_DOC_STORAGE_FILE_DRIVER_HPP
