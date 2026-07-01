#include <store/utils.hpp>

#include <base/logging.hpp>

namespace
{
const base::Name ENGINE_STATUS_DOC {"engine/status/0"};
} // namespace

namespace store::utils
{

bool updateStartStatus(const std::shared_ptr<IStore>& store, std::string_view timestamp)
{
    const auto& document = ENGINE_STATUS_DOC;
    if (!store)
    {
        LOG_WARNING("[Store] Cannot update start status document '{}': Store is unavailable", document.fullName());
        return false;
    }

    const bool firstStart = !store->existsDoc(document);
    bool initializeStatus = firstStart;
    json::Json status;

    if (!firstStart)
    {
        auto response = store->readDoc(document);
        if (base::isError(response))
        {
            LOG_WARNING("[Store] Failed to read start status document '{}': {}. Recreating it",
                        document.fullName(),
                        base::getError(response).message);
            initializeStatus = true;
        }
        else
        {
            status = std::move(base::getResponse(response));
            std::string firstStartTimestamp;
            initializeStatus = !status.isObject()
                               || status.getString(firstStartTimestamp, "/first_start") != json::RetGet::Success
                               || firstStartTimestamp.empty();

            if (initializeStatus)
            {
                LOG_WARNING("[Store] Invalid start status document '{}'. Recreating it", document.fullName());
            }
        }
    }

    if (initializeStatus)
    {
        status.setObject();
        status.setString(timestamp, "/first_start");
    }

    status.setString(timestamp, "/last_start");
    if (const auto error = store->upsertDoc(document, status); base::isError(error))
    {
        LOG_WARNING("[Store] Failed to persist start status document '{}': {}", document.fullName(), error->message);
        return false;
    }

    return firstStart;
}

} // namespace store::utils
