#ifndef REMOTECONF_ISETTINGSSOURCE_HPP
#define REMOTECONF_ISETTINGSSOURCE_HPP

#include <string>

#include <base/json.hpp>

namespace remoteconf
{

enum class FetchStatus
{
    Success,
    NotFound,
    TransportError,
    InvalidPayload
};

inline const char* toString(FetchStatus status)
{
    switch (status)
    {
        case FetchStatus::Success: return "Success";
        case FetchStatus::NotFound: return "NotFound";
        case FetchStatus::TransportError: return "TransportError";
        case FetchStatus::InvalidPayload: return "InvalidPayload";
        default: return "Unknown";
    }
}

struct SettingsFetchResult
{
    FetchStatus status;
    json::Json source; // Valid only when status == Success
    std::string error; // Optional diagnostic message
};

class ISettingsSource
{
public:
    virtual ~ISettingsSource() = default;

    /**
     * @brief Fetches settings document from the authoritative source.
     *
     * Never throws: failures are encoded in the returned status.
     */
    virtual SettingsFetchResult fetchSettings() = 0;
};

} // namespace remoteconf

#endif // REMOTECONF_ISETTINGSSOURCE_HPP
