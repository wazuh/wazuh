#ifndef _API_ADAPTER_HELPERS_HPP
#define _API_ADAPTER_HELPERS_HPP

#include <functional>
#include <optional>
#include <string_view>

#include <fmt/format.h>

#include <api/adapter/adapter.hpp>
#include <base/name.hpp>

namespace api::adapter::helpers
{
template<typename T>
using PropGetter = std::function<T()>;

template<typename Res, typename T>
ResOrErrorResp<T> tryGetProperty(bool exists, PropGetter<T> propGetter, std::string_view field, std::string_view prop)
{
    if (exists)
    {
        try
        {
            return propGetter();
        }
        catch (const std::exception& e)
        {
            return Error {userErrorResponse<Res>(fmt::format("Invalid {} {}: {}", field, prop, e.what()))};
        }
    }
    return Error {userErrorResponse<Res>(fmt::format("Missing /{}", field))};
}

} // namespace api::adapter::helpers

#endif // _API_ADAPTER_HELPERS_HPP
