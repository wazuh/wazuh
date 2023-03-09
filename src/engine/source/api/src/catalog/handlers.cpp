
#include "api/catalog/handlers.hpp"

#include <json/json.hpp>
#include <eMessages/eMessage.h>
#include <eMessages/catalog.pb.h>

#include <api/adapter.hpp>

namespace api::catalog::handlers
{

namespace eCatalog = ::com::wazuh::api::engine::catalog;
namespace eEngine = ::com::wazuh::api::engine;

api::Handler resourcePost(std::shared_ptr<Catalog> catalog)
{
    return [catalog](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourcePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_type()      ? std::make_optional("Missing /type parameter or is invalid")
                           : !eRequest.has_format()  ? std::make_optional("Missing /format parameter or is invalid")
                           : !eRequest.has_content() ? std::make_optional("Missing /content parameter")
                                                     : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {Resource::typeToStr(eRequest.type())};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = catalog->postResource(targetResource, eRequest.content());
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler resourceGet(std::shared_ptr<Catalog> catalog)
{
    return [catalog](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourceGet_Request;
        using ResponseType = eCatalog::ResourceGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_name()     ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_format()  ? std::make_optional("Missing or invalid /format parameter")
                                                    : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        auto query = catalog->getResource(targetResource);
        if (std::holds_alternative<base::Error>(query))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(query).message);
        }
        const auto& content = std::get<std::string>(query);
        ResponseType eResponse;
        eResponse.set_content(content);
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

api::Handler resourceDelete(std::shared_ptr<Catalog> catalog)
{
    return [catalog](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourceDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the name
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name parameter");
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format("Invalid /name parameter: {}", e.what()));
        }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, catalog::Resource::Format::json};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        auto error = catalog->deleteResource(targetResource);
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler resourcePut(std::shared_ptr<Catalog> catalog)
{
    return [catalog](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourcePut_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_name()      ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_format()  ? std::make_optional("Missing or invalid /format parameter")
                           : !eRequest.has_content() ? std::make_optional("Missing /content parameter")
                                                     : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = catalog->putResource(targetResource, eRequest.content());
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler resourceValidate(std::shared_ptr<Catalog> catalog)
{
    return [catalog](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eCatalog::ResourceValidate_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Validate the params request
        const auto error = !eRequest.has_name()      ? std::make_optional("Missing /name parameter")
                           : !eRequest.has_format()  ? std::make_optional("Missing or invalid /format parameter")
                           : !eRequest.has_content() ? std::make_optional("Missing /content parameter")
                                                     : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        // Validate the name
        base::Name name;
        try
        {
            name = base::Name {eRequest.name()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(std::string {"Invalid /name parameter:"} + e.what());
        }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, eRequest.format()};
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        const auto invalid = catalog->validateResource(targetResource, eRequest.content());
        if (invalid)
        {
            return ::api::adapter::genericError<ResponseType>(invalid.value().message);
        }

        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

void registerHandlers(std::shared_ptr<Catalog> catalog, std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerHandler("catalog.resource/post", resourcePost(catalog));
        registry->registerHandler("catalog.resource/get", resourceGet(catalog));
        registry->registerHandler("catalog.resource/put", resourcePut(catalog));
        registry->registerHandler("catalog.resource/delete", resourceDelete(catalog));
        registry->registerHandler("catalog.resource/validate", resourceValidate(catalog));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("An error occurred while registering the commands: {}", e.what()));
    }
}
} // namespace api::catalog::handlers
