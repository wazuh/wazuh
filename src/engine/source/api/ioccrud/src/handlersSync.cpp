
#include <api/ioccrud/handlers.hpp>

namespace api::ioccrud::handlers
{
adapter::RouteHandler syncIoc(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager)
{
    return [weakKvdbManager = std::weak_ptr<::kvdbioc::IKVDBManager>(kvdbManager)](const httplib::Request& req,
                                                                                   httplib::Response& res)
    {
        // TODO
        res.status = httplib::StatusCode::OK_200;
        res.set_content("IOC sync successful", "text/plain");
    };
}

} // namespace api::ioccrud::handlers
