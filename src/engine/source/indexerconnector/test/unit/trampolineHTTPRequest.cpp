#include "trampolineHTTPRequest.hpp"

std::shared_ptr<httprequest::mock::MockHTTPRequest> spHTTPRequest =
    std::make_shared<httprequest::mock::MockHTTPRequest>();
