#include "HTTPRequest.hpp"
#include <gmock/gmock.h>

#ifndef _MOCK_HTTP_REQUEST_HPP
#define _MOCK_HTTP_REQUEST_HPP

namespace httprequest::mock
{
/**
 * @brief Mock class for HTTPRequest using Google Mock.
 */
class MockHTTPRequest : public IURLRequest
{
public:
    /**
     * @brief Mock method for performing an HTTP DOWNLOAD request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    MOCK_METHOD(void,
                download,
                (RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    /**
     * @brief Mock method for performing an HTTP POST request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    MOCK_METHOD(void,
                post,
                (RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    /**
     * @brief Mock method for performing an HTTP GET request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    MOCK_METHOD(void,
                get,
                (RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    /**
     * @brief Mock method for performing an HTTP PUT request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    MOCK_METHOD(void,
                put,
                (RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    /**
     * @brief Mock method for performing an HTTP PATCH request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    MOCK_METHOD(void,
                patch,
                (RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));

    /**
     * @brief Mock method for performing an HTTP DELETE request.
     *
     * @param requestParameters Parameters to be used in the request. Mandatory.
     * @param postRequestParameters Parameters that define the behavior after the request is made.
     * @param configurationParameters Parameters to configure the behavior of the request.
     */
    MOCK_METHOD(void,
                delete_,
                (RequestParameters requestParameters,
                 PostRequestParameters postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
};
} // namespace httprequest::mock
#endif // _MOCK_HTTP_REQUEST_HPP
