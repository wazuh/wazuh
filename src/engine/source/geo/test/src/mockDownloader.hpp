#ifndef _GEO_MOCK_DOWNLOADER_HPP
#define _GEO_MOCK_DOWNLOADER_HPP

#include <gmock/gmock.h>

#include <geo/idownloader.hpp>

namespace geo::mocks
{
class MockDownloader : public IDownloader
{
public:
    MOCK_METHOD((base::RespOrError<std::string>), downloadHTTPS, (const std::string& url), (const override));
    MOCK_METHOD(std::string, computeMD5, (const std::string& data), (const override));
    MOCK_METHOD(base::RespOrError<std::string>, downloadMD5, (const std::string& url), (const override));
};
} // namespace geo::mocks
#endif // _GEO_MOCK_DOWNLOADER_HPP
