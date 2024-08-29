#ifndef _MOCK_DATA_HUB_EXPORTER_HPP
#define _MOCK_DATA_HUB_EXPORTER_HPP

#include <gmock/gmock.h>

#include <metrics/iDataHub.hpp>

class MockDataHubExporter : public metricsManager::IDataHub
{
public:
    MOCK_METHOD(void, setResource, (const std::string&, const json::Json&), (override));
};

#endif //_MOCK_DATA_HUB_EXPORTER_HPP
