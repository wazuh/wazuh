#include "scanOrchestrator.hpp"
#include "base/logging.hpp"
#include "factoryOrchestrator.hpp"
#include "scanContext.hpp"

static const std::map<std::string, PayloadType, std::less<>> SCAN_TYPE {{"packagelist", PayloadType::PackageList},
                                                                        {"fullscan", PayloadType::FullScan}};

ScanOrchestrator::ScanOrchestrator(const std::string& configuration)
{
    // Database feed manager initialization.
    m_databaseFeedManager = std::make_shared<DatabaseFeedManager>(m_mutex);

    // Configuration initialization.
    m_configuration = nlohmann::json::parse(configuration, nullptr, false);
    if (m_configuration.is_discarded())
    {
        throw std::invalid_argument("Invalid configuration");
    }
}

void ScanOrchestrator::processEvent(const std::string& request, std::string& response) const
{
    const auto& requestDeserialized = nlohmann::json::parse(request);
    const auto& scanType = requestDeserialized.at("type").get_ref<const std::string&>();
    run(SCAN_TYPE.at(scanType), requestDeserialized, response);

    LOG_DEBUG("Event type: {} processed", scanType);
}

void ScanOrchestrator::run(const PayloadType type, const nlohmann::json& request, std::string& response) const
{
    auto static osScan = FactoryOrchestrator::create(ScannerType::Os, m_databaseFeedManager);
    auto static packageScan = FactoryOrchestrator::create(ScannerType::Package, m_databaseFeedManager);

    // This locks the mutex to avoid scanning during the feed update processing.
    std::shared_lock lock(m_mutex);
    nlohmann::json responseJson;

    if (type == PayloadType::FullScan)
    {
        osScan->handleRequest(std::make_shared<ScanContext>(
            ScannerType::Os, request.at("agent"), request.at("os"), nullptr, request.at("hotfixes"), responseJson));

        for (const auto& package : request.at("packages"))
        {
            packageScan->handleRequest(std::make_shared<ScanContext>(ScannerType::Package,
                                                                     request.at("agent"),
                                                                     request.at("os"),
                                                                     package,
                                                                     request.at("hotfixes"),
                                                                     responseJson));
        }
    }
    else if (type == PayloadType::PackageList)
    {
        for (const auto& package : request.at("packages"))
        {
            packageScan->handleRequest(std::make_shared<ScanContext>(ScannerType::Package,
                                                                     request.at("agent"),
                                                                     request.at("os"),
                                                                     package,
                                                                     request.at("hotfixes"),
                                                                     responseJson));
        }
    }
    else
    {
        throw std::invalid_argument("Invalid scan type");
    }

    response = responseJson.dump();
}
