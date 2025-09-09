
#include <external/nlohmann/json.hpp>

#include "indexerConnector.hpp"

#include <indexerConnector/wIndexerConnector.hpp>

namespace wiconnector
{
WIndexerConnector::WIndexerConnector(std::string_view host, int port)
{
    nlohmann::json config {};
}
}; // namespace wiconnector
