#ifndef _IWINDEXER_CONNECTOR_HPP
#define _IWINDEXER_CONNECTOR_HPP

#include <string>

namespace wiconnector
{
class IWIndexerConnector
{

public:
    virtual ~IWIndexerConnector() = default;

    virtual void index(std::string_view index, std::string_view data) = 0;
};

} // namespace wiconnector
#endif // _IINDEXER_CONNECTOR_HPP
