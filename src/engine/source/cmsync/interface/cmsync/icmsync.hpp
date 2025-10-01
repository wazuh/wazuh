#ifndef _CM_SYNC_ICSYNC
#define _CM_SYNC_ICSYNC

#include <cstdint>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

#include <ctistore/icmreader.hpp>

namespace cm::sync
{

/**
 * @brief Interface for Content Manager Synchronization operations
 * 
 * This interface defines the contract for Content Manager synchronization implementations.
 * Classes implementing this interface are responsible for coordinating the deployment
 * of content from Content Manager stores to various engine components.
 * 
 * The interface provides a standardized way to handle content deployment operations
 * across different implementations while maintaining consistency in the API.
 */
class ICMSync
{
public:
    /**
     * @brief Virtual destructor for proper cleanup of derived classes
     */
    virtual ~ICMSync() = default;

    /**
     * @brief Deploys content from a Content Manager store to engine components
     *
     * @param ctiStore Shared pointer to the Content Manager reader interface
     * @throws std::invalid_argument If ctiStore is null
     * @throws std::runtime_error If deployment operations fail
     */
    virtual void deploy(const std::shared_ptr<cti::store::ICMReader>& ctiStore) = 0;
};

} // namespace cm::sync

#endif // _CM_SYNC_ICSYNC
