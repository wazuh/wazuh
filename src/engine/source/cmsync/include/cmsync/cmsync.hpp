#ifndef _CMSYNC_CMSYNC
#define _CMSYNC_CMSYNC

#include <string>

#include <wiconnector/iwindexerconnector.hpp>
#include <cmcrud/icmcrudservice.hpp>


#include <cmsync/icmsync.hpp>


namespace cm::sync
{

class CMSync : public ICMSync
{

private:
    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerPtr; ///< Indexer connector resource
    std::weak_ptr<cm::crud::ICrudService> m_cmcrudPtr;           ///< Resource namespace handler

    std::mutex m_mutex;        ///< Only one sync at a time
    std::size_t m_attemps;     ///< Number of attempts to connect or retry operations before failing
    std::size_t m_waitSeconds; ///< Seconds to wait between attempts

    /**
     * @brief Download a full namespace from the indexer to the local cmcrud store
     *
     * @param originSpace Define the source space in the indexer
     * @param destNamespace Define the destination namespace in the local store (Must not exist)
     * @throws std::runtime_error on errors.
     */
    void downloadNamespace(std::string_view originSpace, std::string_view destNamespace);

public:
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::crud::ICrudService>& cmcrudPt)
        : m_indexerPtr(indexerPtr)
        , m_cmcrudPtr(cmcrudPt)
        , m_mutex()
        , m_attemps(3)
        , m_waitSeconds(5)

    {
    }

    
};

} // namespace cm::sync

#endif // _CMSYNC_CMSYNC
