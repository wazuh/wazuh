#ifndef _CMSYNC_CMSYNC
#define _CMSYNC_CMSYNC

#include <string>

#include <wiconnector/iwindexerconnector.hpp>
#include <cmstore/icmstore.hpp>

#include <cmsync/icmsync.hpp>


namespace cm::sync
{

class CMSync : public ICMSync
{

private:
    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerPtr; ///< Indexer connector resource
    std::weak_ptr<cm::store::ICMStore> m_cmstorePtr;             ///< Resource namespace handler

    std::mutex m_mutex;                                          ///< Only one sync at a time
    std::size_t m_attemps = 3;     ///< Number of attempts to connect or retry operations before failing
    std::size_t m_waitSeconds = 5; ///< Seconds to wait between attempts

public:
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::store::ICMStore>& cmstorePtr)
        : m_indexerPtr(indexerPtr)
        , m_cmstorePtr(cmstorePtr)
        , m_mutex()
        , m_attemps(3)
        , m_waitSeconds(5)

    {
    }

    void downloadNamespace(std::string_view originSpace, std::string_view destNamespace);
};

} // namespace cm::sync

#endif // _CMSYNC_CMSYNC
